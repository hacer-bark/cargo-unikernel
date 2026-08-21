//! Mandatory seccomp denylist installed on the app child process. Never on PID 1 itself, which
//! still needs `mount()`/`reboot()`.
//!
//! Two independently-installed filters, stacked: Linux seccomp filters all run for every
//! syscall, and the kernel takes the *most restrictive* result across them. That means each
//! filter only has to get its own, narrow job right:
//!
//! - [`install_arch_gate`]: a tiny, hand-rolled classic-BPF program — 6 instructions, no
//!   denylist — that kills anything arriving via the wrong syscall ABI (`AUDIT_ARCH_X86_64`
//!   mismatch, or the x32 ABI's `__X32_SYSCALL_BIT`). No published crate covers this check: it
//!   isn't a filter *rule* in the usual sense, it's a property of the raw syscall number itself,
//!   and every general-purpose seccomp library we could find (including [`seccompiler`], see
//!   below) leaves it to the caller. Small and static enough to hand-verify, and covered by
//!   kernel-exercised tests below.
//! - [`build_baseline_denylist`] / [`install_baseline_denylist`]: the actual per-syscall
//!   denylist, built and compiled to BPF by [`seccompiler`] (`rust-vmm`, the same crate
//!   Firecracker uses for its own seccomp jailing) rather than hand-rolled — the classic-BPF
//!   jump-table arithmetic that construction needs is exactly the kind of thing worth trusting
//!   to a battle-tested implementation instead of one more hand-rolled copy.
//!
//! Because a *filter* here always means "kill on match, otherwise allow", the two compose
//! correctly regardless of install order: an x32-tagged syscall is killed by the arch gate
//! before the denylist's checks (which don't know about x32 at all) are even relevant.
//!
//! Denylist rather than allowlist: a wrong allowlist silently breaks every app this tool
//! builds, which is worse than "not exhaustive." Each entry has no legitimate use in a
//! single-purpose server and kills the process on first attempt; the watchdog then reboots
//! the VM. `clone`/`fork`/`execve` stay unrestricted — most real servers need threads.
//!
//! Three things this filter deliberately does not deny outright, and what covers them instead:
//! - `execve`/`execveat`: installed via `pre_exec`, so the next syscall the child makes *is*
//!   the exec that starts it. The write half of "drop and run a new binary" is denied instead
//!   ([`WRITE_EXECUTE_SYSCALLS`]); `[app.runtime.danger].allow_write_execute` lifts it.
//! - namespace creation via `clone`/`clone3`: can't deny without breaking thread creation.
//!   `unshare`/`setns` are denied here; `CONFIG_NAMESPACES=n` (legacy-subsystems.config)
//!   closes the `clone3` path at the kernel level.
//! - `prctl`: has ordinary uses (`PR_SET_NAME`, `PR_SET_PDEATHSIG`) that runtimes and
//!   allocators make on startup, so denying the syscall would break real apps. The consequence
//!   is that an app can clear its own `PR_SET_DUMPABLE`; what that would buy — reading its
//!   memory through `/proc` — is closed separately by `yama ptrace_scope=3`, the
//!   `ptrace`/`process_vm_readv`/`process_vm_writev` entries below, `CONFIG_PROC_MEM_NO_FORCE=y`
//!   and `CONFIG_COREDUMP=n`. Filtering it by argument instead is possible but needs 64-bit
//!   argument comparison in classic BPF for one bit of defense-in-depth that four other
//!   mechanisms already hold.
//!
//! `io_uring` is denied for a reason worth stating: its whole point is submitting operations
//! through a shared ring rather than as syscalls, so a filter like this one structurally cannot
//! see what a ring performs. `CONFIG_IO_URING=disable` (legacy-subsystems.config) also closes
//! it, but that file documents re-enabling it via `extra_kernel_config` — without the entries
//! below, doing so would silently forfeit every other denial in this list.
//!
//! Both filters are exercised against the kernel the tests run on — `the_kernel_accepts_the_*` /
//! `a_denied_syscall_actually_kills_the_process` / `an_x32_tagged_syscall_is_killed_by_the_arch_gate`
//! fork a child, install both filters exactly as `spawn_app` does, and check the outcome. That
//! covers the encoding, not the boot path: the filters have not yet been exercised inside a
//! booted guest.

#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "cargo-unikernel-init's seccomp filter is x86_64-only (see AUDIT_ARCH_X86_64 below)"
);

use std::io;

/// Mirrors `struct sock_filter` from `linux/filter.h` bit-for-bit, defined locally rather than
/// trusting `libc` to export it under this exact name for every target.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// Mirrors `struct sock_fprog` from `linux/filter.h`.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

/// `offsetof(struct seccomp_data, nr)` — always 0, it's the first field.
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
/// `offsetof(struct seccomp_data, arch)` — the `u32` right after `nr`.
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

/// `AUDIT_ARCH_X86_64` from `linux/audit.h`. Without gating every syscall check on this, the
/// filter is bypassable via the legacy 32-bit syscall entry point (`int 0x80`), where the same
/// raw number maps to a different syscall than on the 64-bit ABI.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `__X32_SYSCALL_BIT` from `asm/unistd.h`.
///
/// The arch gate above is necessary but *not* sufficient: x32 reports `AUDIT_ARCH_X86_64` too,
/// and distinguishes itself only by setting this bit in the syscall number. So `ptrace` arrives
/// as `0x4000_0065`, matches no denylist entry, and would fall through to `ALLOW` — one bit
/// lifting every denial in this file at once. This is a well-documented class of seccomp
/// bypass (see e.g. the `firejail` and `kafel` issue trackers) that generic seccomp-BPF
/// compilers, `seccompiler` included, leave to the caller rather than handle for every user.
///
/// `CONFIG_X86_X32_ABI=disable` (legacy-subsystems.config) closes it at the kernel level, but
/// that whole fragment is opt-out via `hardening.kernel.disable_legacy_subsystems = false`, so
/// this filter cannot delegate the guarantee to it — the same reasoning that puts the
/// `io_uring` entry points in the denylist despite `CONFIG_IO_URING=disable`.
///
/// Checked with `JGE` rather than a bit test: classic BPF has no `AND`-and-branch, and every
/// legitimate 64-bit syscall number is far below this value, so "greater or equal" covers the
/// x32 range and the `0xFFFF_FFFF`-style invalid numbers above it in one instruction.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// The whole of the arch/x32-ABI gate: load `arch`, kill unless it's `AUDIT_ARCH_X86_64`; load
/// `nr`, kill if the x32 bit is set; otherwise allow (leaving the actual decision to whichever
/// other filter is stacked behind this one — see the module doc). Six fixed instructions, so
/// this is written as literals rather than built by a loop: there is no per-syscall list here
/// for a loop to iterate over.
const ARCH_GATE_PROGRAM: [SockFilter; 6] = [
    SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH_OFFSET,
    },
    // Falls through (jt = 0) to the nr load on a match; on any other ABI, jumps to KILL
    // (index 5), relative to the instruction after this one (index 2): jf = 5 - 2 = 3.
    SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: 3,
        k: AUDIT_ARCH_X86_64,
    },
    SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    },
    // Jumps to KILL (index 5) for anything at or above the x32 bit, relative to the instruction
    // after this one (index 4): jt = 5 - 4 = 1. Falls through to ALLOW otherwise.
    SockFilter {
        code: BPF_JMP | BPF_JGE | BPF_K,
        jt: 1,
        jf: 0,
        k: X32_SYSCALL_BIT,
    },
    SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    },
    SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    },
];

// PR_SET_SECCOMP = 22 — hardcoded rather than trusting `libc` to export the name for every
// target; a long-stable uapi constant (linux/prctl.h).
const PR_SET_SECCOMP: libc::c_int = 22;

/// Installs [`ARCH_GATE_PROGRAM`] on the *calling* process via the classic `prctl(PR_SET_SECCOMP,
/// …)` interface — the older sibling of the `seccomp(2)` syscall `seccompiler` uses internally,
/// equally valid, and all this six-instruction program needs.
///
/// Call only from inside a `Command::pre_exec` closure, never from PID 1 itself.
/// `PR_SET_NO_NEW_PRIVS` is required by the kernel before any unprivileged `seccomp()`/`prctl()`
/// call succeeds; installing it twice (once here, once inside `seccompiler::apply_filter`) is
/// harmless — the flag is one-way and idempotent. Allocation-free and syscall-only, as anything
/// running between `fork()` and `execve()` must be: [`ARCH_GATE_PROGRAM`] is a `const`, so this
/// is a `.rodata` blob the installer just points at.
#[allow(clippy::as_conversions)]
fn install_arch_gate() -> io::Result<()> {
    const _: () = assert!(ARCH_GATE_PROGRAM.len() == 6);
    let fprog = SockFprog {
        len: 6,
        filter: ARCH_GATE_PROGRAM.as_ptr(),
    };

    // SAFETY: `fprog` outlives the call (a stack local; its raw pointer is only read for the
    // syscall's duration) and points at a `'static` program. Both return values are checked.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            std::ptr::addr_of!(fprog) as libc::c_ulong,
            0,
            0,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// `memfd_create`/`memfd_secret` + `execveat(fd, "", AT_EMPTY_PATH)` runs an anonymous
/// in-memory *binary*, invisible to every `noexec` mount flag in `mounts.rs`. This is what
/// `[app.runtime.danger].allow_write_execute` actually gates — see `mounts.rs` for the other
/// half (the writable mounts themselves).
///
/// Denying these closes the "drop a file and exec it" route, not anonymous executable memory in
/// general: `mmap`/`mprotect` with `PROT_WRITE|PROT_EXEC` stay allowed, since filtering their
/// protection argument breaks every JIT and several allocators. Shellcode in an RWX mapping is
/// out of scope for this filter; running a whole new program image is not.
#[cfg(not(feature = "danger-allow-write-execute"))]
const WRITE_EXECUTE_SYSCALLS: &[i64] = &[libc::SYS_memfd_create, libc::SYS_memfd_secret];
#[cfg(feature = "danger-allow-write-execute")]
const WRITE_EXECUTE_SYSCALLS: &[i64] = &[];

/// Only ever installed from inside a `Command::pre_exec` closure for a child — inherited by
/// anything that child itself forks/execs, since seccomp filters survive both.
const BASELINE_SYSCALLS: &[i64] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    libc::SYS_open_by_handle_at,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_acct,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    libc::SYS_personality,
    libc::SYS_bpf,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_kcmp,
    libc::SYS_move_pages,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
];

/// Builds the compiled BPF program for the baseline denylist. Must be called *before* `fork()`
/// — `seccompiler::SeccompFilter::new` allocates (its rule map is a `BTreeMap`), which is unsound
/// to do between `fork()` and `execve()` in a process with other threads: an allocator lock
/// another thread held at fork time is never released in the forked child, so the next
/// allocation there can deadlock. `fatal` is called (and never returns) if construction fails,
/// which given the fixed inputs here only a bug in this crate could cause.
///
/// Call once in the parent (see `main.rs::spawn_app`), then move the result into the
/// `pre_exec` closure that calls [`install_baseline_denylist`] — which performs no allocation of
/// its own, satisfying the fork/exec constraint from the other side.
pub(crate) fn build_baseline_denylist(fatal: fn(&str) -> !) -> seccompiler::BpfProgram {
    let rules = BASELINE_SYSCALLS
        .iter()
        .chain(WRITE_EXECUTE_SYSCALLS)
        .map(|&nr| (nr, Vec::new()))
        .collect();

    let filter = seccompiler::SeccompFilter::new(
        rules,
        seccompiler::SeccompAction::Allow,
        seccompiler::SeccompAction::KillProcess,
        seccompiler::TargetArch::x86_64,
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to build the seccomp denylist filter: {e}")));

    seccompiler::BpfProgram::try_from(filter)
        .unwrap_or_else(|e| fatal(&format!("Failed to compile the seccomp denylist to BPF: {e}")))
}

/// Installs [`install_arch_gate`]'s six-instruction ABI gate, then `program` (from
/// [`build_baseline_denylist`]) as a second, independently-consulted filter — Linux seccomp
/// filters stack, and the kernel takes the most restrictive result across all of them, so an
/// x32-tagged syscall never reaches the second filter's checks at all.
///
/// Call only from inside a `Command::pre_exec` closure, never from PID 1 itself.
///
/// # Errors
///
/// Returns an error if installing either filter fails.
pub(crate) fn install_baseline_denylist(program: &seccompiler::BpfProgram) -> io::Result<()> {
    install_arch_gate()?;
    seccompiler::apply_filter(program).map_err(io::Error::other)
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::as_conversions
)]
mod tests {
    use super::*;

    #[test]
    fn arch_gate_starts_with_an_arch_check_before_loading_the_syscall_number() {
        let arch_load = &ARCH_GATE_PROGRAM[0];
        assert_eq!(arch_load.code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(arch_load.k, SECCOMP_DATA_ARCH_OFFSET);

        let arch_check = &ARCH_GATE_PROGRAM[1];
        assert_eq!(arch_check.code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(arch_check.k, AUDIT_ARCH_X86_64);
        assert_eq!(
            arch_check.jt, 0,
            "must fall through to the nr load on a match"
        );
        assert_eq!(
            2 + arch_check.jf as usize,
            5,
            "mismatched arch must jump to the KILL instruction (index 5)"
        );

        let nr_load = &ARCH_GATE_PROGRAM[2];
        assert_eq!(nr_load.code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(nr_load.k, SECCOMP_DATA_NR_OFFSET);
    }

    /// x32 shares `AUDIT_ARCH_X86_64`, so the arch check alone lets it through — without this
    /// instruction the whole gate is one ABI away from being a no-op.
    #[test]
    fn arch_gate_kills_the_x32_abi() {
        let x32_gate = &ARCH_GATE_PROGRAM[3];
        assert_eq!(x32_gate.code, BPF_JMP | BPF_JGE | BPF_K);
        assert_eq!(x32_gate.k, X32_SYSCALL_BIT);
        assert_eq!(
            x32_gate.jf, 0,
            "an ordinary 64-bit number must fall through to ALLOW"
        );
        assert_eq!(
            4 + x32_gate.jt as usize,
            5,
            "an x32 number must jump to the KILL instruction (index 5)"
        );
    }

    #[test]
    fn arch_gate_ends_with_allow_then_kill() {
        assert_eq!(ARCH_GATE_PROGRAM[4].code, BPF_RET | BPF_K);
        assert_eq!(ARCH_GATE_PROGRAM[4].k, SECCOMP_RET_ALLOW);
        assert_eq!(ARCH_GATE_PROGRAM[5].code, BPF_RET | BPF_K);
        assert_eq!(ARCH_GATE_PROGRAM[5].k, SECCOMP_RET_KILL_PROCESS);
    }

    fn denied() -> Vec<i64> {
        BASELINE_SYSCALLS
            .iter()
            .chain(WRITE_EXECUTE_SYSCALLS)
            .copied()
            .collect()
    }

    #[test]
    fn denylist_has_no_duplicate_syscalls() {
        let mut sorted = denied();
        sorted.sort_unstable();
        let mut deduped = sorted.clone();
        deduped.dedup();
        assert_eq!(deduped.len(), sorted.len(), "denylist has a duplicate");
    }

    /// The `mount(2)`-free mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`) is a complete
    /// second path to the same result if left open.
    #[test]
    fn denylist_covers_the_mount_free_mount_api() {
        let denied = denied();
        for syscall in [
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_move_mount,
            libc::SYS_open_tree,
            libc::SYS_mount_setattr,
        ] {
            assert!(
                denied.contains(&syscall),
                "syscall {syscall} must be denied — the mount API is only closed as a set"
            );
        }
    }

    /// A ring performs its operations without issuing the corresponding syscalls, so leaving
    /// any one of these open would hand back everything else this filter denies.
    #[test]
    fn denylist_covers_the_io_uring_entry_points() {
        let denied = denied();
        for syscall in [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert!(
                denied.contains(&syscall),
                "syscall {syscall} must be denied — io_uring bypasses seccomp by design"
            );
        }
    }

    /// `noexec` mount flags cannot see an anonymous in-memory file, so this is what actually
    /// backs the "no writable+executable paths remain" claim in the default build. Scoped to
    /// executing a new program image — anonymous RWX memory itself is not denied, see
    /// [`WRITE_EXECUTE_SYSCALLS`].
    #[test]
    #[cfg(not(feature = "danger-allow-write-execute"))]
    fn denylist_blocks_executing_a_new_program_image_from_memory_by_default() {
        let denied = denied();
        assert!(denied.contains(&libc::SYS_memfd_create));
        assert!(denied.contains(&libc::SYS_memfd_secret));
    }

    /// The mirror of the test above: opting into `danger-allow-write-execute` is opting into
    /// exactly this capability, so killing the process for using it would be incoherent.
    #[test]
    #[cfg(feature = "danger-allow-write-execute")]
    fn danger_allow_write_execute_permits_anonymous_executable_memory() {
        let denied = denied();
        assert!(!denied.contains(&libc::SYS_memfd_create));
        assert!(!denied.contains(&libc::SYS_memfd_secret));
    }

    /// `execve`/`execveat` must stay allowed: this filter is installed in a `pre_exec` closure,
    /// so denying either would kill every child at the exec that starts it.
    #[test]
    fn denylist_never_blocks_the_exec_that_follows_it() {
        let denied = denied();
        assert!(!denied.contains(&libc::SYS_execve));
        assert!(!denied.contains(&libc::SYS_execveat));
    }

    fn never_returns(_: &str) -> ! {
        panic!("build_baseline_denylist should not fail for this crate's fixed inputs")
    }

    /// Runs `body` in a forked child that has both filters installed exactly as `spawn_app`
    /// does, and reports how it died.
    ///
    /// The array assertions above check the arch gate's jump arithmetic against the encoding
    /// this file believes in; only the kernel can say whether it — and the filter
    /// `seccompiler` compiles — actually behave that way once installed. The child touches only
    /// syscalls between `fork()` and `_exit()`, so the usual fork-in-a-threaded-process
    /// constraint is satisfied; the denylist itself is built before the fork, per
    /// [`build_baseline_denylist`]'s own requirement.
    fn exit_status_under_both_filters(body: impl FnOnce()) -> libc::c_int {
        let program = build_baseline_denylist(never_returns);
        // SAFETY: the child path below calls only async-signal-safe syscalls and never returns
        // to the test harness; the parent only waits on the pid it just created.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                if install_baseline_denylist(&program).is_err() {
                    libc::_exit(97);
                }
                body();
                libc::_exit(0);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0), pid);
            status
        }
    }

    #[test]
    fn the_kernel_accepts_both_filters_and_allows_an_undenied_syscall() {
        let status = exit_status_under_both_filters(|| {
            // SAFETY: `getpid` takes no arguments and cannot fail.
            unsafe {
                libc::getpid();
            }
        });
        assert!(
            libc::WIFEXITED(status),
            "child died instead of exiting — the kernel rejected a filter, or a jump lands on \
             KILL for a syscall that isn't denied"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "97 means installing one of the filters failed outright"
        );
    }

    #[test]
    fn a_denied_syscall_actually_kills_the_process() {
        // `personality` is denied, takes one harmless argument, and has no side effect worth
        // caring about in a child that is about to die either way.
        let status = exit_status_under_both_filters(|| {
            // SAFETY: a plain integer argument, no pointers. Never returns — the filter's
            // `SECCOMP_RET_KILL_PROCESS` takes the process down at the syscall boundary.
            unsafe {
                libc::syscall(libc::SYS_personality, 0xffff_ffff_u64);
            }
        });
        assert!(
            libc::WIFSIGNALED(status),
            "denied syscall returned instead of killing the process — the filter is inert"
        );
        // `SECCOMP_RET_KILL_PROCESS` kills without running a handler, but the wait status still
        // reports `SIGSYS` as the terminating signal, not `SIGKILL`.
        assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
    }

    /// The whole point of stacking the two filters: `personality` isn't on the denylist under
    /// its x32-tagged number (`seccompiler`'s compiled filter only ever compares the plain
    /// 64-bit numbers in [`BASELINE_SYSCALLS`]), so if this test passed only because of the
    /// denylist, removing the arch gate would silently reopen every entry in it via x32.
    #[test]
    fn an_x32_tagged_syscall_is_killed_by_the_arch_gate_not_the_denylist() {
        let status = exit_status_under_both_filters(|| {
            // SAFETY: a plain integer argument, no pointers. `getpid` is never denied by the
            // denylist under either number — if this dies, it's the arch gate's x32 check.
            unsafe {
                libc::syscall(libc::SYS_getpid | i64::from(X32_SYSCALL_BIT));
            }
        });
        assert!(
            libc::WIFSIGNALED(status),
            "an x32-tagged syscall number must be killed by the arch gate, even for a syscall \
             that's otherwise always allowed"
        );
        assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
    }
}
