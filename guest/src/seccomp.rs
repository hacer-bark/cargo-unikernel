//! Mandatory classic-BPF seccomp denylist installed on the app child process. Never on PID 1
//! itself, which still needs `mount()`/`reboot()`.
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
//! The BPF construction (arch gate, x32 gate, jump encoding, terminal ALLOW/KILL) is exercised
//! against the kernel the tests run on — `the_kernel_accepts_the_filter_*` /
//! `a_denied_syscall_actually_kills_the_process` fork a child, install this exact program, and
//! check both halves of it. That covers the encoding, not the boot path: the filter has not yet
//! been exercised inside a booted guest.

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
/// as `0x4000_0065`, matches none of the `JEQ`s below, and falls through to `RET ALLOW` — one
/// bit lifting every denial in this file at once.
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

const DENIED_LEN: usize = BASELINE_SYSCALLS.len() + WRITE_EXECUTE_SYSCALLS.len();
/// Total filter length: 2 (arch load + check) + 2 (nr load + x32 gate) + one `JEQ` per denied
/// syscall + 2 (`RET ALLOW`, `RET KILL`).
const PROGRAM_LEN: usize = DENIED_LEN + 6;

/// `PROGRAM_LEN` is `DENIED_LEN + 6`, and [`PROGRAM`] encodes the KILL instruction's index in a
/// `u8`, so `DENIED_LEN + 5` must still fit one — 250 is the real ceiling, not 255. Checked at
/// compile time rather than at boot: a denylist that outgrew the encoding would otherwise
/// build a silently-truncated, broken filter, and refusing to *compile* beats refusing to boot.
const _: () = assert!(
    DENIED_LEN <= 250,
    "seccomp denylist has outgrown the classic-BPF u8 jump field"
);

/// The two source lists flattened into one array, so [`PROGRAM`] can index it in const context.
///
/// Every index below is in bounds as a direct consequence of the `while` conditions guarding
/// it (`i < BASELINE_SYSCALLS.len()`, then `j < WRITE_EXECUTE_SYSCALLS.len()` with `i` fixed at
/// `BASELINE_SYSCALLS.len()`, and `DENIED_LEN` defined as their sum) — and this all runs at
/// compile time, so a bound that ever did slip would fail the build, not the running guest.
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]
const DENIED: [i64; DENIED_LEN] = {
    let mut out = [0i64; DENIED_LEN];
    let mut i = 0;
    while i < BASELINE_SYSCALLS.len() {
        out[i] = BASELINE_SYSCALLS[i];
        i += 1;
    }
    let mut j = 0;
    while j < WRITE_EXECUTE_SYSCALLS.len() {
        out[i + j] = WRITE_EXECUTE_SYSCALLS[j];
        j += 1;
    }
    out
};

/// The BPF program: an `AUDIT_ARCH_X86_64` gate first (kills on any other syscall ABI), then the
/// syscall number load and an [`X32_SYSCALL_BIT`] gate (kills on the x32 ABI, which shares the
/// `AUDIT_ARCH` value), then one `JEQ` per denylisted syscall (jump to the trailing KILL on a
/// match, fall through otherwise), ending in `RET ALLOW`.
///
/// Built in const context, so the filter is a `.rodata` blob the installer just points at. This
/// is what makes [`install_baseline_denylist`] allocation-free, which matters because its only
/// caller runs it from a `Command::pre_exec` closure — between `fork()` and `execve()`, where a
/// `malloc` can deadlock against a lock another thread held at fork time.
///
/// Every cast and index below is in range as a direct consequence of the `DENIED_LEN <= 250`
/// assertion above, which is why those lints are allowed here rather than per site — and, as
/// with [`DENIED`], this all runs at compile time, so a bound that ever did slip would fail the
/// build, not the running guest.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]
const PROGRAM: [SockFilter; PROGRAM_LEN] = {
    const NOP: SockFilter = SockFilter {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    };
    let mut program = [NOP; PROGRAM_LEN];
    let kill_index = (PROGRAM_LEN - 1) as u8;

    program[0] = SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH_OFFSET,
    };
    // Falls through (jt = 0) to the nr load on a match; on any other ABI, jumps straight to
    // KILL, relative to the instruction after this one (index 2).
    program[1] = SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: kill_index - 2,
        k: AUDIT_ARCH_X86_64,
    };
    program[2] = SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    };
    // Jumps to KILL for anything at or above the x32 bit, falls through to the denylist for the
    // ordinary 64-bit numbers below it. Relative to the instruction after this one (index 4).
    program[3] = SockFilter {
        code: BPF_JMP | BPF_JGE | BPF_K,
        jt: kill_index - 4,
        jf: 0,
        k: X32_SYSCALL_BIT,
    };

    let mut i = 0;
    while i < DENIED_LEN {
        let index = 4 + i;
        program[index] = SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            // Relative jump-if-true, measured from the instruction *after* this one, so it
            // lands exactly on the KILL instruction.
            jt: kill_index - (index as u8) - 1,
            jf: 0,
            k: DENIED[i] as u32,
        };
        i += 1;
    }

    program[PROGRAM_LEN - 2] = SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    };
    program[PROGRAM_LEN - 1] = SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    };
    program
};

// PR_SET_SECCOMP = 22 — hardcoded rather than trusting `libc` to export the name for every
// target; a long-stable uapi constant (linux/prctl.h).
const PR_SET_SECCOMP: libc::c_int = 22;

/// Installs the baseline denylist on the *calling* process.
///
/// Call only from inside a `Command::pre_exec` closure, never from PID 1 itself.
/// `PR_SET_NO_NEW_PRIVS` is required by the kernel before any unprivileged `seccomp()` call
/// succeeds. Allocation-free and syscall-only, as anything running between `fork()` and
/// `execve()` must be — see [`PROGRAM`].
///
/// # Errors
///
/// Returns an error if either underlying `prctl()` call fails.
#[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
pub(crate) fn install_baseline_denylist() -> io::Result<()> {
    let fprog = SockFprog {
        len: PROGRAM_LEN as u16,
        filter: PROGRAM.as_ptr(),
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
    fn program_starts_with_an_arch_gate_before_loading_the_syscall_number() {
        let kill_index = PROGRAM_LEN - 1;

        let arch_load = &PROGRAM[0];
        assert_eq!(arch_load.code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(arch_load.k, SECCOMP_DATA_ARCH_OFFSET);

        let arch_check = &PROGRAM[1];
        assert_eq!(arch_check.code, BPF_JMP | BPF_JEQ | BPF_K);
        assert_eq!(arch_check.k, AUDIT_ARCH_X86_64);
        assert_eq!(
            arch_check.jt, 0,
            "must fall through to the nr load on a match"
        );
        let landing_index = 2 + arch_check.jf as usize;
        assert_eq!(
            landing_index, kill_index,
            "mismatched arch must jump to KILL"
        );

        let nr_load = &PROGRAM[2];
        assert_eq!(nr_load.code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(nr_load.k, SECCOMP_DATA_NR_OFFSET);
    }

    /// x32 shares `AUDIT_ARCH_X86_64`, so the arch gate lets it through and every `JEQ` below
    /// misses by the one set bit — without this instruction the whole denylist is one ABI away
    /// from being a no-op.
    #[test]
    fn x32_syscalls_are_killed_before_reaching_the_denylist() {
        let kill_index = PROGRAM_LEN - 1;

        let x32_gate = &PROGRAM[3];
        assert_eq!(x32_gate.code, BPF_JMP | BPF_JGE | BPF_K);
        assert_eq!(x32_gate.k, X32_SYSCALL_BIT);
        assert_eq!(
            x32_gate.jf, 0,
            "an ordinary 64-bit number must fall through into the denylist"
        );
        let landing_index = 4 + x32_gate.jt as usize;
        assert_eq!(landing_index, kill_index, "an x32 number must jump to KILL");

        // The gate has to sit after the nr load and before the first syscall check, or it is
        // testing the wrong word / running too late to matter.
        assert_eq!(PROGRAM[2].k, SECCOMP_DATA_NR_OFFSET);
        assert_eq!(PROGRAM[4].code, BPF_JMP | BPF_JEQ | BPF_K);

        // One comparison covers every entry only because all of them sit below the threshold
        // on the 64-bit ABI — an entry above it would be killed there too, not just via x32.
        for &nr in &DENIED {
            assert!(
                (nr as u32) < X32_SYSCALL_BIT,
                "syscall {nr} sits at or above the x32 gate's threshold"
            );
        }
    }

    #[test]
    fn program_ends_with_allow_then_kill() {
        let last = PROGRAM[PROGRAM_LEN - 1];
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, SECCOMP_RET_KILL_PROCESS);
        let second_last = PROGRAM[PROGRAM_LEN - 2];
        assert_eq!(second_last.code, BPF_RET | BPF_K);
        assert_eq!(second_last.k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn every_check_jumps_exactly_to_the_kill_instruction() {
        let kill_index = PROGRAM_LEN - 1;

        for (i, &syscall_nr) in DENIED.iter().enumerate() {
            // 0/1 are the arch gate, 2 is the nr LD, 3 is the x32 gate.
            let instr_index = 4 + i;
            let instr = &PROGRAM[instr_index];
            assert_eq!(instr.code, BPF_JMP | BPF_JEQ | BPF_K, "check #{i}");
            assert_eq!(
                instr.k, syscall_nr as u32,
                "check #{i} compares wrong syscall"
            );
            assert_eq!(instr.jf, 0, "check #{i} must fall through on no-match");
            // jt is relative to the *next* instruction (instr_index + 1).
            let landing_index = (instr_index + 1) + instr.jt as usize;
            assert_eq!(
                landing_index, kill_index,
                "check #{i}'s jt doesn't land on the KILL instruction"
            );
        }
    }

    /// Guards the two `.rodata` slots the loop above never writes: a `PROGRAM_LEN` that drifted
    /// out of step with `DENIED` would leave a zeroed `NOP` filler in the middle of the filter,
    /// which the kernel reads as `BPF_LD | BPF_W | BPF_IMM` rather than rejecting.
    #[test]
    fn program_has_no_filler_instructions_left_in_it() {
        assert_eq!(PROGRAM_LEN, DENIED.len() + 6);
        assert!(
            PROGRAM.iter().all(|instr| instr.code != 0),
            "a NOP filler survived into the filter"
        );
    }

    #[test]
    fn denylist_has_no_duplicate_syscalls() {
        let mut sorted = DENIED;
        sorted.sort_unstable();
        let mut deduped = sorted.to_vec();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            DENIED.len(),
            "denylist contains a duplicate syscall"
        );
    }

    /// The `mount(2)`-free mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`) is a complete
    /// second path to the same result if left open.
    #[test]
    fn denylist_covers_the_mount_free_mount_api() {
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
                DENIED.contains(&syscall),
                "syscall {syscall} must be denied — the mount API is only closed as a set"
            );
        }
    }

    /// A ring performs its operations without issuing the corresponding syscalls, so leaving
    /// any one of these open would hand back everything else this filter denies.
    #[test]
    fn denylist_covers_the_io_uring_entry_points() {
        for syscall in [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert!(
                DENIED.contains(&syscall),
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
        assert!(DENIED.contains(&libc::SYS_memfd_create));
        assert!(DENIED.contains(&libc::SYS_memfd_secret));
    }

    /// The mirror of the test above: opting into `danger-allow-write-execute` is opting into
    /// exactly this capability, so killing the process for using it would be incoherent.
    #[test]
    #[cfg(feature = "danger-allow-write-execute")]
    fn danger_allow_write_execute_permits_anonymous_executable_memory() {
        assert!(!DENIED.contains(&libc::SYS_memfd_create));
        assert!(!DENIED.contains(&libc::SYS_memfd_secret));
    }

    /// `execve`/`execveat` must stay allowed: this filter is installed in a `pre_exec` closure,
    /// so denying either would kill every child at the exec that starts it.
    #[test]
    fn denylist_never_blocks_the_exec_that_follows_it() {
        assert!(!DENIED.contains(&libc::SYS_execve));
        assert!(!DENIED.contains(&libc::SYS_execveat));
    }

    /// Runs `body` in a forked child that has this filter installed, and reports how it died.
    ///
    /// The array assertions above check the jump arithmetic against the encoding this file
    /// believes in; only the kernel can say whether it agrees. A filter it rejects, or one whose
    /// jumps land a slot off, is the difference between "denied syscalls kill" and "nothing is
    /// denied at all" — and both spellings pass a purely structural test.
    ///
    /// The child touches only syscalls between `fork()` and `_exit()`, so the usual
    /// fork-in-a-threaded-process constraint is satisfied.
    fn exit_status_under_filter(body: impl FnOnce()) -> libc::c_int {
        // SAFETY: the child path below calls only async-signal-safe syscalls and never returns
        // to the test harness; the parent only waits on the pid it just created.
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                if install_baseline_denylist().is_err() {
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
    fn the_kernel_accepts_the_filter_and_allows_an_undenied_syscall() {
        let status = exit_status_under_filter(|| {
            // SAFETY: `getpid` takes no arguments and cannot fail.
            unsafe {
                libc::getpid();
            }
        });
        assert!(
            libc::WIFEXITED(status),
            "child died instead of exiting — the kernel rejected the filter, or a jump lands on \
             KILL for a syscall that isn't denied"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "97 means prctl() refused the program outright"
        );
    }

    #[test]
    fn a_denied_syscall_actually_kills_the_process() {
        // `personality` is denied, takes one harmless argument, and has no side effect worth
        // caring about in a child that is about to die either way.
        let status = exit_status_under_filter(|| {
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
}
