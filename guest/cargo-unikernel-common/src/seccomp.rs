//! Mandatory classic-BPF seccomp denylist installed on the app and attestation-server child
//! processes. Never on PID 1 itself, which still needs `mount()`/`reboot()`.
//!
//! Denylist rather than allowlist: a wrong allowlist silently breaks every app this tool
//! builds, which is worse than "not exhaustive." Each entry has no legitimate use in a
//! single-purpose server and kills the process on first attempt; the watchdog then reboots
//! the VM. `clone`/`fork`/`execve` stay unrestricted — most real servers need threads.
//!
//! Two things this filter structurally cannot deny, and what covers them instead:
//! - `execve`/`execveat`: installed via `pre_exec`, so the next syscall the child makes *is*
//!   the exec that starts it. The write half of "drop and run a new binary" is denied instead
//!   ([`write_execute_syscalls`]); `[app.runtime.danger].allow_write_execute` lifts it.
//! - namespace creation via `clone`/`clone3`: can't deny without breaking thread creation.
//!   `unshare`/`setns` are denied here; `CONFIG_NAMESPACES=n` (legacy-subsystems.config)
//!   closes the `clone3` path at the kernel level.
//!
//! The BPF construction (arch gate, jump encoding, terminal ALLOW/KILL) was verified against
//! a running Linux 6.12 kernel outside the guest; not yet exercised inside a booted guest.

#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "cargo-unikernel-common's seccomp filter is x86_64-only (see AUDIT_ARCH_X86_64 below)"
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

const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// `memfd_create`/`memfd_secret` + `execveat(fd, "", AT_EMPTY_PATH)` runs an anonymous
/// in-memory binary, invisible to every `noexec` mount flag in `mounts.rs`. This is what
/// `[app.runtime.danger].allow_write_execute` actually gates — see `mounts.rs` for the other
/// half (the writable mounts themselves).
#[cfg(not(feature = "danger-allow-write-execute"))]
fn write_execute_syscalls() -> Vec<i64> {
    vec![libc::SYS_memfd_create, libc::SYS_memfd_secret]
}
#[cfg(feature = "danger-allow-write-execute")]
const fn write_execute_syscalls() -> Vec<i64> {
    Vec::new()
}

/// Only ever installed from inside a `Command::pre_exec` closure for a child — inherited by
/// anything that child itself forks/execs, since seccomp filters survive both.
fn denied_syscalls() -> Vec<i64> {
    let mut denied = vec![
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
    denied.extend(write_execute_syscalls());
    denied
}

/// Builds the BPF program: an `AUDIT_ARCH_X86_64` gate first (kills on any other syscall ABI),
/// then the syscall number load, then one `JEQ` per denylisted syscall (jump to the trailing
/// KILL on a match, fall through otherwise), ending in `RET ALLOW`.
///
/// # Errors
///
/// Returns an error instead of building a silently-truncated (and therefore broken) filter if
/// `denied` has grown past what the classic-BPF `u8` jump field can address — see the 253
/// comment below.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn build_program(denied: &[i64]) -> Result<Vec<SockFilter>, String> {
    // 253 rather than 255 leaves headroom for the largest jump offset (arch gate's `jf`, first
    // syscall check's `jt`) to still fit `u8`. Every cast below is in range as a direct
    // consequence of this check, which is why the truncation/sign-loss lints are allowed here
    // rather than at each individual cast site.
    if denied.len() > 253 {
        return Err(format!(
            "seccomp denylist has grown to {} entries — the largest jump offset no longer fits \
             in the classic-BPF u8 jump field (max 253 supported); this would silently truncate \
             into a broken filter instead of refusing to boot",
            denied.len()
        ));
    }

    let n = denied.len() as u16;
    // 2 (arch load + check) + 1 (nr load) + n (one JEQ per syscall) + 2 (RET ALLOW, RET KILL)
    let kill_index = n + 4;
    let mut program = Vec::with_capacity((kill_index + 1) as usize);

    program.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH_OFFSET,
    });
    // Falls through (jt = 0) to the nr load on a match; on any other ABI, jumps straight to
    // KILL, relative to the instruction after this one (index 2).
    program.push(SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt: 0,
        jf: (kill_index - 2) as u8,
        k: AUDIT_ARCH_X86_64,
    });

    program.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    });

    for (i, &syscall_nr) in denied.iter().enumerate() {
        let i = i as u16;
        // Relative jump-if-true, measured from the instruction *after* this one: skip the
        // remaining (n - 1 - i) checks to land exactly on the KILL instruction.
        let jt_to_kill = (n - 1 - i) + 1;
        program.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: jt_to_kill as u8,
            jf: 0,
            k: syscall_nr as u32,
        });
    }

    program.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    program.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    Ok(program)
}

// PR_SET_SECCOMP = 22 — hardcoded rather than trusting `libc` to export the name for every
// target; a long-stable uapi constant (linux/prctl.h).
const PR_SET_SECCOMP: libc::c_int = 22;

/// Installs the baseline denylist on the *calling* process.
///
/// Call only from inside a `Command::pre_exec` closure, never from PID 1 itself.
/// `PR_SET_NO_NEW_PRIVS` is required by the kernel before any unprivileged `seccomp()` call
/// succeeds.
///
/// # Errors
///
/// Returns an error if the denylist has grown past what the BPF program's jump encoding can
/// address (see [`build_program`]), or if the underlying `prctl()` calls fail.
#[allow(clippy::cast_possible_truncation)]
pub fn install_baseline_denylist() -> io::Result<()> {
    // SAFETY: `fprog` outlives the call (a stack local; its raw pointer is only read for the
    // syscall's duration). Both return values are checked below.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }

        let program = build_program(&denied_syscalls())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let fprog = SockFprog {
            len: program.len() as u16,
            filter: program.as_ptr(),
        };

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
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;

    #[test]
    fn program_starts_with_an_arch_gate_before_loading_the_syscall_number() {
        let program = build_program(&[libc::SYS_ptrace]).unwrap();
        let kill_index = program.len() - 1;

        let arch_load = &program[0];
        assert_eq!(arch_load.code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(arch_load.k, SECCOMP_DATA_ARCH_OFFSET);

        let arch_check = &program[1];
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

        let nr_load = &program[2];
        assert_eq!(nr_load.code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(nr_load.k, SECCOMP_DATA_NR_OFFSET);
    }

    #[test]
    fn program_ends_with_allow_then_kill() {
        let program = build_program(&[libc::SYS_ptrace, libc::SYS_mount]).unwrap();
        let last = program.last().unwrap();
        assert_eq!(last.code, BPF_RET | BPF_K);
        assert_eq!(last.k, SECCOMP_RET_KILL_PROCESS);
        let second_last = program[program.len() - 2];
        assert_eq!(second_last.code, BPF_RET | BPF_K);
        assert_eq!(second_last.k, SECCOMP_RET_ALLOW);
    }

    #[test]
    fn every_check_jumps_exactly_to_the_kill_instruction() {
        let denied = [
            libc::SYS_ptrace,
            libc::SYS_mount,
            libc::SYS_reboot,
            libc::SYS_bpf,
        ];
        let program = build_program(&denied).unwrap();
        let kill_index = program.len() - 1;

        for (i, &syscall_nr) in denied.iter().enumerate() {
            let instr_index = 3 + i; // 0/1 are the arch gate, 2 is the nr LD
            let instr = &program[instr_index];
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

    #[test]
    fn program_length_matches_denylist_size_plus_five() {
        let denied = denied_syscalls();
        let program = build_program(&denied).unwrap();
        // 2 (arch load + check) + 1 (nr LD) + N (one JEQ per syscall) + 2 (RET ALLOW, RET KILL)
        assert_eq!(program.len(), denied.len() + 5);
    }

    #[test]
    fn denylist_has_no_duplicate_syscalls() {
        let denied = denied_syscalls();
        let mut sorted = denied.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            denied.len(),
            "denylist contains a duplicate syscall"
        );
    }

    /// The `mount(2)`-free mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`) is a complete
    /// second path to the same result if left open.
    #[test]
    fn denylist_covers_the_mount_free_mount_api() {
        let denied = denied_syscalls();
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

    /// `noexec` mount flags cannot see an anonymous in-memory file, so this is what actually
    /// backs the "no writable+executable paths remain" claim in the default build.
    #[test]
    #[cfg(not(feature = "danger-allow-write-execute"))]
    fn denylist_blocks_anonymous_executable_memory_by_default() {
        let denied = denied_syscalls();
        assert!(denied.contains(&libc::SYS_memfd_create));
        assert!(denied.contains(&libc::SYS_memfd_secret));
    }

    /// The mirror of the test above: opting into `danger-allow-write-execute` is opting into
    /// exactly this capability, so killing the process for using it would be incoherent.
    #[test]
    #[cfg(feature = "danger-allow-write-execute")]
    fn danger_allow_write_execute_permits_anonymous_executable_memory() {
        let denied = denied_syscalls();
        assert!(!denied.contains(&libc::SYS_memfd_create));
        assert!(!denied.contains(&libc::SYS_memfd_secret));
    }

    /// `execve`/`execveat` must stay allowed: this filter is installed in a `pre_exec` closure,
    /// so denying either would kill every child at the exec that starts it.
    #[test]
    fn denylist_never_blocks_the_exec_that_follows_it() {
        let denied = denied_syscalls();
        assert!(!denied.contains(&libc::SYS_execve));
        assert!(!denied.contains(&libc::SYS_execveat));
    }

    #[test]
    fn build_program_accepts_the_maximum_supported_denylist_size() {
        let denied: Vec<i64> = (0..253).collect();
        let program = build_program(&denied).unwrap();
        assert_eq!(program.len(), denied.len() + 5);
    }

    #[test]
    fn build_program_rejects_a_denylist_past_the_u8_jump_offset_limit() {
        let denied: Vec<i64> = (0..254).collect();
        let err = build_program(&denied).unwrap_err();
        assert!(err.contains("no longer fits"));
    }
}
