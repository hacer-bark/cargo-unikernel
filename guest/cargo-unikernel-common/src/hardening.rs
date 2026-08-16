//! Runtime sysctl hardening applied by the guest init after mounting /proc.
//!
//! Split into one function per category, each gated by its own Cargo feature
//! (`hardening-net-spoofing`, `hardening-icmp`, `hardening-tcp`, `hardening-info-leak`,
//! `hardening-ptrace-bpf`, `hardening-kexec-fs`) instead of a runtime-checked table: a
//! disabled category's sysctl writes are compiled out entirely, not skipped by an `if` that
//! never triggers in a given build.

fn write_sysctl(path: &str, val: &[u8], warn: &impl Fn(&str)) {
    if let Err(e) = std::fs::write(path, val) {
        // Missing means the kernel feature it would tune is already compiled out (e.g.
        // CONFIG_KEXEC, CONFIG_BPF_SYSCALL, or CONFIG_IPV6 when net-ipv6 isn't selected) —
        // nothing to restrict, not a failure.
        if e.kind() == std::io::ErrorKind::NotFound {
            return;
        }
        let val = String::from_utf8_lossy(val);
        warn(&format!("Failed to set sysctl {path} to {val:?}: {e}"));
    }
}

/// `rp_filter` + ICMP redirect accept/send/secure — IP spoofing / MITM redirect defense.
#[cfg(feature = "hardening-net-spoofing")]
fn apply_network_spoofing_protection(warn: &impl Fn(&str)) {
    write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", b"1", warn);
    write_sysctl("/proc/sys/net/ipv4/conf/default/rp_filter", b"1", warn);
    write_sysctl("/proc/sys/net/ipv4/conf/all/accept_redirects", b"0", warn);
    write_sysctl(
        "/proc/sys/net/ipv4/conf/default/accept_redirects",
        b"0",
        warn,
    );
    write_sysctl("/proc/sys/net/ipv4/conf/all/send_redirects", b"0", warn);
    write_sysctl("/proc/sys/net/ipv4/conf/default/send_redirects", b"0", warn);
    write_sysctl("/proc/sys/net/ipv4/conf/all/secure_redirects", b"0", warn);
    write_sysctl(
        "/proc/sys/net/ipv4/conf/default/secure_redirects",
        b"0",
        warn,
    );
    // A single-purpose guest should never silently double as a router between interfaces.
    write_sysctl("/proc/sys/net/ipv4/ip_forward", b"0", warn);
    write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", b"0", warn);
}

/// Ignore ICMP broadcasts/bogus errors, and (optionally) all ICMP echo — Smurf-attack
/// defense and "stealth mode" (don't answer pings at all).
#[cfg(feature = "hardening-icmp")]
fn apply_icmp_hardening(warn: &impl Fn(&str)) {
    write_sysctl("/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts", b"1", warn);
    write_sysctl(
        "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses",
        b"1",
        warn,
    );
    write_sysctl("/proc/sys/net/ipv4/icmp_echo_ignore_all", b"1", warn);
}

/// SYN cookies, `RFC1337`, and connection-table/backlog tuning for `DDoS` resilience.
#[cfg(feature = "hardening-tcp")]
fn apply_tcp_hardening(warn: &impl Fn(&str)) {
    write_sysctl("/proc/sys/net/ipv4/tcp_syncookies", b"1", warn);
    write_sysctl("/proc/sys/net/ipv4/tcp_rfc1337", b"1", warn);
    write_sysctl("/proc/sys/net/core/somaxconn", b"8192", warn);
    write_sysctl("/proc/sys/net/core/netdev_max_backlog", b"16384", warn);
    write_sysctl("/proc/sys/net/ipv4/tcp_max_syn_backlog", b"8192", warn);
    write_sysctl("/proc/sys/net/ipv4/tcp_synack_retries", b"2", warn);
    write_sysctl("/proc/sys/net/ipv4/tcp_fin_timeout", b"10", warn);
    write_sysctl("/proc/sys/net/ipv4/tcp_keepalive_time", b"60", warn);
    write_sysctl("/proc/sys/net/ipv4/tcp_keepalive_intvl", b"10", warn);
    write_sysctl("/proc/sys/net/ipv4/tcp_keepalive_probes", b"6", warn);
    write_sysctl("/proc/sys/net/ipv4/tcp_max_orphans", b"16384", warn);
    write_sysctl("/proc/sys/net/ipv4/tcp_tw_reuse", b"1", warn);
    // Throughput, not security: don't reset a connection's congestion window to the
    // slow-start floor just for going briefly idle — matters for keep-alive servers.
    write_sysctl("/proc/sys/net/ipv4/tcp_slow_start_after_idle", b"0", warn);
    // Throughput, not security: BBR over the kernel's default (cubic) — always compiled in
    // regardless of this toggle, see kconfig/base.config's CONFIG_TCP_CONG_BBR.
    write_sysctl("/proc/sys/net/ipv4/tcp_congestion_control", b"bbr", warn);
}

/// `kptr_restrict`, `dmesg_restrict`, `perf_event_paranoid` — restrict kernel info leaks.
#[cfg(feature = "hardening-info-leak")]
fn apply_info_leak_restriction(warn: &impl Fn(&str)) {
    write_sysctl("/proc/sys/kernel/kptr_restrict", b"2", warn);
    write_sysctl("/proc/sys/kernel/dmesg_restrict", b"1", warn);
    write_sysctl("/proc/sys/kernel/perf_event_paranoid", b"3", warn);
}

/// Disable unprivileged BPF and userfaultfd, and lock down ptrace (YAMA scope 3).
#[cfg(feature = "hardening-ptrace-bpf")]
fn apply_ptrace_and_bpf_restriction(warn: &impl Fn(&str)) {
    write_sysctl("/proc/sys/kernel/unprivileged_bpf_disabled", b"1", warn);
    write_sysctl("/proc/sys/vm/unprivileged_userfaultfd", b"0", warn);
    write_sysctl("/proc/sys/kernel/yama/ptrace_scope", b"3", warn);
    // Constant-blinds the classic-BPF JIT's output against spray-style attacks. "2" (harden
    // always, not just for unprivileged callers) since nothing here needs unhardened JIT output.
    write_sysctl("/proc/sys/net/core/bpf_jit_harden", b"2", warn);
}

/// Disable kexec loading and protect VFS symlinks/hardlinks/fifos/regular files.
#[cfg(feature = "hardening-kexec-fs")]
fn apply_kexec_and_fs_protection(warn: &impl Fn(&str)) {
    write_sysctl("/proc/sys/kernel/kexec_load_disabled", b"1", warn);
    write_sysctl("/proc/sys/fs/protected_symlinks", b"1", warn);
    write_sysctl("/proc/sys/fs/protected_hardlinks", b"1", warn);
    write_sysctl("/proc/sys/fs/protected_fifos", b"2", warn);
    write_sysctl("/proc/sys/fs/protected_regular", b"2", warn);
}

/// Applies every compiled-in hardening category, then any `extra` (path, value) pairs from
/// `cargo-unikernel.toml`'s `hardening.extra_sysctls`.
///
/// Logs (but does not fail the boot on) any write error.
pub fn apply(extra: &[(&str, &str)], warn: impl Fn(&str)) {
    #[cfg(feature = "hardening-net-spoofing")]
    apply_network_spoofing_protection(&warn);
    #[cfg(feature = "hardening-icmp")]
    apply_icmp_hardening(&warn);
    #[cfg(feature = "hardening-tcp")]
    apply_tcp_hardening(&warn);
    #[cfg(feature = "hardening-info-leak")]
    apply_info_leak_restriction(&warn);
    #[cfg(feature = "hardening-ptrace-bpf")]
    apply_ptrace_and_bpf_restriction(&warn);
    #[cfg(feature = "hardening-kexec-fs")]
    apply_kexec_and_fs_protection(&warn);

    for (path, val) in extra {
        if !is_sysctl_path(path) {
            warn(&format!(
                "Refusing to write {path:?}: `extra_sysctls` keys must be paths under \
                 /proc/sys/ with no `..` component"
            ));
            continue;
        }
        write_sysctl(path, val.as_bytes(), &warn);
    }
}

/// Whether `path` is confined to `/proc/sys/`.
///
/// The host tool checks this too, when it validates the config that bakes these keys in
/// (`schema::Config::validate_extra_sysctl_paths`) — this is the same check standing where the
/// write actually happens. PID 1 runs it as root, before `lockdown_filesystem` seals anything,
/// so an unconfined key isn't a broken sysctl, it's a root write to whatever path it names. That
/// is worth two lines on this side rather than resting entirely on a check in a different
/// binary, built at a different time, from a version of the tool this image can't inspect.
///
/// `..` is rejected separately: a prefix check alone accepts `/proc/sys/../../etc/passwd`.
fn is_sysctl_path(path: &str) -> bool {
    path.starts_with("/proc/sys/") && !path.split('/').any(|part| part == "..")
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_paths_are_confined_to_proc_sys() {
        assert!(is_sysctl_path("/proc/sys/net/ipv4/ip_forward"));
        assert!(!is_sysctl_path("/etc/passwd"));
        assert!(!is_sysctl_path("proc/sys/net/ipv4/ip_forward"));
        assert!(!is_sysctl_path("/proc/self/mem"));
        // A prefix check alone would accept this one.
        assert!(!is_sysctl_path("/proc/sys/../../payload/app"));
    }

    /// The guard has to reject before the write, not merely log alongside it.
    #[test]
    fn an_unconfined_key_is_skipped_rather_than_written() {
        let target = std::env::temp_dir().join("cuk-sysctl-escape-test");
        let _ = std::fs::remove_file(&target);
        let path = target.to_str().unwrap().to_string();

        let warnings = std::cell::RefCell::new(Vec::new());
        apply(&[(path.as_str(), "1")], |w| {
            warnings.borrow_mut().push(w.to_string());
        });

        assert!(!target.exists(), "the write escaped /proc/sys/");
        assert!(warnings.borrow().iter().any(|w| w.contains("Refusing")));
    }
}
