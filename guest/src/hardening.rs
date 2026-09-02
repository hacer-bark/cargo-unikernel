//! Runtime sysctl hardening applied by the guest init after mounting /proc.
//!
//! Split into one function per category, each gated by its own Cargo feature
//! (`hardening-net-spoofing`, `hardening-icmp`, `hardening-tcp`, `hardening-info-leak`,
//! `hardening-ptrace-bpf`, `hardening-kexec-fs`) instead of a runtime-checked table: a
//! disabled category's sysctl writes are compiled out entirely, not skipped by an `if` that
//! never triggers in a given build. A category itself may split further into private
//! sub-functions (e.g. `hardening-net-spoofing`'s redirect/source-route/ARP groups) purely for
//! readability — the Cargo feature gate is always on the public per-category function, so this
//! never changes what a toggle in `[hardening.runtime]` controls.
//!
//! [`apply_baseline_tuning`] is the one exception: it's not a hardening category, isn't
//! feature-gated, and always runs — see its doc comment.

/// Tally of what [`write_sysctl`] actually did, reported once by [`apply`].
///
/// An absent knob is skipped silently and for good reason (see [`write_sysctl`]), but "silently"
/// applied to a whole category is how a hardening pass turns into a no-op nobody notices — a
/// renamed knob upstream, or a category running before the subsystem it tunes exists. Two
/// counters and one summary line make the difference between "24 applied" and "0 applied, 24
/// absent" visible without weakening the per-write behaviour. Plain statics rather than a
/// counter threaded through every category function: PID 1 applies these once, from one thread,
/// and the alternative is an extra parameter on ten call sites.
static APPLIED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static ABSENT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn bump(counter: &std::sync::atomic::AtomicU32) {
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

fn write_sysctl(path: &str, val: &[u8], warn: &impl Fn(&str)) {
    match std::fs::write(path, val) {
        Ok(()) => bump(&APPLIED),
        // Missing means the kernel feature it would tune is already compiled out (e.g.
        // CONFIG_KEXEC, CONFIG_BPF_SYSCALL, or CONFIG_IPV6 when net-ipv6 isn't selected) —
        // nothing to restrict, not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bump(&ABSENT),
        Err(e) => {
            let val = String::from_utf8_lossy(val);
            warn(&format!("Failed to set sysctl {path} to {val:?}: {e}"));
        }
    }
}

/// Anti-spoofing / anti-MITM network hardening — everything here defends against a peer on the
/// guest's network segment forging, redirecting, or route-steering traffic. Cross-checked
/// against Kicksecure's `usr/lib/sysctl.d/990-security-misc.conf` (the audited upstream this
/// category is aligned to); every setting below has a matching entry there unless a comment
/// says otherwise.
#[cfg(feature = "hardening-net-spoofing")]
fn apply_network_spoofing_protection(warn: &impl Fn(&str)) {
    apply_redirect_and_forwarding_protection(warn);
    apply_source_routing_protection(warn);
    apply_arp_hardening(warn);
    write_sysctl("/proc/sys/net/ipv4/conf/all/log_martians", b"1", warn);
    write_sysctl("/proc/sys/net/ipv4/conf/default/log_martians", b"1", warn);
}

/// `rp_filter`, ICMP redirect accept/send/secure (v4 and v6), and forwarding — refuses to
/// silently double as a router between interfaces, and refuses route changes suggested by an
/// on-link peer instead of the guest's own configuration.
#[cfg(feature = "hardening-net-spoofing")]
fn apply_redirect_and_forwarding_protection(warn: &impl Fn(&str)) {
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
    // The IPv6 half of the same protection — a gap versus the IPv4 rules above until now. A
    // no-op write (ENOENT, silently ignored by write_sysctl) on an IPv4-only build with no
    // IPv6 stack compiled in.
    write_sysctl("/proc/sys/net/ipv6/conf/all/accept_redirects", b"0", warn);
    write_sysctl(
        "/proc/sys/net/ipv6/conf/default/accept_redirects",
        b"0",
        warn,
    );
    // A single-purpose guest should never silently double as a router between interfaces.
    write_sysctl("/proc/sys/net/ipv4/ip_forward", b"0", warn);
    write_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", b"0", warn);
}

/// Refuses IP source-routed packets (v4 and v6) — a classic spoofing primitive that lets a
/// packet dictate its own return path instead of following normal routing.
#[cfg(feature = "hardening-net-spoofing")]
fn apply_source_routing_protection(warn: &impl Fn(&str)) {
    write_sysctl(
        "/proc/sys/net/ipv4/conf/all/accept_source_route",
        b"0",
        warn,
    );
    write_sysctl(
        "/proc/sys/net/ipv4/conf/default/accept_source_route",
        b"0",
        warn,
    );
    write_sysctl(
        "/proc/sys/net/ipv6/conf/all/accept_source_route",
        b"0",
        warn,
    );
    write_sysctl(
        "/proc/sys/net/ipv6/conf/default/accept_source_route",
        b"0",
        warn,
    );
}

/// ARP cache poisoning / spoofing defense. Modest value on a single-NIC virtio guest — most of
/// these matter more on a multi-homed host — but free, and part of Kicksecure's audited
/// baseline, so included for parity rather than left as a silent gap.
#[cfg(feature = "hardening-net-spoofing")]
fn apply_arp_hardening(warn: &impl Fn(&str)) {
    write_sysctl("/proc/sys/net/ipv4/conf/all/arp_filter", b"1", warn);
    // "1" (answer only for an address local to the receiving interface), not "2" (also require
    // the sender to be in the same subnet as the target). On the single-NIC guest this runs in,
    // the two are equivalent right up until the provider puts the gateway *outside* the guest's
    // subnet — a point-to-point /32 layout several large hosts use — where "2" makes the guest
    // refuse to answer its own gateway's ARP and silently fall off the network. "1" is the whole
    // of the protection that actually applies here; "2" only adds a way to be unreachable.
    write_sysctl("/proc/sys/net/ipv4/conf/all/arp_ignore", b"1", warn);
    write_sysctl(
        "/proc/sys/net/ipv4/conf/all/drop_gratuitous_arp",
        b"1",
        warn,
    );
    write_sysctl("/proc/sys/net/ipv4/conf/all/shared_media", b"0", warn);
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
    // SysRq is reached over the serial console, which on sev-snp is the *hypervisor* — outside
    // the trust boundary — and answers with task lists, register dumps and memory state.
    // `CONFIG_MAGIC_SYSRQ=disable` (debug-interfaces.config) already removes it, but that whole
    // fragment is opt-out, exactly like the kexec/module knobs pinned elsewhere in this file.
    write_sysctl("/proc/sys/kernel/sysrq", b"0", warn);
    // An oops prints a full register and stack trace to that same console and then leaves the
    // kernel running in a state it just declared inconsistent. Stopping at the first one is both
    // the smaller leak and the honest response to a guest whose integrity is already in question.
    write_sysctl("/proc/sys/kernel/panic_on_oops", b"1", warn);
    // TCP timestamps carry a monotonic counter derived from the guest's uptime, which is a
    // fingerprint and a boot-time oracle for any peer that can reach the listener. Costs PAWS
    // and finer RTT estimation, which matters on long fat networks — the trade this category
    // exists to let a deployment make.
    write_sysctl("/proc/sys/net/ipv4/tcp_timestamps", b"0", warn);
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
    // A no-op write today (CONFIG_MODULES=disable already means the path doesn't exist), but
    // survives someone re-enabling modules via `extra_kernel_config` the same way the
    // `io_uring` seccomp entries survive `CONFIG_IO_URING` being re-enabled.
    write_sysctl("/proc/sys/kernel/modules_disabled", b"1", warn);
    // "2": refuse io_uring even for CAP_SYS_ADMIN, not just unprivileged callers — closes the
    // same door as the seccomp io_uring entries and CONFIG_IO_URING=disable, again for a
    // build that re-enables the kernel option without touching this file.
    write_sysctl("/proc/sys/kernel/io_uring_disabled", b"2", warn);
}

/// Disable kexec loading and protect VFS symlinks/hardlinks/fifos/regular files.
#[cfg(feature = "hardening-kexec-fs")]
fn apply_kexec_and_fs_protection(warn: &impl Fn(&str)) {
    write_sysctl("/proc/sys/kernel/kexec_load_disabled", b"1", warn);
    write_sysctl("/proc/sys/fs/protected_symlinks", b"1", warn);
    write_sysctl("/proc/sys/fs/protected_hardlinks", b"1", warn);
    write_sysctl("/proc/sys/fs/protected_fifos", b"2", warn);
    write_sysctl("/proc/sys/fs/protected_regular", b"2", warn);
    // CONFIG_COREDUMP=disable already means no core is ever written, but a build that
    // re-enables it via `extra_kernel_config` should not also inherit "a setuid binary's core
    // is world-writable" for free.
    write_sysctl("/proc/sys/fs/suid_dumpable", b"0", warn);
}

/// Not a hardening category and not feature-gated: raises the mmap-count ceiling well above the
/// kernel's default (~65530), which some mmap-heavy workloads (large heaps, embedded databases,
/// JIT runtimes) exhaust in normal operation. No security trade-off either direction — this
/// stays applied even if every `hardening.runtime` category is turned off.
fn apply_baseline_tuning(warn: &impl Fn(&str)) {
    write_sysctl("/proc/sys/vm/max_map_count", b"1048576", warn);
    // Pinned rather than inherited from CONFIG_RANDOMIZE_BASE/RANDOMIZE_MEMORY's own default
    // (already "2" today) — a build that lowers those Kconfig options shouldn't silently take
    // this with it.
    write_sysctl("/proc/sys/kernel/randomize_va_space", b"2", warn);
}

/// What one [`apply`] pass did, for the caller to log as boot progress rather than as a warning.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Summary {
    /// Knobs written successfully.
    pub(crate) applied: u32,
    /// Knobs this kernel doesn't have, skipped (see [`write_sysctl`]).
    pub(crate) absent: u32,
}

/// Applies every compiled-in hardening category, then any `extra` (path, value) pairs from
/// `Cargo-Unikernel.toml`'s `hardening.extra_sysctls`.
///
/// Logs (but does not fail the boot on) any write error.
pub(crate) fn apply(extra: &[(&str, &str)], warn: impl Fn(&str)) -> Summary {
    apply_baseline_tuning(&warn);
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

    apply_extra(extra, &warn);

    Summary {
        applied: APPLIED.load(std::sync::atomic::Ordering::Relaxed),
        absent: ABSENT.load(std::sync::atomic::Ordering::Relaxed),
    }
}

/// The `hardening.extra_sysctls` half of [`apply`], split out so that function reads as the list
/// of categories it is.
fn apply_extra(extra: &[(&str, &str)], warn: &impl Fn(&str)) {
    for (path, val) in extra {
        if !is_sysctl_path(path) {
            warn(&format!(
                "Refusing to write {path:?}: `extra_sysctls` keys must be paths under \
                 /proc/sys/ with no `..` component"
            ));
            continue;
        }
        write_sysctl(path, val.as_bytes(), warn);
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
