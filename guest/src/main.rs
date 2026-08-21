//! Minimal guest PID-1 for a unikernel image. The app binary is embedded into the image at
//! build time (see `cargo-unikernel`'s rootfs pipeline), so there is no runtime fetch,
//! signature check, or secure-time bootstrap here — the SEV-SNP launch measurement (or the
//! image's own hash, for casual builds) already covers the exact app bytes.
//!
//! `unsafe` is unavoidable and expected throughout this crate — it wraps raw Linux syscalls
//! (`mount`, `ioctl`, `prctl`, signal handling) that have no safe abstraction available in a
//! `no_std`-adjacent, dependency-minimal PID-1 binary. What is not acceptable is a runtime
//! panic: every fallible path here either returns a `Result` or takes a `fatal: fn(&str) -> !`
//! callback so the caller can trigger the guest's own wipe-and-power-off shutdown protocol
//! instead of unwinding.

#![forbid(unsafe_op_in_unsafe_fn, elided_lifetimes_in_paths)]
#![allow(clippy::redundant_pub_crate)]

mod entropy;
mod hardening;
mod mounts;
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
mod network;
mod seccomp;
mod shutdown;
#[cfg(feature = "storage-persistent")]
mod storage;

use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Writes `len` zero bytes to `sink`, reusing one caller-supplied `zeros` buffer rather than
/// allocating per call — both callers (scrubbing a tmpfs file, wiping a whole block device)
/// are on paths where an allocation sized to the target would be absurd.
fn write_zeros(sink: &mut impl std::io::Write, len: u64, zeros: &[u8]) -> std::io::Result<()> {
    let mut remaining = len;
    while remaining > 0 {
        let n = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(zeros.len());
        sink.write_all(zeros.get(..n).unwrap_or(zeros))?;
        remaining = remaining.saturating_sub(u64::try_from(n).unwrap_or(remaining));
    }
    Ok(())
}

/// `Instant::now() + timeout`, saturating to "now" instead of panicking if the addition would
/// overflow. Shared by every bounded wait in this crate (entropy, network settle, shutdown
/// timeouts) so there is exactly one place that gets this idiom right, rather than one
/// `checked_add`/`unwrap_or_else` pair per call site to keep in sync.
fn deadline_after(timeout: std::time::Duration) -> std::time::Instant {
    std::time::Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(std::time::Instant::now)
}

const PAYLOAD_DIR: &str = env!("CARGO_UNIKERNEL_PAYLOAD_DIR");
const APP_PATH: &str = env!("CARGO_UNIKERNEL_APP_PATH");
const APP_UID: &str = env!("CARGO_UNIKERNEL_APP_UID");
const APP_GID: &str = env!("CARGO_UNIKERNEL_APP_GID");
const APP_ENV: &str = env!("CARGO_UNIKERNEL_APP_ENV");
const EXTRA_SYSCTLS: &str = env!("CARGO_UNIKERNEL_EXTRA_SYSCTLS");
#[cfg(feature = "net-ipv6")]
const IPV6_STATIC: &str = env!("CARGO_UNIKERNEL_IPV6_STATIC");
#[cfg(feature = "net-ipv6")]
const IPV6_GATEWAY: &str = env!("CARGO_UNIKERNEL_IPV6_GATEWAY");
#[cfg(feature = "net-ipv6")]
const IPV6_IFACE: &str = env!("CARGO_UNIKERNEL_IPV6_IFACE");

const LIMIT_NOFILE: &str = env!("CARGO_UNIKERNEL_LIMIT_NOFILE");
const LIMIT_NPROC: &str = env!("CARGO_UNIKERNEL_LIMIT_NPROC");
const LIMIT_AS_MB: &str = env!("CARGO_UNIKERNEL_LIMIT_AS_MB");
const LIMIT_MEMLOCK_MB: &str = env!("CARGO_UNIKERNEL_LIMIT_MEMLOCK_MB");

/// Splits a `';'`-joined list of `key=value` pairs (see `build.rs`) into its parts.
///
/// A pair with no `=` runs the wipe protocol rather than being silently dropped — these
/// strings come from validated host-side config, so a malformed one means the two sides
/// disagree about the encoding. `what` names the setting in the shutdown message.
fn parse_pairs<'a>(raw: &'a str, what: &str) -> Vec<(&'a str, &'a str)> {
    raw.split(';')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            pair.split_once('=').unwrap_or_else(|| {
                fatal_shutdown(&format!(
                    "Malformed entry in {what}: {pair:?} is not a 'key=value' pair"
                ))
            })
        })
        .collect()
}

/// Parses a build-time-baked constant (see `build.rs`) rather than untrusted runtime input, but
/// a malformed override is still something this process can only observe at its own runtime —
/// so a parse failure runs the wipe protocol via [`fatal_shutdown`] rather than unwinding.
/// `what` names the constant in the shutdown message.
fn baked<T: std::str::FromStr>(raw: &str, what: &str) -> T {
    raw.parse().unwrap_or_else(|_| {
        fatal_shutdown(&format!("{what} must be a {}", std::any::type_name::<T>()))
    })
}

fn app_ids() -> (u32, u32) {
    (
        baked(APP_UID, "CARGO_UNIKERNEL_APP_UID"),
        baked(APP_GID, "CARGO_UNIKERNEL_APP_GID"),
    )
}

fn log(msg: &str) {
    println!("[INIT] {msg}");
}

/// `/var` is mounted root:root mode 0755 (tmpfs default, or `mke2fs`'s ext4 default) — the app
/// runs as an unprivileged, non-root uid/gid, so without this it could never write into `/var`
/// at all, in either storage mode.
fn chown_var_for_app(uid: u32, gid: u32, fatal: fn(&str) -> !) {
    if let Err(e) = std::os::unix::fs::chown("/var", Some(uid), Some(gid)) {
        fatal(&format!("Failed to chown /var to the app's uid/gid: {e}"));
    }
}

fn is_pid1() -> bool {
    std::process::id() == 1
}

/// Logs a fatal error and exits, without touching the VM.
///
/// Only reachable when this binary is running as something other than PID 1 — which nothing in
/// a built image does, since PID 1 spawns the app binary and never re-execs itself. A process
/// that got here anyway can't power off (it is not PID 1, so it has neither `CAP_SYS_BOOT` nor
/// the standing to `kill(-1)`), and exiting is the only safe thing left.
fn non_pid1_fatal_exit(message: &str) -> ! {
    eprintln!("\n======================================================================");
    eprintln!("FATAL (PID {}): {message}", std::process::id());
    eprintln!("Exiting — only PID 1 may run the guest's shutdown protocol.");
    eprintln!("======================================================================\n");
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(1);
}

/// The guest's wipe-and-shutdown protocol for any unrecoverable or integrity-compromising error.
///
/// Never unwinds or returns. From PID 1, kills every other process, zeroes the same writable
/// state a graceful stop zeroes, and powers off; anywhere else, defers to
/// [`non_pid1_fatal_exit`]. This is the *only* sanctioned way any critical failure in this crate
/// ends — production code paths call this instead of panicking so a bug or bypassed check fails
/// safely rather than continuing in an unknown state.
///
/// Wiping rather than powering off on the spot: a bare `reboot(2)` leaves every tmpfs page the
/// app wrote sitting in guest RAM, and a fatal error is not a reason to protect that data less
/// carefully than an orderly stop does. The wipe cannot delay the power-off unboundedly — see
/// [`crate::shutdown::wipe_and_power_off`] for the deadline and re-entry
/// guarantees that make "try to clean up" safe on a path that only runs when something is
/// already wrong.
///
/// There is deliberately no build that suppresses the power-off to keep a failed guest alive
/// for inspection: a fatal error means the guest's state is already untrusted, and any binary
/// carrying that behavior could be deployed by mistake.
fn fatal_shutdown(message: &str) -> ! {
    if !is_pid1() {
        non_pid1_fatal_exit(message);
    }

    eprintln!("\n======================================================================");
    eprintln!("FATAL: {message}");
    eprintln!("SHUTDOWN: wiping writable state, then powering off.");
    eprintln!("======================================================================\n");
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    crate::shutdown::wipe_and_power_off(log);
}

/// Marks PID 1 non-dumpable, so `/proc/1/mem`/`maps` stay unreadable.
///
/// Not applied in the app's `pre_exec` chain — `execve` resets `dumpable` on any exec
/// that isn't a "secure exec", and [`drop_privileges`] switches uid *before* the exec, so it
/// would just get cleared again there. PID 1 never execs, so here it sticks. The app is
/// covered instead by `yama ptrace_scope=3`, the seccomp `ptrace`/`process_vm_readv`/`writev`
/// entries, `CONFIG_COREDUMP=n`, and `CONFIG_PROC_MEM_NO_FORCE=y`.
fn set_self_non_dumpable(warn: impl Fn(&str)) {
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        warn(&format!("Failed to mark PID 1 non-dumpable: {e}"));
    }
}

/// Drops every capability from the bounding set, then drops root entirely (supplementary
/// groups, gid, uid), in that order.
///
/// Hand-rolled here rather than via `Command::uid`/`gid` because `Command`'s own uid/gid
/// switch always runs *before* any `pre_exec` closure, and `PR_CAPBSET_DROP` needs
/// `CAP_SETPCAP`, which the setuid transition below would already have stripped. The
/// bounding-set drop matters beyond setuid alone: setuid only clears the permitted/effective
/// sets, not the bounding set, which is what would otherwise gate any capability regained via
/// file capabilities or an inheritable set. `EINVAL` is ignored (the running kernel doesn't
/// define that capability number); any other error aborts the boot.
fn drop_privileges(uid: u32, gid: u32) -> impl Fn() -> std::io::Result<()> {
    move || {
        // SAFETY: plain integer arguments throughout, except `setgroups`'s null pointer paired
        // with a zero count (the well-defined way to clear the supplementary group list).
        // Every return value is checked below.
        unsafe {
            for cap in 0..64 {
                let ret = libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
                if ret != 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() != Some(libc::EINVAL) {
                        return Err(err);
                    }
                }
            }
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// Caps the child's open-file, process/thread, locked-memory and (optionally) address-space
/// limits before exec.
///
/// Defense-in-depth against a compromised/buggy app fork-bombing, exhausting fds, or growing
/// unboundedly. Sets both soft and hard limits, since the child loses `CAP_SYS_RESOURCE` after
/// `drop_privileges` and can't raise them back. `max_memory_mb == 0` means no `RLIMIT_AS` cap.
/// `RLIMIT_MEMLOCK` is raised above the kernel's small default (so an app can `mlock` key
/// material out of swap) but stays bounded — unlimited would let a compromised app pin all of
/// guest RAM.
///
fn apply_resource_limits() -> std::io::Result<()> {
    use rustix::process::Resource;

    set_rlimit(
        Resource::Nofile,
        baked(LIMIT_NOFILE, "CARGO_UNIKERNEL_LIMIT_NOFILE"),
    )?;
    set_rlimit(
        Resource::Nproc,
        baked(LIMIT_NPROC, "CARGO_UNIKERNEL_LIMIT_NPROC"),
    )?;
    set_rlimit(
        Resource::Memlock,
        baked::<u64>(LIMIT_MEMLOCK_MB, "CARGO_UNIKERNEL_LIMIT_MEMLOCK_MB")
            .saturating_mul(1024 * 1024),
    )?;
    let as_mb: u64 = baked(LIMIT_AS_MB, "CARGO_UNIKERNEL_LIMIT_AS_MB");
    if as_mb > 0 {
        set_rlimit(Resource::As, as_mb.saturating_mul(1024 * 1024))?;
    }
    Ok(())
}

fn set_rlimit(resource: rustix::process::Resource, value: u64) -> std::io::Result<()> {
    rustix::process::setrlimit(
        resource,
        rustix::process::Rlimit {
            current: Some(value),
            maximum: Some(value),
        },
    )
    .map_err(Into::into)
}

/// Runs after fork, before exec — installs the mandatory baseline seccomp denylist on the app
/// child.
///
/// A failure here surfaces through `Command::spawn()` into `fatal_shutdown`: booting without
/// the filter silently in place would be worse than refusing to boot.
fn install_seccomp_baseline(program: &seccompiler::BpfProgram) -> std::io::Result<()> {
    crate::seccomp::install_baseline_denylist(program)
}

/// Checks the embedded app binary is present and makes it read-only + executable.
///
/// Split out of [`spawn_app`] so it runs *before* [`crate::mounts::lockdown_filesystem`]
/// seals `PAYLOAD_DIR`
/// read-only — this `chmod` would fail against an already-locked-down mount.
fn prepare_app_binary() {
    if !std::path::Path::new(APP_PATH).exists() {
        fatal_shutdown(&format!(
            "Embedded app binary not found at {APP_PATH} — this image was not built correctly"
        ));
    }
    std::fs::set_permissions(APP_PATH, Permissions::from_mode(0o555)).unwrap_or_else(|e| {
        fatal_shutdown(&format!("Failed to set permissions on {APP_PATH}: {e}"))
    });
}

/// Spawns the embedded app as a stripped-down, unprivileged child. See the `pre_exec` chain's
/// own comment (inside) for why each closure runs, and in that specific order.
fn spawn_app() -> u32 {
    log("Spawning embedded app as child process...");

    // Built here, before the fork below, and moved into the `pre_exec` closure that installs
    // it: `seccomp::build_baseline_denylist` allocates, which is unsound to do between `fork()`
    // and `execve()` — see its own doc comment.
    let seccomp_program = crate::seccomp::build_baseline_denylist(fatal_shutdown);

    // SAFETY: `pre_exec` closures run in the forked child between `fork()` and `execve()`,
    // where only async-signal-safe operations are sound; each closure here calls only a fixed,
    // small number of setrlimit/setgroups/setgid/setuid/seccomp syscalls.
    let (uid, gid) = app_ids();
    let child = unsafe {
        Command::new(APP_PATH)
            .env_clear()
            .envs(parse_pairs(APP_ENV, "[app.runtime].env"))
            .pre_exec(apply_resource_limits)
            .pre_exec(drop_privileges(uid, gid))
            .pre_exec(move || install_seccomp_baseline(&seccomp_program))
            .spawn()
            .unwrap_or_else(|e| fatal_shutdown(&format!("Failed to spawn app: {e}")))
    };
    let child_pid = child.id();
    log(&format!("App launched as PID {child_pid}."));
    child_pid
}

/// Makes `/dev/sev-guest` (if present — only ever true on the sev-snp profile) openable by the
/// app.
///
/// The guest ships no attestation service of its own: proving to a remote peer that this
/// measured image is what's running is the app's job, because only the app knows what it needs
/// bound into the report's `REPORT_DATA` (a TLS key, a request hash, a session identifier) for
/// the proof to cover the channel the peer actually talks over. A generic server that echoed a
/// caller's nonce could only prove "some VM with this measurement is alive", which is relayable.
/// So the guest just hands the app the device and stays out of the protocol.
///
/// The app is the only process that ever runs in this guest besides PID 1 (which is
/// non-dumpable and doesn't need the device), so 0666 here doesn't broaden exposure beyond the
/// app's own uid — it just stops requiring a shared group to express that.
#[cfg(feature = "sev-snp")]
fn expose_sev_guest_device() {
    if std::path::Path::new("/dev/sev-guest").exists() {
        let _ = std::fs::set_permissions("/dev/sev-guest", Permissions::from_mode(0o666));
    }
}

/// PID 1's final role once boot completes: blocks in `waitpid` for a child to exit, and
/// treats any exit that wasn't asked for by graceful shutdown as a compromise.
///
/// Blocking (no `WNOHANG`): the kernel wakes this thread only when a child actually changes
/// state, so PID 1 costs zero CPU while idle instead of polling on a timer.
///
/// Waits on `-1` rather than `app_pid` alone: PID 1 inherits every orphan the app leaves behind
/// and has to reap them, or they accumulate as zombies. A result that isn't `app_pid` is one of
/// those — not the supervised process, so not a compromise.
///
fn watchdog_loop(app_pid: u32) -> ! {
    loop {
        let shutting_down =
            crate::shutdown::SHUTDOWN_IN_PROGRESS.load(std::sync::atomic::Ordering::SeqCst);

        let pid = match rustix::process::wait(rustix::process::WaitOptions::empty()) {
            Ok(Some((pid, _status))) => pid,
            Err(rustix::io::Errno::CHILD) if !shutting_down => {
                fatal_shutdown("No supervised processes remain. System integrity compromised.");
            }
            // `Ok(None)` only happens with `NOHANG`, which this blocking call never sets, but
            // handling it the same as any other transient error (retry) beats assuming it can't
            // happen.
            Ok(None) | Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(250));
                continue;
            }
        };
        let pid = u32::try_from(pid.as_raw_pid()).unwrap_or(0);

        if pid != app_pid {
            continue;
        }
        if shutting_down {
            log(&format!(
                "App process (PID {pid}) exited (graceful shutdown)."
            ));
        } else {
            fatal_shutdown(&format!(
                "App process (PID {pid}) exited. System integrity compromised."
            ));
        }
    }
}

fn main() {
    // Failure is ignored: best-effort, a guest without the memory to lock everything should
    // still boot.
    let _ = rustix::mm::mlockall(
        rustix::mm::MlockAllFlags::CURRENT
            | rustix::mm::MlockAllFlags::FUTURE
            | rustix::mm::MlockAllFlags::ONFAULT,
    );

    if !is_pid1() {
        non_pid1_fatal_exit("This binary is the guest's init and only runs as PID 1");
    }

    println!("[INIT] cargo-unikernel guest init starting (PID 1)...");
    set_self_non_dumpable(|w| log(&format!("[WARN] {w}")));

    crate::mounts::prepare_system_env(PAYLOAD_DIR, log, fatal_shutdown);

    // Armed here rather than alongside `spawn_watcher` below: evdev only queues events for a
    // client from the moment it opens the device, and everything between this line and that one
    // (the entropy and network-settle waits alone allow 30s each) is time a hypervisor's
    // graceful-stop request would otherwise land in and be lost.
    let shutdown_triggers = crate::shutdown::arm_shutdown_triggers();
    let (uid, gid) = app_ids();
    chown_var_for_app(uid, gid, fatal_shutdown);

    let extra_sysctls = parse_pairs(EXTRA_SYSCTLS, "[hardening].extra_sysctls");
    crate::hardening::apply(&extra_sysctls, |w| {
        log(&format!("[WARN] {w}"));
    });

    crate::entropy::wait_for_entropy(log, fatal_shutdown);

    #[cfg(feature = "sev-snp")]
    expose_sev_guest_device();

    // Before the settle wait, not after: the wait polls for a default route, and a configured
    // gateway is the only thing that installs one where the provider routes a prefix instead of
    // advertising it. Doing this afterwards would mean always paying the full 30s timeout there.
    #[cfg(feature = "net-ipv6")]
    crate::network::configure_static_ipv6(IPV6_STATIC, IPV6_GATEWAY, IPV6_IFACE, &log);

    #[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
    crate::network::wait_for_network_settle(
        std::time::Duration::from_secs(30),
        std::time::Duration::from_millis(100),
        log,
    );

    // Lockdown before the app exists, so "the payload is read-only" holds for the app's whole
    // lifetime instead of depending on file ownership during a window before the remount.
    prepare_app_binary();
    crate::mounts::lockdown_filesystem(PAYLOAD_DIR, log, fatal_shutdown);

    let app_pid = spawn_app();

    // Spawned only now that the app exists: `Command::pre_exec` runs between `fork()` and
    // `execve()`, where only async-signal-safe work is sound, and forking a process that
    // already has other threads is what makes that a real constraint rather than a formality.
    crate::shutdown::spawn_watcher(shutdown_triggers, app_pid, log);

    log("Boot sequence complete. System operational. PID 1 entering watchdog mode.");
    watchdog_loop(app_pid);
}
