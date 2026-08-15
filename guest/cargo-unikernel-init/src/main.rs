//! Minimal guest PID-1 for a unikernel image. The app binary is embedded into the image at
//! build time (see `cargo-unikernel`'s rootfs pipeline), so there is no runtime fetch,
//! signature check, or secure-time bootstrap here — the SEV-SNP launch measurement (or the
//! image's own hash, for casual builds) already covers the exact app bytes.

#![forbid(unsafe_op_in_unsafe_fn, elided_lifetimes_in_paths)]

#[cfg(feature = "attestation")]
mod attestation;

use std::fs::Permissions;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;

const PAYLOAD_DIR: &str = env!("CARGO_UNIKERNEL_PAYLOAD_DIR");
const APP_PATH: &str = env!("CARGO_UNIKERNEL_APP_PATH");
const APP_UID: &str = env!("CARGO_UNIKERNEL_APP_UID");
const APP_GID: &str = env!("CARGO_UNIKERNEL_APP_GID");
const APP_ENV: &str = env!("CARGO_UNIKERNEL_APP_ENV");
#[cfg(feature = "attestation")]
const ATTEST_UID: &str = env!("CARGO_UNIKERNEL_ATTEST_UID");
#[cfg(feature = "attestation")]
const ATTEST_GID: &str = env!("CARGO_UNIKERNEL_ATTEST_GID");
const EXTRA_SYSCTLS: &str = env!("CARGO_UNIKERNEL_EXTRA_SYSCTLS");

const LIMIT_NOFILE: &str = env!("CARGO_UNIKERNEL_LIMIT_NOFILE");
const LIMIT_NPROC: &str = env!("CARGO_UNIKERNEL_LIMIT_NPROC");
const LIMIT_AS_MB: &str = env!("CARGO_UNIKERNEL_LIMIT_AS_MB");
const LIMIT_MEMLOCK_MB: &str = env!("CARGO_UNIKERNEL_LIMIT_MEMLOCK_MB");

/// Splits a `';'`-joined list of `key=value` pairs (see `build.rs`) into its parts.
///
/// A pair with no `=` runs the wipe protocol rather than being silently dropped — these
/// strings come from validated host-side config, so a malformed one means the two sides
/// disagree about the encoding. `what` names the setting in the panic message.
fn parse_pairs<'a>(raw: &'a str, what: &str) -> Vec<(&'a str, &'a str)> {
    raw.split(';')
        .filter(|s| !s.is_empty())
        .map(|pair| {
            pair.split_once('=').unwrap_or_else(|| {
                panic_shutdown(&format!(
                    "Malformed entry in {what}: {pair:?} is not a 'key=value' pair"
                ))
            })
        })
        .collect()
}

/// Every `*_uid`/`*_gid`/`limit_*` accessor below parses a build-time-baked constant (see
/// `build.rs`) rather than untrusted runtime input, but a malformed override is still
/// something this process can observe at its own runtime — so a parse failure runs the wipe
/// protocol via [`panic_shutdown`] rather than unwinding.
fn app_uid() -> u32 {
    APP_UID
        .parse()
        .unwrap_or_else(|_| panic_shutdown("CARGO_UNIKERNEL_APP_UID must be a u32"))
}
fn app_gid() -> u32 {
    APP_GID
        .parse()
        .unwrap_or_else(|_| panic_shutdown("CARGO_UNIKERNEL_APP_GID must be a u32"))
}
#[cfg(feature = "attestation")]
fn attest_uid() -> u32 {
    ATTEST_UID
        .parse()
        .unwrap_or_else(|_| panic_shutdown("CARGO_UNIKERNEL_ATTEST_UID must be a u32"))
}
#[cfg(feature = "attestation")]
fn attest_gid() -> u32 {
    ATTEST_GID
        .parse()
        .unwrap_or_else(|_| panic_shutdown("CARGO_UNIKERNEL_ATTEST_GID must be a u32"))
}

fn log(msg: &str) {
    println!("[INIT] {msg}");
}

/// `/var` is mounted root:root mode 0755 (tmpfs default, or `mke2fs`'s ext4 default) — the app
/// runs as an unprivileged, non-root uid/gid, so without this it could never write into `/var`
/// at all, in either storage mode.
fn chown_var_for_app(uid: u32, gid: u32, fatal: fn(&str) -> !) {
    // SAFETY: `c"/var"` is a `'static` NUL-terminated C string literal.
    let ret = unsafe { libc::chown(c"/var".as_ptr(), uid, gid) };
    if ret != 0 {
        fatal(&format!(
            "Failed to chown /var to the app's uid/gid: {}",
            std::io::Error::last_os_error()
        ));
    }
}

fn is_pid1() -> bool {
    std::process::id() == 1
}

/// Logs a fatal error and exits the calling child, without touching the VM.
///
/// A child can't power off: `drop_privileges` already removed `CAP_SYS_BOOT`, and `reboot` is
/// seccomp-denied. Exiting gets to the same place one hop later, via PID 1's watchdog treating
/// the exit as a compromise. Runs even under `debug-mode` — a child parked in the debug halt
/// loop would stay alive and the watchdog would never fire.
fn child_fatal_exit(message: &str) -> ! {
    eprintln!("\n======================================================================");
    eprintln!("FATAL (child PID {}): {message}", std::process::id());
    eprintln!("Exiting — PID 1's watchdog will take the guest down.");
    eprintln!("======================================================================\n");
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(1);
}

/// The guest's wipe-and-exit protocol for any unrecoverable or integrity-compromising error.
///
/// Never unwinds or returns. From PID 1, logs and powers the VM off immediately; from a child,
/// defers to [`child_fatal_exit`]. This is the *only* sanctioned way any critical failure in
/// this crate ends — production code paths call this instead of panicking so a bug or bypassed
/// check fails safely rather than continuing in an unknown state.
///
/// Two implementations selected by the `debug-mode` feature, not a runtime flag: the
/// "stay up and halt instead of powering off" behavior below must never exist in a binary
/// that wasn't deliberately built with it — see that feature's doc comment in Cargo.toml.
#[cfg(not(feature = "debug-mode"))]
pub(crate) fn panic_shutdown(message: &str) -> ! {
    if !is_pid1() {
        child_fatal_exit(message);
    }

    eprintln!("\n======================================================================");
    eprintln!("FATAL: {message}");
    eprintln!("PANIC SHUTDOWN: Powering off immediately.");
    eprintln!("======================================================================\n");
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    // SAFETY: plain integer command code, no pointers; PID 1 is who is allowed to call it.
    unsafe {
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    std::process::exit(1);
}

/// `debug-mode` build: suppresses the power-off so a fatal error can be read off a
/// slow-to-connect console instead of vanishing with the guest. Never compiled into a real
/// deployment — see this feature's doc comment in Cargo.toml.
#[cfg(feature = "debug-mode")]
pub(crate) fn panic_shutdown(message: &str) -> ! {
    if !is_pid1() {
        child_fatal_exit(message);
    }

    eprintln!("\n======================================================================");
    eprintln!("FATAL: {message}");
    eprintln!("PANIC SHUTDOWN SUPPRESSED (debug-mode): guest stays up. Not secure.");
    eprintln!("======================================================================\n");
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    loop {
        eprintln!("[DEBUG] Halted after fatal error (see above). Guest intentionally not powered off.");
        let _ = std::io::stderr().flush();
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

/// Marks PID 1 non-dumpable, so `/proc/1/mem`/`maps` stay unreadable.
///
/// Not applied in the children's `pre_exec` chain — `execve` resets `dumpable` on any exec
/// that isn't a "secure exec", and [`drop_privileges`] switches uid *before* the exec, so it
/// would just get cleared again there. PID 1 never execs, so here it sticks. The app is
/// covered instead by `yama ptrace_scope=3`, the seccomp `ptrace`/`process_vm_readv`/`writev`
/// entries, `CONFIG_COREDUMP=n`, and `CONFIG_PROC_MEM_NO_FORCE=y`.
fn set_self_non_dumpable(warn: impl Fn(&str)) {
    // SAFETY: plain integer arguments, no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        warn(&format!(
            "Failed to mark PID 1 non-dumpable: {}",
            std::io::Error::last_os_error()
        ));
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

fn limit_nofile() -> u64 {
    LIMIT_NOFILE
        .parse()
        .unwrap_or_else(|_| panic_shutdown("CARGO_UNIKERNEL_LIMIT_NOFILE must be a u64"))
}
fn limit_nproc() -> u64 {
    LIMIT_NPROC
        .parse()
        .unwrap_or_else(|_| panic_shutdown("CARGO_UNIKERNEL_LIMIT_NPROC must be a u64"))
}
fn limit_as_mb() -> u64 {
    LIMIT_AS_MB
        .parse()
        .unwrap_or_else(|_| panic_shutdown("CARGO_UNIKERNEL_LIMIT_AS_MB must be a u64"))
}
fn limit_memlock_mb() -> u64 {
    LIMIT_MEMLOCK_MB
        .parse()
        .unwrap_or_else(|_| panic_shutdown("CARGO_UNIKERNEL_LIMIT_MEMLOCK_MB must be a u64"))
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
/// `RLIMIT_*` are small, fixed uapi constants that always fit `c_int` — the narrowing casts
/// below are exact, never lossy.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn apply_resource_limits() -> std::io::Result<()> {
    set_rlimit(libc::RLIMIT_NOFILE as libc::c_int, limit_nofile())?;
    set_rlimit(libc::RLIMIT_NPROC as libc::c_int, limit_nproc())?;
    set_rlimit(
        libc::RLIMIT_MEMLOCK as libc::c_int,
        limit_memlock_mb().saturating_mul(1024 * 1024),
    )?;
    let as_mb = limit_as_mb();
    if as_mb > 0 {
        set_rlimit(
            libc::RLIMIT_AS as libc::c_int,
            as_mb.saturating_mul(1024 * 1024),
        )?;
    }
    Ok(())
}

/// `resource as _`: `setrlimit`'s parameter type differs across libcs (glibc: `c_uint`; musl:
/// `c_int`); this crate only targets musl but must still type-check on a glibc host. Every
/// `resource` passed in is a small, non-negative `RLIMIT_*` constant, so the conversion is
/// always exact regardless of which one applies.
#[allow(clippy::cast_sign_loss)]
fn set_rlimit(resource: libc::c_int, value: u64) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: `limit` is a valid, in-scope `libc::rlimit`, only read for the call's duration.
    let ret = unsafe { libc::setrlimit(resource as _, std::ptr::addr_of!(limit)) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Runs after fork, before exec — installs the mandatory baseline seccomp denylist on every
/// child this init spawns.
///
/// A failure here surfaces through `Command::spawn()` into `panic_shutdown`: booting without
/// the filter silently in place would be worse than refusing to boot.
fn install_seccomp_baseline() -> std::io::Result<()> {
    cargo_unikernel_common::seccomp::install_baseline_denylist()
}

/// Checks the embedded app binary is present and makes it read-only + executable.
///
/// Split out of [`spawn_app`] so it runs *before* [`cargo_unikernel_common::mounts::lockdown_filesystem`]
/// seals `PAYLOAD_DIR`
/// read-only — this `chmod` would fail against an already-locked-down mount.
fn prepare_app_binary() {
    if !std::path::Path::new(APP_PATH).exists() {
        panic_shutdown(&format!(
            "Embedded app binary not found at {APP_PATH} — this image was not built correctly"
        ));
    }
    std::fs::set_permissions(APP_PATH, Permissions::from_mode(0o555)).unwrap_or_else(|e| {
        panic_shutdown(&format!("Failed to set permissions on {APP_PATH}: {e}"))
    });
}

/// Spawns the embedded app as a stripped-down, unprivileged child. See the `pre_exec` chain's
/// own comment (inside) for why each closure runs, and in that specific order.
fn spawn_app() -> u32 {
    log("Spawning embedded app as child process...");

    // SAFETY: `pre_exec` closures run in the forked child between `fork()` and `execve()`,
    // where only async-signal-safe operations are sound; each closure here calls only a fixed,
    // small number of setrlimit/setgroups/setgid/setuid/seccomp syscalls. Not using
    // `Command::uid`/`gid`: its built-in switch always runs before `pre_exec`, which would
    // leave `drop_privileges`'s capability-bounding-set drop without `CAP_SETPCAP` (see its
    // doc comment). Order matters: `apply_resource_limits` must run before `drop_privileges`,
    // since raising a hard rlimit above the kernel's default needs `CAP_SYS_RESOURCE`, which
    // `drop_privileges` removes.
    let child = unsafe {
        Command::new(APP_PATH)
            .env_clear()
            .envs(parse_pairs(APP_ENV, "[app.runtime].env"))
            .pre_exec(apply_resource_limits)
            .pre_exec(drop_privileges(app_uid(), app_gid()))
            .pre_exec(install_seccomp_baseline)
            .spawn()
            .unwrap_or_else(|e| panic_shutdown(&format!("Failed to spawn app: {e}")))
    };
    let child_pid = child.id();
    log(&format!("App launched as PID {child_pid}."));
    child_pid
}

/// Makes `/dev/sev-guest` (if present — only ever true on the sev-snp profile) openable by
/// both the app AND the attestation server.
///
/// Gated on the `sev-snp` feature (set for every sev-snp-profile build), not `attestation`:
/// the app legitimately wants to fetch/verify its own SEV-SNP report (e.g. to attest itself to
/// a peer, or sanity-check its own launch measurement) whether or not this build also runs the
/// separate attestation server — tying this to `attestation` would silently leave the app
/// locked out of a device it's entitled to whenever the user hadn't also enabled that server.
/// The only processes that ever run in this guest are the app and (if compiled in) the
/// attestation server, both under their own fixed uids — 0666 here doesn't broaden exposure
/// beyond those two, it just stops requiring a shared group to express that.
#[cfg(feature = "sev-snp")]
fn expose_sev_guest_device() {
    if std::path::Path::new("/dev/sev-guest").exists() {
        let _ = std::fs::set_permissions("/dev/sev-guest", Permissions::from_mode(0o666));
    }
}

/// Spawns the optional SEV-SNP attestation server as an isolated, separately-privileged
/// child. Only exists at all when the `attestation` feature is compiled in.
#[cfg(feature = "attestation")]
fn spawn_attestation_server() -> u32 {
    let current_exe =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/init"));
    // SAFETY: same pre_exec-in-forked-child reasoning, and the same ordering requirement, as
    // the app spawn in `spawn_app`.
    let attest_child = unsafe {
        Command::new(current_exe)
            .arg("run-attestation-server")
            // PID 1's env comes from the host-supplied kernel cmdline; nothing this server
            // needs travels that way (port/uid/gid are env!-baked at build time).
            .env_clear()
            .pre_exec(apply_resource_limits)
            .pre_exec(drop_privileges(attest_uid(), attest_gid()))
            .pre_exec(install_seccomp_baseline)
            .spawn()
            .unwrap_or_else(|e| panic_shutdown(&format!("Failed to spawn attestation server: {e}")))
    };
    let pid = attest_child.id();
    log(&format!("Attestation server spawned as isolated PID {pid}."));
    pid
}

/// PID 1's final role once boot completes: blocks in `waitpid` for a child to exit, and
/// treats any exit that wasn't asked for by graceful shutdown as a compromise.
///
/// Blocking (no `WNOHANG`): the kernel wakes this thread only when a child actually changes
/// state, so PID 1 costs zero CPU while idle instead of polling on a timer.
///
/// PIDs never exceed `i32::MAX` on Linux (`pid_max` is capped well below that), so the
/// `u32`/`pid_t` conversions below are always exact.
#[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
fn watchdog_loop(child_pid: u32, attest_pid: Option<u32>) -> ! {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid, in-scope `i32`, written only within this call.
        let pid = unsafe { libc::waitpid(-1, std::ptr::addr_of_mut!(status), 0) };
        // A child that exited because graceful shutdown asked it to isn't a compromise.
        let shutting_down = cargo_unikernel_common::shutdown::SHUTDOWN_IN_PROGRESS
            .load(std::sync::atomic::Ordering::SeqCst);

        if pid <= 0 {
            let err = std::io::Error::last_os_error();
            // ECHILD means every supervised process is gone. Expected during graceful
            // shutdown (the watcher is already headed to reboot()); otherwise the workload
            // vanished without the watchdog seeing how, which is exactly what to power off for.
            if err.raw_os_error() == Some(libc::ECHILD) && !shutting_down {
                panic_shutdown("No supervised processes remain. System integrity compromised.");
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        }
        if pid == child_pid as i32 {
            if shutting_down {
                log(&format!("App process (PID {pid}) exited (graceful shutdown)."));
            } else {
                panic_shutdown(&format!(
                    "App process (PID {pid}) exited. System integrity compromised."
                ));
            }
        } else if Some(pid as u32) == attest_pid {
            if shutting_down {
                log(&format!(
                    "Attestation server (PID {pid}) exited (graceful shutdown)."
                ));
            } else {
                panic_shutdown(&format!(
                    "Attestation server (PID {pid}) exited. System integrity compromised."
                ));
            }
        }
    }
}

fn main() {
    // SAFETY: plain integer flags, no pointers. Failure is ignored: best-effort, a guest
    // without the memory to lock everything should still boot.
    unsafe {
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT);
    }

    #[cfg(feature = "attestation")]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.len() == 2 && args[1] == "run-attestation-server" {
            println!(
                "[ATTEST] Starting isolated attestation server (PID {})",
                std::process::id()
            );
            attestation::run_attestation_server();
        }
    }

    println!("[INIT] cargo-unikernel guest init starting (PID 1)...");
    set_self_non_dumpable(|w| log(&format!("[WARN] {w}")));

    cargo_unikernel_common::mounts::prepare_system_env(PAYLOAD_DIR, log, panic_shutdown);
    chown_var_for_app(app_uid(), app_gid(), panic_shutdown);

    let extra_sysctls = parse_pairs(EXTRA_SYSCTLS, "[hardening].extra_sysctls");
    cargo_unikernel_common::hardening::apply(&extra_sysctls, |w| {
        log(&format!("[WARN] {w}"));
    });

    cargo_unikernel_common::entropy::wait_for_entropy(log);

    #[cfg(feature = "sev-snp")]
    expose_sev_guest_device();

    #[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
    cargo_unikernel_common::mounts::wait_for_network_settle(
        std::time::Duration::from_secs(30),
        std::time::Duration::from_millis(100),
        log,
    );

    // Lockdown before the app exists, so "the payload is read-only" holds for the app's whole
    // lifetime instead of depending on file ownership during a window before the remount.
    prepare_app_binary();
    cargo_unikernel_common::mounts::lockdown_filesystem(PAYLOAD_DIR, log, panic_shutdown);

    let child_pid = spawn_app();

    #[cfg(feature = "attestation")]
    let attest_pid = Some(spawn_attestation_server());
    #[cfg(not(feature = "attestation"))]
    let attest_pid: Option<u32> = None;

    let mut watched_pids = vec![child_pid];
    watched_pids.extend(attest_pid);
    cargo_unikernel_common::shutdown::spawn_watcher(watched_pids, log);

    log("Boot sequence complete. System operational. PID 1 entering watchdog mode.");
    watchdog_loop(child_pid, attest_pid);
}
