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
mod etcfiles;
#[cfg(feature = "firewall")]
mod firewall;
mod hardening;
#[cfg(feature = "landlock")]
mod landlock;
mod mounts;
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
mod network;
mod seccomp;
mod shutdown;
#[cfg(feature = "storage-persistent")]
mod storage;

use std::fs::Permissions;
#[cfg(feature = "logging")]
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

#[cfg(feature = "landlock")]
const LANDLOCK_RO: &str = env!("CARGO_UNIKERNEL_LANDLOCK_RO");
#[cfg(feature = "landlock")]
const LANDLOCK_RW: &str = env!("CARGO_UNIKERNEL_LANDLOCK_RW");

#[cfg(feature = "firewall")]
const FIREWALL_RULES: &str = env!("CARGO_UNIKERNEL_FIREWALL_RULES");

const NAMESERVERS: &str = env!("CARGO_UNIKERNEL_NAMESERVERS");
const DNS_SEARCH: &str = env!("CARGO_UNIKERNEL_DNS_SEARCH");

/// Splits a `';'`-joined path list (see `build.rs`) into its parts — the `landlock` feature's
/// `extra_read`/`extra_read_write`, which unlike [`parse_pairs`] carry no `=value` half.
#[cfg(feature = "landlock")]
fn parse_path_list(raw: &str) -> Vec<&str> {
    raw.split(';').filter(|s| !s.is_empty()).collect()
}

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

/// Boot-progress and `[WARN]` output. Compiled to a true no-op — no `println!`, no write
/// syscall — when the `logging` feature is off, which is the default: on sev-snp the serial
/// console is read by the hypervisor, outside the trust boundary, so "off" has to mean no
/// bytes ever reach it, not merely a flag this function chooses not to check.
#[cfg(feature = "logging")]
fn log(msg: &str) {
    println!("[INIT] {msg}");
}
#[cfg(not(feature = "logging"))]
const fn log(_msg: &str) {}

/// The writable mounts that belong to the app but are not world-writable.
///
/// `/var` is mounted root:root mode 0755 (tmpfs default, or `mke2fs`'s ext4 default) and `/run`
/// root:root mode 0755 — the app runs as an unprivileged, non-root uid/gid, so without this it
/// could never write into either at all. `/tmp`, `/var/tmp` and `/dev/shm` need no equivalent:
/// they are mounted `1777`, where the sticky bit is what keeps "writable by the app" from also
/// meaning "any process may unlink another's files". `/run` is not given that treatment because
/// nothing else in this guest has any business in it; a single owner is the tighter expression.
const APP_OWNED_DIRS: [&str; 2] = ["/var", "/run"];

fn chown_dirs_for_app(uid: u32, gid: u32, fatal: fn(&str) -> !) {
    for dir in APP_OWNED_DIRS {
        if let Err(e) = std::os::unix::fs::chown(dir, Some(uid), Some(gid)) {
            fatal(&format!("Failed to chown {dir} to the app's uid/gid: {e}"));
        }
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
    #[cfg(feature = "logging")]
    {
        eprintln!("\n======================================================================");
        eprintln!("FATAL (PID {}): {message}", std::process::id());
        eprintln!("Exiting — only PID 1 may run the guest's shutdown protocol.");
        eprintln!("======================================================================\n");
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
    }
    #[cfg(not(feature = "logging"))]
    let _ = message;
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

    #[cfg(feature = "logging")]
    {
        eprintln!("\n======================================================================");
        eprintln!("FATAL: {message}");
        eprintln!("SHUTDOWN: wiping writable state, then powering off.");
        eprintln!("======================================================================\n");
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
    }
    #[cfg(not(feature = "logging"))]
    let _ = message;

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

/// Refuses to let the app turn a writable mapping executable, or `mmap` a fresh
/// `PROT_WRITE|PROT_EXEC` one — `PR_SET_MDWE` (Linux 6.3+, the kernel this image pins is far
/// newer). This is what closes the one gap `mounts.rs`'s `noexec` flags admit to leaving open:
/// they seal file-backed routes to new code, not anonymous `mmap`/`mprotect`. `execve` itself
/// is untouched — the ELF loader maps a fresh image's text as `PROT_EXEC` directly, never via a
/// writable-then-executable transition, so this does not affect spawning subprocesses at all,
/// only turning memory the app already holds writable into memory it then runs.
///
/// The one real cost: it also blocks any JIT the app embeds, which needs exactly this
/// transition to emit and run generated code. `danger-allow-write-execute` already exists for
/// that population (today via `/tmp`'s mount flags and the `memfd_create`/`memfd_secret`
/// seccomp entries) — this ties into the same feature rather than adding a second toggle, so
/// enabling one opt-out coherently lifts every "no writable+executable memory" guarantee at
/// once instead of half of them.
///
/// Two functions selected by `#[cfg]`, matching every other opt-out in this crate: a build
/// without the escape hatch doesn't carry a runtime check that could be bypassed, it carries
/// no call to `PR_SET_MDWE` at all is the *danger* build, and the default build carries no
/// branch that skips it.
#[cfg(not(feature = "danger-allow-write-execute"))]
fn set_mdwe() -> std::io::Result<()> {
    // PR_SET_MDWE = 65, PR_MDWE_REFUSE_EXEC_GAIN = 1 (linux/prctl.h) — hardcoded rather than
    // trusting `libc` to export names this recent for every target this crate might build on.
    const PR_SET_MDWE: libc::c_int = 65;
    const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;
    // SAFETY: plain integer arguments; the return value is checked.
    unsafe {
        if libc::prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
// `Result` here is never an `Err` — but this must share `set_mdwe`'s other-cfg signature,
// since both are passed to `Command::pre_exec` as plain `fn` values from the same call site.
#[cfg(feature = "danger-allow-write-execute")]
#[allow(clippy::unnecessary_wraps)]
const fn set_mdwe() -> std::io::Result<()> {
    Ok(())
}

/// The child's `setrlimit` ceilings, parsed from their baked-in strings.
///
/// A plain struct of numbers so [`apply_resource_limits`] can be handed values rather than
/// parsing in the forked child: `baked`'s failure path formats a message and runs the wipe
/// protocol, both of which allocate, and a `pre_exec` closure must not — see [`spawn_app`].
#[derive(Debug, Clone, Copy)]
struct ResourceLimits {
    nofile: u64,
    nproc: u64,
    memlock_bytes: u64,
    /// `0` means no `RLIMIT_AS` cap.
    address_space_bytes: u64,
}

const MIB: u64 = 1024 * 1024;

/// Parses every limit constant. Called in the parent, before the fork.
fn resource_limits() -> ResourceLimits {
    ResourceLimits {
        nofile: baked(LIMIT_NOFILE, "CARGO_UNIKERNEL_LIMIT_NOFILE"),
        nproc: baked(LIMIT_NPROC, "CARGO_UNIKERNEL_LIMIT_NPROC"),
        memlock_bytes: baked::<u64>(LIMIT_MEMLOCK_MB, "CARGO_UNIKERNEL_LIMIT_MEMLOCK_MB")
            .saturating_mul(MIB),
        address_space_bytes: baked::<u64>(LIMIT_AS_MB, "CARGO_UNIKERNEL_LIMIT_AS_MB")
            .saturating_mul(MIB),
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
/// Takes already-parsed values (see [`ResourceLimits`]) so the closure this returns performs
/// nothing but `setrlimit` syscalls in the forked child.
fn apply_resource_limits(limits: ResourceLimits) -> impl Fn() -> std::io::Result<()> {
    use rustix::process::Resource;

    move || {
        set_rlimit(Resource::Nofile, limits.nofile)?;
        set_rlimit(Resource::Nproc, limits.nproc)?;
        set_rlimit(Resource::Memlock, limits.memlock_bytes)?;
        if limits.address_space_bytes > 0 {
            set_rlimit(Resource::As, limits.address_space_bytes)?;
        }
        Ok(())
    }
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

    // Built here, before the fork below, and moved into the `pre_exec` closures that apply
    // them: `seccomp::build_baseline_denylist` allocates, which is unsound to do between
    // `fork()` and `execve()` — see its own doc comment. `landlock::build` carries the same
    // constraint (it opens files and allocates a `Vec`), and so does `resource_limits`, whose
    // parse failures format a message and run the wipe protocol.
    let seccomp_program = crate::seccomp::build_baseline_denylist(fatal_shutdown);
    let limits = resource_limits();
    #[cfg(feature = "landlock")]
    let landlock_ruleset = crate::landlock::build(
        PAYLOAD_DIR,
        &parse_path_list(LANDLOCK_RO),
        &parse_path_list(LANDLOCK_RW),
        log,
        fatal_shutdown,
    );

    // SAFETY: `pre_exec` closures run in the forked child between `fork()` and `execve()`,
    // where only async-signal-safe operations are sound; each closure here calls only a fixed,
    // small number of setrlimit/setgroups/setgid/setuid/prctl/landlock/seccomp syscalls.
    let (uid, gid) = app_ids();
    let mut command = Command::new(APP_PATH);
    command
        .env_clear()
        .envs(parse_pairs(APP_ENV, "[app.runtime].env"));
    // Without the `app-console` feature (the default): the app's stdio goes to /dev/null
    // rather than PID 1's inherited serial console. On sev-snp that console is read by the
    // hypervisor — outside the trust boundary — so the app's own output must not reach it
    // unless this feature was deliberately compiled in. `app-console`'s build simply doesn't
    // call `.stdin`/`.stdout`/`.stderr` here, so `Command`'s default (inherit) applies.
    #[cfg(not(feature = "app-console"))]
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(feature = "landlock")]
    let ruleset_fd = landlock_ruleset.raw_fd();
    let child = unsafe {
        command
            .pre_exec(apply_resource_limits(limits))
            .pre_exec(drop_privileges(uid, gid))
            .pre_exec(set_mdwe);
        #[cfg(feature = "landlock")]
        command.pre_exec(move || crate::landlock::restrict_self(ruleset_fd));
        command
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
        let wait_result = rustix::process::wait(rustix::process::WaitOptions::empty());

        // Read *after* the wait returns, never before it. The shutdown watcher runs on another
        // thread and sets this flag while this one is already blocked, so a value sampled before
        // the wait is stale by however long the guest sat idle — which would make every graceful
        // stop look like the app exiting on its own, i.e. a compromise, and race a second
        // kill-and-wipe against the one the watcher thread is already running.
        let shutting_down =
            crate::shutdown::SHUTDOWN_IN_PROGRESS.load(std::sync::atomic::Ordering::SeqCst);

        let pid = match wait_result {
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

    log("cargo-unikernel guest init starting (PID 1)...");
    set_self_non_dumpable(|w| log(&format!("[WARN] {w}")));

    // Ahead of `prepare_system_env`, which is what brings the interfaces up: the filter has to
    // be in place before the guest can receive a packet, not shortly afterwards.
    #[cfg(feature = "firewall")]
    crate::firewall::install(
        &crate::firewall::parse_rules(FIREWALL_RULES, fatal_shutdown),
        log,
        fatal_shutdown,
    );

    crate::mounts::prepare_system_env(PAYLOAD_DIR, log, fatal_shutdown);

    // Armed here rather than alongside `spawn_watcher` below: evdev only queues events for a
    // client from the moment it opens the device, and everything between this line and that one
    // (the entropy and network-settle waits alone allow 30s each) is time a hypervisor's
    // graceful-stop request would otherwise land in and be lost.
    let shutdown_triggers = crate::shutdown::arm_shutdown_triggers();
    let (uid, gid) = app_ids();
    chown_dirs_for_app(uid, gid, fatal_shutdown);

    // After /proc is mounted (for /proc/net/pnp) but otherwise placement-insensitive — nothing
    // else reads /etc before the app starts, and nothing after lockdown can write to it anyway.
    crate::etcfiles::write_etc(uid, gid, NAMESERVERS, DNS_SEARCH, &|w: &str| {
        log(&format!("[WARN] {w}"));
    });

    let extra_sysctls = parse_pairs(EXTRA_SYSCTLS, "[hardening].extra_sysctls");
    let sysctls = crate::hardening::apply(&extra_sysctls, |w| {
        log(&format!("[WARN] {w}"));
    });
    log(&format!(
        "Sysctl hardening applied: {} knobs set, {} absent on this kernel.",
        sysctls.applied, sysctls.absent
    ));

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
