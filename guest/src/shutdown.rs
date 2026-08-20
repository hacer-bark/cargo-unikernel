//! Graceful shutdown.
//!
//! A hypervisor's "graceful stop" (QEMU's ACPI shutdown) asserts the guest's ACPI power
//! button rather than signaling any guest process directly, so without something reading
//! that event it has nowhere to land, and a force-stop skips app cleanup and the scrub below.
//!
//! Watches for either trigger (ACPI power button via evdev, or SIGTERM to PID 1), then: asks
//! the app to exit (`SIGTERM`), gives it a bounded grace period, force-kills anything still
//! alive, best-effort zeroes writable tmpfs state, and powers off.
//!
//! [`wipe_and_power_off`] is the other way in: the same wipe, reached from a fatal error rather
//! than a shutdown request. It skips the `SIGTERM` grace period (nothing is owed a clean exit
//! at that point) and is bounded by a hard deadline, but it scrubs the same paths — an
//! integrity failure should not leave more behind than an orderly stop does.

use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// Set the moment a shutdown request is observed.
///
/// Checked by `main.rs`'s watchdog loop before treating the app's exit as an integrity
/// violation. An app dying because graceful shutdown asked it to isn't a compromise.
pub(crate) static SHUTDOWN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Write end of the self-pipe `on_sigterm` wakes: `write(2)` is one of the few calls safe to
/// use from a signal handler, unlike condvars/channels — this is the standard self-pipe trick
/// for turning a signal into something `epoll_wait` can block on.
static SIGTERM_PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);
/// Belt-and-suspenders alongside the pipe: only consulted by `wait_for_trigger_polling`, the
/// rare fallback used if `epoll`/`pipe2` setup itself fails.
static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

const SIGTERM_GRACE: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Hard ceiling on the whole of [`wipe_and_power_off`], enforced by a watchdog thread that
/// powers off regardless of what the wipe is doing.
///
/// The wipe runs on a path that was reached *because* something is already wrong, so it must
/// not be able to keep a compromised guest alive by being slow — a `read_dir` on a corrupted
/// mount, a `write_all` to a full tmpfs, or an `unmount` that blocks would otherwise leave the
/// VM up indefinitely. Generous enough for a full 64 MB `/tmp` plus an ext4 unmount, short
/// enough that a wedged wipe is bounded.
const EMERGENCY_WIPE_DEADLINE: Duration = Duration::from_secs(20);

/// How long [`wipe_and_power_off`] waits for `SIGKILL`ed processes to actually leave the
/// process table before scrubbing, so nothing is still writing into what's being scrubbed.
const KILL_SETTLE_TIMEOUT: Duration = Duration::from_secs(2);

/// Guards against re-entering the wipe. A second entry means the wipe itself is what failed
/// (it called `fatal` again), so the only remaining safe move is to stop trying and power off.
static EMERGENCY_WIPE_STARTED: AtomicBool = AtomicBool::new(false);

const EV_KEY: u16 = 0x01;
const KEY_POWER: u16 = 116;

#[repr(C)]
struct InputEvent {
    tv_sec: i64,
    tv_usec: i64,
    ev_type: u16,
    code: u16,
    value: i32,
}

extern "C" fn on_sigterm(_: libc::c_int) {
    // Async-signal-safe: `write(2)` on an already-open fd is one of the few things safe to do
    // from a handler (unlike condvars/channels) — wakes the watcher thread's `epoll_wait`
    // instead of it having to poll for this flag on a timer.
    SIGTERM_RECEIVED.store(true, Ordering::SeqCst);
    let fd = SIGTERM_PIPE_WRITE_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        let byte = 1u8;
        unsafe {
            libc::write(fd, std::ptr::addr_of!(byte).cast::<libc::c_void>(), 1);
        }
    }
}

/// The armed shutdown triggers: the SIGTERM handler is installed and every evdev device is
/// open, so a trigger that fires before the watcher thread exists is still observed.
#[derive(Debug)]
pub(crate) struct ShutdownTriggers {
    devices: Vec<std::fs::File>,
}

/// Installs the SIGTERM handler and opens every `/dev/input/event*` device.
///
/// Separate from [`spawn_watcher`], and called as early in boot as `/dev` allows, because evdev
/// only queues events for a client from the moment that client opens the device: a power button
/// pressed before the open is not buffered anywhere, it is simply never seen. Boot between the
/// two calls can take a minute (the entropy and network-settle waits alone allow 30s each), and
/// a hypervisor's graceful-stop request landing in that window must not be silently dropped.
///
/// The SIGTERM half has no such window — PID 1 ignores signals it has no handler for — but the
/// two triggers belong together.
/// Turning a function pointer into the raw integer `libc::signal` expects has no stable
/// non-`as` route on Rust today — there is no `TryFrom`/safe wrapper for a fn-pointer-to-integer
/// conversion, so the cast lint is allowed here rather than worked around.
#[must_use]
#[allow(clippy::as_conversions)]
pub(crate) fn arm_shutdown_triggers() -> ShutdownTriggers {
    // SAFETY: `on_sigterm`'s signature matches what the C ABI expects for a signal handler.
    unsafe {
        libc::signal(libc::SIGTERM, on_sigterm as *const () as libc::sighandler_t);
    }

    ShutdownTriggers {
        devices: find_input_event_devices()
            .into_iter()
            .filter_map(|p| std::fs::File::open(p).ok())
            .inspect(set_nonblocking)
            .collect(),
    }
}

/// Spawns the watcher thread over already-armed triggers.
///
/// `app_pid` is the process this init asks to exit first, before the blanket kill that follows
/// it. `log` is called from the watcher thread, so it must be `Send`.
pub(crate) fn spawn_watcher(
    triggers: ShutdownTriggers,
    app_pid: u32,
    log: impl Fn(&str) + Send + 'static,
) {
    std::thread::spawn(move || {
        wait_for_trigger(&triggers.devices);
        SHUTDOWN_IN_PROGRESS.store(true, Ordering::SeqCst);
        log("Graceful shutdown requested — signaling the app...");
        run_graceful_shutdown(app_pid, &log);
    });
}

/// Blocks in `epoll_wait` until either trigger fires, rather than polling both on a timer —
/// this thread costs zero CPU for as long as the guest just sits idle, which for most of a
/// unikernel's lifetime is the whole point.
///
/// File descriptors are always small non-negative `c_int`s in this function, and the epoll
/// event buffer length is a fixed fits-in-`i32` constant — the following casts are all exact,
/// never truncating/wrapping/losing sign in practice.
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::as_conversions
)]
fn wait_for_trigger(devices: &[std::fs::File]) {
    use std::os::fd::{FromRawFd as _, IntoRawFd as _, OwnedFd};

    // SAFETY: a plain integer flags argument; the returned fd (or -1 on error) is checked below.
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        // Falls back to the old polling behaviour rather than blocking forever on a broken
        // epoll — this should never happen in practice.
        return wait_for_trigger_polling(devices);
    }
    // Owned from here on, so every `return` below closes it — there are five, and this function
    // is the only thing that ever holds this descriptor.
    // SAFETY: `epfd` was just created, is non-negative, and is not owned by anything else.
    let epfd = unsafe { OwnedFd::from_raw_fd(epfd) };
    let epfd_raw = epfd.as_raw_fd();

    // SAFETY: `pipefds` is a valid, in-scope `[c_int; 2]`; the call fills both entries.
    let mut pipefds: [libc::c_int; 2] = [0; 2];
    if unsafe { libc::pipe2(pipefds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
        return wait_for_trigger_polling(devices);
    }
    // SAFETY: both were just created by `pipe2`, are non-negative, and are not owned elsewhere.
    let (sigterm_read, sigterm_write) = unsafe {
        (
            OwnedFd::from_raw_fd(pipefds[0]),
            OwnedFd::from_raw_fd(pipefds[1]),
        )
    };
    let sigterm_read_fd = sigterm_read.as_raw_fd();

    let register = |fd: libc::c_int| {
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: fd as u64,
        };
        // SAFETY: `epfd_raw` is the just-created epoll instance; `ev` is a valid, in-scope event
        // struct only read for the duration of this call; `fd` is a live, open descriptor.
        unsafe {
            libc::epoll_ctl(
                epfd_raw,
                libc::EPOLL_CTL_ADD,
                fd,
                std::ptr::addr_of_mut!(ev),
            )
        }
    };
    // Registered before the fd is published to the handler below, so the one path that can still
    // give up on epoll is also the last one where closing the pipe is safe.
    if register(sigterm_read_fd) != 0 {
        return wait_for_trigger_polling(devices);
    }

    // Deliberately released to the process, not leaked by accident: from the store below,
    // `on_sigterm` may write to this descriptor at any moment, and a signal handler has no way
    // to coordinate with a close. The pair therefore lives as long as the process does — two
    // descriptors, in a process that exists to power the machine off.
    let sigterm_write_fd = sigterm_write.into_raw_fd();
    let _sigterm_read_fd_owned_by_process = sigterm_read.into_raw_fd();
    SIGTERM_PIPE_WRITE_FD.store(sigterm_write_fd, Ordering::SeqCst);

    // A SIGTERM delivered any time between `arm_shutdown_triggers()` installing the handler and
    // the store just above would have run `on_sigterm`, which always sets `SIGTERM_RECEIVED` —
    // but found `SIGTERM_PIPE_WRITE_FD` still at its `-1` sentinel, so it wrote no wakeup byte.
    // Left unchecked, that signal is silently lost: the epoll loop below has no other way to
    // learn about it and would block forever. The handler is armed early in boot, so this window
    // spans the whole boot sequence rather than a few instructions.
    if SIGTERM_RECEIVED.load(Ordering::SeqCst) {
        return;
    }

    for device in devices {
        register(device.as_raw_fd());
    }

    let mut events: [libc::epoll_event; 16] = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: `events` is a valid, in-scope buffer of the given length; `-1` blocks with no
        // timeout. A spurious `EINTR` wakeup just loops back into another wait.
        let n = unsafe { libc::epoll_wait(epfd_raw, events.as_mut_ptr(), events.len() as i32, -1) };
        if n < 0 {
            continue;
        }
        let ready = usize::try_from(n).unwrap_or(0).min(events.len());
        for ev in events.get(..ready).unwrap_or(&[]) {
            let fd = ev.u64 as libc::c_int;
            if fd == sigterm_read_fd {
                return;
            }
            if let Some(device) = devices.iter().find(|d| d.as_raw_fd() == fd)
                && power_button_pressed(device)
            {
                return;
            }
        }
    }
}

/// Fallback used only if `epoll`/`pipe2` setup itself fails (should never happen in practice) —
/// the original timer-based poll, so a shutdown trigger is still noticed even then.
fn wait_for_trigger_polling(devices: &[std::fs::File]) {
    loop {
        if SIGTERM_RECEIVED.load(Ordering::SeqCst) {
            return;
        }
        if devices.iter().any(power_button_pressed) {
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn find_input_event_devices() -> Vec<std::path::PathBuf> {
    let Ok(entries) = std::fs::read_dir("/dev/input") else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("event"))
        })
        .collect()
}

fn set_nonblocking(file: &std::fs::File) {
    // SAFETY: reads/sets file status flags on an already-open, valid fd; no pointers involved.
    unsafe {
        let fd = file.as_raw_fd();
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

/// Drains every currently-queued event on this (non-blocking) device, returning `true` if any
/// was a power-button press. Draining rather than stopping at the first read avoids leaving
/// events unread and re-triggering next poll for no reason.
fn power_button_pressed(file: &std::fs::File) -> bool {
    let mut buf = [0u8; std::mem::size_of::<InputEvent>()];
    let mut pressed = false;
    loop {
        match (&*file).read(&mut buf) {
            Ok(n) if n == buf.len() => {
                // SAFETY: `buf` holds exactly `size_of::<InputEvent>()` bytes just read from
                // the kernel's evdev char device, whose ABI matches this repr(C) layout.
                // `read_unaligned` rather than `read`: `buf`'s alignment is only 1 (a `[u8; N]`
                // array), which doesn't satisfy `InputEvent`'s natural alignment.
                let ev: InputEvent =
                    unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<InputEvent>()) };
                if ev.ev_type == EV_KEY && ev.code == KEY_POWER && ev.value == 1 {
                    pressed = true;
                }
            }
            _ => return pressed,
        }
    }
}

/// PIDs never exceed `i32::MAX` on Linux (`/proc/sys/kernel/pid_max` is capped well below
/// that), so `pid as libc::pid_t` here is always exact.
#[allow(clippy::cast_possible_wrap, clippy::as_conversions)]
fn run_graceful_shutdown(app_pid: u32, log: &impl Fn(&str)) {
    // SAFETY: `kill` takes a pid and a signal number, no pointers.
    unsafe {
        libc::kill(app_pid as libc::pid_t, libc::SIGTERM);
    }

    let deadline = Instant::now()
        .checked_add(SIGTERM_GRACE)
        .unwrap_or_else(Instant::now);
    while process_alive(app_pid) {
        if Instant::now() >= deadline {
            log("[WARN] The app did not exit within the grace period — force-killing it.");
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    // Every descendant, not just the app itself: `clone`/`fork` are unrestricted, so the app may
    // have left children that no SIGTERM above reached. One of those still running would
    // repopulate what the scrub is about to clear, and would keep its own anonymous memory alive
    // right up to the power-off — the same reason the fatal path in `wipe_and_power_off` kills
    // the whole process table before wiping.
    kill_wipe_and_power_off(log, "Graceful shutdown complete. Powering off.");
}

/// Shared tail of [`run_graceful_shutdown`] and [`wipe_and_power_off`]: `SIGKILL`s every
/// remaining process, waits for them to actually leave the process table, scrubs writable
/// state, logs `final_message`, then powers off. Never returns.
///
/// SAFETY: `kill(2)` takes a pid and a signal number, no pointers. `-1` means every process
/// this one may signal, which the kernel defines as excluding PID 1 itself.
fn kill_wipe_and_power_off(log: &impl Fn(&str), final_message: &str) -> ! {
    unsafe {
        libc::kill(-1, libc::SIGKILL);
    }
    wait_for_processes_to_exit(
        Instant::now()
            .checked_add(KILL_SETTLE_TIMEOUT)
            .unwrap_or_else(Instant::now),
    );

    wipe_writable_state(log);
    log(final_message);
    force_power_off()
}

/// Zeroes every writable path the guest owns, then commits it.
///
/// Shared by the graceful path and by [`wipe_and_power_off`], so a fatal error wipes exactly
/// what an orderly stop wipes. Caller must have stopped every process that could still be
/// writing — a live writer would just repopulate what this clears.
///
/// Best-effort throughout: an unreadable directory or a failed write is skipped rather than
/// aborting the rest of the wipe, since a partial wipe beats none.
fn wipe_writable_state(log: &impl Fn(&str)) {
    log("Scrubbing writable state before power-off...");
    // `/var/tmp` before `/var`: it's a tmpfs mounted over a subdirectory of `/var` in both
    // storage modes, so scrubbing `/var` first would walk into it and do the same work twice.
    scrub_dir(std::path::Path::new("/var/tmp"), 0);
    scrub_dir(std::path::Path::new("/tmp"), 0);
    scrub_dir(std::path::Path::new("/run"), 0);
    scrub_dir(std::path::Path::new("/dev/shm"), 0);

    // Persistent mode deliberately leaves `/var` itself intact — that's the whole point of the
    // mode — and unmounts it instead, so ext4's journal and metadata land on the device before
    // power-off. RAM mode has nothing to flush, so it scrubs the tmpfs pages.
    #[cfg(feature = "storage-persistent")]
    if !crate::storage::unmount_var() {
        log("[WARN] Failed to unmount /var — falling back to sync(2) alone.");
    }
    #[cfg(not(feature = "storage-persistent"))]
    scrub_dir(std::path::Path::new("/var"), 0);

    // SAFETY: `sync(2)` takes no arguments.
    unsafe {
        libc::sync();
    }
}

/// Powers the VM off immediately, with no cleanup of any kind. Never returns.
///
/// `reboot(2)` only returns at all if it failed, so the fallbacks below are the "the kernel
/// refused to power us off" path: try `HALT`, and failing that exit, which from PID 1 is itself
/// a kernel panic and stops the guest just as dead.
pub(crate) fn force_power_off() -> ! {
    // SAFETY: `reboot(2)` takes a plain integer command code and no pointers; PID 1 is who is
    // entitled to call it.
    unsafe {
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        libc::reboot(libc::LINUX_REBOOT_CMD_HALT);
    }
    std::process::exit(1);
}

/// Kills everything, wipes writable state, and powers off. Never returns.
///
/// This is what a fatal error runs instead of powering off on the spot: the same wipe an
/// orderly stop performs, so an integrity failure doesn't leave secrets sitting in RAM that a
/// bare `reboot(2)` would have left behind. Ordering matters — every other process is
/// `SIGKILL`ed *first*, both so nothing rewrites what's being scrubbed and so the app's own
/// anonymous memory and any unlinked-but-open files are released before the scrub, letting
/// `CONFIG_INIT_ON_FREE_DEFAULT_ON` zero them.
///
/// Two independent guarantees that this cannot hang a compromised guest: a watchdog thread
/// powers off unconditionally after [`EMERGENCY_WIPE_DEADLINE`], and re-entry (the wipe itself
/// hitting a fatal error) powers off immediately rather than recursing. If the watchdog thread
/// can't even be spawned, the wipe is skipped entirely — losing the scrub is acceptable, losing
/// the power-off is not.
///
/// Call only from PID 1; a child has neither `CAP_SYS_BOOT` nor permission to signal others.
pub(crate) fn wipe_and_power_off(log: impl Fn(&str)) -> ! {
    // Not just an assertion of the doc comment above: `kill(-1, SIGKILL)` below means "every
    // process I am allowed to signal", which anywhere other than a guest's PID 1 is the
    // caller's entire session. Refusing outright is the only safe response to being called
    // from the wrong place.
    if std::process::id() != 1 {
        eprintln!(
            "[SHUTDOWN] wipe_and_power_off() called from PID {} — only PID 1 may run it.",
            std::process::id()
        );
        std::process::exit(1);
    }

    if EMERGENCY_WIPE_STARTED.swap(true, Ordering::SeqCst) {
        force_power_off();
    }

    if std::thread::Builder::new()
        .spawn(|| {
            std::thread::sleep(EMERGENCY_WIPE_DEADLINE);
            eprintln!("[SHUTDOWN] Wipe exceeded its deadline — powering off now.");
            force_power_off();
        })
        .is_err()
    {
        eprintln!("[SHUTDOWN] Could not arm the wipe deadline — powering off without wiping.");
        force_power_off();
    }

    // Stops the watchdog loop in `main.rs` from treating the kills below as a fresh compromise
    // and re-entering here.
    SHUTDOWN_IN_PROGRESS.store(true, Ordering::SeqCst);

    log("Killing every remaining process before the wipe...");
    kill_wipe_and_power_off(&log, "Wipe complete. Powering off.")
}

/// Waits, bounded by `deadline`, for every other process to leave the process table.
///
/// Reaps as it goes: a `SIGKILL`ed child lingers as a zombie until someone waits on it, and a
/// zombie still answers `kill(pid, 0)`, so without reaping the probe below would never clear.
fn wait_for_processes_to_exit(deadline: Instant) {
    while Instant::now() < deadline {
        // SAFETY: `WNOHANG` never blocks; a null status pointer means "don't report status".
        while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
        // SAFETY: signal 0 sends nothing, it only probes for existence/permission.
        if unsafe { libc::kill(-1, 0) } != 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// See [`run_graceful_shutdown`]'s cast justification.
#[allow(clippy::cast_possible_wrap, clippy::as_conversions)]
fn process_alive(pid: u32) -> bool {
    // SAFETY: signal 0 sends nothing, it only checks existence/permission — `pid` is a plain
    // integer, no pointers involved.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

/// Fixed and reused across files rather than one `vec![0; len]` per file — scrubbing a full
/// 64 MB `/tmp` shouldn't need a 64 MB allocation on the shutdown path.
const SCRUB_CHUNK: usize = 16 * 1024;

/// Overwrites a regular file's contents in place with zeros.
///
/// Not `std::fs::write`: its `O_TRUNC` releases tmpfs's backing pages (contents intact) before
/// the zeros land in freshly-allocated *different* pages, leaving the original data in the
/// free pool. Opening without truncation and writing over the existing extent is what actually
/// overwrites it. `sync_data` before return so the write commits before the caller unlinks.
///
/// `O_NOFOLLOW` closes the gap between the caller's `is_file()` check and this open: without
/// it, an entry swapped for a symlink in that window would redirect these zeros at whatever it
/// points to — `/dev/vda` in persistent storage mode, for one.
fn overwrite_file(path: &std::path::Path, len: u64) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    crate::write_zeros(&mut file, len, &[0u8; SCRUB_CHUNK])?;
    file.sync_data()
}

/// Depth ceiling for [`scrub_dir`]'s recursion.
///
/// The directory tree it walks is app-controlled, and this runs in PID 1 under `panic =
/// "abort"` — an unbounded recursion would meet a nested-enough `/tmp` with a stack overflow,
/// which from PID 1 is a kernel panic that skips the power-off this whole path exists to reach.
/// Far deeper than any real scratch directory; the aborted subtree is left for
/// `CONFIG_INIT_ON_FREE_DEFAULT_ON` to zero on reclaim.
const MAX_SCRUB_DEPTH: u32 = 64;

/// Best-effort: overwrites every regular file under `dir` with zeros before removing it, then
/// removes now-empty subdirectories bottom-up. `/tmp`, `/run`, `/dev/shm` and (RAM storage
/// mode) `/var` are tmpfs, so this overwrites the RAM pages backing each file.
///
/// Defense in depth, not the primary guarantee — `CONFIG_INIT_ON_FREE_DEFAULT_ON` already
/// zeroes pages on free, and sev-snp encrypts guest RAM regardless. This just bounds the
/// window to scrub time instead of whenever the kernel reclaims the page.
///
/// Symlinks aren't followed (`DirEntry::metadata` doesn't traverse them) so they fall through
/// untouched, still removed with their parent directory.
fn scrub_dir(dir: &std::path::Path, depth: u32) {
    if depth >= MAX_SCRUB_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            scrub_dir(&path, depth.saturating_add(1));
            let _ = std::fs::remove_dir(&path);
        } else if meta.is_file() {
            let _ = overwrite_file(&path, meta.len());
            let _ = std::fs::remove_file(&path);
        }
    }
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_wrap,
    clippy::as_conversions
)]
mod tests {
    use super::*;

    /// Preserved length is the proof `O_TRUNC` didn't fire and free the original pages first.
    #[test]
    fn overwrite_file_zeroes_in_place_without_truncating() {
        let path = std::env::temp_dir().join("cuk-scrub-in-place-test");
        let secret = b"secret-bytes-that-must-not-survive".repeat(100);
        std::fs::write(&path, &secret).unwrap();

        overwrite_file(&path, secret.len() as u64).unwrap();

        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            after.len(),
            secret.len(),
            "file was truncated — the original pages were freed instead of overwritten"
        );
        assert!(
            after.iter().all(|&b| b == 0),
            "file contents were not zeroed"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `wait_for_trigger` must actually return once `SIGTERM` arrives — this is the one thing
    /// the epoll/self-pipe rewrite must not get wrong, since a bug here would mean the guest
    /// never reacts to a graceful-stop request at all instead of just being slow about it.
    /// Deliberately doesn't go through `spawn_watcher`/`run_graceful_shutdown`: those end in a
    /// real `reboot(2)` power-off, which must never run in a test process.
    #[test]
    fn wait_for_trigger_returns_promptly_on_sigterm() {
        unsafe {
            libc::signal(libc::SIGTERM, on_sigterm as *const () as libc::sighandler_t);
        }

        let handle = std::thread::spawn(|| wait_for_trigger(&[]));

        // Give the watcher thread time to reach epoll_wait before signalling it.
        std::thread::sleep(Duration::from_millis(100));
        unsafe {
            libc::kill(std::process::id() as libc::pid_t, libc::SIGTERM);
        }

        let start = Instant::now();
        loop {
            if handle.is_finished() {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "wait_for_trigger did not return within 5s of SIGTERM"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        handle.join().unwrap();

        // Second scenario, run in the same test (rather than a separate `#[test]`) because both
        // touch the same process-wide statics and Rust's default test harness runs tests in
        // parallel within one process — interleaving would make either flaky.
        //
        // Reproduces a SIGTERM landing *before* the watcher thread has finished its own setup:
        // this is the case a real boot hits when a hypervisor's shutdown request arrives between
        // `arm_shutdown_triggers()` installing the handler and the watcher thread reaching
        // `epoll_create1`/`pipe2` — the whole boot sequence. Reset the statics
        // `wait_for_trigger` consults, since the first phase left them in its post-shutdown state.
        SIGTERM_PIPE_WRITE_FD.store(-1, Ordering::SeqCst);
        SIGTERM_RECEIVED.store(false, Ordering::SeqCst);

        unsafe {
            libc::kill(std::process::id() as libc::pid_t, libc::SIGTERM);
        }
        // Confirm the signal actually landed (and was recorded) before any watcher thread
        // exists to consume it via the self-pipe.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            SIGTERM_RECEIVED.load(Ordering::SeqCst),
            "handler did not run — test setup is broken, not the thing under test"
        );

        let handle = std::thread::spawn(|| wait_for_trigger(&[]));
        let start = Instant::now();
        loop {
            if handle.is_finished() {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "wait_for_trigger missed a SIGTERM that arrived before its own setup finished"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        handle.join().unwrap();
    }
}
