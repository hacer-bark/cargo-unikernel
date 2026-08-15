//! Graceful shutdown.
//!
//! A hypervisor's "graceful stop" (QEMU's ACPI shutdown) asserts the guest's ACPI power
//! button rather than signaling any guest process directly, so without something reading
//! that event it has nowhere to land. `panic_shutdown` (instant power-off for detected
//! integrity violations) is the wrong tool here, and a force-stop skips app cleanup and the
//! scrub below.
//!
//! Watches for either trigger (ACPI power button via evdev, or SIGTERM to PID 1), then: asks
//! every child to exit (`SIGTERM`), gives it a bounded grace period, force-kills anything
//! still alive, best-effort zeroes writable tmpfs state, and powers off.

use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// Set the moment a shutdown request is observed.
///
/// Checked by `main.rs`'s watchdog loop before treating a child's exit as an integrity
/// violation. A child dying because graceful shutdown asked it to isn't a compromise.
pub static SHUTDOWN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Write end of the self-pipe `on_sigterm` wakes: `write(2)` is one of the few calls safe to
/// use from a signal handler, unlike condvars/channels — this is the standard self-pipe trick
/// for turning a signal into something `epoll_wait` can block on.
static SIGTERM_PIPE_WRITE_FD: AtomicI32 = AtomicI32::new(-1);
/// Belt-and-suspenders alongside the pipe: only consulted by `wait_for_trigger_polling`, the
/// rare fallback used if `epoll`/`pipe2` setup itself fails.
static SIGTERM_RECEIVED: AtomicBool = AtomicBool::new(false);

const SIGTERM_GRACE: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(250);

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

/// Spawns the watcher thread and installs the SIGTERM handler.
///
/// `child_pids` are every process this init should ask to exit (the app, and the attestation
/// server if enabled). `log` is called from the watcher thread, so it must be `Send`.
pub fn spawn_watcher(child_pids: Vec<u32>, log: impl Fn(&str) + Send + 'static) {
    // SAFETY: `on_sigterm`'s signature matches what the C ABI expects for a signal handler.
    unsafe {
        libc::signal(libc::SIGTERM, on_sigterm as *const () as libc::sighandler_t);
    }

    std::thread::spawn(move || {
        wait_for_trigger();
        SHUTDOWN_IN_PROGRESS.store(true, Ordering::SeqCst);
        log("Graceful shutdown requested — signaling children...");
        run_graceful_shutdown(&child_pids, &log);
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
    clippy::cast_possible_wrap
)]
fn wait_for_trigger() {
    let devices: Vec<std::fs::File> = find_input_event_devices()
        .into_iter()
        .filter_map(|p| std::fs::File::open(p).ok())
        .inspect(set_nonblocking)
        .collect();

    // SAFETY: a plain integer flags argument; the returned fd (or -1 on error) is checked below.
    let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    if epfd < 0 {
        // Falls back to the old polling behaviour rather than blocking forever on a broken
        // epoll — this should never happen in practice.
        return wait_for_trigger_polling(&devices);
    }

    // SAFETY: `pipefds` is a valid, in-scope `[c_int; 2]`; the call fills both entries.
    let mut pipefds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(pipefds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } != 0 {
        return wait_for_trigger_polling(&devices);
    }
    let [sigterm_read_fd, sigterm_write_fd] = pipefds;
    SIGTERM_PIPE_WRITE_FD.store(sigterm_write_fd, Ordering::SeqCst);

    // A SIGTERM delivered any time between `spawn_watcher()` installing the handler and the
    // store just above would have run `on_sigterm`, which always sets `SIGTERM_RECEIVED` — but
    // found `SIGTERM_PIPE_WRITE_FD` still at its `-1` sentinel, so it wrote no wakeup byte. Left
    // unchecked, that signal is silently lost: the epoll loop below has no other way to learn
    // about it and would block forever. Opening every `/dev/input/event*` device above (real
    // hardware can have several) widens this window further, so it's not just a theoretical gap.
    if SIGTERM_RECEIVED.load(Ordering::SeqCst) {
        return;
    }

    let register = |fd: libc::c_int| {
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: fd as u64,
        };
        // SAFETY: `epfd` is the just-created epoll instance; `ev` is a valid, in-scope event
        // struct only read for the duration of this call; `fd` is a live, open descriptor.
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, std::ptr::addr_of_mut!(ev)) }
    };
    if register(sigterm_read_fd) != 0 {
        return wait_for_trigger_polling(&devices);
    }
    for device in &devices {
        register(device.as_raw_fd());
    }

    let mut events: [libc::epoll_event; 16] = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: `events` is a valid, in-scope buffer of the given length; `-1` blocks with no
        // timeout. A spurious `EINTR` wakeup just loops back into another wait.
        let n = unsafe { libc::epoll_wait(epfd, events.as_mut_ptr(), events.len() as i32, -1) };
        if n < 0 {
            continue;
        }
        for ev in &events[..n as usize] {
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
#[allow(clippy::cast_possible_wrap)]
fn run_graceful_shutdown(child_pids: &[u32], log: &impl Fn(&str)) {
    for &pid in child_pids {
        // SAFETY: `kill` takes a pid and a signal number, no pointers.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }

    let deadline = Instant::now() + SIGTERM_GRACE;
    loop {
        if child_pids.iter().all(|&pid| !process_alive(pid)) {
            break;
        }
        if Instant::now() >= deadline {
            log("[WARN] Not every child exited within the grace period — force-killing the rest.");
            for &pid in child_pids {
                if process_alive(pid) {
                    // SAFETY: same as above.
                    unsafe {
                        libc::kill(pid as libc::pid_t, libc::SIGKILL);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(500));
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }

    #[cfg(feature = "storage-persistent")]
    crate::storage::unmount_var();
    #[cfg(not(feature = "storage-persistent"))]
    scrub_dir("/var");

    log("Scrubbing writable state before power-off...");
    scrub_dir("/tmp");
    scrub_dir("/run");
    scrub_dir("/dev/shm");
    scrub_dir("/var/tmp");
    // SAFETY: `sync(2)` takes no arguments.
    unsafe {
        libc::sync();
    }

    log("Graceful shutdown complete. Powering off.");
    // SAFETY: `reboot(2)` takes a plain integer command code and no pointers; PID 1 is who is
    // entitled to call it (same as `panic_shutdown`).
    unsafe {
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
}

/// See [`run_graceful_shutdown`]'s cast justification.
#[allow(clippy::cast_possible_wrap)]
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
fn overwrite_file(path: &std::path::Path, len: u64) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .truncate(false)
        .open(path)?;
    let zeros = [0u8; SCRUB_CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let n = usize::try_from(remaining).unwrap_or(SCRUB_CHUNK).min(SCRUB_CHUNK);
        file.write_all(&zeros[..n])?;
        remaining -= n as u64;
    }
    file.sync_data()
}

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
fn scrub_dir(dir: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            scrub_dir(&path.to_string_lossy());
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
    clippy::cast_possible_wrap
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
        assert!(after.iter().all(|&b| b == 0), "file contents were not zeroed");
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

        let handle = std::thread::spawn(wait_for_trigger);

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
        // this is the case a real boot could hit if a hypervisor's shutdown request races
        // `spawn_watcher()` installing the handler against the watcher thread opening
        // `/dev/input` devices, `epoll_create1`, and `pipe2`. Reset the statics `wait_for_trigger`
        // consults, since the first phase left them in its post-shutdown state.
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

        let handle = std::thread::spawn(wait_for_trigger);
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
