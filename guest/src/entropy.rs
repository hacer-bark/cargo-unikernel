//! Blocks until the kernel's CRNG has enough entropy to be considered initialized.

use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// A blocking read on `/dev/random` has no bound; RDSEED/RDRAND or virtio-rng
/// (`CONFIG_HW_RANDOM_VIRTIO`) initializes the CRNG in under a second, so a wait this long
/// means something is actually wrong, not merely slow.
const MAX_WAIT: Duration = Duration::from_secs(30);
const POLL_TIMEOUT_MS: libc::c_int = 250;

/// Waits, up to [`MAX_WAIT`], for the kernel's CRNG to report itself initialized, and refuses to
/// start the app if it doesn't.
///
/// `poll(2)` rather than a blocking read: `/dev/random` becomes readable exactly when the CRNG
/// initializes, so this observes the condition without consuming a byte or blocking forever.
///
/// Fatal rather than a warning, unlike most of what this crate does best-effort. Booting anyway
/// means handing the app a `getrandom` that answers from a pool the kernel itself says is not
/// ready, which is how long-lived keys get generated from predictable state — a failure that
/// leaves no trace in the running system and is not recoverable after the fact. On an image
/// whose whole point is that key material is generated inside a confidential guest, "continue
/// and log a warning" is the wrong trade: refusing to boot is loud, and the operator can retry
/// on a host whose RNG works.
///
/// Every reachable failure here is fatal for the same reason, including an unopenable
/// `/dev/random` — a guest that can't even ask the question can't be said to have gotten an
/// answer.
pub(crate) fn wait_for_entropy(log: impl Fn(&str), fatal: fn(&str) -> !) {
    log("Waiting for kernel entropy pool (CRNG) to initialize...");
    let file = match std::fs::File::open("/dev/random") {
        Ok(f) => f,
        Err(e) => fatal(&format!(
            "Failed to open /dev/random: {e} — cannot confirm the kernel CRNG is seeded, so any \
             key this guest generates could be predictable"
        )),
    };

    let deadline = Instant::now()
        .checked_add(MAX_WAIT)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        let mut fds = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `fds` is a valid, in-scope `pollfd` for a live descriptor, written only for
        // this call's duration; the count matches the single element passed.
        let ret = unsafe { libc::poll(std::ptr::addr_of_mut!(fds), 1, POLL_TIMEOUT_MS) };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            // A signal interrupting the wait is not a failure — poll again.
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            fatal(&format!(
                "poll() on /dev/random failed: {e} — cannot confirm the kernel CRNG is seeded"
            ));
        }
        if ret > 0 && fds.revents & libc::POLLIN != 0 {
            log("Entropy pool ready.");
            return;
        }
    }

    fatal(
        "Kernel CRNG did not initialize within 30s. Refusing to start the app: keys generated \
         now would be based on an unseeded entropy pool. Check that the host provides virtio-rng \
         (CONFIG_HW_RANDOM_VIRTIO) or that RDRAND/RDSEED is available to the guest.",
    );
}
