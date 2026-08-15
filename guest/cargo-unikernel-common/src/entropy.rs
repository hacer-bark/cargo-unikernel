//! Blocks until the kernel's CRNG has enough entropy to be considered initialized.

use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// A blocking read on `/dev/random` has no bound; RDSEED/RDRAND or virtio-rng
/// (`CONFIG_HW_RANDOM_VIRTIO`) initializes the CRNG in under a second, so a wait this long
/// means something is actually wrong, not merely slow.
const MAX_WAIT: Duration = Duration::from_secs(30);
const POLL_TIMEOUT_MS: libc::c_int = 250;

/// Waits, up to [`MAX_WAIT`], for the kernel's CRNG to report itself initialized.
///
/// `poll(2)` rather than a blocking read: `/dev/random` becomes readable exactly when the CRNG
/// initializes, so this observes the condition without consuming a byte or blocking forever.
/// Best-effort — any open/poll failure is logged and treated as non-fatal, never triggers the
/// shutdown protocol.
pub fn wait_for_entropy(log: impl Fn(&str)) {
    log("Waiting for kernel entropy pool (CRNG) to initialize...");
    let file = match std::fs::File::open("/dev/random") {
        Ok(f) => f,
        Err(e) => {
            log(&format!(
                "[WARN] Failed to open /dev/random: {e}. Continuing anyway..."
            ));
            return;
        }
    };

    let deadline = Instant::now() + MAX_WAIT;
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
            log(&format!(
                "[WARN] poll() on /dev/random failed: {e}. Continuing anyway..."
            ));
            return;
        }
        if ret > 0 && fds.revents & libc::POLLIN != 0 {
            log("Entropy pool ready.");
            return;
        }
    }

    log(
        "[WARN] Kernel CRNG did not initialize within the timeout — continuing anyway. Keys \
         generated early in this boot may be based on a weak entropy pool.",
    );
}
