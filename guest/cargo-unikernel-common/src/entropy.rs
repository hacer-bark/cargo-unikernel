//! Blocks until the kernel's CRNG has enough entropy to be considered initialized.

use std::io::Read;

/// Blocks on a one-byte read from `/dev/random` until the kernel's CRNG is initialized.
///
/// Any failure to open or read the device is logged and treated as non-fatal — this is a
/// best-effort wait, not a security boundary, so it never invokes the shutdown protocol.
pub fn wait_for_entropy(log: impl Fn(&str)) {
    log("Waiting for kernel entropy pool (CRNG) to initialize...");
    let mut file = match std::fs::File::open("/dev/random") {
        Ok(f) => f,
        Err(e) => {
            log(&format!(
                "[WARN] Failed to open /dev/random: {e}. Continuing anyway..."
            ));
            return;
        }
    };
    let mut buf = [0u8; 1];
    if let Err(e) = file.read_exact(&mut buf) {
        log(&format!(
            "[WARN] Failed to read from /dev/random: {e}. Continuing anyway..."
        ));
    } else {
        log("Entropy pool ready.");
    }
}
