//! Live `/var` storage for `storage-persistent`.
//!
//! `/dev/vda` is formatted ext4 (via the statically-linked `mke2fs` bundled into the image —
//! there's no other userspace in this initramfs to do it) on first use, then mounted directly
//! at `/var`. All file I/O from then on goes through the kernel's own ext4 driver, journal,
//! and page cache — not a RAM-resident copy. A device that doesn't carry this crate's own
//! marker file (unformatted, or holding someone else's data) is wiped and reformatted rather
//! than trusted.

use crate::mounts::{mount, writable_exec_mount_flags};
use std::io::{Seek, SeekFrom, Write};
use std::process::Command;

const DEVICE_PATH: &str = "/dev/vda";
const MOUNT_TARGET: &str = "/var";
const MKE2FS_PATH: &str = "/sbin/mke2fs";
const MARKER_PATH: &str = "/var/.cuk_init";
const MARKER_CONTENT: &[u8] = b"cargo-unikernel persistent /var\n";

/// Returns whether the unmount actually succeeded — `wipe_and_format` runs `mke2fs -F`, which
/// suppresses its own "device appears mounted" check, so a caller about to wipe must not treat
/// a failed unmount as a no-op.
fn umount(target: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(target) else {
        return false;
    };
    // SAFETY: `c` is a valid, live NUL-terminated `CString` for the duration of this call.
    unsafe { libc::umount2(c.as_ptr(), 0) == 0 }
}

fn marker_is_ours() -> bool {
    std::fs::read(MARKER_PATH).is_ok_and(|c| c == MARKER_CONTENT)
}

fn write_marker() -> std::io::Result<()> {
    std::fs::write(MARKER_PATH, MARKER_CONTENT)
}

fn write_zeros(dev: &mut std::fs::File, mut remaining: u64) -> std::io::Result<()> {
    let chunk = vec![0u8; 1024 * 1024];
    while remaining > 0 {
        let n = usize::try_from(remaining).unwrap_or(chunk.len()).min(chunk.len());
        dev.write_all(&chunk[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}

/// Zeroes the whole device, then runs the bundled static `mke2fs` over it. Zeroing first (not
/// just reformatting) means bytes from whatever was on the device before are never left
/// sitting in blocks the new filesystem simply doesn't reference yet.
fn wipe_and_format(fatal: fn(&str) -> !) {
    let mut dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEVICE_PATH)
        .unwrap_or_else(|e| fatal(&format!("Failed to open {DEVICE_PATH}: {e}")));
    let device_len = dev
        .seek(SeekFrom::End(0))
        .unwrap_or_else(|e| fatal(&format!("Failed to size {DEVICE_PATH}: {e}")));
    dev.seek(SeekFrom::Start(0))
        .and_then(|_| write_zeros(&mut dev, device_len))
        .unwrap_or_else(|e| fatal(&format!("Failed to wipe {DEVICE_PATH}: {e}")));
    dev.sync_all()
        .unwrap_or_else(|e| fatal(&format!("Failed to sync {DEVICE_PATH} after wipe: {e}")));
    drop(dev);

    let status = Command::new(MKE2FS_PATH)
        .args(["-q", "-F", "-t", "ext4", "-L", "CUKINIT", DEVICE_PATH])
        .status()
        .unwrap_or_else(|e| fatal(&format!("Failed to run {MKE2FS_PATH}: {e}")));
    if !status.success() {
        fatal(&format!("{MKE2FS_PATH} exited with {status}"));
    }
}

/// Mounts `/dev/vda` at `/var`, formatting it first if needed.
///
/// Fatal on any failure — `[storage].mode = "persistent"` is an explicit promise, so silently
/// falling back to RAM instead would violate it invisibly.
pub fn mount_persistent_var(log: &impl Fn(&str), fatal: fn(&str) -> !) {
    let already_mounted =
        mount(Some(DEVICE_PATH), MOUNT_TARGET, Some("ext4"), writable_exec_mount_flags(), None)
            .is_ok();

    if already_mounted && marker_is_ours() {
        log("[storage] Using existing persistent /var.");
        return;
    }

    if already_mounted {
        log("[storage] /dev/vda has data but no recognized marker — wiping it (first use, or foreign data).");
        if !umount(MOUNT_TARGET) {
            fatal("Failed to unmount /dev/vda before reformatting it");
        }
    } else {
        log("[storage] /dev/vda is unformatted — initializing it.");
    }

    wipe_and_format(fatal);
    mount(Some(DEVICE_PATH), MOUNT_TARGET, Some("ext4"), writable_exec_mount_flags(), None)
        .unwrap_or_else(|e| fatal(&format!("Failed to mount freshly-formatted {DEVICE_PATH}: {e}")));
    write_marker().unwrap_or_else(|e| fatal(&format!("Failed to write {MARKER_PATH}: {e}")));
    log("[storage] /var initialized on /dev/vda.");
}

/// Unmounts `/var` so the journal/metadata is flushed cleanly before power-off, rather than
/// relying solely on `sync(2)`.
pub fn unmount_var() {
    let _ = umount(MOUNT_TARGET);
}
