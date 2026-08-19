//! Live `/var` storage for `storage-persistent`.
//!
//! `/dev/vda` is formatted ext4 with the bundled static `mke2fs` on first use, then mounted
//! at `/var`. A device that doesn't carry this crate's volume label (unformatted, or someone
//! else's data) is wiped and reformatted.
//!
//! Not encrypted or integrity-checked: `/dev/vda` is hypervisor-supplied, and on sev-snp the
//! host can read and tamper with it between boots — SEV-SNP protects guest memory, not a
//! virtio-blk device. `storage.mode = "persistent"` is a documented step outside the sev-snp
//! confidentiality guarantee (see `docs/threat_model.md`); closing it needs dm-crypt +
//! dm-integrity keyed from an `SNP_GET_DERIVED_KEY` secret, not implemented here. Treat `/var`
//! as untrusted, host-visible scratch space.
//!
//! What this module does address, and how far: the superblock is read from userspace
//! ([`device_carries_our_marker`]) before the kernel's ext4 driver ever sees the device, so a
//! device that isn't recognizably this image's is wiped rather than parsed. That screens
//! *unrecognized* images — a blank device, another workload's filesystem, a corrupted one. It is
//! not a defense against a hostile one: the marker is a 16-byte volume label in a field the host
//! can write, so a host that wants its ext4 metadata parsed just copies the label. On sev-snp
//! that means the in-kernel ext4 parser, inside the TCB, reading host-controlled input. Nothing
//! short of dm-integrity changes that.

use crate::mounts::{mount, writable_exec_mount_flags};
use std::io::{Read, Seek, SeekFrom};
use std::process::Command;

const DEVICE_PATH: &str = "/dev/vda";
const MOUNT_TARGET: &str = "/var";
/// Submount of [`MOUNT_TARGET`] — see [`unmount_var`] for why this module has to know about it.
const VAR_TMP: &str = "/var/tmp";
const MKE2FS_PATH: &str = "/sbin/mke2fs";

/// Written into the ext4 superblock's volume-label field by `wipe_and_format`'s `mke2fs -L`,
/// and checked straight off the raw device before any mount. The label is 16 bytes, NUL-padded.
const VOLUME_LABEL: &[u8] = b"CUKINIT";

fn umount(target: &str) -> bool {
    let Ok(c) = std::ffi::CString::new(target) else {
        return false;
    };
    // SAFETY: `c` is a valid, live NUL-terminated `CString` for the duration of this call.
    unsafe { libc::umount2(c.as_ptr(), 0) == 0 }
}

/// Byte offset of the ext4 superblock. Fixed by the on-disk format: the first 1024 bytes are
/// reserved for a boot sector.
const SUPERBLOCK_OFFSET: u64 = 1024;
/// `s_magic` (0xEF53) lives at offset 0x38 within the superblock, `s_volume_name` (16 bytes) at
/// 0x78 — both fixed by the ext2/3/4 on-disk format.
const SB_MAGIC_OFFSET: usize = 0x38;
const SB_LABEL_OFFSET: usize = 0x78;
const SB_LABEL_LEN: usize = 16;
const EXT4_MAGIC: u16 = 0xEF53;
/// Enough to cover both fields above without reading the whole 1024-byte superblock.
const SUPERBLOCK_PREFIX_LEN: usize = SB_LABEL_OFFSET + SB_LABEL_LEN;

/// Reads the ext4 superblock straight off the block device and reports whether it carries this
/// crate's volume label.
///
/// Runs *before* [`mount_persistent_var`] mounts anything, so an unrecognized filesystem is
/// wiped rather than handed to the in-kernel ext4 parser. That is a trust decision about which
/// images reach the parser, not an integrity check on the ones that do — the label is
/// host-writable, so this stops accidents and unrelated data, not a host that means it. See the
/// module doc.
///
/// Any read error, short device, or bad magic means "not ours"; the caller wipes and reformats.
fn device_carries_our_marker() -> bool {
    let Ok(mut dev) = std::fs::File::open(DEVICE_PATH) else {
        return false;
    };
    if dev.seek(SeekFrom::Start(SUPERBLOCK_OFFSET)).is_err() {
        return false;
    }
    let mut sb = [0u8; SUPERBLOCK_PREFIX_LEN];
    if dev.read_exact(&mut sb).is_err() {
        return false;
    }
    superblock_is_ours(&sb)
}

/// The pure half of [`device_carries_our_marker`], split out so the offsets and the
/// NUL-padding rule are testable without a block device.
fn superblock_is_ours(sb: &[u8; SUPERBLOCK_PREFIX_LEN]) -> bool {
    let magic = u16::from_le_bytes([sb[SB_MAGIC_OFFSET], sb[SB_MAGIC_OFFSET + 1]]);
    if magic != EXT4_MAGIC {
        return false;
    }

    let label = &sb[SB_LABEL_OFFSET..SB_LABEL_OFFSET + SB_LABEL_LEN];
    let (expected, padding) = label.split_at(VOLUME_LABEL.len());
    expected == VOLUME_LABEL && padding.iter().all(|&b| b == 0)
}

/// Larger than the tmpfs scrub chunk in `shutdown.rs`: this one goes to a virtio-blk device
/// where a bigger write per syscall measurably shortens a full-device wipe.
const WIPE_CHUNK: usize = 1024 * 1024;

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
    let zeros = vec![0u8; WIPE_CHUNK];
    dev.seek(SeekFrom::Start(0))
        .and_then(|_| crate::write_zeros(&mut dev, device_len, &zeros))
        .unwrap_or_else(|e| fatal(&format!("Failed to wipe {DEVICE_PATH}: {e}")));
    dev.sync_all()
        .unwrap_or_else(|e| fatal(&format!("Failed to sync {DEVICE_PATH} after wipe: {e}")));
    drop(dev);

    // Shares VOLUME_LABEL with device_carries_our_marker rather than a second literal.
    let label = std::str::from_utf8(VOLUME_LABEL)
        .unwrap_or_else(|_| fatal("VOLUME_LABEL must be valid UTF-8"));
    let status = Command::new(MKE2FS_PATH)
        .args(["-q", "-F", "-t", "ext4", "-L", label, DEVICE_PATH])
        .status()
        .unwrap_or_else(|e| fatal(&format!("Failed to run {MKE2FS_PATH}: {e}")));
    if !status.success() {
        fatal(&format!("{MKE2FS_PATH} exited with {status}"));
    }
}

/// Mounts `/dev/vda` at `/var`, formatting it first if it isn't already one of ours.
///
/// Fatal on any failure — `[storage].mode = "persistent"` is an explicit promise, so silently
/// falling back to RAM would violate it invisibly.
pub(crate) fn mount_persistent_var(log: &impl Fn(&str), fatal: fn(&str) -> !) {
    if device_carries_our_marker() {
        log("[storage] /dev/vda carries this image's volume label — reusing existing /var.");
    } else {
        log(
            "[storage] /dev/vda is unformatted, or holds a filesystem this image didn't write — \
             wiping and reformatting it.",
        );
        wipe_and_format(fatal);
    }

    mount(
        Some(DEVICE_PATH),
        MOUNT_TARGET,
        Some("ext4"),
        writable_exec_mount_flags(),
        None,
    )
    .unwrap_or_else(|e| {
        fatal(&format!(
            "Failed to mount {DEVICE_PATH} at {MOUNT_TARGET}: {e}"
        ))
    });
    log("[storage] /var is live on /dev/vda.");
}

/// Unmounts `/var` so the journal/metadata is flushed cleanly before power-off, rather than
/// relying solely on `sync(2)`.
///
/// `/var/tmp` is a tmpfs mounted *over* a subdirectory of this filesystem (see
/// `mounts::prepare_system_env`), and `umount(2)` refuses a mount point that still has a
/// submount — so unmounting it first is what makes the `/var` unmount able to succeed at all
/// rather than silently returning `EBUSY`. Returns whether `/var` itself came away cleanly.
#[must_use]
pub(crate) fn unmount_var() -> bool {
    umount(VAR_TMP);
    umount(MOUNT_TARGET)
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn superblock_with(magic: u16, label: &[u8]) -> [u8; SUPERBLOCK_PREFIX_LEN] {
        let mut sb = [0u8; SUPERBLOCK_PREFIX_LEN];
        sb[SB_MAGIC_OFFSET..SB_MAGIC_OFFSET + 2].copy_from_slice(&magic.to_le_bytes());
        sb[SB_LABEL_OFFSET..SB_LABEL_OFFSET + label.len()].copy_from_slice(label);
        sb
    }

    #[test]
    fn accepts_a_superblock_this_crate_wrote() {
        assert!(superblock_is_ours(&superblock_with(
            EXT4_MAGIC,
            VOLUME_LABEL
        )));
    }

    #[test]
    fn rejects_a_foreign_or_unformatted_device() {
        assert!(
            !superblock_is_ours(&superblock_with(EXT4_MAGIC, b"SOMEONE-ELSE")),
            "another filesystem's label must not pass"
        );
        assert!(
            !superblock_is_ours(&superblock_with(0x0000, VOLUME_LABEL)),
            "a bad ext4 magic must not pass, whatever the label says"
        );
        assert!(
            !superblock_is_ours(&[0u8; SUPERBLOCK_PREFIX_LEN]),
            "an unformatted (all-zero) device must not pass"
        );
    }

    /// `CUKINIT` is a prefix of `CUKINITIAL`; without the NUL-padding check a longer label
    /// starting with ours would be accepted as ours.
    #[test]
    fn rejects_a_label_that_merely_starts_with_ours() {
        assert!(!superblock_is_ours(&superblock_with(
            EXT4_MAGIC,
            b"CUKINITIAL"
        )));
    }
}
