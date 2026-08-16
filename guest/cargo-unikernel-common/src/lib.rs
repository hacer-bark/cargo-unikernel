//! Shared guest-side primitives for `cargo-unikernel-init`'s PID-1 duties: filesystem/network
//! bring-up, sysctl hardening, the seccomp denylist, and graceful shutdown.
//!
//! `unsafe` is unavoidable and expected throughout this crate — it wraps raw Linux syscalls
//! (`mount`, `ioctl`, `prctl`, signal handling) that have no safe abstraction available in a
//! `no_std`-adjacent, dependency-minimal PID-1 binary. What is not acceptable is a runtime
//! panic: every fallible path here either returns a `Result` or takes a `fatal: fn(&str) -> !`
//! callback so the caller can trigger the guest's own wipe-and-power-off shutdown protocol
//! instead of unwinding.

#![forbid(unsafe_op_in_unsafe_fn, elided_lifetimes_in_paths)]

pub mod entropy;
pub mod hardening;
pub mod mounts;
pub mod seccomp;
pub mod shutdown;
#[cfg(feature = "storage-persistent")]
pub mod storage;

/// Writes `len` zero bytes to `sink`, reusing one caller-supplied `zeros` buffer rather than
/// allocating per call — both callers (scrubbing a tmpfs file, wiping a whole block device)
/// are on paths where an allocation sized to the target would be absurd.
pub(crate) fn write_zeros(
    sink: &mut impl std::io::Write,
    len: u64,
    zeros: &[u8],
) -> std::io::Result<()> {
    let mut remaining = len;
    while remaining > 0 {
        // `zeros.len()` bounds the min, so the narrowing is always exact.
        #[allow(clippy::cast_possible_truncation)]
        let n = remaining.min(zeros.len() as u64) as usize;
        sink.write_all(&zeros[..n])?;
        remaining -= n as u64;
    }
    Ok(())
}
