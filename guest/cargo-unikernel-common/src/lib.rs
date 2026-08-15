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
