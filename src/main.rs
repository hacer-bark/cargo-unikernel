//! Thin entry point — all real logic lives in the `cargo_unikernel` library crate (`src/lib.rs`).

#![forbid(unsafe_code, elided_lifetimes_in_paths)]
#![allow(clippy::multiple_crate_versions)]

fn main() -> anyhow::Result<()> {
    cargo_unikernel::run()
}
