#!/bin/sh
# Materializes guest/**/Cargo.toml from their checked-in Cargo.toml.dist copies.
#
# The manifests are checked in under a `.dist` suffix — never as a literal `Cargo.toml` —
# because `cargo package` unconditionally excludes any subdirectory containing a `Cargo.toml`
# from the published tarball, with no `include`/`exclude` override. Since this guest tree is
# published as plain source (embedded and cross-compiled inside the build container, never a
# crates.io dependency of the host crate), a real `Cargo.toml` here would silently vanish
# from every published release. Run this script before building, testing, or linting the
# guest workspace directly; the runtime pipeline restores the same names itself when it
# extracts the embedded copy (see `extract_guest` in `src/assets.rs`).
set -eu
cd "$(dirname "$0")"
cp Cargo.toml.dist Cargo.toml
