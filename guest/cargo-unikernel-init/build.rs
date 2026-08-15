//! Bakes build-time-only config into compile-time constants (via `env!`), so the guest init
//! never reads a mutable runtime config file.
//!
//! `cargo-unikernel` sets the corresponding `CARGO_UNIKERNEL_*` env vars when it invokes
//! `cargo build`; sensible defaults apply otherwise (e.g. `cargo check` run directly during
//! development of this crate).

/// Re-exports `name` (or `default`, if unset in the host environment) as `rustc-env`, so
/// `env!(name)` resolves to it inside this crate.
fn passthrough(name: &str, default: &str) {
    let value = std::env::var(name).unwrap_or_else(|_| default.to_string());
    println!("cargo:rustc-env={name}={value}");
    println!("cargo:rerun-if-env-changed={name}");
}

fn main() {
    // Not under /run: it gets a fresh tmpfs mounted over it during boot (see
    // cargo-unikernel-common::mounts::prepare_system_env), hiding anything baked in there.
    passthrough("CARGO_UNIKERNEL_PAYLOAD_DIR", "/payload");
    passthrough("CARGO_UNIKERNEL_APP_PATH", "/payload/app");
    passthrough("CARGO_UNIKERNEL_APP_UID", "65534");
    passthrough("CARGO_UNIKERNEL_APP_GID", "65534");
    // ';'-joined "key=value" pairs from [app.runtime].env, applied to the app's process
    // environment before exec. Empty by default (no env vars passed).
    passthrough("CARGO_UNIKERNEL_APP_ENV", "");
    // Fixed, distinct from the app's uid/gid (see schema::ATTESTATION_UID on the host side) —
    // keeps the attestation server isolated from the app by Unix DAC, not just by PID.
    passthrough("CARGO_UNIKERNEL_ATTEST_UID", "65533");
    passthrough("CARGO_UNIKERNEL_ATTEST_GID", "65533");
    passthrough("CARGO_UNIKERNEL_ATTESTATION_PORT", "8080");
    // Note what's deliberately NOT here: allow_write_execute, attestation-enabled, debug-mode,
    // and each [hardening.runtime] category used to be env!()-baked booleans checked with a
    // runtime `if`/`==`. They're now Cargo features (danger-allow-write-execute, attestation,
    // debug-mode, hardening-*) selected via `--features` when cargo-unikernel invokes this
    // crate's build — see src/pipeline/docker/guest_init_script.rs. A disabled one is compiled
    // out entirely, not left in the binary behind a branch that happens not to trigger.

    // Semicolon-separated "path=value" pairs from [hardening].extra_sysctls, applied after
    // the compiled-in named categories — arbitrary per-deployment data, not a toggle, so this
    // one still travels as a plain baked-in string rather than a feature.
    passthrough("CARGO_UNIKERNEL_EXTRA_SYSCTLS", "");

    // setrlimit ceilings for the app/attestation-server child — see schema::AppLimits. "0"
    // for max_memory_mb means no RLIMIT_AS cap.
    passthrough("CARGO_UNIKERNEL_LIMIT_NOFILE", "65536");
    passthrough("CARGO_UNIKERNEL_LIMIT_NPROC", "2048");
    passthrough("CARGO_UNIKERNEL_LIMIT_AS_MB", "0");
}
