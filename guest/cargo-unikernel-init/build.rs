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
    // [network.ipv6_static], as "address/prefix_len" — empty means SLAAC only. The gateway and
    // interface are separate and each empty unless configured.
    passthrough("CARGO_UNIKERNEL_IPV6_STATIC", "");
    passthrough("CARGO_UNIKERNEL_IPV6_GATEWAY", "");
    passthrough("CARGO_UNIKERNEL_IPV6_IFACE", "");
    // Semicolon-separated "path=value" pairs from [hardening].extra_sysctls, applied after
    // the compiled-in named categories — arbitrary per-deployment data, not a toggle, so this
    // one still travels as a plain baked-in string rather than a feature.
    passthrough("CARGO_UNIKERNEL_EXTRA_SYSCTLS", "");
    // setrlimit ceilings for the app child — see schema::AppLimits. "0" for max_memory_mb
    // means no RLIMIT_AS cap.
    passthrough("CARGO_UNIKERNEL_LIMIT_NOFILE", "65536");
    passthrough("CARGO_UNIKERNEL_LIMIT_NPROC", "2048");
    passthrough("CARGO_UNIKERNEL_LIMIT_AS_MB", "0");
    // RLIMIT_MEMLOCK in MiB — finite on purpose, see schema::AppLimits::max_locked_memory_mb.
    passthrough("CARGO_UNIKERNEL_LIMIT_MEMLOCK_MB", "64");
}
