use super::helpers::{rustflags_export, write_export};
use crate::schema::{ATTESTATION_GID, ATTESTATION_UID, Config, ProfileKind, StorageMode};
use std::fmt::Write as _;

/// Stage 2: cross-compile `cargo-unikernel-init` (the embedded guest source) with the
/// app-uid/gid/attestation env vars baked in via its `build.rs`, and every config-selected
/// toggle (network protocols, runtime hardening categories, `danger.allow_write_execute`,
/// `attestation`, `debug`) compiled in via `cargo build --features`, not left in the binary
/// behind a runtime `if` that happens not to trigger.
pub(super) fn script_guest_init_build(config: &Config) -> String {
    let mut s = String::new();
    s.push_str("export CARGO_TARGET_DIR=/tmp/cargo-target\n");
    s.push_str(&rustflags_export());
    app_env_exports(config, &mut s);
    attestation_exports(config, &mut s);

    let features = init_features(config).join(",");
    let features_flag = if features.is_empty() {
        String::new()
    } else {
        format!("--features {features}")
    };
    let _ = write!(
        s,
        "cargo build --locked --release --target x86_64-unknown-linux-musl \
         --manifest-path /assets-guest/cargo-unikernel-init/Cargo.toml {features_flag}\n\n"
    );
    s
}

/// Every Cargo feature `cargo-unikernel-init` should be built with for this `config` — see
/// that crate's `Cargo.toml` for what each one gates.
fn init_features(config: &Config) -> Vec<&'static str> {
    let mut features = Vec::new();

    if config.profile.kind == ProfileKind::SevSnp {
        features.push("sev-snp");
    }

    if config.network.mode.has_ipv4() {
        features.push("net-ipv4");
    }
    if config.network.mode.has_ipv6() {
        features.push("net-ipv6");
    }
    if config.storage.mode == StorageMode::Persistent {
        features.push("storage-persistent");
    }

    let rh = &config.hardening.runtime;
    let enabled = |v: Option<bool>| v.unwrap_or(true);
    if enabled(rh.network_spoofing_protection) {
        features.push("hardening-net-spoofing");
    }
    if enabled(rh.icmp_hardening) {
        features.push("hardening-icmp");
    }
    if enabled(rh.tcp_hardening) {
        features.push("hardening-tcp");
    }
    if enabled(rh.info_leak_restriction) {
        features.push("hardening-info-leak");
    }
    if enabled(rh.ptrace_and_bpf_restriction) {
        features.push("hardening-ptrace-bpf");
    }
    if enabled(rh.kexec_and_fs_protection) {
        features.push("hardening-kexec-fs");
    }

    if config.app.runtime.danger.allow_write_execute {
        features.push("danger-allow-write-execute");
    }
    if matches!(&config.attestation, Some(a) if a.enabled) {
        features.push("attestation");
    }
    if config.debug {
        features.push("debug-mode");
    }

    features
}

/// Exports `[app.runtime]`'s uid/gid/env/limits, plus the attestation server's fixed
/// (non-user-configurable) uid/gid. `danger.allow_write_execute` and `[hardening.runtime]`
/// are compile-time features now (see [`init_features`]), not env vars.
fn app_env_exports(config: &Config, s: &mut String) {
    write_export(s, "CARGO_UNIKERNEL_APP_UID", config.app.runtime.uid);
    write_export(s, "CARGO_UNIKERNEL_APP_GID", config.app.runtime.gid);
    if !config.app.runtime.env.is_empty() {
        // Same encoding as [hardening].extra_sysctls below: ';'-joined "key=value" pairs.
        // Values containing ';' aren't representable — acceptable for the same reason it's
        // acceptable there (matches this codebase's existing convention rather than adding a
        // second, inconsistent encoding scheme for one field).
        write_export(
            s,
            "CARGO_UNIKERNEL_APP_ENV",
            encode_kv_pairs(&config.app.runtime.env),
        );
    }
    // Fixed, not user-configurable (see schema::ATTESTATION_UID) — the attestation server
    // drops to this uid/gid instead of the app's, so the two child processes are actually
    // isolated from each other by Unix DAC, not just by being separate processes.
    write_export(s, "CARGO_UNIKERNEL_ATTEST_UID", ATTESTATION_UID);
    write_export(s, "CARGO_UNIKERNEL_ATTEST_GID", ATTESTATION_GID);
    let limits = &config.app.runtime.limits;
    write_export(s, "CARGO_UNIKERNEL_LIMIT_NOFILE", limits.max_open_files);
    write_export(s, "CARGO_UNIKERNEL_LIMIT_NPROC", limits.max_processes);
    write_export(s, "CARGO_UNIKERNEL_LIMIT_AS_MB", limits.max_memory_mb);
    if !config.hardening.extra_sysctls.is_empty() {
        write_export(
            s,
            "CARGO_UNIKERNEL_EXTRA_SYSCTLS",
            encode_kv_pairs(&config.hardening.extra_sysctls),
        );
    }
}

/// Encodes a `key=value` map as ';'-joined pairs — the shared wire format for env vars that
/// pass a whole map through a single shell-exported string.
fn encode_kv_pairs(pairs: &std::collections::BTreeMap<String, String>) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(";")
}

/// Exports the attestation-server's port (its `enabled` bit is now the `attestation` Cargo
/// feature — see [`init_features`] — not an env var).
fn attestation_exports(config: &Config, s: &mut String) {
    if let Some(a) = &config.attestation {
        write_export(s, "CARGO_UNIKERNEL_ATTESTATION_PORT", a.port);
    }
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::test_fixtures::*;
    use super::*;
    use crate::schema::{Attestation, NetworkMode, OutputFormat};

    #[test]
    fn guest_init_build_pins_codegen_units_for_reproducibility() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_guest_init_build(&config);
        let rustflags_pos = script.find("RUSTFLAGS=\"-C codegen-units=1\"").unwrap();
        let cargo_pos = script.find("cargo build --locked --release").unwrap();
        assert!(rustflags_pos < cargo_pos);
    }

    #[test]
    fn allow_write_execute_off_by_default_omits_the_feature() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_guest_init_build(&config);
        assert!(!script.contains("danger-allow-write-execute"));
    }

    #[test]
    fn allow_write_execute_danger_flag_adds_the_feature() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.app.runtime.danger.allow_write_execute = true;
        let script = script_guest_init_build(&config);
        assert!(script.contains("--features"));
        assert!(script.contains("danger-allow-write-execute"));
    }

    #[test]
    fn attestation_server_gets_a_uid_distinct_from_the_configured_app_uid() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.app.runtime.uid = 12345;
        config.app.runtime.gid = 12345;
        let script = script_guest_init_build(&config);
        assert!(script.contains(&format!("CARGO_UNIKERNEL_ATTEST_UID=\"{ATTESTATION_UID}\"")));
        assert!(script.contains(&format!("CARGO_UNIKERNEL_ATTEST_GID=\"{ATTESTATION_GID}\"")));
        assert_ne!(ATTESTATION_UID, config.app.runtime.uid);
    }

    #[test]
    fn sev_snp_profile_gets_the_sev_snp_feature_regardless_of_attestation() {
        // Independent of `attestation` — the app needs `/dev/sev-guest` fixed up even when
        // it's the only process running (no attestation server compiled in at all).
        let config = sev_snp_config_with_formats(vec![OutputFormat::Cpio]);
        assert!(!config.attestation.as_ref().is_some_and(|a| a.enabled));
        let features = init_features(&config);
        assert!(features.contains(&"sev-snp"));
    }

    #[test]
    fn casual_profile_never_gets_the_sev_snp_feature() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let features = init_features(&config);
        assert!(!features.contains(&"sev-snp"));
    }

    #[test]
    fn persistent_storage_mode_adds_the_feature() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.storage.mode = crate::schema::StorageMode::Persistent;
        assert!(init_features(&config).contains(&"storage-persistent"));
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        assert!(!init_features(&config).contains(&"storage-persistent"));
    }

    #[test]
    fn default_network_mode_enables_only_ipv4_feature() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        assert_eq!(config.network.mode, NetworkMode::Ipv4);
        let features = init_features(&config);
        assert!(features.contains(&"net-ipv4"));
        assert!(!features.contains(&"net-ipv6"));
    }

    #[test]
    fn dual_network_mode_enables_both_features() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.network.mode = NetworkMode::Dual;
        let features = init_features(&config);
        assert!(features.contains(&"net-ipv4"));
        assert!(features.contains(&"net-ipv6"));
    }

    #[test]
    fn none_network_mode_enables_neither_feature() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.network.mode = NetworkMode::None;
        let features = init_features(&config);
        assert!(!features.contains(&"net-ipv4"));
        assert!(!features.contains(&"net-ipv6"));
    }

    #[test]
    fn disabled_hardening_category_omits_its_feature() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.hardening.runtime.icmp_hardening = Some(false);
        let features = init_features(&config);
        assert!(!features.contains(&"hardening-icmp"));
        assert!(features.contains(&"hardening-tcp"));
    }

    #[test]
    fn attestation_enabled_adds_the_feature_and_port_env_var() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.network.mode = NetworkMode::Ipv4;
        config.attestation = Some(Attestation {
            enabled: true,
            port: 9443,
        });
        let features = init_features(&config);
        assert!(features.contains(&"attestation"));
        let script = script_guest_init_build(&config);
        assert!(script.contains("CARGO_UNIKERNEL_ATTESTATION_PORT=\"9443\""));
    }

    #[test]
    fn debug_flag_adds_debug_mode_feature() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.debug = true;
        let features = init_features(&config);
        assert!(features.contains(&"debug-mode"));
    }
}
