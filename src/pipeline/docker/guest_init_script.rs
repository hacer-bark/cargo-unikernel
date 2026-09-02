use super::helpers::{rustflags_export, write_export};
use crate::schema::{Config, ProfileKind, StorageMode};
use std::fmt::Write as _;

/// Stage 2: cross-compile `cargo-unikernel-init` (the embedded guest source) with the app's
/// uid/gid/env/limits baked in via its `build.rs`, and every config-selected toggle (network
/// protocols, runtime hardening categories, `danger.allow_write_execute`) compiled in via
/// `cargo build --features`, not left in the binary behind a runtime `if` that happens not to
/// trigger.
pub(super) fn script_guest_init_build(config: &Config) -> String {
    let mut s = String::new();
    s.push_str("export CARGO_TARGET_DIR=/tmp/cargo-target\n");
    s.push_str(&rustflags_export());
    app_env_exports(config, &mut s);

    let features = init_features(config).join(",");
    let features_flag = if features.is_empty() {
        String::new()
    } else {
        format!("--features {features}")
    };
    let _ = write!(
        s,
        "cargo build --locked --release --target x86_64-unknown-linux-musl \
         --manifest-path /assets-guest/Cargo.toml {features_flag}\n\n"
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

    if rh.proc_subset_pid {
        features.push("proc-subset-pid");
    }
    if config.app.runtime.landlock.enabled {
        features.push("landlock");
    }
    if config.network.firewall.enabled && config.network.mode.has_any() {
        features.push("firewall");
    }
    if config.app.runtime.console {
        features.push("app-console");
    }
    if config.logging.enabled {
        features.push("logging");
    }

    features
}

/// Exports `[app.runtime]`'s uid/gid/env/limits. `danger.allow_write_execute` and
/// `[hardening.runtime]` are compile-time features now (see [`init_features`]), not env vars.
fn app_env_exports(config: &Config, s: &mut String) {
    write_export(s, "CARGO_UNIKERNEL_APP_UID", config.app.runtime.uid);
    write_export(s, "CARGO_UNIKERNEL_APP_GID", config.app.runtime.gid);
    if !config.app.runtime.env.is_empty() {
        // Same encoding as [hardening].extra_sysctls below: ';'-joined "key=value" pairs.
        // Values containing ';' aren't representable, which `Config::validate_kv_encoding`
        // rejects up front rather than letting it reach the guest as a malformed pair.
        write_export(
            s,
            "CARGO_UNIKERNEL_APP_ENV",
            encode_kv_pairs(&config.app.runtime.env),
        );
    }
    let limits = &config.app.runtime.limits;
    write_export(s, "CARGO_UNIKERNEL_LIMIT_NOFILE", limits.max_open_files);
    write_export(s, "CARGO_UNIKERNEL_LIMIT_NPROC", limits.max_processes);
    write_export(s, "CARGO_UNIKERNEL_LIMIT_AS_MB", limits.max_memory_mb);
    write_export(
        s,
        "CARGO_UNIKERNEL_LIMIT_MEMLOCK_MB",
        limits.max_locked_memory_mb,
    );
    if let Some(static_v6) = &config.network.ipv6_static {
        // Address and prefix travel as one "addr/len" string: they are meaningless apart, and
        // the guest parses them in one place rather than re-deriving which default applies.
        write_export(
            s,
            "CARGO_UNIKERNEL_IPV6_STATIC",
            format!("{}/{}", static_v6.address, static_v6.prefix_len),
        );
        if let Some(gateway) = &static_v6.gateway {
            write_export(s, "CARGO_UNIKERNEL_IPV6_GATEWAY", gateway);
        }
        if let Some(interface) = &static_v6.interface {
            write_export(s, "CARGO_UNIKERNEL_IPV6_IFACE", interface);
        }
    }
    if !config.hardening.extra_sysctls.is_empty() {
        write_export(
            s,
            "CARGO_UNIKERNEL_EXTRA_SYSCTLS",
            encode_kv_pairs(&config.hardening.extra_sysctls),
        );
    }

    let tmpfs = &config.storage.tmpfs;
    write_export(s, "CARGO_UNIKERNEL_TMPFS_TMP_MB", tmpfs.tmp_mb);
    write_export(s, "CARGO_UNIKERNEL_TMPFS_RUN_MB", tmpfs.run_mb);
    write_export(s, "CARGO_UNIKERNEL_TMPFS_SHM_MB", tmpfs.shm_mb);
    write_export(s, "CARGO_UNIKERNEL_TMPFS_VAR_TMP_MB", tmpfs.var_tmp_mb);

    if config.app.runtime.landlock.enabled {
        if !config.app.runtime.landlock.extra_read_paths.is_empty() {
            write_export(
                s,
                "CARGO_UNIKERNEL_LANDLOCK_RO",
                encode_path_list(&config.app.runtime.landlock.extra_read_paths),
            );
        }
        if !config
            .app
            .runtime
            .landlock
            .extra_read_write_paths
            .is_empty()
        {
            write_export(
                s,
                "CARGO_UNIKERNEL_LANDLOCK_RW",
                encode_path_list(&config.app.runtime.landlock.extra_read_write_paths),
            );
        }
    }

    if config.network.firewall.enabled && config.network.mode.has_any() {
        // ';'-joined "proto:ports" entries, e.g. "tcp:80;tcp:443;udp:443". Exported even when
        // empty is impossible here (an empty list encodes as an empty string, which build.rs's
        // own default already is), so the guest reads "answer nothing" either way.
        write_export(
            s,
            "CARGO_UNIKERNEL_FIREWALL_RULES",
            config
                .network
                .firewall
                .inbound
                .iter()
                .map(|entry| format!("{}:{}", entry.proto, entry.ports))
                .collect::<Vec<_>>()
                .join(";"),
        );
    }

    if !config.network.nameservers.is_empty() {
        write_export(
            s,
            "CARGO_UNIKERNEL_NAMESERVERS",
            encode_path_list(&config.network.nameservers),
        );
    }
    if let Some(search) = &config.network.search {
        write_export(s, "CARGO_UNIKERNEL_DNS_SEARCH", search);
    }
}

/// Encodes a list of strings as ';'-joined entries — the shared wire format for env vars that
/// pass a whole list through a single shell-exported string, mirroring [`encode_kv_pairs`] for
/// plain entries with no `=value` half.
fn encode_path_list(entries: &[String]) -> String {
    entries.join(";")
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

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::test_fixtures::*;
    use super::*;
    use crate::schema::{NetworkMode, OutputFormat};

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

    /// The app is what fetches SEV-SNP reports (the guest ships no attestation service of its
    /// own), so this feature — which is what chmods `/dev/sev-guest` into its reach — has to
    /// follow the profile alone.
    #[test]
    fn sev_snp_profile_gets_the_sev_snp_feature() {
        let config = sev_snp_config_with_formats(vec![OutputFormat::Cpio]);
        let features = init_features(&config);
        assert!(features.contains(&"sev-snp"));
    }

    #[test]
    fn static_ipv6_is_exported_as_one_address_slash_prefix_string() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.network.mode = NetworkMode::Ipv6;
        config.network.ipv6_static = Some(crate::schema::Ipv6Static {
            address: "2001:db8:1:2::1".to_string(),
            prefix_len: 64,
            gateway: Some("fe80::1".to_string()),
            interface: Some("eth0".to_string()),
        });
        let script = script_guest_init_build(&config);
        assert!(script.contains(r#"CARGO_UNIKERNEL_IPV6_STATIC="2001:db8:1:2::1/64""#));
        assert!(script.contains(r#"CARGO_UNIKERNEL_IPV6_GATEWAY="fe80::1""#));
        assert!(script.contains(r#"CARGO_UNIKERNEL_IPV6_IFACE="eth0""#));
    }

    /// The guest reads an unset value as "SLAAC only", so the optional halves must stay unset
    /// rather than being exported empty.
    #[test]
    fn omitted_static_ipv6_exports_nothing() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_guest_init_build(&config);
        assert!(!script.contains("CARGO_UNIKERNEL_IPV6_STATIC"));
        assert!(!script.contains("CARGO_UNIKERNEL_IPV6_GATEWAY"));
        assert!(!script.contains("CARGO_UNIKERNEL_IPV6_IFACE"));

        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.network.mode = NetworkMode::Ipv6;
        config.network.ipv6_static = Some(crate::schema::Ipv6Static {
            address: "2001:db8::5".to_string(),
            prefix_len: 128,
            gateway: None,
            interface: None,
        });
        let script = script_guest_init_build(&config);
        assert!(script.contains(r#"CARGO_UNIKERNEL_IPV6_STATIC="2001:db8::5/128""#));
        assert!(!script.contains("CARGO_UNIKERNEL_IPV6_GATEWAY"));
        assert!(!script.contains("CARGO_UNIKERNEL_IPV6_IFACE"));
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

    /// The whole point of the default: an image nobody configured still answers on the three
    /// web ports and is silent everywhere else — and the guest gets the ports as data, not as a
    /// promise the host tool made in a comment somewhere.
    #[test]
    fn the_firewall_is_on_by_default_and_exports_the_web_ports() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        assert!(init_features(&config).contains(&"firewall"));
        let script = script_guest_init_build(&config);
        assert!(script.contains(r#"CARGO_UNIKERNEL_FIREWALL_RULES="tcp:80;tcp:443;udp:443""#));
    }

    /// Turning it off must remove the feature *and* the rules: a build that carried the ports
    /// but not the code that enforces them would read as configured-and-filtered while being
    /// neither.
    #[test]
    fn disabling_the_firewall_omits_both_the_feature_and_the_rules() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.network.firewall.enabled = false;
        assert!(!init_features(&config).contains(&"firewall"));
        assert!(!script_guest_init_build(&config).contains("CARGO_UNIKERNEL_FIREWALL_RULES"));
    }

    /// A guest with no NIC has nothing to filter, whatever the section says.
    #[test]
    fn a_guest_with_no_network_gets_no_firewall() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.network.mode = NetworkMode::None;
        assert!(!init_features(&config).contains(&"firewall"));
    }

    #[test]
    fn landlock_is_enabled_by_default() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        assert!(init_features(&config).contains(&"landlock"));
    }

    #[test]
    fn disabling_landlock_omits_the_feature() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.app.runtime.landlock.enabled = false;
        assert!(!init_features(&config).contains(&"landlock"));
    }

    #[test]
    fn proc_subset_pid_is_off_by_default() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        assert!(!init_features(&config).contains(&"proc-subset-pid"));
    }

    #[test]
    fn app_console_is_off_by_default() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        assert!(!init_features(&config).contains(&"app-console"));
    }

    #[test]
    fn logging_is_off_by_default() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        assert!(!init_features(&config).contains(&"logging"));
    }

    #[test]
    fn logging_enabled_adds_the_feature() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.logging.enabled = true;
        assert!(init_features(&config).contains(&"logging"));
    }

    #[test]
    fn landlock_extra_paths_are_exported_only_when_the_feature_is_on() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.app.runtime.landlock.extra_read_paths = vec!["/some/path".to_string()];
        let script = script_guest_init_build(&config);
        assert!(script.contains(r#"CARGO_UNIKERNEL_LANDLOCK_RO="/some/path""#));

        config.app.runtime.landlock.enabled = false;
        let script = script_guest_init_build(&config);
        assert!(!script.contains("CARGO_UNIKERNEL_LANDLOCK_RO"));
    }

    #[test]
    fn nameservers_and_search_are_exported_as_configured() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.network.nameservers = vec!["9.9.9.9".to_string(), "149.112.112.112".to_string()];
        config.network.search = Some("corp.example".to_string());
        let script = script_guest_init_build(&config);
        assert!(script.contains(r#"CARGO_UNIKERNEL_NAMESERVERS="9.9.9.9;149.112.112.112""#));
        assert!(script.contains(r#"CARGO_UNIKERNEL_DNS_SEARCH="corp.example""#));
    }

    #[test]
    fn tmpfs_sizes_are_always_exported() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_guest_init_build(&config);
        assert!(script.contains(r#"CARGO_UNIKERNEL_TMPFS_TMP_MB="64""#));
        assert!(script.contains(r#"CARGO_UNIKERNEL_TMPFS_RUN_MB="16""#));
    }
}
