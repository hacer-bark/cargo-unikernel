//! Kernel-build parameterization.
//!
//! The actual build stays in `assets/kernel/build_kernel.sh` (pure shell/Kconfig —
//! reimplementing that in Rust would add code and audit surface for no security benefit);
//! this module just knows how `Cargo-Unikernel.toml` maps onto the env vars that script
//! reads.

use crate::schema::{KernelHardening, Network, NetworkMode, ProfileKind, StorageMode};

/// The `PROFILE` env var value `assets/kernel/build_kernel.sh` expects for `kind`.
#[must_use]
pub const fn profile_env_value(kind: ProfileKind) -> &'static str {
    match kind {
        ProfileKind::Casual => "casual",
        ProfileKind::SevSnp => "sev-snp",
    }
}

/// Env vars gating the Kconfig category fragments under `assets/kernel/kconfig/categories/`.
///
/// Each defaults to enabled — see `build_kernel.sh`'s `CATEGORY_ENV` table, which this must
/// stay in sync with.
#[must_use]
pub fn hardening_env_vars(kh: &KernelHardening) -> [(&'static str, &'static str); 5] {
    let flag = |v: Option<bool>| if v.unwrap_or(true) { "1" } else { "0" };
    [
        (
            "CARGO_UNIKERNEL_KHARD_LEGACY_SUBSYSTEMS",
            flag(kh.disable_legacy_subsystems),
        ),
        (
            "CARGO_UNIKERNEL_KHARD_DEBUG_INTERFACES",
            flag(kh.disable_debug_interfaces),
        ),
        (
            "CARGO_UNIKERNEL_KHARD_SELF_PROTECTION",
            flag(kh.kernel_self_protection),
        ),
        (
            "CARGO_UNIKERNEL_KHARD_EXPLOIT_MITIGATIONS",
            flag(kh.exploit_mitigations),
        ),
        ("CARGO_UNIKERNEL_KHARD_SECCOMP", flag(kh.seccomp)),
    ]
}

/// Env vars gating `assets/kernel/kconfig/network/{ipv4,ipv6}.config`.
///
/// See `build_kernel.sh`. Unlike [`hardening_env_vars`], both default to *disabled* in the
/// shell script if unset; this function always sets them explicitly from `[network].mode`.
#[must_use]
pub const fn network_env_vars(mode: NetworkMode) -> [(&'static str, &'static str); 2] {
    const fn bit(b: bool) -> &'static str {
        if b { "1" } else { "0" }
    }
    [
        ("CARGO_UNIKERNEL_NET_IPV4", bit(mode.has_ipv4())),
        ("CARGO_UNIKERNEL_NET_IPV6", bit(mode.has_ipv6())),
    ]
}

/// Env var gating `assets/kernel/kconfig/categories/fips.config`.
///
/// See `build_kernel.sh`. Defaults to *disabled* if unset, the opposite of every category in
/// [`hardening_env_vars`]; this function always sets it explicitly.
#[must_use]
pub const fn fips_env_var(kh: &KernelHardening) -> (&'static str, &'static str) {
    (
        "CARGO_UNIKERNEL_KHARD_FIPS",
        if kh.fips { "1" } else { "0" },
    )
}

/// Env var gating `assets/kernel/kconfig/network/firewall.config`.
///
/// See `build_kernel.sh`. Defaults to *disabled* if unset; this function always sets it
/// explicitly from `[network.firewall]`. A guest with no NIC has nothing to filter, so the
/// fragment is deselected there too rather than compiling netfilter in for no reason.
#[must_use]
pub const fn firewall_env_var(network: &Network) -> (&'static str, &'static str) {
    (
        "CARGO_UNIKERNEL_FIREWALL",
        if network.firewall.enabled && network.mode.has_any() {
            "1"
        } else {
            "0"
        },
    )
}

/// Env var gating `assets/kernel/kconfig/storage/{ram,persistent}.config`.
#[must_use]
pub const fn storage_env_var(mode: StorageMode) -> (&'static str, &'static str) {
    (
        "CARGO_UNIKERNEL_STORAGE_PERSISTENT",
        if matches!(mode, StorageMode::Persistent) {
            "1"
        } else {
            "0"
        },
    )
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn profile_env_values_match_build_kernel_sh_cases() {
        // build_kernel.sh's `case "$CARGO_UNIKERNEL_PROFILE"` only recognizes these two
        // literal strings — if this drifts, the container build fails opaquely.
        assert_eq!(profile_env_value(ProfileKind::Casual), "casual");
        assert_eq!(profile_env_value(ProfileKind::SevSnp), "sev-snp");
    }

    #[test]
    fn unset_categories_default_to_enabled() {
        let vars = hardening_env_vars(&KernelHardening::default());
        for (name, value) in vars {
            assert_eq!(value, "1", "{name} should default to enabled");
        }
    }

    #[test]
    fn explicit_false_disables_only_that_category() {
        let kh = KernelHardening {
            seccomp: Some(false),
            ..KernelHardening::default()
        };
        let vars = hardening_env_vars(&kh);
        let map: std::collections::HashMap<_, _> = vars.into_iter().collect();
        assert_eq!(map["CARGO_UNIKERNEL_KHARD_SECCOMP"], "0");
        assert_eq!(map["CARGO_UNIKERNEL_KHARD_LEGACY_SUBSYSTEMS"], "1");
        assert_eq!(map["CARGO_UNIKERNEL_KHARD_DEBUG_INTERFACES"], "1");
        assert_eq!(map["CARGO_UNIKERNEL_KHARD_SELF_PROTECTION"], "1");
        assert_eq!(map["CARGO_UNIKERNEL_KHARD_EXPLOIT_MITIGATIONS"], "1");
    }

    #[test]
    fn network_env_vars_match_mode() {
        assert_eq!(
            network_env_vars(NetworkMode::Ipv4),
            [
                ("CARGO_UNIKERNEL_NET_IPV4", "1"),
                ("CARGO_UNIKERNEL_NET_IPV6", "0")
            ]
        );
        assert_eq!(
            network_env_vars(NetworkMode::Ipv6),
            [
                ("CARGO_UNIKERNEL_NET_IPV4", "0"),
                ("CARGO_UNIKERNEL_NET_IPV6", "1")
            ]
        );
        assert_eq!(
            network_env_vars(NetworkMode::Dual),
            [
                ("CARGO_UNIKERNEL_NET_IPV4", "1"),
                ("CARGO_UNIKERNEL_NET_IPV6", "1")
            ]
        );
        assert_eq!(
            network_env_vars(NetworkMode::None),
            [
                ("CARGO_UNIKERNEL_NET_IPV4", "0"),
                ("CARGO_UNIKERNEL_NET_IPV6", "0")
            ]
        );
    }

    #[test]
    fn storage_env_var_reflects_mode() {
        assert_eq!(
            storage_env_var(StorageMode::Ram),
            ("CARGO_UNIKERNEL_STORAGE_PERSISTENT", "0")
        );
        assert_eq!(
            storage_env_var(StorageMode::Persistent),
            ("CARGO_UNIKERNEL_STORAGE_PERSISTENT", "1")
        );
    }

    #[test]
    fn fips_env_var_defaults_to_disabled() {
        assert_eq!(
            fips_env_var(&KernelHardening::default()),
            ("CARGO_UNIKERNEL_KHARD_FIPS", "0")
        );
        let kh = KernelHardening {
            fips: true,
            ..KernelHardening::default()
        };
        assert_eq!(fips_env_var(&kh), ("CARGO_UNIKERNEL_KHARD_FIPS", "1"));
    }
}
