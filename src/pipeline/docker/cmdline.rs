use crate::schema::{Config, NetworkMode};

/// The casual-profile default cmdline, minus the network fragment (see
/// [`network_cmdline_fragment`]) — inserted right after `console=ttyS0`. See
/// `docs/architecture.md`'s cmdline rationale section for why each flag is here (and what
/// was deliberately left out).
const CASUAL_CMDLINE_PREFIX: &str = "console=ttyS0";
const CASUAL_CMDLINE_SUFFIX: &str = "quiet loglevel=3 panic=-1 random.trust_cpu=off \
     random.trust_bootloader=off page_alloc.shuffle=1 lockdown=integrity \
     transparent_hugepage=madvise init_on_alloc=1 init_on_free=1";

/// The kernel cmdline fragment for `mode` — `ip=dhcp` for IPv4 autoconfig; empty for IPv6
/// (SLAAC needs no cmdline parameter) or no networking at all.
#[must_use]
const fn network_cmdline_fragment(mode: NetworkMode) -> &'static str {
    if mode.has_ipv4() { "ip=dhcp " } else { "" }
}

fn casual_cmdline(mode: NetworkMode) -> String {
    format!(
        "{CASUAL_CMDLINE_PREFIX} {}{CASUAL_CMDLINE_SUFFIX}",
        network_cmdline_fragment(mode)
    )
}

/// Resolves the kernel cmdline this build actually boots with.
#[must_use]
pub fn cmdline_for(config: &Config) -> String {
    config.sev_snp.as_ref().map_or_else(
        || casual_cmdline(config.network.mode),
        |sev| sev.kernel_cmdline.clone(),
    )
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::test_fixtures::casual_config_with_formats;
    use super::*;
    use crate::schema::OutputFormat;

    fn config_with_mode(mode: NetworkMode) -> Config {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.network.mode = mode;
        config
    }

    #[test]
    fn ipv4_and_dual_get_ip_dhcp() {
        assert!(cmdline_for(&config_with_mode(NetworkMode::Ipv4)).contains("ip=dhcp"));
        assert!(cmdline_for(&config_with_mode(NetworkMode::Dual)).contains("ip=dhcp"));
    }

    #[test]
    fn ipv6_and_none_omit_ip_dhcp() {
        assert!(!cmdline_for(&config_with_mode(NetworkMode::Ipv6)).contains("ip=dhcp"));
        assert!(!cmdline_for(&config_with_mode(NetworkMode::None)).contains("ip=dhcp"));
    }

    #[test]
    fn omitting_the_fragment_leaves_no_double_space() {
        let cmdline = cmdline_for(&config_with_mode(NetworkMode::None));
        assert!(!cmdline.contains("  "), "cmdline: {cmdline:?}");
    }
}
