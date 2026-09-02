use super::helpers::{shell_quote, write_export};
use crate::pipeline::kernel;
use crate::schema::Config;
use std::fmt::Write as _;

/// Stage 1: build the Linux kernel (`/assets/kernel/build_kernel.sh`), parameterized by the
/// resolved profile/version/hardening env vars.
pub(super) fn script_kernel_build(config: &Config) -> String {
    let mut s = String::new();
    write_export(
        &mut s,
        "CARGO_UNIKERNEL_PROFILE",
        kernel::profile_env_value(config.profile.kind),
    );
    let _ = writeln!(
        s,
        "export CARGO_UNIKERNEL_KERNEL_VERSION={}",
        shell_quote(&config.kernel.version)
    );
    if let Some(sha256) = &config.kernel.sha256_for_build() {
        let _ = writeln!(
            s,
            "export CARGO_UNIKERNEL_KERNEL_SHA256={}",
            shell_quote(sha256)
        );
    }
    for (name, value) in kernel::network_env_vars(config.network.mode)
        .into_iter()
        .chain(kernel::hardening_env_vars(&config.hardening.kernel))
        .chain([
            kernel::fips_env_var(&config.hardening.kernel),
            kernel::storage_env_var(config.storage.mode),
            kernel::firewall_env_var(&config.network),
        ])
    {
        write_export(&mut s, name, value);
    }
    if !config.hardening.extra_kernel_config.is_empty() {
        // Written host-side to ~/.cache/cargo-unikernel/last-build/generated/ and bind-
        // mounted at /build-meta — see pipeline::docker::run_reproducible_build.
        s.push_str(
            "export CARGO_UNIKERNEL_EXTRA_KCONFIG_FILE=\"/build-meta/generated/extra-kconfig.config\"\n",
        );
    }
    s.push_str("/assets/kernel/build_kernel.sh\n\n");
    s
}
