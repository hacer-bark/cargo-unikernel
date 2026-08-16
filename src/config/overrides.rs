use crate::cli::ProfileArg;
use crate::schema::{Config, OutputFormat, ProfileKind};
use anyhow::{Result, bail};

/// `cargo unikernel build`'s CLI flags that override a loaded (or auto-detected) `Config`.
#[derive(Debug, Default)]
pub struct BuildOverrides {
    /// Overrides `output.formats` — parsed comma-separated format names.
    pub format: Option<Vec<String>>,
    /// Overrides `profile.kind`.
    pub profile: Option<ProfileArg>,
    /// Overrides `sev_snp.vcpus`.
    pub vcpus: Option<u32>,
    /// Overrides `sev_snp.vcpu_type`.
    pub vcpu_type: Option<String>,
}

/// Applies CLI-flag `overrides` on top of `config`, then re-validates the result.
///
/// # Errors
///
/// Returns an error if an override's value doesn't parse (e.g. an unrecognized format name),
/// or if the resulting config fails `Config::validate`.
pub fn apply_overrides(mut config: Config, overrides: BuildOverrides) -> Result<Config> {
    if let Some(profile) = overrides.profile {
        config.profile.kind = match profile {
            ProfileArg::Casual => ProfileKind::Casual,
            ProfileArg::SevSnp => ProfileKind::SevSnp,
        };
    }

    if let Some(formats) = overrides.format {
        let mut parsed = Vec::with_capacity(formats.len());
        for f in formats {
            parsed.push(match f.trim() {
                "cpio" => OutputFormat::Cpio,
                "iso" => OutputFormat::Iso,
                "uki" => OutputFormat::Uki,
                "binary" => OutputFormat::Binary,
                other => {
                    bail!("unknown --format value '{other}' (expected cpio, iso, uki, or binary)")
                }
            });
        }
        config.output.formats = parsed;
    }

    if let Some(vcpus) = overrides.vcpus {
        let sev_snp = config
            .sev_snp
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("--vcpus requires profile.kind = \"sev-snp\""))?;
        sev_snp.vcpus = vcpus;
    }

    if let Some(vcpu_type) = overrides.vcpu_type {
        let sev_snp = config
            .sev_snp
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("--vcpu-type requires profile.kind = \"sev-snp\""))?;
        sev_snp.vcpu_type = vcpu_type;
    }

    config.validate()?;
    Ok(config)
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::schema::{
        App, AppMode, AppRuntime, AppSource, Hardening, Kernel, Network, Output, OutputFormat,
        Profile, Project, Release, Storage, Toolchain, ToolchainPins,
    };

    fn base_config() -> Config {
        Config {
            project: Project {
                name: "test-app".to_string(),
                cargo_unikernel_version: None,
            },
            profile: Profile {
                kind: ProfileKind::Casual,
            },
            app: App {
                mode: AppMode::Source,
                source: Some(AppSource {
                    path: Some(".".to_string()),
                    toolchain: Toolchain::Rust,
                    package_path: ".".to_string(),
                    cargo_profile: "release".to_string(),
                    features: Vec::new(),
                    build_command: None,
                    output_binary: None,
                    extra_apt_packages: Vec::new(),
                }),
                binary: None,
                runtime: AppRuntime::default(),
            },
            network: Network::default(),
            storage: Storage::default(),
            kernel: Kernel::default(),
            toolchain: ToolchainPins::default(),
            hardening: Hardening::default(),
            sev_snp: None,
            output: Output {
                formats: vec![OutputFormat::Cpio],
                dir: "dist/".to_string(),
            },
            release: Release::default(),
        }
    }

    #[test]
    fn format_override_parses_known_values() {
        let config = apply_overrides(
            base_config(),
            BuildOverrides {
                format: Some(vec![
                    "cpio".to_string(),
                    "iso".to_string(),
                    "uki".to_string(),
                    "binary".to_string(),
                ]),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            config.output.formats,
            vec![
                OutputFormat::Cpio,
                OutputFormat::Iso,
                OutputFormat::Uki,
                OutputFormat::Binary
            ]
        );
    }

    #[test]
    fn format_override_rejects_unknown_value() {
        let err = apply_overrides(
            base_config(),
            BuildOverrides {
                format: Some(vec!["exe".to_string()]),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown --format value"));
    }

    #[test]
    fn vcpus_override_requires_sev_snp_profile() {
        let err = apply_overrides(
            base_config(),
            BuildOverrides {
                vcpus: Some(4),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("--vcpus requires profile.kind"));
    }

    #[test]
    fn vcpu_type_override_requires_sev_snp_profile() {
        let err = apply_overrides(
            base_config(),
            BuildOverrides {
                vcpu_type: Some("EPYC-v4".to_string()),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("--vcpu-type requires profile.kind")
        );
    }

    #[test]
    fn profile_override_switching_to_sev_snp_without_section_fails_final_validation() {
        // Switching profile alone doesn't fabricate a required [sev_snp] section — the
        // final config.validate() call should catch that, not silently produce a broken one.
        // The CLI version is pre-pinned here so that check (also enforced for sev-snp) doesn't
        // mask the one this test is actually about.
        let mut config = base_config();
        config.project.cargo_unikernel_version = Some(crate::schema::CLI_VERSION.to_string());
        let err = apply_overrides(
            config,
            BuildOverrides {
                profile: Some(ProfileArg::SevSnp),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("[sev_snp]"));
    }
}
