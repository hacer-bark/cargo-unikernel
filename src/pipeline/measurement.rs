//! Reads back the SEV-SNP launch measurement produced inside the build container.
//!
//! Also records a JSON sidecar of exactly which inputs produced it (see
//! `pipeline::docker::generate_build_script`'s `sev-snp-measure.py` invocation), so a
//! hypervisor operator can verify those inputs independently of trusting this tool's run.

use crate::pipeline::docker::BuildArtifacts;
use crate::schema::Config;
use anyhow::{Context, Result, bail};
use std::path::Path;

/// The SEV-SNP launch measurement read back from the build container.
#[derive(Debug)]
pub struct Measurement {
    /// Raw hex measurement, as written by `sev-snp-measure.py`.
    pub hex: String,
}

/// Reads back `artifacts.sev_measurement` and writes `dist/sev_measurement.json`.
///
/// The sidecar records every input (vcpus, `vcpu_type`, cmdline, kernel/initrd identity, OVMF
/// source) that produced the measurement, plus a `ComponentHashes` block.
///
/// # Errors
///
/// Returns an error if `artifacts.sev_measurement` wasn't produced, or if reading it / writing
/// the JSON sidecar fails.
pub fn compute(
    config: &Config,
    project_dir: &Path,
    artifacts: &BuildArtifacts,
) -> Result<Measurement> {
    let Some(path) = &artifacts.sev_measurement else {
        bail!("sev_snp profile requires a measurement, but none was produced by the container");
    };
    let hex = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?
        .trim()
        .to_string();

    let Some(sev) = &config.sev_snp else {
        bail!("measurement computed but config has no [sev_snp] section");
    };

    // The OVMF source collapses to whichever single value `[sev_snp.ovmf]` actually set
    // (`Config::validate` guarantees exactly one of the two).
    let ovmf_source = sev
        .ovmf
        .preset
        .clone()
        .or_else(|| sev.ovmf.path.clone())
        .unwrap_or_default();

    let sidecar = serde_json::json!({
        "measurement_sha384": hex,
        "vcpus": sev.vcpus,
        "vcpu_type": sev.vcpu_type,
        "kernel_cmdline": sev.kernel_cmdline,
        "ovmf_source": ovmf_source,
        // sha256 of each individual input that determines the measurement above — lets two
        // builds that produced different measurements be diffed component-by-component
        // (kernel vs. cpio vs. the raw app binary vs. cargo-unikernel-init vs. OVMF)
        // instead of only knowing the final hash differs. `null` for any component whose
        // hash file wasn't available (see pipeline::docker::run_reproducible_build).
        "component_sha256": {
            "kernel": artifacts.component_hashes.kernel_sha256,
            "cpio": artifacts.component_hashes.cpio_sha256,
            "app": artifacts.component_hashes.app_sha256,
            "guest_init": artifacts.component_hashes.guest_init_sha256,
            "ovmf": artifacts.component_hashes.ovmf_sha256,
        },
    });
    let sidecar_path = project_dir
        .join(&config.output.dir)
        .join("sev_measurement.json");
    std::fs::write(&sidecar_path, serde_json::to_string_pretty(&sidecar)?)
        .with_context(|| format!("failed to write {}", sidecar_path.display()))?;

    Ok(Measurement { hex })
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
    use crate::schema::{
        App, AppMode, AppRuntime, Hardening, Kernel, Network, Output, OutputFormat, OvmfSource,
        Profile, ProfileKind, Project, Release, SevSnp, Storage, ToolchainPins,
    };
    use std::path::PathBuf;

    fn sev_snp_config() -> Config {
        Config {
            project: Project {
                name: "test-app".to_string(),
                cargo_unikernel_version: None,
            },
            profile: Profile {
                kind: ProfileKind::SevSnp,
            },
            app: App {
                mode: AppMode::Binary,
                source: None,
                binary: Some(crate::schema::AppBinary {
                    path: Some("./app".to_string()),
                }),
                runtime: AppRuntime::default(),
            },
            network: Network::default(),
            storage: Storage::default(),
            kernel: Kernel::default(),
            toolchain: ToolchainPins::default(),
            hardening: Hardening::default(),
            sev_snp: Some(SevSnp {
                vcpus: 2,
                vcpu_type: "EPYC-v3".to_string(),
                kernel_cmdline: "console=ttyS0".to_string(),
                ovmf: OvmfSource {
                    preset: Some("builtin".to_string()),
                    path: None,
                },
                measured_boot: None,
            }),
            output: Output {
                formats: vec![OutputFormat::Cpio],
                dir: "dist/".to_string(),
            },
            release: Release::default(),
        }
    }

    #[test]
    fn reads_hex_and_writes_sidecar() {
        let dir = std::env::temp_dir().join(format!("cu-measurement-test-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("dist")).unwrap();
        let measurement_path = dir.join("dist/sev_measurement.txt");
        std::fs::write(&measurement_path, "  abcd1234  \n").unwrap();

        let artifacts = BuildArtifacts {
            bzimage: PathBuf::from("/build/bzImage"),
            cpio: PathBuf::from("/build/initrd.cpio"),
            uki: None,
            binary: None,
            sev_measurement: Some(measurement_path),
            component_hashes: crate::pipeline::docker::ComponentHashes {
                kernel_sha256: Some("kernel-hash".to_string()),
                cpio_sha256: Some("cpio-hash".to_string()),
                app_sha256: Some("app-hash".to_string()),
                guest_init_sha256: Some("guest-init-hash".to_string()),
                ovmf_sha256: Some("ovmf-hash".to_string()),
            },
        };
        let m = compute(&sev_snp_config(), &dir, &artifacts).unwrap();
        assert_eq!(m.hex, "abcd1234");

        let sidecar: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("dist/sev_measurement.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(sidecar["measurement_sha384"], "abcd1234");
        assert_eq!(sidecar["vcpus"], 2);
        assert_eq!(sidecar["vcpu_type"], "EPYC-v3");
        assert_eq!(sidecar["ovmf_source"], "builtin");
        assert!(sidecar.get("bzimage").is_none());
        assert!(sidecar.get("cpio").is_none());
        assert_eq!(sidecar["component_sha256"]["kernel"], "kernel-hash");
        assert_eq!(sidecar["component_sha256"]["cpio"], "cpio-hash");
        assert_eq!(sidecar["component_sha256"]["app"], "app-hash");
        assert_eq!(sidecar["component_sha256"]["guest_init"], "guest-init-hash");
        assert_eq!(sidecar["component_sha256"]["ovmf"], "ovmf-hash");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ovmf_source_reflects_path_too() {
        let dir =
            std::env::temp_dir().join(format!("cu-measurement-test-ovmf-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("dist")).unwrap();
        std::fs::write(dir.join("dist/sev_measurement.txt"), "abcd1234").unwrap();
        let artifacts = BuildArtifacts {
            bzimage: PathBuf::from("/build/bzImage"),
            cpio: PathBuf::from("/build/initrd.cpio"),
            uki: None,
            binary: None,
            sev_measurement: Some(dir.join("dist/sev_measurement.txt")),
            component_hashes: crate::pipeline::docker::ComponentHashes::default(),
        };

        let mut config = sev_snp_config();
        config.sev_snp.as_mut().unwrap().ovmf = OvmfSource {
            preset: None,
            path: Some("./firmware/OVMF.fd".to_string()),
        };
        compute(&config, &dir, &artifacts).unwrap();
        let sidecar: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("dist/sev_measurement.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(sidecar["ovmf_source"], "./firmware/OVMF.fd");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn errors_when_no_measurement_artifact_produced() {
        let dir = std::env::temp_dir().join(format!(
            "cu-measurement-test-missing-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let artifacts = BuildArtifacts {
            bzimage: PathBuf::from("/build/bzImage"),
            cpio: PathBuf::from("/build/initrd.cpio"),
            uki: None,
            binary: None,
            sev_measurement: None,
            component_hashes: crate::pipeline::docker::ComponentHashes::default(),
        };
        let err = compute(&sev_snp_config(), &dir, &artifacts).unwrap_err();
        assert!(err.to_string().contains("requires a measurement"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
