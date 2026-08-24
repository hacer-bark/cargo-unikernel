//! Zero-config "one call" build: when no `Cargo-Unikernel.toml` exists, figure out
//! sensible defaults from whatever's in the current directory rather than making the user
//! write a config file first.

use crate::schema::{
    App, AppBinary, AppMode, AppRuntime, AppSource, Config, Hardening, Kernel, Network, Output,
    OutputFormat, Profile, ProfileKind, Project, Release, Storage, Toolchain, ToolchainPins,
};
use anyhow::{Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct CargoTomlPackage {
    package: CargoPackage,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
}

pub(super) fn detect(project_dir: &Path, binary_override: Option<PathBuf>) -> Result<Config> {
    if let Some(binary) = binary_override {
        let name = binary
            .file_stem()
            .map_or_else(|| "app".to_string(), |s| s.to_string_lossy().to_string());
        return Ok(build_config(
            name,
            App {
                mode: AppMode::Binary,
                source: None,
                binary: Some(AppBinary {
                    path: Some(binary.to_string_lossy().to_string()),
                }),
                runtime: AppRuntime::default(),
            },
        ));
    }

    let cargo_toml = project_dir.join("Cargo.toml");
    if let Ok(raw) = std::fs::read_to_string(&cargo_toml) {
        let name = toml::from_str::<CargoTomlPackage>(&raw).map_or_else(
            |_| {
                project_dir
                    .file_name()
                    .map_or_else(|| "app".to_string(), |s| s.to_string_lossy().to_string())
            },
            |c| c.package.name,
        );

        println!(
            "No Cargo-Unikernel.toml found — auto-detected Cargo project '{name}'. \
             Run `cargo unikernel init` to customize instead of relying on defaults."
        );

        return Ok(build_config(
            name,
            App {
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
        ));
    }

    bail!(
        "no Cargo-Unikernel.toml and no Cargo.toml found in {} — either run \
         `cargo unikernel init`, or pass `--binary <path>` to embed an existing binary",
        project_dir.display()
    )
}

fn build_config(name: String, app: App) -> Config {
    Config {
        project: Project {
            name,
            cargo_unikernel_version: None,
        },
        profile: Profile {
            kind: ProfileKind::Casual,
        },
        app,
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

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::schema::AppMode;

    #[test]
    fn detects_cargo_project_as_rust_source() {
        let dir = std::env::temp_dir().join(format!("cargo-unikernel-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            "[package]\nname = \"my-app\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let config = detect(&dir, None).unwrap();
        assert_eq!(config.project.name, "my-app");
        assert_eq!(config.app.mode, AppMode::Source);
        let source = config.app.source.unwrap();
        assert_eq!(source.toolchain, Toolchain::Rust);
        assert_eq!(source.path.as_deref(), Some("."));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn binary_override_wins_regardless_of_cargo_toml() {
        let dir =
            std::env::temp_dir().join(format!("cargo-unikernel-test-bin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let config = detect(&dir, Some(PathBuf::from("/tmp/my-binary"))).unwrap();
        assert_eq!(config.project.name, "my-binary");
        assert_eq!(config.app.mode, AppMode::Binary);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_cargo_toml_and_no_binary_override_errors() {
        let dir =
            std::env::temp_dir().join(format!("cargo-unikernel-test-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        assert!(detect(&dir, None).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
