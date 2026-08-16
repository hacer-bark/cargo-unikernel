//! `cargo-unikernel release`: build (unless `--no-build`) and publish the resulting
//! artifacts as a GitHub Release via the `gh` CLI.
//!
//! Which `dist/` assets are attached and the release body/metadata are driven by the
//! optional `[release]` section of `cargo-unikernel.toml` (`schema::Release`) — the same
//! config a `github init`-generated workflow passes via `--config`, so local and CI releases
//! always agree.

use crate::pipeline::ovmf;
use crate::schema::{Config, ReleaseAsset};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every possible `dist/` asset, tagged with the `ReleaseAsset` kind used to select it via
/// `[release].assets`.
fn candidate_assets(config: &Config, dist_dir: &Path) -> Vec<(ReleaseAsset, PathBuf)> {
    let name = &config.project.name;
    vec![
        (
            ReleaseAsset::Bzimage,
            dist_dir.join(format!("{name}.bzImage")),
        ),
        (ReleaseAsset::Cpio, dist_dir.join(format!("{name}.cpio"))),
        (ReleaseAsset::Iso, dist_dir.join(format!("{name}.iso"))),
        (ReleaseAsset::Uki, dist_dir.join(format!("{name}.efi"))),
        (ReleaseAsset::Binary, dist_dir.join(format!("{name}.bin"))),
        (
            ReleaseAsset::Measurement,
            dist_dir.join("sev_measurement.txt"),
        ),
        (
            ReleaseAsset::Measurement,
            dist_dir.join("sev_measurement.json"),
        ),
        // Only ever exists for sev-snp builds (script_sev_snp_measurement stages it there
        // unconditionally, regardless of preset/path/url source) — the existence filter in
        // select_assets skips it entirely for casual builds.
        (ReleaseAsset::Ovmf, ovmf::host_path(dist_dir)),
    ]
}

/// Every candidate asset whose kind is selected by `[release].assets` (or every kind, if
/// unset) and which actually exists in `dist_dir`.
fn select_assets(config: &Config, dist_dir: &Path) -> Vec<PathBuf> {
    let selected = config.release.assets.as_deref();
    candidate_assets(config, dist_dir)
        .into_iter()
        .filter(|(kind, _)| selected.is_none_or(|kinds| kinds.contains(kind)))
        .map(|(_, path)| path)
        .filter(|path| path.exists())
        .collect()
}

/// Builds (unless `no_build`) and publishes a GitHub Release with the resulting `dist/`
/// assets, via the `gh` CLI.
///
/// # Errors
///
/// Returns an error if `gh` isn't available, the build fails, no matching assets exist in
/// `dist/`, no tag was given and none could be resolved from git, or the `gh release`
/// invocation itself fails.
pub fn run(config: &Config, project_dir: &Path, tag: Option<String>, no_build: bool) -> Result<()> {
    check_gh_available()?;

    if !no_build {
        crate::pipeline::build(config, project_dir)?;
    }

    let dist_dir = project_dir.join(config.output.dir.trim_end_matches('/'));
    let assets = select_assets(config, &dist_dir);
    if assets.is_empty() {
        bail!(
            "no matching build artifacts found in {} — nothing to release",
            dist_dir.display()
        );
    }

    let tag = tag
        .or_else(resolve_git_tag)
        .context("--tag not given and no git tag/commit could be resolved for this HEAD")?;

    let existing = Command::new("gh")
        .args(["release", "view", &tag])
        .output()
        .is_ok_and(|o| o.status.success());

    let mut cmd = Command::new("gh");
    if existing {
        cmd.args(["release", "upload", &tag, "--clobber"]);
        cmd.args(assets.iter().map(|p| p.as_os_str()));
    } else {
        cmd.args(["release", "create", &tag]);
        if let Some(title) = &config.release.title {
            cmd.args(["--title", title]);
        }
        match (&config.release.notes, &config.release.notes_file) {
            (Some(notes), None) => {
                cmd.args(["--notes", notes]);
            }
            (None, Some(notes_file)) => {
                let notes_path = project_dir.join(notes_file);
                cmd.arg("--notes-file").arg(&notes_path);
            }
            (None, None) => {
                cmd.arg("--generate-notes");
            }
            (Some(_), Some(_)) => {
                bail!("rejected by Config::validate: notes and notes_file both set")
            }
        }
        if config.release.draft {
            cmd.arg("--draft");
        }
        if config.release.prerelease {
            cmd.arg("--prerelease");
        }
        cmd.args(assets.iter().map(|p| p.as_os_str()));
    }

    let status = cmd.status().context("failed to run `gh release`")?;
    if !status.success() {
        bail!("`gh release` failed — see output above");
    }

    println!("Published release {tag} with {} asset(s).", assets.len());
    Ok(())
}

fn check_gh_available() -> Result<()> {
    let ok = Command::new("gh")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        bail!(
            "the GitHub CLI (`gh`) is required for `cargo-unikernel release` — \
             install it from https://cli.github.com and run `gh auth login`"
        );
    }
    Ok(())
}

fn resolve_git_tag() -> Option<String> {
    std::process::Command::new("git")
        .args(["describe", "--tags", "--exact-match"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "--short", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| format!("build-{}", String::from_utf8_lossy(&o.stdout).trim()))
        })
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::schema::{
        App, AppMode, AppRuntime, AppSource, Hardening, Kernel, Network, Output, OutputFormat,
        Profile, ProfileKind, Project, Release, Storage, Toolchain, ToolchainPins,
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

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"stub").unwrap();
    }

    fn temp_dist_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cu-release-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn selects_every_existing_asset_when_unset() {
        let dir = temp_dist_dir("default");
        touch(&dir, "test-app.bzImage");
        touch(&dir, "test-app.cpio");
        touch(&dir, "test-app.bin");

        let config = base_config();
        let assets = select_assets(&config, &dir);
        assert_eq!(assets.len(), 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restricts_to_configured_asset_kinds() {
        let dir = temp_dist_dir("restricted");
        touch(&dir, "test-app.bzImage");
        touch(&dir, "test-app.cpio");
        touch(&dir, "test-app.bin");

        let mut config = base_config();
        config.release.assets = Some(vec![ReleaseAsset::Binary]);
        let assets = select_assets(&config, &dir);
        assert_eq!(assets, vec![dir.join("test-app.bin")]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn skips_configured_kinds_that_were_not_produced() {
        let dir = temp_dist_dir("missing");
        touch(&dir, "test-app.cpio");

        let mut config = base_config();
        config.release.assets = Some(vec![ReleaseAsset::Cpio, ReleaseAsset::Uki]);
        let assets = select_assets(&config, &dir);
        assert_eq!(assets, vec![dir.join("test-app.cpio")]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ovmf_firmware_is_included_by_default_when_present() {
        let dir = temp_dist_dir("ovmf-default");
        touch(&dir, "test-app.cpio");
        std::fs::create_dir_all(dir.join(".ovmf-cache")).unwrap();
        touch(&dir, ".ovmf-cache/OVMF.fd");

        let config = base_config();
        let assets = select_assets(&config, &dir);
        assert_eq!(
            assets,
            vec![dir.join("test-app.cpio"), dir.join(".ovmf-cache/OVMF.fd")]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ovmf_firmware_excluded_when_not_in_configured_assets() {
        let dir = temp_dist_dir("ovmf-excluded");
        touch(&dir, "test-app.cpio");
        std::fs::create_dir_all(dir.join(".ovmf-cache")).unwrap();
        touch(&dir, ".ovmf-cache/OVMF.fd");

        let mut config = base_config();
        config.release.assets = Some(vec![ReleaseAsset::Cpio]);
        let assets = select_assets(&config, &dir);
        assert_eq!(assets, vec![dir.join("test-app.cpio")]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
