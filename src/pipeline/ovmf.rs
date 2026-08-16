//! Resolves `[sev_snp.ovmf]` (preset or local path) into a firmware file the build container
//! can see.
//!
//! Different cloud providers ship different OVMF builds for SEV-SNP, so unlike the
//! kernel/toolchain pins, this one is deliberately user-overridable — but always from the
//! local machine, never fetched over the network at build time.
//!
//! `preset` and the standard casual-profile OVMF are both baked into this CLI binary as
//! build assets (`assets/ovmf/`, embedded via `crate::assets`) — pulled once from Ubuntu's
//! `ovmf` package. The tests below pin their hashes so any drift is caught by `cargo test`.

use crate::schema::OvmfSource;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// The in-container path the rest of the pipeline should reference.
///
/// For `preset`, this is the embedded firmware's materialized path under `/assets` — no
/// staging needed. For `path`, it's staged host-side into `dist/.ovmf-cache` first.
#[must_use]
pub fn in_container_path(ovmf: &OvmfSource, output_dir: &str) -> String {
    if ovmf.preset.is_some() {
        return "/assets/ovmf/OVMF.amdsev.fd".to_string();
    }
    let dir = output_dir.trim_end_matches('/');
    format!("/workspace/{dir}/.ovmf-cache/OVMF.fd")
}

/// The host-visible path to the resolved OVMF firmware (e.g. for including it in a GitHub
/// Release — see `release.rs`).
///
/// Same path regardless of source — `docker.rs` always stages the resolved firmware to
/// `dist/.ovmf-cache/OVMF.fd` inside the container.
#[must_use]
pub fn host_path(dist_dir: &Path) -> PathBuf {
    dist_dir.join(".ovmf-cache/OVMF.fd")
}

/// Stages a `path` OVMF firmware file host-side. No-op for `preset` (the Dockerfile already
/// provides it at a fixed path).
///
/// # Errors
///
/// Returns an error if creating the staging directory fails, reading the local `path` fails,
/// or writing the staged file fails.
pub fn stage(ovmf: &OvmfSource, project_dir: &Path, output_dir: &str) -> Result<()> {
    if ovmf.preset.is_some() {
        return Ok(());
    }

    let Some(path) = &ovmf.path else {
        bail!("[sev_snp.ovmf] must set exactly one of preset or path");
    };

    let dest_dir = project_dir
        .join(output_dir.trim_end_matches('/'))
        .join(".ovmf-cache");
    std::fs::create_dir_all(&dest_dir)
        .with_context(|| format!("failed to create {}", dest_dir.display()))?;
    let dest = dest_dir.join("OVMF.fd");

    let src = project_dir.join(path);
    let bytes = std::fs::read(&src)
        .with_context(|| format!("failed to read sev_snp.ovmf.path {}", src.display()))?;
    std::fs::write(&dest, bytes).with_context(|| format!("failed to write {}", dest.display()))?;
    Ok(())
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn preset_uses_embedded_asset_path() {
        let ovmf = OvmfSource {
            preset: Some("builtin".to_string()),
            path: None,
        };
        assert_eq!(
            in_container_path(&ovmf, "dist/"),
            "/assets/ovmf/OVMF.amdsev.fd"
        );
    }

    /// Expected sha256 of `assets/ovmf/OVMF.amdsev.fd` — AMD SEV-SNP guest firmware, used by
    /// the sev-snp profile's `preset` source. Must not deviate; see the module doc comment.
    const SEV_SNP_OVMF_SHA256: &str =
        "a24a1be2472ea4d620425974d9fb63d7f43c45ed209d0447c1b9f705706c202e";

    /// Expected sha256 of `assets/ovmf/OVMF.fd` — standard (non-confidential) OVMF, the same
    /// firmware Ubuntu ships for ordinary QEMU UEFI boot. Not yet wired into a
    /// casual-profile boot path, but baked in and hash-pinned alongside the sev-snp firmware
    /// so both live under one verified source.
    const CASUAL_OVMF_SHA256: &str =
        "60812c18e81f0f50e94ee50628bcdf2f3df4cf049abe356403054a76a308b7ff";

    /// Guards against the checked-in firmware bytes ever silently drifting from what's
    /// documented/pinned — see the module doc comment.
    #[test]
    fn embedded_ovmf_binaries_match_pinned_hashes() {
        fn sha256_of(path: &Path) -> String {
            let bytes = std::fs::read(path).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            crate::hex::encode(&hasher.finalize())
        }

        let assets_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/ovmf");
        assert_eq!(
            sha256_of(&assets_dir.join("OVMF.amdsev.fd")),
            SEV_SNP_OVMF_SHA256,
            "assets/ovmf/OVMF.amdsev.fd no longer matches its pinned hash"
        );
        assert_eq!(
            sha256_of(&assets_dir.join("OVMF.fd")),
            CASUAL_OVMF_SHA256,
            "assets/ovmf/OVMF.fd no longer matches its pinned hash"
        );
    }

    #[test]
    fn path_uses_staged_cache_path() {
        let via_path = OvmfSource {
            preset: None,
            path: Some("./firmware/OVMF.fd".to_string()),
        };
        assert_eq!(
            in_container_path(&via_path, "dist/"),
            "/workspace/dist/.ovmf-cache/OVMF.fd"
        );
    }

    #[test]
    fn in_container_path_respects_custom_output_dir() {
        let via_path = OvmfSource {
            preset: None,
            path: Some("./firmware/OVMF.fd".to_string()),
        };
        assert_eq!(
            in_container_path(&via_path, "build-output/"),
            "/workspace/build-output/.ovmf-cache/OVMF.fd"
        );
    }

    #[test]
    fn host_path_is_the_same_regardless_of_source() {
        let dist_dir = Path::new("/home/user/myproject/dist");
        assert_eq!(
            host_path(dist_dir),
            Path::new("/home/user/myproject/dist/.ovmf-cache/OVMF.fd")
        );
    }

    #[test]
    fn stage_is_a_noop_for_preset() {
        let ovmf = OvmfSource {
            preset: Some("builtin".to_string()),
            path: None,
        };
        let dir = std::env::temp_dir().join(format!("cu-ovmf-test-preset-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        stage(&ovmf, &dir, "dist/").unwrap();
        assert!(!dir.join("dist/.ovmf-cache").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stage_copies_local_path_into_ovmf_cache() {
        let dir = std::env::temp_dir().join(format!("cu-ovmf-test-path-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("my-firmware.fd"), b"fake-firmware-bytes").unwrap();

        let ovmf = OvmfSource {
            preset: None,
            path: Some("my-firmware.fd".to_string()),
        };
        stage(&ovmf, &dir, "dist/").unwrap();
        let staged = std::fs::read(dir.join("dist/.ovmf-cache/OVMF.fd")).unwrap();
        assert_eq!(staged, b"fake-firmware-bytes");

        std::fs::remove_dir_all(&dir).ok();
    }
}
