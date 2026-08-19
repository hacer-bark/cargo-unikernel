//! Provisions the persistent-storage disk image for `[storage].mode = "persistent"`.

use crate::schema::{Config, StorageMode};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// `dist/<name>.data.img` — the persisted-storage disk image's host path.
#[must_use]
fn host_path(dist_dir: &Path, name: &str) -> PathBuf {
    dist_dir.join(format!("{name}.data.img"))
}

/// Creates the sparse raw disk image if it doesn't already exist. Never truncates or
/// recreates an existing one — that's the guest's persisted `/var`.
///
/// # Errors
///
/// Returns an error if creating or sizing the image file fails.
pub fn stage(config: &Config, project_dir: &Path) -> Result<()> {
    if config.storage.mode != StorageMode::Persistent {
        return Ok(());
    }
    let dist_dir = super::host_dist_dir(config, project_dir);
    std::fs::create_dir_all(&dist_dir)
        .with_context(|| format!("failed to create {}", dist_dir.display()))?;
    let path = host_path(&dist_dir, &config.project.name);
    if path.exists() {
        return Ok(());
    }
    let file = std::fs::File::create(&path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.set_len(
        u64::from(config.storage.size_mib)
            .saturating_mul(1024)
            .saturating_mul(1024),
    )
    .with_context(|| format!("failed to size {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::pipeline::docker::test_fixtures::casual_config_with_formats;
    use crate::schema::{OutputFormat, StorageMode};

    #[test]
    fn ram_mode_creates_nothing() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.storage.mode = StorageMode::Ram;
        let dir = std::env::temp_dir().join(format!("cu-storage-test-ram-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        stage(&config, &dir).unwrap();
        assert!(!host_path(&dir.join("dist"), &config.project.name).exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn persistent_mode_creates_a_sized_sparse_image() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.storage.mode = StorageMode::Persistent;
        config.storage.size_mib = 16;
        let dir =
            std::env::temp_dir().join(format!("cu-storage-test-persistent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        stage(&config, &dir).unwrap();
        let path = host_path(&dir.join("dist"), &config.project.name);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 16 * 1024 * 1024);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn existing_image_is_never_touched() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.storage.mode = StorageMode::Persistent;
        let dir =
            std::env::temp_dir().join(format!("cu-storage-test-preserve-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("dist")).unwrap();
        let path = host_path(&dir.join("dist"), &config.project.name);
        std::fs::write(&path, b"existing user data").unwrap();

        stage(&config, &dir).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"existing user data");

        std::fs::remove_dir_all(&dir).ok();
    }
}
