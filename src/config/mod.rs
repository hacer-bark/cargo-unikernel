//! Loading, scaffolding, and applying CLI overrides to a `cargo-unikernel.toml`.

/// Zero-config "one call" build.
///
/// Figures out a build when no `cargo-unikernel.toml` exists.
pub mod auto_detect;
/// CLI-flag overrides applied on top of a loaded `Config`.
pub mod overrides;
/// `cargo-unikernel init` — writes a starting `cargo-unikernel.toml`.
pub mod scaffold;

pub use overrides::{BuildOverrides, apply_overrides};
pub use scaffold::scaffold;

use crate::schema::Config;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Reads and parses `path` as a `cargo-unikernel.toml`, then validates it.
///
/// # Errors
///
/// Returns an error if the file can't be read, doesn't parse as valid TOML for this schema,
/// or fails `Config::validate`.
pub fn load(path: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file at {}", path.display()))?;
    let config: Config = toml::from_str(&raw).with_context(|| {
        format!(
            "failed to parse {} as cargo-unikernel config TOML",
            path.display()
        )
    })?;
    config.toolchain.warn_if_limine_unverified();
    config.toolchain.warn_if_e2fsprogs_unverified();
    config
        .validate()
        .with_context(|| format!("{} failed validation", path.display()))?;
    Ok(config)
}

/// Resolves the effective config + project directory for `cargo-unikernel build`:
/// - an explicit `-c/--config` always loads that exact file (error if missing)
/// - otherwise, `./cargo-unikernel.toml` is used if it exists
/// - otherwise, zero-config auto-detection kicks in (see `auto_detect`)
///
/// # Errors
///
/// Returns an error if an explicit `-c/--config` path doesn't load/validate, or if
/// zero-config auto-detection can't determine how to build the current directory.
pub fn resolve_for_build(
    explicit_config: Option<PathBuf>,
    binary_override: Option<PathBuf>,
) -> Result<(Config, PathBuf)> {
    if let Some(path) = explicit_config {
        let project_dir = project_dir_of(&path);
        let config = load(&path).with_context(|| format!("loading {}", path.display()))?;
        return Ok((config, project_dir));
    }

    let default_path = PathBuf::from("cargo-unikernel.toml");
    let project_dir = PathBuf::from(".");
    if default_path.exists() {
        let config = load(&default_path)?;
        return Ok((config, project_dir));
    }

    let config = auto_detect::detect(&project_dir, binary_override)?;
    Ok((config, project_dir))
}

fn project_dir_of(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(std::path::Path::to_path_buf)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| ".".into())
}
