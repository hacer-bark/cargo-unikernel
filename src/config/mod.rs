//! Loading, scaffolding, and applying CLI overrides to a `Cargo-Unikernel.toml`.

/// Zero-config "one call" build.
///
/// Figures out a build when no `Cargo-Unikernel.toml` exists.
pub mod auto_detect;
/// CLI-flag overrides applied on top of a loaded `Config`.
pub mod overrides;
/// `cargo unikernel init` — writes a starting `Cargo-Unikernel.toml`.
pub mod scaffold;

pub use overrides::{BuildOverrides, apply_overrides};
pub use scaffold::scaffold;

use crate::schema::Config;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Canonical config file name, matching `Cargo.toml`'s capitalization.
pub const CONFIG_FILE_NAME: &str = "Cargo-Unikernel.toml";

/// Pre-rename file name, still read as a fallback when `CONFIG_FILE_NAME` isn't present, so
/// existing projects keep working without an immediate rename.
pub const LEGACY_CONFIG_FILE_NAME: &str = "cargo-unikernel.toml";

/// The config path to use when none is given explicitly.
///
/// `CONFIG_FILE_NAME` if present, else `LEGACY_CONFIG_FILE_NAME` if only that exists, else
/// `CONFIG_FILE_NAME` (so callers get a "file not found" error naming the current name).
#[must_use]
pub fn default_config_path() -> PathBuf {
    let canonical = PathBuf::from(CONFIG_FILE_NAME);
    if canonical.exists() {
        return canonical;
    }
    let legacy = PathBuf::from(LEGACY_CONFIG_FILE_NAME);
    if legacy.exists() {
        return legacy;
    }
    canonical
}

/// Reads and parses `path` as a `Cargo-Unikernel.toml`, then validates it.
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
    config.toolchain.warn_if_e2fsprogs_unverified();
    config
        .validate()
        .with_context(|| format!("{} failed validation", path.display()))?;
    Ok(config)
}

/// Resolves the effective config + project directory for `cargo unikernel build`:
/// - an explicit `-c/--config` always loads that exact file (error if missing)
/// - otherwise, `./Cargo-Unikernel.toml` is used if it exists, falling back to the legacy
///   `./cargo-unikernel.toml` if only that does
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

    let default_path = default_config_path();
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

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// `default_config_path` reads relative to the *process* cwd, not a path parameter — use
    /// the crate-wide `TEST_CWD_LOCK` (shared with every other module that does this) so cwd
    /// changes across modules serialize under `cargo test`'s multi-threaded runner too.
    fn in_temp_dir<T>(f: impl FnOnce(&Path) -> T) -> T {
        let _guard = crate::TEST_CWD_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("cu-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let result = f(&dir);
        std::env::set_current_dir(original).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        result
    }

    #[test]
    fn default_config_path_prefers_the_capitalized_name_when_both_exist() {
        in_temp_dir(|_dir| {
            std::fs::write(CONFIG_FILE_NAME, "").unwrap();
            std::fs::write(LEGACY_CONFIG_FILE_NAME, "").unwrap();
            assert_eq!(default_config_path(), PathBuf::from(CONFIG_FILE_NAME));
        });
    }

    #[test]
    fn default_config_path_falls_back_to_the_legacy_name() {
        in_temp_dir(|_dir| {
            std::fs::write(LEGACY_CONFIG_FILE_NAME, "").unwrap();
            assert_eq!(
                default_config_path(),
                PathBuf::from(LEGACY_CONFIG_FILE_NAME)
            );
        });
    }

    #[test]
    fn default_config_path_is_the_capitalized_name_when_neither_exists() {
        in_temp_dir(|_dir| {
            assert_eq!(default_config_path(), PathBuf::from(CONFIG_FILE_NAME));
        });
    }
}
