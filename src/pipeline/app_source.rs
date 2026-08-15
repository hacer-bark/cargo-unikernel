//! Resolves `[app]` config into something `pipeline::docker` can embed into the image.
//!
//! Mode B (bring your own binary) is fully host-side: a local file, already on disk, staged
//! for the container — no network fetch, so no trust decision about what came back over the
//! wire. Mode A (compile from source) just confirms the project directory looks buildable —
//! the actual build happens inside the pinned container in `pipeline::docker`.

use crate::schema::{AppMode, Config};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// How the app was resolved from `[app]` config — what `pipeline::docker` embeds into the
/// image.
#[derive(Debug)]
pub enum AcquiredApp {
    /// A binary already verified and staged on the host, ready to hand to the container.
    Binary(PathBuf),
    /// The project directory itself (mounted as `/workspace`) is the source — the
    /// recommended, flagship "drop this tool into your own project" flow. No git involved
    /// at all: the container just runs `cargo build` against whatever's on disk right now.
    LocalSource {
        /// Subdirectory (relative to the project root) containing the buildable package.
        package_path: String,
    },
}

/// Resolves `[app]` config into an `AcquiredApp`, dispatching on `app.mode`.
///
/// # Errors
///
/// Returns an error if the required section (`[app.source]`/`[app.binary]`) is missing, or
/// `app.binary.path` doesn't exist inside the project directory.
pub fn acquire(config: &Config, project_dir: &Path) -> Result<AcquiredApp> {
    match config.app.mode {
        AppMode::Binary => acquire_binary(config, project_dir),
        AppMode::Source => acquire_source(config, project_dir),
    }
}

fn acquire_binary(config: &Config, project_dir: &Path) -> Result<AcquiredApp> {
    let binary = config
        .app
        .binary
        .as_ref()
        .context("app.mode = \"binary\" requires an [app.binary] section")?;
    let path = binary
        .path
        .as_ref()
        .context("[app.binary] must set `path`")?;

    let candidate = project_dir.join(path);
    let canonical_project = project_dir
        .canonicalize()
        .context("failed to canonicalize project directory")?;
    let canonical_candidate = candidate
        .canonicalize()
        .with_context(|| format!("app.binary.path '{path}' does not exist"))?;
    if !canonical_candidate.starts_with(&canonical_project) {
        bail!("app.binary.path must live inside the project directory (got {path})");
    }
    // The build container only ever sees `project_dir` bind-mounted at `/workspace` (see
    // `pipeline::docker::run_reproducible_build`), never the host's own absolute path — so
    // the script-visible APP_BIN must be rewritten relative to that mount, not the
    // host-canonical path.
    let relative = canonical_candidate
        .strip_prefix(&canonical_project)
        .context("canonical_candidate starts_with canonical_project but strip_prefix failed")?;
    Ok(AcquiredApp::Binary(Path::new("/workspace").join(relative)))
}

fn acquire_source(config: &Config, project_dir: &Path) -> Result<AcquiredApp> {
    let source = config
        .app
        .source
        .as_ref()
        .context("app.mode = \"source\" requires an [app.source] section")?;

    let path = source
        .path
        .as_ref()
        .context("[app.source] must set `path`")?;
    let candidate = project_dir.join(path);
    if !candidate.join("Cargo.toml").exists() {
        bail!("app.source.path '{path}' has no Cargo.toml — expected a Rust project there");
    }
    Ok(AcquiredApp::LocalSource {
        package_path: source.package_path.clone(),
    })
}
