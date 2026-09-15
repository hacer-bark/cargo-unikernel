//! The build pipeline: app-source resolution, the Docker container, image formats, and
//! SEV-SNP measurement.

pub mod app_source;
pub mod docker;
/// Verifies and reports each requested output image format, once the build container has
/// produced it.
pub mod image;
pub mod kernel;
pub mod measurement;
pub mod ovmf;
pub mod storage;

use crate::schema::{Config, ProfileKind};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// `<project_dir>/dist` (or wherever `[output].dir` points) — the host-side directory every
/// pipeline stage writes/reads its artifacts under.
///
/// # Errors
///
/// Returns an error if the directory cannot be created or resolves outside `project_dir`.
pub fn host_dist_dir(config: &Config, project_dir: &Path) -> Result<PathBuf> {
    let project_dir = project_dir
        .canonicalize()
        .context("failed to canonicalize project directory")?;
    if config.output.dir.trim().is_empty() {
        bail!("output.dir must not be empty");
    }
    let mut output_dir = project_dir.clone();
    for component in Path::new(&config.output.dir).components() {
        match component {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(name) => output_dir.push(name),
            _ => bail!("output.dir must be a relative path inside the project directory"),
        }
        match std::fs::create_dir(&output_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create {}", output_dir.display()));
            }
        }
        output_dir = output_dir
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", output_dir.display()))?;
        if !output_dir.starts_with(&project_dir) {
            bail!("output.dir resolves outside the project directory");
        }
    }
    Ok(output_dir)
}

/// Orchestrates a full `cargo unikernel build`.
///
/// # Errors
///
/// Returns an error if any stage fails: staging OVMF, resolving the app source, the
/// reproducible Docker build, image-format verification, or SEV-SNP measurement.
pub fn build(config: &Config, project_dir: &Path) -> Result<()> {
    if let Some(sev) = &config.sev_snp {
        ovmf::stage(&sev.ovmf, project_dir, &config.output.dir)?;
    }
    storage::stage(config, project_dir)?;

    let app_binary = app_source::acquire(config, project_dir)?;
    let artifacts = docker::run_reproducible_build(config, project_dir, &app_binary)?;

    for format in &config.output.formats {
        image::write(*format, &artifacts)?;
    }

    if config.profile.kind == ProfileKind::SevSnp {
        let m = measurement::compute(config, project_dir, &artifacts)?;
        println!("SEV-SNP measurement: {}", m.hex);
    }

    Ok(())
}
