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
use anyhow::Result;
use std::path::{Path, PathBuf};

/// `<project_dir>/dist` (or wherever `[output].dir` points) — the host-side directory every
/// pipeline stage writes/reads its artifacts under.
#[must_use]
pub fn host_dist_dir(config: &Config, project_dir: &Path) -> PathBuf {
    project_dir.join(config.output.dir.trim_end_matches('/'))
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
