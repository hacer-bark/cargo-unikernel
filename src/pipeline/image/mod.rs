use crate::pipeline::docker::BuildArtifacts;
use crate::schema::{Config, OutputFormat, ProfileKind};
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};

/// Dispatches to the matching format's verification — confirms `format` landed in `dist/` and
/// reports it.
///
/// Every format is actually produced inside the build container (see `pipeline::docker`);
/// this just confirms the expected output landed, giving each format a dedicated seam for any
/// host-side post-processing that gets added later (e.g. signing).
///
/// # Errors
///
/// Returns an error if the build container didn't actually produce `format`.
pub fn write(
    format: OutputFormat,
    config: &Config,
    _project_dir: &Path,
    artifacts: &BuildArtifacts,
) -> Result<()> {
    match format {
        OutputFormat::Cpio => {
            if !artifacts.cpio.exists() || !artifacts.bzimage.exists() {
                bail!("cpio/bzImage output was requested but not produced by the build container");
            }
            println!(
                "cpio+bzImage ready: {} + {}",
                artifacts.bzimage.display(),
                artifacts.cpio.display()
            );
        }
        OutputFormat::Iso => {
            let iso = require(
                artifacts.iso.as_ref(),
                "iso output was requested but not produced by build/scripts/make_iso.sh",
            )?;
            if config.profile.kind == ProfileKind::SevSnp {
                println!(
                    "iso ready: {} (note: for sev-snp, this is a convenience/testing image — the \
                     measured boot path is cpio+bzImage or uki, matching what sev-snp-measure.py saw)",
                    iso.display()
                );
            } else {
                println!("iso ready: {}", iso.display());
            }
        }
        OutputFormat::Uki => {
            let uki = require(
                artifacts.uki.as_ref(),
                "uki output was requested but not produced by `ukify` in the build container",
            )?;
            println!("uki ready: {}", uki.display());
        }
        OutputFormat::Binary => {
            let binary = require(
                artifacts.binary.as_ref(),
                "binary output was requested but not produced by the build container",
            )?;
            println!("app binary ready: {}", binary.display());
        }
    }
    Ok(())
}

fn require<'a>(artifact: Option<&'a PathBuf>, missing_msg: &str) -> Result<&'a PathBuf> {
    artifact.ok_or_else(|| anyhow::anyhow!(missing_msg.to_string()))
}
