use crate::pipeline::docker::BuildArtifacts;
use crate::schema::OutputFormat;
use anyhow::{Result, bail};
use std::path::PathBuf;

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
pub fn write(format: OutputFormat, artifacts: &BuildArtifacts) -> Result<()> {
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
