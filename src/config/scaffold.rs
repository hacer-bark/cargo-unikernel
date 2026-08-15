use crate::cli::ProfileArg;
use crate::schema::CLI_VERSION;
use anyhow::{Context, Result, bail};
use std::path::Path;

const CASUAL: &str = include_str!("../../examples/cargo-unikernel.casual.toml");
const SEV_SNP: &str = include_str!("../../examples/cargo-unikernel.sev-snp.toml");

/// Writes a starting `cargo-unikernel.toml` into `dir`, picked from the bundled `examples/`
/// config matching `profile`.
///
/// Both bundled configs document every app-acquisition mode (`toolchain = "rust"`/
/// `"generic"`, or `[app.binary]`) inline — hand-edit after scaffolding to pick a different
/// one.
///
/// # Errors
///
/// Returns an error if `dir/cargo-unikernel.toml` already exists, or if writing the file
/// fails.
pub fn scaffold(profile: ProfileArg, dir: &Path) -> Result<()> {
    let template = match profile {
        ProfileArg::Casual => CASUAL,
        ProfileArg::SevSnp => SEV_SNP,
    };

    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    let target = dir.join("cargo-unikernel.toml");
    if target.exists() {
        bail!(
            "{} already exists — remove it first if you want to re-scaffold",
            target.display()
        );
    }

    std::fs::write(&target, pin_tool_version(template))
        .with_context(|| format!("failed to write {}", target.display()))?;

    std::fs::create_dir_all(dir.join("dist"))
        .with_context(|| format!("failed to create {}/dist", dir.display()))?;

    println!("Scaffolded {}", target.display());
    Ok(())
}

/// Inserts `project.cargo_unikernel_version` set to the running CLI's own version right
/// after the `[project]` header of a bundled template — every template starts with exactly
/// one `[project]\n` line, so this always fires once. Pinning it at scaffold time (rather
/// than leaving it commented out like the bundled example this template is copied from)
/// means a freshly scaffolded config immediately requires the same CLI version to build,
/// which is what SEV-SNP measurement reproducibility (and casual-profile determinism)
/// depends on — a different CLI version can bundle a different pinned kernel/Dockerfile.
pub(crate) fn pin_tool_version(template: &str) -> String {
    template.replacen(
        "[project]\n",
        &format!("[project]\ncargo_unikernel_version = \"{CLI_VERSION}\"\n"),
        1,
    )
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::schema::Config;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cu-scaffold-test-{label}-{}", std::process::id()))
    }

    #[test]
    fn every_bundled_profile_scaffolds_a_config_that_parses_and_validates() {
        for (profile, label) in [
            (ProfileArg::Casual, "casual"),
            (ProfileArg::SevSnp, "sevsnp"),
        ] {
            let dir = temp_dir(label);
            std::fs::remove_dir_all(&dir).ok();
            scaffold(profile, &dir).unwrap();

            let written = std::fs::read_to_string(dir.join("cargo-unikernel.toml")).unwrap();
            let config: Config = toml::from_str(&written)
                .unwrap_or_else(|e| panic!("{label}: scaffolded config didn't parse: {e}"));
            config
                .validate()
                .unwrap_or_else(|e| panic!("{label}: scaffolded config didn't validate: {e}"));
            assert_eq!(
                config.project.cargo_unikernel_version.as_deref(),
                Some(crate::schema::CLI_VERSION),
                "{label}: scaffolded config wasn't pinned to the running CLI version"
            );
            assert!(dir.join("dist").is_dir(), "{label}: dist/ not created");

            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn pin_tool_version_inserts_exactly_one_pin_with_no_comment_above_it() {
        let pinned = pin_tool_version(CASUAL);
        let expected = format!("[project]\ncargo_unikernel_version = \"{CLI_VERSION}\"\n");
        assert_eq!(pinned.matches(&expected).count(), 1);
        assert_eq!(pinned.matches("[project]").count(), 1);
    }

    #[test]
    fn refuses_to_overwrite_existing_config() {
        let dir = temp_dir("no-clobber");
        std::fs::remove_dir_all(&dir).ok();
        scaffold(ProfileArg::Casual, &dir).unwrap();
        let err = scaffold(ProfileArg::Casual, &dir).unwrap_err();
        assert!(err.to_string().contains("already exists"));
        std::fs::remove_dir_all(&dir).ok();
    }
}
