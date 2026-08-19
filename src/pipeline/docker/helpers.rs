use crate::schema::{Config, ToolchainPins};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

/// The invoking host user's uid/gid, used to hand root-owned build-cache files in
/// `~/.cache/cargo-unikernel/` back to whoever actually owns that directory (see the
/// comment at the `docker run` call site). Best-effort — `None` just skips the chown.
pub(super) fn host_uid_gid() -> Option<(String, String)> {
    let uid = String::from_utf8(Command::new("id").arg("-u").output().ok()?.stdout)
        .ok()?
        .trim()
        .to_string();
    let gid = String::from_utf8(Command::new("id").arg("-g").output().ok()?.stdout)
        .ok()?
        .trim()
        .to_string();
    if uid.is_empty() || gid.is_empty() {
        return None;
    }
    Some((uid, gid))
}

/// `/workspace/dist` (or wherever `[output].dir` points), as seen from inside the build
/// container — the in-container counterpart of `pipeline::host_dist_dir`.
#[must_use]
pub(super) fn in_container_dist(config: &Config) -> String {
    "/workspace/".to_string() + config.output.dir.trim_end_matches('/')
}

/// sha256 of an actual artifact file, read host-side.
///
/// Used for bzImage/cpio, which always land somewhere host-visible — `dist/` if `cpio` was
/// requested as an output format, otherwise the last-build staging dir.
///
/// # Errors
///
/// Returns an error if `path` can't be read.
pub fn sha256_hex_of_file(path: &Path) -> Result<String> {
    let mut file = std::io::BufReader::new(
        std::fs::File::open(path)
            .with_context(|| format!("failed to read {} to compute its sha256", path.display()))?,
    );
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)
            .with_context(|| format!("failed to read {} to compute its sha256", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n).unwrap_or_default());
    }
    Ok(crate::hex::encode(&hasher.finalize()))
}

/// Reads a `<name>.sha256` file the in-container script already wrote (a bare hex digest,
/// not a file to hash).
///
/// For artifacts (raw app/guest-init binaries, `preset` OVMF) that only ever exist inside the
/// container, never as standalone files on the host. Missing/unreadable is `None`, not an
/// error: these are diagnostic extras, not required outputs.
#[must_use]
pub fn read_hash_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// POSIX single-quote-escapes a string for safe interpolation into a generated shell script.
///
/// So a config-controlled value (project name, cmdline, git ref, ...) can't break out of its
/// argument and inject commands. Not used for `build_command` (generic toolchain), which is
/// deliberately raw shell.
#[must_use]
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// `docker build --build-arg` pairs for any `[toolchain]` override — empty when nothing is
/// set, so `Dockerfile.reproducible`'s own `ARG NAME=<default>` applies silently. See
/// `docs/reproducible_builds.md`.
pub(super) fn build_args_for(toolchain: &ToolchainPins) -> Result<Vec<(String, String)>> {
    let mut args = Vec::new();
    if let Some(snapshot) = &toolchain.apt_snapshot {
        let resolved = if snapshot == "latest" {
            resolve_latest_apt_snapshot()?
        } else {
            snapshot.clone()
        };
        args.push(("SNAPSHOT_TS".to_string(), resolved));
    }
    for (name, value) in [
        ("RUST_VERSION", &toolchain.rust_version),
        ("LIMINE_VERSION", &toolchain.limine_version),
        ("LIMINE_SHA256", &toolchain.limine_sha256),
        ("E2FSPROGS_VERSION", &toolchain.e2fsprogs_version),
        ("E2FSPROGS_SHA256", &toolchain.e2fsprogs_sha256),
    ] {
        if let Some(v) = value {
            args.push((name.to_string(), v.clone()));
        }
    }
    Ok(args)
}

/// Resolves `apt_snapshot = "latest"` to the current UTC instant in snapshot.ubuntu.com's
/// `YYYYMMDDTHHMMSSZ` format — casual-profile-only (rejected for sev-snp at config-validation
/// time). Shells out to `date` rather than adding a datetime dependency for one timestamp
/// format.
fn resolve_latest_apt_snapshot() -> Result<String> {
    let output = Command::new("date")
        .args(["-u", "+%Y%m%dT%H%M%SZ"])
        .output()
        .context("failed to run `date` to resolve toolchain.apt_snapshot = \"latest\"")?;
    if !output.status.success() {
        bail!("`date -u` failed while resolving toolchain.apt_snapshot = \"latest\"");
    }
    Ok(String::from_utf8(output.stdout)
        .context("`date -u` produced non-UTF8 output")?
        .trim()
        .to_string())
}

/// Prints which `[toolchain]` pins (if any) are overridden for this build, with a
/// reproducibility caveat — the discoverability this whole feature exists for for a user who
/// forgets what they patched. Silent when nothing is overridden.
pub(super) fn print_toolchain_overrides(toolchain: &ToolchainPins) {
    let overrides: Vec<String> = [
        ("apt_snapshot", &toolchain.apt_snapshot),
        ("rust_version", &toolchain.rust_version),
        ("limine_version", &toolchain.limine_version),
        ("e2fsprogs_version", &toolchain.e2fsprogs_version),
    ]
    .into_iter()
    .filter_map(|(name, value)| value.as_ref().map(|v| format!("{name}={v}")))
    .collect();
    if overrides.is_empty() {
        return;
    }
    println!(
        "Toolchain overrides in effect: {} — this build's toolchain differs from this CLI \
         version's own defaults, so its reproducibility is only as strong as these pins.",
        overrides.join(", ")
    );
}

/// Appends `export NAME="value"\n` to `s` — the shared shape of every env-var export line
/// the generated build script writes.
pub(super) fn write_export(s: &mut String, name: &str, value: impl std::fmt::Display) {
    use std::fmt::Write as _;
    let _ = writeln!(s, "export {name}=\"{value}\"");
}

/// `RUSTFLAGS` for every Rust build in the pipeline (guest init and Mode A `rust` toolchain
/// app builds). `-C codegen-units=1` forces sequential codegen — with Cargo's default
/// parallel units, racing LLVM codegen threads make the final object's section/symbol order
/// nondeterministic across otherwise-identical builds. See `docs/reproducible_builds.md`.
pub(super) fn rustflags_export() -> String {
    "export RUSTFLAGS=\"-C codegen-units=1\"\n".to_string()
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn build_args_for_is_empty_when_nothing_overridden() {
        let toolchain = ToolchainPins::default();
        assert!(build_args_for(&toolchain).unwrap().is_empty());
    }

    #[test]
    fn build_args_for_includes_only_the_overridden_pins() {
        let toolchain = ToolchainPins {
            apt_snapshot: Some("20250101T000000Z".to_string()),
            rust_version: Some("1.99.0".to_string()),
            limine_version: None,
            limine_sha256: None,
            e2fsprogs_version: None,
            e2fsprogs_sha256: None,
        };
        let args = build_args_for(&toolchain).unwrap();
        assert_eq!(
            args,
            vec![
                ("SNAPSHOT_TS".to_string(), "20250101T000000Z".to_string()),
                ("RUST_VERSION".to_string(), "1.99.0".to_string()),
            ]
        );
    }

    #[test]
    fn build_args_for_resolves_latest_apt_snapshot_to_a_real_timestamp() {
        let toolchain = ToolchainPins {
            apt_snapshot: Some("latest".to_string()),
            ..ToolchainPins::default()
        };
        let args = build_args_for(&toolchain).unwrap();
        assert_eq!(args.len(), 1);
        let (name, value) = &args[0];
        assert_eq!(name, "SNAPSHOT_TS");
        assert_ne!(value, "latest");
        assert_eq!(value.len(), 16, "expected YYYYMMDDTHHMMSSZ, got {value}");
        assert!(value.ends_with('Z'));
    }
}
