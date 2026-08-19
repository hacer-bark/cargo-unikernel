//! Everything the build container needs, embedded into this binary at compile time.
//!
//! So `cargo install cargo-unikernel` works from any directory on any machine — there is no
//! "clone this tool's repo and run a script from inside it" step. At build time, these are
//! materialized to a cache directory and mounted read-only into the build container alongside
//! the user's project.

use anyhow::{Context, Result};
use include_dir::{Dir, include_dir};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Dockerfile, kernel build script + Kconfig fragments, ISO build script, and QEMU
/// templates.
static BUILD_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/assets");

/// The guest-side source (`cargo-unikernel-init`), cross-compiled inside the container for
/// every build. Not a Cargo dependency of this crate — only ever needed as source text to
/// hand to `cargo build` inside the container.
static GUEST_SOURCE: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/guest");

/// Extracts the embedded assets/guest source into a cache directory, returning its path.
///
/// Writes to `~/.cache/cargo-unikernel/assets-<version>-<content-hash>/` (idempotent —
/// skipped if that exact content was already materialized). Keyed on a content hash (not
/// just the crate version) so that reinstalling a locally-built binary whose embedded assets
/// changed — but whose Cargo.toml version didn't — never serves a stale cache directory.
///
/// # Errors
///
/// Returns an error if any filesystem operation (creating the cache dir, writing the
/// embedded files) fails.
pub fn materialize() -> Result<PathBuf> {
    let fingerprint = content_fingerprint();
    let root = cache_root().join(format!(
        "assets-{}-{}",
        env!("CARGO_PKG_VERSION"),
        fingerprint
    ));
    let marker = root.join(".complete");
    if marker.exists() {
        return Ok(root);
    }

    let build_dir = root.join("build");
    let guest_dir = root.join("guest");
    std::fs::create_dir_all(&build_dir)
        .with_context(|| format!("failed to create {}", build_dir.display()))?;
    std::fs::create_dir_all(&guest_dir)
        .with_context(|| format!("failed to create {}", guest_dir.display()))?;

    extract(&BUILD_ASSETS, &build_dir)?;
    extract(&GUEST_SOURCE, &guest_dir)?;
    restore_guest_manifests(&guest_dir)?;

    make_scripts_executable(&build_dir)?;
    std::fs::write(&marker, b"")
        .with_context(|| format!("failed to write {}", marker.display()))?;

    Ok(root)
}

fn extract(dir: &Dir<'_>, dest: &Path) -> Result<()> {
    for file in dir.files() {
        let target = dest.join(file.path());
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::write(&target, file.contents())
            .with_context(|| format!("failed to write {}", target.display()))?;
    }
    for sub in dir.dirs() {
        extract(sub, dest)?;
    }
    Ok(())
}

/// Renames every extracted `Cargo.toml.dist` back to `Cargo.toml`, so the container sees a
/// normal Cargo workspace.
///
/// The guest tree is checked in with that suffix in the first place because `cargo package`
/// unconditionally excludes any subdirectory containing a literal `Cargo.toml` from the
/// published tarball — with no `include`/`exclude` override — which would otherwise make
/// this whole guest source vanish from every crates.io release. See `guest/setup.sh`, which
/// does the same rename for local guest-workspace development.
fn restore_guest_manifests(guest_dir: &Path) -> Result<()> {
    for entry in walk(guest_dir)? {
        if entry.file_name().is_some_and(|n| n == "Cargo.toml.dist") {
            let restored = entry.with_extension("");
            std::fs::rename(&entry, &restored).with_context(|| {
                format!(
                    "failed to rename {} to {}",
                    entry.display(),
                    restored.display()
                )
            })?;
        }
    }
    Ok(())
}

fn walk(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path)?);
        } else {
            out.push(path);
        }
    }
    Ok(out)
}

fn make_scripts_executable(build_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for rel in ["kernel/build_kernel.sh", "scripts/make_iso.sh"] {
            let path = build_dir.join(rel);
            if path.exists() {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
            }
        }
    }
    Ok(())
}

fn content_fingerprint() -> String {
    let mut hasher = Sha256::new();
    hash_dir(&BUILD_ASSETS, &mut hasher);
    hash_dir(&GUEST_SOURCE, &mut hasher);
    let digest = hasher.finalize();
    crate::hex::encode(digest.get(..8).unwrap_or(&digest))
}

fn hash_dir(dir: &Dir<'_>, hasher: &mut Sha256) {
    for file in dir.files() {
        hasher.update(file.path().to_string_lossy().as_bytes());
        hasher.update(file.contents());
    }
    for sub in dir.dirs() {
        hash_dir(sub, hasher);
    }
}

fn cache_root() -> PathBuf {
    std::env::var("HOME").map_or_else(
        |_| PathBuf::from("/tmp/cargo-unikernel-cache"),
        |h| PathBuf::from(h).join(".cache/cargo-unikernel"),
    )
}
