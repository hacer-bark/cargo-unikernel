//! Drives the pinned reproducible-build container.
//!
//! Mounts the user's project as `/workspace`, the materialized embedded assets as `/assets`
//! (see `crate::assets::materialize()`), and does all kernel/rootfs scratch work under
//! `/build` so the project directory only ever gains a `dist/` folder.
//!
//! Split by build stage into one submodule per concern: `kernel_script`, `guest_init_script`,
//! `app_script`, `rootfs_script`, and `measurement_script` each emit the shell fragment for
//! their stage; `helpers` and `cmdline` hold shared plumbing; this module owns orchestration
//! (`run_reproducible_build`, `generate_build_script`) plus the re-exports external code uses.

/// Emits the shell fragment that builds (or stages) the user's app.
pub mod app_script;
/// Resolves the kernel cmdline for a given `Config`.
pub mod cmdline;
/// Emits the shell fragment that cross-compiles `cargo-unikernel-init`.
pub mod guest_init_script;
/// Shared plumbing: docker build-args, host uid/gid lookup, hashing, shell-quoting.
pub mod helpers;
/// Emits the shell fragment that builds the Linux kernel.
pub mod kernel_script;
/// Emits the shell fragment that computes the SEV-SNP launch measurement.
pub mod measurement_script;
/// Emits the shell fragment that assembles the rootfs and packs the requested image formats.
pub mod rootfs_script;

use crate::pipeline::app_source::AcquiredApp;
use crate::schema::{Config, OutputFormat};
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

use app_script::script_app_build;
use guest_init_script::script_guest_init_build;
use helpers::{build_args_for, host_uid_gid, print_toolchain_overrides};
use kernel_script::script_kernel_build;
use measurement_script::script_sev_snp_measurement;
use rootfs_script::script_rootfs_and_images;

// Re-exported so external call sites (`lib.rs`) keep referencing `pipeline::docker::X`
// unchanged after this module was split up.
pub use helpers::{read_hash_file, sha256_hex_of_file};

/// Env var the host passes the invoking user's uid through as, for
/// `script_reclaim_cache_ownership`'s in-container `chown` back to it.
const HOST_UID_VAR: &str = "CARGO_UNIKERNEL_HOST_UID";
/// Same as `HOST_UID_VAR`, for the gid.
const HOST_GID_VAR: &str = "CARGO_UNIKERNEL_HOST_GID";

/// The build artifacts a `run_reproducible_build` call actually produced.
#[derive(Debug)]
pub struct BuildArtifacts {
    /// Host path to the built kernel image.
    pub bzimage: PathBuf,
    /// Host path to the built initramfs.
    pub cpio: PathBuf,
    /// Host path to the built ISO, if `OutputFormat::Iso` was requested.
    pub iso: Option<PathBuf>,
    /// Host path to the built UKI `.efi`, if `OutputFormat::Uki` was requested.
    pub uki: Option<PathBuf>,
    /// Host path to the raw app binary, if `OutputFormat::Binary` was requested.
    pub binary: Option<PathBuf>,
    /// Host path to the raw SEV-SNP measurement file (sev-snp profile only).
    pub sev_measurement: Option<PathBuf>,
    /// sha256 of each individual input that determines the final measurement/image, so a
    /// mismatch between two builds can be attributed to a specific component rather than
    /// just "the final hash differs" — see `ComponentHashes` and
    /// `pipeline::measurement::compute`, which records these in `sev_measurement.json`.
    pub component_hashes: ComponentHashes,
}

/// sha256 of each build component, recorded in `sev_measurement.json` for diffing two builds
/// that produced different measurements.
#[derive(Debug, Default, serde::Serialize)]
pub struct ComponentHashes {
    /// sha256 of `BuildArtifacts::bzimage`.
    pub kernel_sha256: Option<String>,
    /// sha256 of `BuildArtifacts::cpio`.
    pub cpio_sha256: Option<String>,
    /// sha256 of the raw app binary embedded in the image.
    pub app_sha256: Option<String>,
    /// sha256 of the cross-compiled `cargo-unikernel-init` binary.
    pub guest_init_sha256: Option<String>,
    /// sha256 of the OVMF firmware used (sev-snp profile only).
    pub ovmf_sha256: Option<String>,
}

/// Checks that `docker info` succeeds — the build container's prerequisite.
///
/// # Errors
///
/// Returns an error (with a specific fix suggestion for the common "user not in the docker
/// group" case) if Docker isn't installed, isn't running, or the current user lacks
/// permission to use it.
pub fn check_available() -> Result<()> {
    let output = Command::new("docker").arg("info").output();
    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let detail = stderr.trim();
            if detail.contains("permission denied") {
                bail!(
                    "`docker info` failed: {detail}\n\n\
                     This is the classic \"user not in the docker group\" error. Fix with:\n  \
                     sudo usermod -aG docker $USER\nthen log out and back in (or run \
                     `newgrp docker` in this shell) — no need to use sudo for `cargo-unikernel` itself."
                );
            }
            bail!("`docker info` failed: {detail}");
        }
        Err(e) => bail!("failed to run `docker` — is it installed? ({e})"),
    }
}

/// Runs the full reproducible build: `docker build` the pinned toolchain image, generate and
/// run the in-container build script, and collect the resulting artifacts.
///
/// # Errors
///
/// Returns an error if Docker isn't available, the `docker build`/`docker run` invocations
/// fail, or any host-side filesystem operation (creating cache dirs, writing the generated
/// build script) fails.
pub fn run_reproducible_build(
    config: &Config,
    project_dir: &Path,
    app: &AcquiredApp,
) -> Result<BuildArtifacts> {
    check_available()?;

    let project_dir = project_dir
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", project_dir.display()))?;
    let assets_dir = crate::assets::materialize()?;
    let dist_dir = super::host_dist_dir(config, &project_dir);
    std::fs::create_dir_all(&dist_dir)
        .with_context(|| format!("failed to create {}", dist_dir.display()))?;

    print_toolchain_overrides(&config.toolchain);

    let image_tag = build_toolchain_image(config, &assets_dir)?;

    // Internal orchestration artifacts (the generated build script, the extra-Kconfig
    // fragment) live under the host cache dir, never inside the user's own `dist/` — that
    // directory should only ever contain the actual build outputs the user asked for.
    let cache_root = cache_root();
    let last_build_dir = cache_root.join("last-build");
    let script_path = write_build_script(config, app, &last_build_dir)?;

    run_build_container(
        image_tag,
        &project_dir,
        &assets_dir,
        &cache_root,
        &last_build_dir,
        &script_path,
    )?;

    collect_artifacts(config, &dist_dir, &last_build_dir)
}

/// `docker build`s the pinned reproducible-toolchain image, returning its tag.
fn build_toolchain_image(config: &Config, assets_dir: &Path) -> Result<&'static str> {
    let image_tag = "cargo-unikernel-builder";
    let mut build_cmd = Command::new("docker");
    build_cmd.args(["build", "--network", "host"]);
    for (name, value) in build_args_for(&config.toolchain)? {
        build_cmd.arg("--build-arg").arg(format!("{name}={value}"));
    }
    let status = build_cmd
        .args(["-t", image_tag, "-f"])
        .arg(assets_dir.join("build/docker/Dockerfile.reproducible"))
        .arg(assets_dir.join("build"))
        .status()
        .context("failed to run `docker build`")?;
    if !status.success() {
        bail!("docker build failed");
    }
    Ok(image_tag)
}

/// Generates the in-container build script (and, if configured, the extra-Kconfig fragment
/// it references) under `last_build_dir`, returning the script's host path.
fn write_build_script(
    config: &Config,
    app: &AcquiredApp,
    last_build_dir: &Path,
) -> Result<PathBuf> {
    let generated_dir = last_build_dir.join("generated");
    std::fs::create_dir_all(&generated_dir)
        .with_context(|| format!("failed to create {}", generated_dir.display()))?;

    if !config.hardening.extra_kernel_config.is_empty() {
        let extra_kconfig_path = generated_dir.join("extra-kconfig.config");
        std::fs::write(
            &extra_kconfig_path,
            config.hardening.extra_kernel_config.join("\n") + "\n",
        )
        .with_context(|| format!("failed to write {}", extra_kconfig_path.display()))?;
    }

    let script = generate_build_script(config, app)?;
    let script_path = last_build_dir.join("build.sh");
    std::fs::write(&script_path, &script)
        .with_context(|| format!("failed to write {}", script_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(script_path)
}

/// Creates the host cache directories bind-mounted into the container, then runs the
/// generated build script inside `image_tag` via `docker run`.
fn run_build_container(
    image_tag: &str,
    project_dir: &Path,
    assets_dir: &Path,
    cache_root: &Path,
    last_build_dir: &Path,
    script_path: &Path,
) -> Result<()> {
    let mounts = [
        (project_dir.to_path_buf(), "/workspace", false),
        (assets_dir.join("build"), "/assets", true),
        (assets_dir.join("guest"), "/assets-guest", true),
        (last_build_dir.to_path_buf(), "/build-meta", false),
        (cache_root.join("kernel-build"), "/build", false),
        (cache_root.join("ccache"), "/root/.cache/ccache", false),
        (
            cache_root.join("cargo/registry"),
            "/root/.cargo/registry",
            false,
        ),
        (cache_root.join("cargo/git"), "/root/.cargo/git", false),
        (cache_root.join("target"), "/tmp/cargo-target", false),
    ];
    // Only the cache_root subdirs need creating here — /workspace, the assets dirs, and
    // last_build_dir already exist by this point (canonicalized project dir,
    // `assets::materialize()`, and `write_build_script`'s `generated/` subdir, respectively).
    for (host, _, _) in &mounts[4..] {
        std::fs::create_dir_all(host)?;
    }

    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--network", "host"]);
    // The container builds as root, so files it writes into the bind-mounted host cache
    // dirs come out root-owned — harmless locally, but breaks GitHub Actions' `actions/cache`
    // save step, which runs as the unprivileged runner user. Pass the host uid/gid in so the
    // in-container script can chown the cache back at the end. Best-effort: if `id` isn't
    // available, the build still succeeds, just leaves the cache root-owned.
    if let Some((uid, gid)) = host_uid_gid() {
        cmd.arg("-e").arg(format!("{HOST_UID_VAR}={uid}"));
        cmd.arg("-e").arg(format!("{HOST_GID_VAR}={gid}"));
    }
    for (host, container, read_only) in &mounts {
        let suffix = if *read_only { ":ro" } else { "" };
        cmd.arg("-v")
            .arg(format!("{}:{container}{suffix}", host.display()));
    }
    let status = cmd
        .args(["-w", "/workspace"])
        .arg(image_tag)
        .arg("/bin/bash")
        .arg("/build-meta/build.sh")
        .status()
        .context("failed to run build container")?;
    if !status.success() {
        bail!(
            "in-container build failed — see output above (generated script kept at {} for debugging)",
            script_path.display()
        );
    }
    Ok(())
}

/// Confirms the required artifacts landed in `dist_dir` and assembles the `BuildArtifacts`
/// (including each component's sha256) the rest of the pipeline consumes.
fn collect_artifacts(
    config: &Config,
    dist_dir: &Path,
    last_build_dir: &Path,
) -> Result<BuildArtifacts> {
    let name = &config.project.name;
    // bzImage/cpio are always built (every other format is assembled from them), but only
    // land in dist_dir when `cpio` was actually requested as an output format — otherwise
    // they stay staged under last_build_dir (the host side of /build-meta). See
    // script_rootfs_and_images.
    let (bzimage, cpio) = if config.output.formats.contains(&OutputFormat::Cpio) {
        (
            dist_dir.join(format!("{name}.bzImage")),
            dist_dir.join(format!("{name}.cpio")),
        )
    } else {
        (
            last_build_dir.join(format!("{name}.bzImage")),
            last_build_dir.join(format!("{name}.cpio")),
        )
    };
    let iso = dist_dir.join(format!("{name}.iso"));
    let uki = dist_dir.join(format!("{name}.efi"));
    let binary = dist_dir.join(format!("{name}.bin"));
    let measurement = dist_dir.join("sev_measurement.txt");

    for required in [&bzimage, &cpio] {
        if !required.exists() {
            bail!(
                "expected build artifact {} was not produced by the container script",
                required.display()
            );
        }
    }

    let component_hashes = ComponentHashes {
        kernel_sha256: Some(sha256_hex_of_file(&bzimage)?),
        cpio_sha256: Some(sha256_hex_of_file(&cpio)?),
        // Written in-container (script_rootfs_and_images/script_sev_snp_measurement) since
        // the raw app/guest-init binaries, and (for `preset`) the OVMF firmware, never
        // otherwise reach the host as standalone files — only read_to_string, not
        // sha256_hex_of_file, since these already *are* hex digests, not raw binaries.
        app_sha256: read_hash_file(&last_build_dir.join("app.sha256")),
        guest_init_sha256: read_hash_file(&last_build_dir.join("guest-init.sha256")),
        ovmf_sha256: read_hash_file(&last_build_dir.join("ovmf.sha256")),
    };

    Ok(BuildArtifacts {
        bzimage,
        cpio,
        iso: iso.exists().then_some(iso),
        uki: uki.exists().then_some(uki),
        binary: binary.exists().then_some(binary),
        sev_measurement: measurement.exists().then_some(measurement),
        component_hashes,
    })
}

/// Builds the bash script that runs *inside* the container. Kept as a single generated
/// script (rather than several Rust-orchestrated `docker exec` calls) so the whole build is
/// one auditable, reproducible unit. Split into one function per build stage purely for
/// readability — each returns the script fragment for its stage, concatenated in order here.
fn generate_build_script(config: &Config, app: &AcquiredApp) -> Result<String> {
    let mut s = String::new();
    s.push_str("#!/bin/bash\nset -euo pipefail\n\n");
    // The reproducible-builds.org standard knob, fixed once here so every stage sees the
    // same value instead of each tool falling back to "now" independently.
    s.push_str("export SOURCE_DATE_EPOCH=0\n");
    // Blocks the `ext::<command>` transport (arbitrary command execution via a crafted
    // "URL") for the sev-snp-measure.py clone below — defense-in-depth even though that URL
    // is fixed, not config-controlled.
    s.push_str("export GIT_ALLOW_PROTOCOL=file:git:http:https:ssh\n");
    // All kernel-build/rootfs-assembly scratch work happens in /build, so the user's own
    // project directory (/workspace) only ever gains a dist/ output folder.
    s.push_str("mkdir -p /build\ncd /build\n\n");

    s.push_str(&script_kernel_build(config));
    s.push_str(&script_app_build(config, app)?);
    s.push_str(&script_guest_init_build(config));
    s.push_str(&script_rootfs_and_images(config));
    s.push_str(&script_sev_snp_measurement(config));
    s.push_str(&script_reclaim_cache_ownership());
    Ok(s)
}

/// Final stage: hand the host cache directories (kernel-build, ccache, cargo registry/git,
/// cargo target, and the generated-build-script dir) back to the invoking host user. Only
/// runs if `run_reproducible_build` could determine that user's uid/gid — see the comment
/// at its `docker run` call site for why this exists (root-owned files otherwise break
/// `actions/cache` in CI). Never fails the build: `|| true` on a best-effort cleanup step.
fn script_reclaim_cache_ownership() -> String {
    format!(
        "\nif [ -n \"${{{HOST_UID_VAR}:-}}\" ] && [ -n \"${{{HOST_GID_VAR}:-}}\" ]; then\n\
         \x20   chown -R \"${HOST_UID_VAR}:${HOST_GID_VAR}\" \
         /build /build-meta /root/.cache/ccache /root/.cargo/registry /root/.cargo/git \
         /tmp/cargo-target 2>/dev/null || true\n\
         fi\n"
    )
}

/// `~/.cache/cargo-unikernel` (or `/tmp/cargo-unikernel-cache` if `$HOME` isn't set).
#[must_use]
pub fn cache_root() -> PathBuf {
    std::env::var("HOME").map_or_else(
        |_| PathBuf::from("/tmp/cargo-unikernel-cache"),
        |h| PathBuf::from(h).join(".cache/cargo-unikernel"),
    )
}

/// Shared `#[cfg(test)]` fixture builders used by more than one build-stage submodule's test
/// block, kept in one place instead of duplicated per submodule.
#[cfg(test)]
pub mod test_fixtures {
    use crate::schema::{AppSource, Config, OutputFormat, ProfileKind, Toolchain, ToolchainPins};

    /// A minimal valid `[app.source]` for `toolchain = "rust"`.
    #[must_use]
    pub fn rust_source() -> AppSource {
        AppSource {
            path: Some(".".to_string()),
            toolchain: Toolchain::Rust,
            package_path: ".".to_string(),
            cargo_profile: "release".to_string(),
            features: Vec::new(),
            build_command: None,
            output_binary: None,
            extra_apt_packages: Vec::new(),
        }
    }

    /// A minimal valid `[app.source]` for `toolchain = "generic"` (a stubbed Go build).
    #[must_use]
    pub fn generic_source() -> AppSource {
        AppSource {
            path: Some(".".to_string()),
            toolchain: Toolchain::Generic,
            package_path: ".".to_string(),
            cargo_profile: "release".to_string(),
            features: Vec::new(),
            build_command: Some("go build -o app .".to_string()),
            output_binary: Some("app".to_string()),
            extra_apt_packages: vec!["golang".to_string()],
        }
    }

    /// A minimal valid casual-profile `Config` requesting the given output `formats`.
    #[must_use]
    pub fn casual_config_with_formats(formats: Vec<OutputFormat>) -> Config {
        use crate::schema::{
            App, AppMode, AppRuntime, Hardening, Kernel, Network, Output, Profile, Project,
            Release, Storage,
        };
        Config {
            project: Project {
                name: "test-app".to_string(),
                cargo_unikernel_version: None,
            },
            profile: Profile {
                kind: ProfileKind::Casual,
            },
            app: App {
                mode: AppMode::Source,
                source: Some(rust_source()),
                binary: None,
                runtime: AppRuntime::default(),
            },
            network: Network::default(),
            storage: Storage::default(),
            kernel: Kernel::default(),
            toolchain: ToolchainPins::default(),
            hardening: Hardening::default(),
            sev_snp: None,
            output: Output {
                formats,
                dir: "dist/".to_string(),
            },
            release: Release::default(),
        }
    }

    /// A minimal valid sev-snp-profile `Config` requesting the given output `formats`.
    #[must_use]
    pub fn sev_snp_config_with_formats(formats: Vec<OutputFormat>) -> Config {
        use crate::schema::{OvmfSource, SevSnp};
        let mut config = casual_config_with_formats(formats);
        config.profile.kind = ProfileKind::SevSnp;
        config.project.cargo_unikernel_version = Some(crate::schema::CLI_VERSION.to_string());
        config.sev_snp = Some(SevSnp {
            vcpus: 2,
            vcpu_type: "EPYC-v3".to_string(),
            kernel_cmdline: "console=ttyS0".to_string(),
            ovmf: OvmfSource {
                preset: Some("builtin".to_string()),
                path: None,
            },
            measured_boot: None,
        });
        config
    }
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::test_fixtures::*;
    use super::*;
    use crate::schema::OutputFormat;

    #[test]
    fn build_script_restricts_git_transport_protocols() {
        // Blocks the `ext::<command>` transport (arbitrary command execution via a crafted
        // "URL") for every git invocation in the generated script, including the pinned
        // sev-snp-measure.py clone.
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let app = AcquiredApp::LocalSource {
            package_path: ".".to_string(),
        };
        let script = generate_build_script(&config, &app).unwrap();
        assert!(script.contains("export GIT_ALLOW_PROTOCOL=file:git:http:https:ssh"));
    }

    #[test]
    fn full_build_script_pins_source_date_epoch_up_front() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let app = AcquiredApp::LocalSource {
            package_path: ".".to_string(),
        };
        let script = generate_build_script(&config, &app).unwrap();
        let epoch_pos = script.find("export SOURCE_DATE_EPOCH=0").unwrap();
        let kernel_pos = script.find("build_kernel.sh").unwrap();
        assert!(epoch_pos < kernel_pos);
    }

    #[test]
    fn reclaim_cache_ownership_stage_is_conditional_and_best_effort() {
        // Every file the container writes into the bind-mounted host cache dirs comes out
        // owned by root (the container always builds as root); without this stage those
        // dirs become unreadable by an unprivileged CI user later (e.g. `actions/cache`'s
        // save step failing with "Permission denied" on a root-owned kernel-build file).
        let script = script_reclaim_cache_ownership();
        assert!(script.contains("chown -R"));
        assert!(script.contains("CARGO_UNIKERNEL_HOST_UID"));
        assert!(script.contains("CARGO_UNIKERNEL_HOST_GID"));
        // Must never fail the overall build if chown itself fails for some reason.
        assert!(script.contains("|| true"));
        // And must be skipped entirely if the host uid/gid couldn't be determined.
        assert!(script.trim_start().starts_with("if [ -n"));
    }

    #[test]
    fn app_binary_is_checked_for_dynamic_linking_before_guest_init_builds() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let app = AcquiredApp::LocalSource {
            package_path: ".".to_string(),
        };
        let script = generate_build_script(&config, &app).unwrap();
        let static_check_pos = script
            .find("readelf -l \"$APP_BIN\"")
            .expect("static-link check must run");
        let guest_init_build_pos = script
            .find("--manifest-path /assets-guest/Cargo.toml")
            .expect("guest init must be built");
        assert!(static_check_pos < guest_init_build_pos);
        // Must actually abort the build, not just warn.
        assert!(script.contains("exit 1"));
        // Checks both signals of dynamic linking: a PT_INTERP segment (needs a dynamic
        // linker at all) and any DT_NEEDED entries (specific shared libraries required).
        assert!(script.contains("NEEDED"));
    }

    #[test]
    fn static_link_check_applies_to_prebuilt_binary_mode_too() {
        // Mode B (bring-your-own-binary) must get the same check as a source build — a
        // dynamically-linked binary the user supplies directly is just as unbootable.
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let app = AcquiredApp::Binary(std::path::PathBuf::from("/workspace/app.bin"));
        let script = generate_build_script(&config, &app).unwrap();
        assert!(script.contains("readelf -l \"$APP_BIN\""));
    }

    #[test]
    fn full_build_script_ends_with_cache_ownership_reclaim() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let app = AcquiredApp::LocalSource {
            package_path: ".".to_string(),
        };
        let script = generate_build_script(&config, &app).unwrap();
        let chown_pos = script
            .find("chown -R")
            .expect("chown stage must be present");
        // Must run last, after rootfs assembly/image generation/measurement — chowning
        // /build before those steps finish would just get re-rooted by the next `cp`/`make`.
        assert!(chown_pos > script.rfind("cpio -o -H newc").unwrap());
    }
}
