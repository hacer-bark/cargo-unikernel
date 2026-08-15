#![forbid(unsafe_code, elided_lifetimes_in_paths)]
#![allow(clippy::multiple_crate_versions)]

//! `cargo-unikernel`'s implementation.
//!
//! Split out from `main.rs` into a library target so the CLI's own module tree can use
//! ordinary `pub` visibility for cross-module items: as a `--bin`-only crate, nothing is ever
//! externally reachable, which puts rustc's `unreachable_pub` and clippy's
//! `redundant_pub_crate` in permanent conflict over anything wider than module-private. With
//! a lib+bin split, the bin is a genuine external consumer of this crate, so `pub` here is
//! real API surface rather than a lint contradiction.

pub mod assets;
pub mod cli;
pub mod config;
pub mod doctor;
pub mod github;
pub mod hex;
pub mod pipeline;
pub mod release;
pub mod schema;

use anyhow::{Context, Result, bail};
use clap::Parser;
use cli::{Cli, Command, GithubCommand};
use config::BuildOverrides;
use schema::ProfileKind;

/// Runs the CLI end to end: parses arguments (including the `cargo unikernel ...` shim, see
/// below) and dispatches to the matching subcommand.
///
/// # Errors
///
/// Returns an error if the requested subcommand fails — an invalid config, a build pipeline
/// failure, a missing host toolchain, and so on. See each subcommand's own module for specifics.
pub fn run() -> Result<()> {
    // The binary is named `cargo-unikernel` so Cargo itself picks it up as an external
    // subcommand: `cargo unikernel build` execs this binary as `cargo-unikernel unikernel
    // build` (Cargo passes the subcommand name through as argv[1], it doesn't strip it —
    // same reason `cargo-clippy` and other Cargo plugins do this same shim). Drop it so
    // `cargo unikernel build` and running this binary directly as `cargo-unikernel build`
    // parse identically.
    let mut args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "unikernel") {
        args.remove(1);
    }
    let cli = Cli::parse_from(args);

    match cli.command {
        Command::Init { profile, path } => {
            let dir = path.unwrap_or_else(|| ".".into());
            config::scaffold(profile, &dir)?;
        }
        Command::Build {
            config: config_path,
            binary,
            format,
            profile,
            vcpus,
            vcpu_type,
        } => {
            let (loaded, project_dir) = config::resolve_for_build(config_path, binary)?;
            let overrides = BuildOverrides {
                format,
                profile,
                vcpus,
                vcpu_type,
            };
            let final_config = config::apply_overrides(loaded, overrides)?;
            pipeline::build(&final_config, &project_dir)?;
        }
        Command::Measure {
            config: config_path,
        } => {
            let project_dir = config_path
                .parent()
                .map(std::path::Path::to_path_buf)
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| ".".into());
            let loaded = config::load(&config_path)?;
            if loaded.profile.kind != ProfileKind::SevSnp {
                bail!("`cargo-unikernel measure` only applies to profile.kind = \"sev-snp\"");
            }
            let dist = project_dir.join(loaded.output.dir.trim_end_matches('/'));
            let bzimage = dist.join(format!("{}.bzImage", loaded.project.name));
            let cpio = dist.join(format!("{}.cpio", loaded.project.name));
            if !bzimage.exists() || !cpio.exists() {
                bail!(
                    "no existing build artifacts found in {} — run `cargo-unikernel build` first",
                    dist.display()
                );
            }
            // Best-effort: the per-component hash files only exist under the build cache
            // (~/.cache/cargo-unikernel/last-build/), which may have since been cleared or
            // belong to a different build than these artifacts — `read_hash_file` returns
            // `None` rather than erroring if they're missing or stale-looking.
            let last_build_dir = pipeline::docker::cache_root().join("last-build");
            let component_hashes = pipeline::docker::ComponentHashes {
                kernel_sha256: pipeline::docker::sha256_hex_of_file(&bzimage).ok(),
                cpio_sha256: pipeline::docker::sha256_hex_of_file(&cpio).ok(),
                app_sha256: pipeline::docker::read_hash_file(&last_build_dir.join("app.sha256")),
                guest_init_sha256: pipeline::docker::read_hash_file(
                    &last_build_dir.join("guest-init.sha256"),
                ),
                ovmf_sha256: pipeline::docker::read_hash_file(&last_build_dir.join("ovmf.sha256")),
            };
            let artifacts = pipeline::docker::BuildArtifacts {
                bzimage,
                cpio,
                iso: None,
                uki: None,
                binary: None,
                sev_measurement: Some(dist.join("sev_measurement.txt")),
                component_hashes,
            };
            let m = pipeline::measurement::compute(&loaded, &project_dir, &artifacts)?;
            println!("{}", m.hex);
        }
        Command::Doctor => doctor::run()?,
        Command::Github {
            command:
                GithubCommand::Init {
                    config,
                    attest_provenance,
                },
        } => github::init(&config, attest_provenance)?,
        Command::Release {
            config: config_path,
            tag,
            no_build,
        } => {
            let (loaded, project_dir) = config::resolve_for_build(config_path, None)?;
            release::run(&loaded, &project_dir, tag, no_build).with_context(|| "release failed")?;
        }
    }

    Ok(())
}
