//! CLI argument parsing (`clap`).

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Top-level CLI parser.
#[derive(Parser, Debug)]
#[command(
    name = "cargo-unikernel",
    version,
    about = "Turn a Rust project, another language's static build, or a pre-built binary into a minimal, hardened bootable unikernel image"
)]
pub struct Cli {
    /// Which subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scaffold a Cargo-Unikernel.toml (optional — `build` works with zero config too)
    Init {
        /// Which profile to scaffold: `casual` or `sev-snp`.
        #[arg(long, value_enum, default_value = "casual")]
        profile: ProfileArg,
        /// Directory to scaffold into (defaults to the current directory)
        path: Option<PathBuf>,
    },
    /// Build a unikernel image. With no config file present, auto-detects the current
    /// directory: a Cargo project is compiled directly (no config needed at all); otherwise
    /// pass `--binary <path>` to embed an existing binary.
    Build {
        /// Path to Cargo-Unikernel.toml. If omitted, looks for ./Cargo-Unikernel.toml (or
        /// the legacy ./cargo-unikernel.toml), and falls back to zero-config auto-detection
        /// if neither exists.
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Zero-config only: embed this pre-built binary instead of compiling the cwd.
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Comma-separated override of output.formats, e.g. cpio,iso,uki,binary
        #[arg(long, value_delimiter = ',')]
        format: Option<Vec<String>>,
        /// Override `profile.kind`.
        #[arg(long, value_enum)]
        profile: Option<ProfileArg>,
        /// Override `sev_snp.vcpus`.
        #[arg(long)]
        vcpus: Option<u32>,
        /// Override `sev_snp.vcpu_type`.
        #[arg(long)]
        vcpu_type: Option<String>,
    },
    /// Recompute the SEV-SNP measurement from already-built artifacts (sev-snp profile only)
    Measure {
        /// Path to Cargo-Unikernel.toml. If omitted, looks for ./Cargo-Unikernel.toml, then
        /// falls back to the legacy ./cargo-unikernel.toml.
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Check the host toolchain needed to build (Docker, git, gh)
    Doctor,
    /// Manage the GitHub Actions release pipeline for this project
    Github {
        /// Which `github` subcommand to run.
        #[command(subcommand)]
        command: GithubCommand,
    },
    /// Build (if needed) and publish a GitHub release with the built artifacts, via `gh`
    Release {
        /// Path to Cargo-Unikernel.toml.
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Tag for the release (e.g. v1.0.0). Defaults to the current HEAD's short SHA.
        #[arg(long)]
        tag: Option<String>,
        /// Skip building — publish whatever is already in dist/
        #[arg(long)]
        no_build: bool,
    },
}

/// `cargo unikernel github` subcommands.
#[derive(Subcommand, Debug)]
pub enum GithubCommand {
    /// Write .github/workflows/cargo-unikernel.yml, which builds and publishes a release
    /// on every tag push using this project's Cargo-Unikernel.toml.
    Init {
        /// Path to Cargo-Unikernel.toml the generated workflow will pass via `--config`. If
        /// omitted, looks for ./Cargo-Unikernel.toml, then falls back to the legacy
        /// ./cargo-unikernel.toml.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Also add a GitHub build-provenance attestation step for the published dist/
        /// artifacts — a Sigstore-backed proof of exactly which workflow run/commit produced
        /// them. Off by default: it requires granting the workflow `id-token: write`/
        /// `attestations: write`.
        #[arg(long)]
        attest_provenance: bool,
    },
}

/// `--profile` CLI value, mirroring `schema::ProfileKind`.
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ProfileArg {
    /// The default, no-frills profile.
    Casual,
    /// AMD SEV-SNP confidential computing.
    SevSnp,
}
