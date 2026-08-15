use super::helpers::{rustflags_export, shell_quote};
use crate::pipeline::app_source::AcquiredApp;
use crate::schema::{AppSource, Config, Toolchain};
use anyhow::{Context, Result};
use std::fmt::Write as _;

/// Stage 3: build (or stage) the user's app and leave it at `$APP_BIN`. Dispatches on
/// `AcquiredApp` and, for source builds, on `Toolchain`: `Rust` runs `cargo build`;
/// `Generic` runs the user's own `build_command` and expects `output_binary` to exist
/// afterward. Either way the result must be statically linked — the guest has no dynamic
/// linker or libc.
pub(super) fn script_app_build(config: &Config, app: &AcquiredApp) -> Result<String> {
    let mut s = String::new();
    match app {
        AcquiredApp::LocalSource { package_path } => {
            // The user's own project is already mounted at /workspace — build it directly,
            // no clone/copy needed at all.
            let source = config
                .app
                .source
                .as_ref()
                .context("AcquiredApp::LocalSource implies app.source is set")?;
            let package_dir = format!("/workspace/{package_path}");
            s.push_str(&script_build_at(source, &package_dir)?);
        }
        AcquiredApp::Binary(path) => {
            let _ = writeln!(s, "APP_BIN={}", shell_quote(&path.display().to_string()));
        }
    }
    s.push_str(&script_verify_static_binary());
    Ok(s)
}

/// Fails the build, with an actionable error, if `$APP_BIN` needs a dynamic linker or any
/// shared library — the guest rootfs ships neither, so a dynamically-linked binary would
/// otherwise only fail at boot, as an opaque watchdog reboot loop. See `docs/toolchains.md`.
fn script_verify_static_binary() -> String {
    "\n\
if readelf -l \"$APP_BIN\" 2>/dev/null | grep -q 'INTERP' || \
   readelf -d \"$APP_BIN\" 2>/dev/null | grep -q 'NEEDED'; then\n\
    NEEDED=$(readelf -d \"$APP_BIN\" 2>/dev/null | grep NEEDED | sed -E 's/.*\\[(.*)\\].*/  - \\1/')\n\
    echo \"\" >&2\n\
    echo \"======================================================================\" >&2\n\
    echo \"ERROR: app binary is dynamically linked — this image cannot boot it.\" >&2\n\
    echo \"======================================================================\" >&2\n\
    echo \"The unikernel guest ships no dynamic linker and no shared libraries at\" >&2\n\
    echo \"all (only your app binary and a tiny init) — a dynamically-linked app\" >&2\n\
    echo \"would fail to even start after boot.\" >&2\n\
    if [ -n \"$NEEDED\" ]; then\n\
        echo \"\" >&2\n\
        echo \"This binary requires these shared libraries at runtime:\" >&2\n\
        echo \"$NEEDED\" >&2\n\
    fi\n\
    echo \"\" >&2\n\
    echo \"Statically link your app instead, e.g.:\" >&2\n\
    echo \"  Rust:  --target x86_64-unknown-linux-musl (already the default here)\" >&2\n\
    echo \"  Go:    CGO_ENABLED=0 go build\" >&2\n\
    echo \"  C/C++: gcc -static ...\" >&2\n\
    echo \"  Zig:   zig build -Dtarget=x86_64-linux-musl\" >&2\n\
    echo \"If this pulls in OpenSSL specifically, switch to a statically-linked build\" >&2\n\
    echo \"(e.g. a vendored/static openssl-sys feature) or a pure-Rust TLS stack (e.g.\" >&2\n\
    echo \"rustls) — a dynamically-linked OpenSSL cannot be satisfied by this image.\" >&2\n\
    echo \"======================================================================\" >&2\n\
    exit 1\n\
fi\n"
        .to_string()
}

/// Emits the toolchain-specific build for a source app rooted at `package_dir` (a
/// subdirectory of the mounted `/workspace`), leaving the result at `$APP_BIN`. A target dir
/// distinct from `CARGO_TARGET_DIR` (used for `cargo-unikernel-init` above) keeps the two
/// binaries from landing in the same directory, where a `find | head -n1` could
/// non-deterministically pick up the wrong one.
pub(super) fn script_build_at(source: &AppSource, package_dir: &str) -> Result<String> {
    let mut s = String::new();
    let package_dir_q = shell_quote(package_dir);
    match source.toolchain {
        Toolchain::Rust => {
            s.push_str(&rustflags_export());
            let features_flag = if source.features.is_empty() {
                String::new()
            } else {
                format!(" --features {}", shell_quote(&source.features.join(",")))
            };
            let _ = writeln!(
                s,
                "CARGO_TARGET_DIR=/tmp/cargo-target-app cargo build --locked --profile {} \
                 --target x86_64-unknown-linux-musl{features_flag} \
                 --manifest-path {package_dir_q}/Cargo.toml",
                shell_quote(&source.cargo_profile)
            );
            // `sort` before `head -n1`: if the crate happens to define more than one
            // `[[bin]]` target, `find`'s own enumeration order is filesystem/directory-
            // entry order, not anything stable — sorting at least makes "which one we pick"
            // a function of the names involved, not of the build environment's directory
            // iteration order.
            let _ = writeln!(
                s,
                "APP_BIN=$(find /tmp/cargo-target-app/x86_64-unknown-linux-musl/{} \
                 -maxdepth 1 -type f -executable | sort | head -n1)",
                profile_dir(&source.cargo_profile)
            );
        }
        Toolchain::Generic => {
            if !source.extra_apt_packages.is_empty() {
                let packages = source
                    .extra_apt_packages
                    .iter()
                    .map(|p| shell_quote(p))
                    .collect::<Vec<_>>()
                    .join(" ");
                let _ = writeln!(s, "apt-get update && apt-get install -y {packages}");
            }
            let build_command = source
                .build_command
                .as_ref()
                .context("validated: generic toolchain requires build_command")?;
            let output_binary = source
                .output_binary
                .as_ref()
                .context("validated: generic toolchain requires output_binary")?;
            // `build_command` is deliberately NOT shell-quoted — it's meant to run as raw
            // shell (that's the whole point of the generic toolchain), so it's the one
            // field in this function that keeps its existing bare interpolation.
            let _ = writeln!(s, "(cd {package_dir_q} && {build_command})");
            let _ = writeln!(s, "APP_BIN={package_dir_q}/{}", shell_quote(output_binary));
        }
    }
    Ok(s)
}

/// Cargo puts `dev`-profile artifacts under `target/debug` (a historical quirk) but every
/// other profile — including custom ones — under `target/<profile-name>` verbatim.
fn profile_dir(cargo_profile: &str) -> &str {
    if cargo_profile == "dev" {
        "debug"
    } else {
        cargo_profile
    }
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::test_fixtures::*;
    use super::*;

    #[test]
    fn rust_toolchain_emits_cargo_build() {
        let script = script_build_at(&rust_source(), "/workspace").unwrap();
        assert!(script.contains("cargo build --locked --profile 'release'"));
        assert!(script.contains("--manifest-path '/workspace'/Cargo.toml"));
        assert!(!script.contains("apt-get"));
    }

    #[test]
    fn rust_toolchain_pins_codegen_units_for_reproducibility() {
        // Parallel codegen units make final section/symbol order depend on which LLVM
        // codegen thread finishes first — genuine run-to-run nondeterminism on identical
        // source, which is exactly what silently changed dist/<name>.cpio's hash across
        // rebuilds while bzImage stayed identical. RUSTFLAGS must appear *before* the
        // cargo invocation on its own export line so it's in effect when cargo runs.
        let script = script_build_at(&rust_source(), "/workspace").unwrap();
        let rustflags_pos = script.find("RUSTFLAGS=\"-C codegen-units=1\"").unwrap();
        let cargo_pos = script
            .find("cargo build --locked --profile 'release'")
            .unwrap();
        assert!(rustflags_pos < cargo_pos);
    }

    #[test]
    fn rust_toolchain_passes_configured_features_to_cargo() {
        let mut source = rust_source();
        source.features = vec!["foo".to_string(), "bar".to_string()];
        let script = script_build_at(&source, "/workspace").unwrap();
        assert!(script.contains("--features 'foo,bar'"));
    }

    #[test]
    fn rust_toolchain_omits_features_flag_when_none_configured() {
        let script = script_build_at(&rust_source(), "/workspace").unwrap();
        assert!(!script.contains("--features"));
    }

    #[test]
    fn generic_toolchain_does_not_set_rust_codegen_flags() {
        // The generic toolchain runs the user's own build_command, not cargo — forcing
        // RUSTFLAGS on it would be a no-op at best and a surprising override at worst if
        // their build_command happens to invoke cargo itself for something unrelated.
        let script = script_build_at(&generic_source(), "/workspace").unwrap();
        assert!(!script.contains("codegen-units"));
    }

    #[test]
    fn generic_toolchain_emits_build_command_and_apt_packages() {
        let script = script_build_at(&generic_source(), "/workspace").unwrap();
        assert!(script.contains("apt-get install -y 'golang'"));
        assert!(script.contains("(cd '/workspace' && go build -o app .)"));
        assert!(script.contains("APP_BIN='/workspace'/'app'"));
        assert!(!script.contains("cargo build"));
    }

    #[test]
    fn generic_toolchain_skips_apt_when_no_extra_packages() {
        let mut source = generic_source();
        source.extra_apt_packages.clear();
        let script = script_build_at(&source, "/workspace").unwrap();
        assert!(!script.contains("apt-get"));
    }
}
