//! `cargo-unikernel doctor` — checks the host toolchain (Docker, git, gh).

use anyhow::Result;

/// Checks the host toolchain needed to build: Docker, `git`, `gh`. Prints one `[ok]`/`[MISS]`
/// line per tool and returns an error if any are missing.
///
/// # Errors
///
/// Returns an error (after printing the full checklist) if any required tool is missing.
pub fn run() -> Result<()> {
    let mut ok = true;

    match crate::pipeline::docker::check_available() {
        Ok(()) => println!("[ok]   docker"),
        Err(e) => {
            println!("[MISS] docker — {e}");
            ok = false;
        }
    }
    check("git", &["git", "--version"], &mut ok);
    let mut gh_ok = true;
    check(
        "gh (optional, for `cargo-unikernel release`)",
        &["gh", "--version"],
        &mut gh_ok,
    );

    let assets_dir = crate::assets::materialize()?;
    println!(
        "\nEmbedded build assets + guest source materialized to: {}",
        assets_dir.display()
    );
    println!(
        "Runtime sysctl hardening table lives at: {}",
        assets_dir
            .join("guest/cargo-unikernel-common/src/hardening.rs")
            .display()
    );

    if !ok {
        anyhow::bail!("one or more required host tools are missing — see above");
    }
    println!(
        "\nDocker + git (+ gh, for `cargo-unikernel release`) are all this host needs — \
         cpio/xorriso/ukify/sev-snp-measure.py run inside the pinned build container."
    );
    Ok(())
}

fn check(name: &str, cmd: &[&str], ok: &mut bool) {
    let found = std::process::Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .is_ok_and(|o| o.status.success());
    if found {
        println!("[ok]   {name}");
    } else {
        println!("[MISS] {name}");
        *ok = false;
    }
}
