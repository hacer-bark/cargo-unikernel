use super::cmdline::cmdline_for;
use super::helpers::{in_container_dist, shell_quote};
use crate::schema::{Config, OutputFormat, StorageMode};
use std::fmt::Write as _;

/// Stage 4: assemble the reproducible rootfs (`cargo-unikernel-init` as `/init`, the app as
/// `/payload/app`, zeroed timestamps) into a cpio, copy out the kernel, then produce every
/// other requested output format from those two artifacts.
pub(super) fn script_rootfs_and_images(config: &Config) -> String {
    let mut s = String::new();
    s.push_str(
        "\nrm -rf /build/rootfs && mkdir -p /build/rootfs/proc /build/rootfs/sys \
         /build/rootfs/dev /build/rootfs/tmp /build/rootfs/run /build/rootfs/payload\n",
    );
    s.push_str(
        "cp /tmp/cargo-target/x86_64-unknown-linux-musl/release/cargo-unikernel-init \
         /build/rootfs/init\n",
    );
    s.push_str("cp \"$APP_BIN\" /build/rootfs/payload/app\n");

    if config.storage.mode == StorageMode::Persistent {
        // Only bundled when actually needed — a RAM-mode image has no use for it.
        s.push_str(
            "mkdir -p /build/rootfs/sbin && cp /opt/e2fsprogs/sbin/mke2fs /build/rootfs/sbin/mke2fs\n",
        );
    }

    // Hashes of the two binaries that actually go into the image, taken before they're
    // packed into the cpio — read back host-side (via /build-meta, the last-build cache dir
    // bind mount) and recorded in sev_measurement.json, so a measurement mismatch between
    // two builds can be narrowed down to "the app changed" vs. "cargo-unikernel-init
    // changed" vs. "the kernel changed" instead of just "the final hash differs."
    s.push_str("sha256sum /build/rootfs/init | cut -d' ' -f1 > /build-meta/guest-init.sha256\n");
    s.push_str("sha256sum /build/rootfs/payload/app | cut -d' ' -f1 > /build-meta/app.sha256\n");
    // Explicit, not inherited from whatever `cp`/`cargo` happened to leave the source file
    // at — mode bits go into the cpio archive same as content does, so leaving them
    // implicit is one more thing that could (in principle) vary by build environment.
    s.push_str("chmod 555 /build/rootfs/init /build/rootfs/payload/app\n");
    if config.storage.mode == StorageMode::Persistent {
        s.push_str("chmod 555 /build/rootfs/sbin/mke2fs\n");
    }
    s.push_str("find /build/rootfs -type d -exec chmod 755 {} +\n");
    s.push_str("find /build/rootfs -exec touch -h -d @0 {} +\n");

    let dist_q = shell_quote(&in_container_dist(config));
    let _ = writeln!(s, "mkdir -p {dist_q}");
    let name = &config.project.name;
    let name_q = shell_quote(name);
    let _ = writeln!(
        s,
        "(cd /build/rootfs && find . -mindepth 1 | LC_ALL=C sort | cpio -o -H newc -R 0:0 --reproducible) > /build-meta/{name_q}.cpio"
    );
    let _ = writeln!(
        s,
        "cp /build/linux-kernel/arch/x86/boot/bzImage /build-meta/{name_q}.bzImage"
    );

    for format in &config.output.formats {
        match format {
            OutputFormat::Cpio => {
                let _ = writeln!(
                    s,
                    "cp /build-meta/{name_q}.cpio {dist_q}/{name_q}.cpio && \
                     cp /build-meta/{name_q}.bzImage {dist_q}/{name_q}.bzImage"
                );
            }
            OutputFormat::Binary => {
                let _ = writeln!(
                    s,
                    "cp \"$APP_BIN\" {dist_q}/{name_q}.bin && chmod 555 {dist_q}/{name_q}.bin"
                );
            }
            OutputFormat::Iso => {
                let cmdline_q = shell_quote(&cmdline_for(config));
                let _ = writeln!(
                    s,
                    "/assets/scripts/make_iso.sh /build-meta/{name_q}.bzImage \
                     /build-meta/{name_q}.cpio {dist_q}/{name_q}.iso {cmdline_q}"
                );
            }
            OutputFormat::Uki => {
                let cmdline_q = shell_quote(&cmdline_for(config));
                let uname_q = shell_quote(&config.kernel.version);
                let _ = writeln!(
                    s,
                    "PYTHONHASHSEED=0 ukify build --linux=/build-meta/{name_q}.bzImage \
                     --initrd=/build-meta/{name_q}.cpio --cmdline={cmdline_q} --uname={uname_q} \
                     --output={dist_q}/{name_q}.efi"
                );
            }
        }
    }
    s
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::cmdline::cmdline_for;
    use super::super::test_fixtures::*;
    use super::*;

    #[test]
    fn ram_mode_does_not_bundle_mke2fs() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_rootfs_and_images(&config);
        assert!(!script.contains("mke2fs"));
    }

    #[test]
    fn persistent_mode_bundles_and_chmods_mke2fs() {
        let mut config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        config.storage.mode = StorageMode::Persistent;
        let script = script_rootfs_and_images(&config);
        assert!(script.contains("cp /opt/e2fsprogs/sbin/mke2fs /build/rootfs/sbin/mke2fs"));
        assert!(script.contains("chmod 555 /build/rootfs/sbin/mke2fs"));
    }

    #[test]
    fn iso_build_passes_the_actual_cmdline_not_the_script_default() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio, OutputFormat::Iso]);
        let script = script_rootfs_and_images(&config);
        assert!(script.contains("make_iso.sh"));
        assert!(script.contains("'/workspace/dist'/'test-app'.iso"));
        assert!(script.contains(&shell_quote(&cmdline_for(&config))));
    }

    #[test]
    fn uki_build_uses_same_cmdline_as_iso() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio, OutputFormat::Uki]);
        let script = script_rootfs_and_images(&config);
        assert!(script.contains(&format!("--cmdline={}", shell_quote(&cmdline_for(&config)))));
    }

    #[test]
    fn uki_build_pins_python_hash_seed() {
        // ukify is a Python tool; without a fixed PYTHONHASHSEED, string-keyed dict/set
        // iteration order in its section-assembly code is randomized per process, which
        // could reorder bytes in the assembled .efi across otherwise-identical builds.
        let config = casual_config_with_formats(vec![OutputFormat::Cpio, OutputFormat::Uki]);
        let script = script_rootfs_and_images(&config);
        assert!(script.contains("PYTHONHASHSEED=0 ukify build"));
    }

    #[test]
    fn binary_format_copies_app_bin_to_dist() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio, OutputFormat::Binary]);
        let script = script_rootfs_and_images(&config);
        assert!(script.contains("cp \"$APP_BIN\" '/workspace/dist'/'test-app'.bin"));
    }

    #[test]
    fn uki_only_build_does_not_copy_cpio_or_bzimage_into_dist() {
        // bzImage/cpio are always assembled (uki is built from them), but they're
        // intermediate inputs, not a requested output — they should stay staged under
        // `/build-meta` and never reach `dist/` unless `cpio` is itself in `output.formats`.
        let config = casual_config_with_formats(vec![OutputFormat::Uki]);
        let script = script_rootfs_and_images(&config);
        assert!(script.contains("/build-meta/'test-app'.cpio"));
        assert!(script.contains("/build-meta/'test-app'.bzImage"));
        assert!(!script.contains("'/workspace/dist'/'test-app'.cpio"));
        assert!(!script.contains("'/workspace/dist'/'test-app'.bzImage"));
    }

    #[test]
    fn cpio_format_copies_staged_cpio_and_bzimage_into_dist() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_rootfs_and_images(&config);
        assert!(script.contains(
            "cp /build-meta/'test-app'.cpio '/workspace/dist'/'test-app'.cpio"
        ));
        assert!(script.contains(
            "cp /build-meta/'test-app'.bzImage '/workspace/dist'/'test-app'.bzImage"
        ));
    }

    #[test]
    fn rootfs_assembly_sets_explicit_mode_on_both_binaries() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_rootfs_and_images(&config);
        assert!(script.contains("chmod 555 /build/rootfs/init /build/rootfs/payload/app"));
    }

    #[test]
    fn rootfs_assembly_records_app_and_guest_init_hashes() {
        // Written before packing so a measurement mismatch across builds can be attributed
        // to a specific component instead of just "the final hash differs" — read back
        // host-side in run_reproducible_build and surfaced in sev_measurement.json.
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_rootfs_and_images(&config);
        assert!(script.contains(
            "sha256sum /build/rootfs/init | cut -d' ' -f1 > /build-meta/guest-init.sha256"
        ));
        assert!(script.contains(
            "sha256sum /build/rootfs/payload/app | cut -d' ' -f1 > /build-meta/app.sha256"
        ));
    }
}
