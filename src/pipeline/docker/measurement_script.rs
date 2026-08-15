use super::cmdline::cmdline_for;
use super::helpers::{in_container_dist, shell_quote};
use crate::pipeline::ovmf;
use crate::schema::{Config, MeasuredBoot, OutputFormat, ProfileKind};
use std::fmt::Write as _;

/// Stage 5 (sev-snp profile only): compute the launch measurement with `sev-snp-measure.py`,
/// using exactly the vcpu count/type/cmdline the config resolved to.
pub(super) fn script_sev_snp_measurement(config: &Config) -> String {
    let mut s = String::new();
    if config.profile.kind != ProfileKind::SevSnp {
        return s;
    }
    let Some(sev) = &config.sev_snp else {
        return s;
    };
    let dist_q = shell_quote(&in_container_dist(config));
    let name_q = shell_quote(&config.project.name);
    let ovmf_path = ovmf::in_container_path(&sev.ovmf, &config.output.dir);
    let ovmf_path_q = shell_quote(&ovmf_path);
    let vcpu_type_q = shell_quote(&sev.vcpu_type);
    // Not pinned to a commit: sev-snp-measure.py only *predicts* the launch measurement for
    // convenience/verification here — it has no influence on the actual boot image bytes or
    // on the hardware-computed measurement AMD's Secure Processor produces at launch, so
    // there's nothing for a pin to make more reproducible.
    let _ = writeln!(
        s,
        "if [ ! -d /build/sev-snp-measure ]; then git clone --depth 1 \
         https://github.com/virtee/sev-snp-measure.git /build/sev-snp-measure; fi"
    );
    // For `preset`, `ovmf_path` already points at the embedded firmware under `/assets/ovmf`
    // (see `pipeline::ovmf`) — nothing to fetch. Stage it out to dist/.ovmf-cache/OVMF.fd so
    // the host-side run-script has a real path once the container exits.
    let _ = writeln!(
        s,
        "mkdir -p {dist_q}/.ovmf-cache && [ -f {dist_q}/.ovmf-cache/OVMF.fd ] || \
         cp {ovmf_path_q} {dist_q}/.ovmf-cache/OVMF.fd"
    );
    // Providers that direct-boot the UKI itself (via QEMU's fw_cfg SNP_KERNEL_HASHES
    // mechanism — confirmed against Onidel's own launch-measurement docs) hash the whole
    // assembled UKI as a single "kernel" blob, with no separate initrd/cmdline entries since
    // both are already embedded inside it. Without a UKI, the guest boots via the traditional
    // -kernel/-initrd/-append triple, which sev-snp-measure models as three separate inputs —
    // passing the UKI there instead would silently predict a measurement for a boot mode
    // nobody is using. `[sev_snp].measured_boot` overrides the auto-detect from
    // `[output].formats` for providers whose actual boot mode doesn't follow from that alone
    // (`Config::validate` already guarantees `Uki` only appears here when a UKI is produced).
    let use_uki = match sev.measured_boot {
        Some(MeasuredBoot::Uki) => true,
        Some(MeasuredBoot::KernelInitrd) => false,
        None => config.output.formats.contains(&OutputFormat::Uki),
    };
    let kernel_args = if use_uki {
        format!("--kernel={dist_q}/{name_q}.efi")
    } else {
        let cmdline_q = shell_quote(&cmdline_for(config));
        format!(
            "--kernel={dist_q}/{name_q}.bzImage --initrd={dist_q}/{name_q}.cpio \
             --append={cmdline_q}"
        )
    };
    let _ = writeln!(
        s,
        "python3 /build/sev-snp-measure/sev-snp-measure.py --mode snp --vcpus={} \
         --vcpu-type={vcpu_type_q} --ovmf={ovmf_path_q} \
         {kernel_args} | tr -d '\\n' > {dist_q}/sev_measurement.txt",
        sev.vcpus,
    );
    // Same reasoning as the app/guest-init hashes in script_rootfs_and_images: the firmware
    // is one of the measurement's inputs, so recording its hash lets a mismatch be
    // attributed to "the OVMF build/provider changed" instead of just "the measurement
    // changed." Computed here (not host-side) because for `preset` this file only exists
    // inside the container image, at a path the host never sees.
    let _ = writeln!(
        s,
        "sha256sum {ovmf_path_q} | cut -d' ' -f1 > /build-meta/ovmf.sha256"
    );
    s
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::test_fixtures::*;
    use super::*;
    use crate::schema::OutputFormat;

    #[test]
    fn sev_snp_measurement_stage_records_ovmf_hash() {
        let config = sev_snp_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_sev_snp_measurement(&config);
        assert!(script.contains(
            "sha256sum '/assets/ovmf/OVMF.amdsev.fd' | cut -d' ' -f1 > /build-meta/ovmf.sha256"
        ));
    }

    #[test]
    fn sev_snp_measurement_clones_sev_snp_measure_shallow() {
        let config = sev_snp_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_sev_snp_measurement(&config);
        assert!(script.contains("git clone --depth 1"));
        assert!(script.contains("https://github.com/virtee/sev-snp-measure.git"));
    }

    #[test]
    fn casual_profile_never_emits_sev_snp_measurement_stage() {
        let config = casual_config_with_formats(vec![OutputFormat::Cpio]);
        assert!(script_sev_snp_measurement(&config).is_empty());
    }

    #[test]
    fn uki_output_measures_the_assembled_efi_with_no_initrd_or_append() {
        // Providers that direct-boot the UKI via QEMU's fw_cfg SNP_KERNEL_HASHES mechanism
        // (e.g. Onidel) hash the whole assembled .efi as a single "kernel" blob — passing
        // the separate bzImage/cpio/cmdline instead predicts a measurement for a boot mode
        // nobody is using, and never matches the real launch measurement.
        let config = sev_snp_config_with_formats(vec![OutputFormat::Uki]);
        let script = script_sev_snp_measurement(&config);
        assert!(script.contains("--kernel='/workspace/dist'/'test-app'.efi"));
        assert!(!script.contains("--initrd="));
        assert!(!script.contains("--append="));
    }

    #[test]
    fn non_uki_output_still_measures_bzimage_cpio_and_append_separately() {
        let config = sev_snp_config_with_formats(vec![OutputFormat::Cpio]);
        let script = script_sev_snp_measurement(&config);
        assert!(script.contains("--kernel='/workspace/dist'/'test-app'.bzImage"));
        assert!(script.contains("--initrd='/workspace/dist'/'test-app'.cpio"));
        assert!(script.contains("--append="));
    }
}
