#!/bin/bash
# Builds a hybrid BIOS+UEFI bootable ISO from a bzImage + cpio initramfs, using Limine
# (small, auditable, actively-maintained bootloader — see docs/reproducible_builds.md for
# why this was chosen over GRUB) and `xorriso -as mkisofs`.
#
# Usage: make_iso.sh <bzimage> <initrd.cpio> <output.iso> [<cmdline>]
set -euo pipefail

BZIMAGE="$1"
INITRD="$2"
OUT_ISO="$3"
CMDLINE="${4:-console=ttyS0 ip=dhcp quiet loglevel=0}"

LIMINE_DIR="${LIMINE_DIR:-/opt/limine}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/iso_root/boot/limine"
cp "$BZIMAGE" "$WORK/iso_root/boot/vmlinuz"
cp "$INITRD" "$WORK/iso_root/boot/initramfs.cpio"

cat > "$WORK/iso_root/boot/limine/limine.conf" <<EOF
timeout: 0

/cargo-unikernel
    protocol: linux
    kernel_path: boot():/boot/vmlinuz
    module_path: boot():/boot/initramfs.cpio
    cmdline: ${CMDLINE}
EOF

cp "$LIMINE_DIR/limine-bios.sys" "$WORK/iso_root/boot/limine/"
cp "$LIMINE_DIR/limine-bios-cd.bin" "$WORK/iso_root/boot/limine/"
cp "$LIMINE_DIR/limine-uefi-cd.bin" "$WORK/iso_root/boot/limine/"

# Deterministic timestamps, matching the discipline used for the cpio initramfs.
find "$WORK/iso_root" -exec touch -h -d @0 {} +

# This is Limine's own documented recipe (USAGE.md), not an ad-hoc one: `limine-uefi-cd.bin`
# is a pre-built FAT image (containing EFI/BOOT/BOOTX64.EFI) that xorriso embeds as a real
# El Torito EFI boot image via --efi-boot/-efi-boot-part/-efi-boot-image, which is what
# makes firmware (OVMF, real hardware) recognize it as an actual ESP. Copying BOOTX64.EFI
# onto the ISO's own filesystem and referencing it via -eltorito-alt-boot/-isohybrid-gpt-
# basdat instead produces an ISO that boots fine over BIOS but that UEFI firmware cannot
# find any ESP on at all (OVMF's UEFI shell sees no fs0:/fs1: mapping whatsoever for it).
#
# SOURCE_DATE_EPOCH (not the native-mode-only `-volume_date`, which `-as mkisofs` rejects)
# is xorriso's own reproducible-builds.org-standard knob: it pins --modification-date= and
# --set_all_file_dates. --gpt_disk_guid must still be pinned explicitly, though: verified
# that without it, two back-to-back builds from byte-identical inputs produced ISOs
# differing in exactly the 4-byte MBR disk-signature field at offset 440 — xorriso's
# default there is a fresh random GUID every run, SOURCE_DATE_EPOCH notwithstanding.
SOURCE_DATE_EPOCH=0 xorriso -as mkisofs \
    -R -J \
    -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -hfsplus -apm-block-size 2048 \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    --gpt_disk_guid modification-date \
    -o "$OUT_ISO" \
    "$WORK/iso_root"

"$LIMINE_DIR/limine" bios-install "$OUT_ISO"

# `bios-install`'s GPT->MBR compatibility conversion (needed: without it, install fails
# outright with "no BIOS boot partition specified or detected" since our GPT has none)
# reseeds a fresh, non-deterministic 4-byte "MBR disk signature" on every run, even given
# byte-identical input — verified two builds from identical bzImage/cpio/kernel-cmdline
# differed in exactly bytes 440-443 of the output, seeded from wall-clock time rather than
# content. That field only disambiguates disks for the OS's own bookkeeping (e.g. Windows'
# drive-letter assignment) — it plays no role in booting — so zero it unconditionally here
# rather than trusting Limine to produce it deterministically.
dd if=/dev/zero of="$OUT_ISO" bs=1 seek=440 count=4 conv=notrunc status=none

echo "Wrote $OUT_ISO"
