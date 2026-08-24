# Building a bootable ISO manually

*[docs index](README.md) · [project README](../README.md)*

`cargo-unikernel` doesn't produce `.iso` output itself — only `cpio`+`bzImage` and `uki`
(see [`architecture.md#image-formats`](architecture.md#image-formats)). Both of those already
cover the common cases (QEMU `-kernel`/`-initrd`, or a UEFI direct-boot provider), and neither
needs a third-party bootloader baked into this tool's own build container.

If you specifically need a `.iso` — for local testing on a hypervisor that only accepts disk
images, or to hand someone a single file — here's how to assemble one yourself from either
output. Both approaches use `xorriso`, which is packaged by every major Linux distro
(`apt install xorriso`, `dnf install xorriso`, ...).

## Option A: from the UKI (simplest, UEFI-only)

The UKI (`dist/<name>.efi`) is already a single, self-contained, directly-bootable UEFI
executable — kernel, initramfs, and cmdline are all assembled into it by `ukify`. No
bootloader is needed at all: UEFI firmware can boot it straight from the ESP.

```bash
name=my-server   # your project.name

mkdir -p iso_root/EFI/BOOT
cp "dist/${name}.efi" iso_root/EFI/BOOT/BOOTX64.EFI

xorriso -as mkisofs \
    -R -J \
    -e EFI/BOOT/BOOTX64.EFI -no-emul-boot \
    -o "dist/${name}.iso" \
    iso_root
```

This produces a UEFI-only ISO (no BIOS/legacy boot). If your target only boots UEFI (true for
most cloud hypervisors and modern QEMU/OVMF setups), this is all you need.

## Option B: from cpio + bzImage (BIOS, or hybrid BIOS+UEFI)

For a target that boots legacy BIOS, or where you want one ISO that works either way, you
need a real bootloader to chainload the kernel — `xorriso` alone can't hand control to
`bzImage`+`initrd.cpio` directly. [Limine](https://github.com/limine-bootloader/limine) and
[GRUB](https://www.gnu.org/software/grub/) both work; Limine is smaller and simpler to drive
from a script. Example with Limine (install it yourself — see its `USAGE.md` — this tool no
longer bundles or pins a Limine build):

```bash
name=my-server
cmdline="console=ttyS0 ip=dhcp quiet loglevel=0"   # match what your build actually uses

mkdir -p iso_root/boot/limine
cp "dist/${name}.bzImage" iso_root/boot/vmlinuz
cp "dist/${name}.cpio" iso_root/boot/initramfs.cpio

cat > iso_root/boot/limine/limine.conf <<EOF
timeout: 0

/cargo-unikernel
    protocol: linux
    kernel_path: boot():/boot/vmlinuz
    module_path: boot():/boot/initramfs.cpio
    cmdline: ${cmdline}
EOF

# From your Limine install (built per its USAGE.md, or its prebuilt binary release):
cp /path/to/limine/limine-bios.sys iso_root/boot/limine/
cp /path/to/limine/limine-bios-cd.bin iso_root/boot/limine/
cp /path/to/limine/limine-uefi-cd.bin iso_root/boot/limine/

xorriso -as mkisofs \
    -R -J \
    -b boot/limine/limine-bios-cd.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    --efi-boot boot/limine/limine-uefi-cd.bin \
    -efi-boot-part --efi-boot-image --protective-msdos-label \
    -o "dist/${name}.iso" \
    iso_root

/path/to/limine/limine bios-install "dist/${name}.iso"
```

A `WARNING: EFI boot equipment is provided but no directory /EFI/BOOT` from `xorriso` here is
expected and harmless — the EFI boot image is embedded via a real El Torito boot catalog entry
(Limine's own documented recipe), not a `/EFI/BOOT/BOOTX64.EFI` file, and UEFI firmware still
finds it as a proper ESP.

## Notes

- Neither recipe here is reproducible/pinned the way `cargo-unikernel`'s own build container
  is (see [`reproducible_builds.md`](reproducible_builds.md)) — pin your own Limine/GRUB/xorriso 
  versions if that matters for your use case.
- For SEV-SNP, an ISO built this way is never the measured artifact — the launch measurement
  is always computed from `cpio`+`bzImage` or the UKI (see
  [`architecture.md`](architecture.md#build-pipeline-host)). Treat any ISO as a
  convenience/testing image only.
