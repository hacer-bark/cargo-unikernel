# Architecture

*[docs index](README.md) · [project README](../README.md)*

`cargo-unikernel` publishes as a **single crate** (`cargo install cargo-unikernel`) that
drops into any project. There is **no traditional Linux distribution** in the built image —
no systemd, no bash, no SSH, no package manager. Just a hardened kernel, a tiny init binary,
and your app. Everything the build needs beyond your own project — Dockerfile, kernel build
script + Kconfig, ISO/UKI tooling, the guest init's source — is embedded in the published
binary, so the tool works from any directory after a plain `cargo install`.

```mermaid
flowchart TB
    subgraph HOST["Host: cargo-unikernel binary"]
        PROJ["Your project (any dir, cargo install'd tool)"]
        BUILD["cargo unikernel build"]
        ASSETS["crate::assets::materialize()<br/>embedded via include_dir! at compile time"]
        PROJ --> BUILD
        ASSETS --> BUILD
    end
    subgraph DOCKER_INNER["Inside the pinned build container"]
        KERNEL["/assets/kernel/build_kernel.sh<br/>(base.config + profile fragment)"]
        APP["Your app: cargo build directly on /workspace (Mode A)<br/>or pre-verified binary (Mode B)"]
        INIT["cargo build --manifest-path /assets-guest/cargo-unikernel-init/Cargo.toml"]
        ROOTFS["/build/rootfs assembly:<br/>/init = cargo-unikernel-init, /payload/app = your app"]
        IMG["cpio / ukify / xorriso+limine"]
        MEASURE["sev-snp-measure.py (sev-snp profile only)"]
        KERNEL --> ROOTFS
        APP --> ROOTFS
        INIT --> ROOTFS
        ROOTFS --> IMG
        IMG --> MEASURE
    end
    BUILD -->|"mounts project dir as /workspace,<br/>materialized assets as /assets, /assets-guest"| DOCKER_INNER
    DOCKER_INNER --> DIST["your-project/dist/: bzImage, cpio, iso, efi,<br/>sev_measurement.{txt,json}"]
```

## Repo layout

- **`src/`** — the CLI crate. `schema.rs`: config schema + validation. `pipeline/`:
  app-source resolution, the Docker container, image formats, SEV-SNP measurement.
  `assets.rs`: embeds `assets/`+`guest/` via `include_dir!`, materializes to
  `~/.cache/cargo-unikernel/` on first use.
- **`assets/`** — Dockerfile, kernel build script + Kconfig, ISO build script, the two pinned
  OVMF firmware binaries. Mounted read-only as `/assets`.
- **`guest/`** — a separate, nested Cargo workspace: `cargo-unikernel-init` (guest PID 1) +
  `cargo-unikernel-common` (mount/hardening/entropy/seccomp). Not a Rust dependency of the
  CLI — only its source text is embedded and cross-compiled per build. Its own workspace so
  it builds/tests standalone (`cd guest && cargo build`); dependency graph is `libc` alone.

## Boot sequence (guest init)

The app is already embedded at build time, so the sequence is short:

1. `mlockall` — lock all pages, no swap.
2. Mount `/proc` (`hidepid=2`), `/sys`, `/dev`, `/tmp`+`/var` (noexec unless
   `[app.runtime.danger].allow_write_execute`), `/run`, `/dev/shm`, `/payload`. Every writable
   tmpfs carries an explicit `size=` (none defaults to half of guest RAM). `/var` is tmpfs
   unless `[storage].mode = "persistent"`, in which case it's the virtio-blk device,
   formatted ext4 on first use — a device whose superblock doesn't carry this tool's volume
   label is wiped rather than mounted (checked from userspace, before the kernel's ext4
   driver sees it) — then `chown`'d to the app's uid/gid.
3. Bring up loopback + admin-down interfaces, apply sysctl hardening for whatever's enabled.
   Only `lo`'s IPv4 address is set here; everything else comes from DHCP or SLAAC — see
   [Network addressing](#network-addressing).
4. Wait (up to 30s) for the kernel CRNG to report itself seeded — **fatal if it doesn't**,
   since starting the app anyway means it may generate keys from an unseeded pool. Then poll
   (up to 30s) for an up default route — skipped when `[network].mode = "none"`.
5. Remount `/payload` read-only and `/tmp`/`/run` back to noexec (unless
   `allow_write_execute`); `/var` is never remounted. This happens before the app exists, so
   there is no window in which a running app faces a still-writable payload mount.
6. `exec` the app as an unprivileged child. Before `execve`, in order: apply `setrlimit`
   ceilings from `[app.runtime.limits]` (raising one above the kernel default needs
   `CAP_SYS_RESOURCE`, so this runs before the capability drop removes it); drop the
   capability bounding set (`PR_CAPBSET_DROP`, while still root — dropping it needs
   `CAP_SETPCAP`); clear supplementary groups and `setgid`/`setuid` to the configured
   uid/gid; install a mandatory classic-BPF seccomp denylist — gated on the x86_64 syscall
   ABI, then permanently blocking `ptrace`, kernel-module loading, both mount APIs
   (`mount(2)` and `fsopen`/`fsmount`/`move_mount`), `kexec`/`reboot`, keyring syscalls,
   `open_by_handle_at`, clock-setting syscalls, and `memfd_create`/`memfd_secret` (unless
   `allow_write_execute`). The filter gates on `AUDIT_ARCH_X86_64` *and* rejects any syscall
   number carrying `__X32_SYSCALL_BIT`, since x32 reports the same arch and would otherwise
   slip every check below it. Ordinary `clone`/`fork`/`execve` is untouched; namespace
   creation via `clone` is blocked by `CONFIG_NAMESPACES=n` instead.
7. On sev-snp builds, `/dev/sev-guest` (if present) opens to the app, which is what fetches
   and binds SEV-SNP reports — the image runs no attestation service of its own. See
   [`threat_model.md`](threat_model.md#remote-attestation-is-the-apps-job).
8. PID 1 watchdog loop: the app's death or any earlier failure triggers immediate power-off —
   the system never lingers in a degraded state.

## Network addressing

The init brings interfaces up and nothing else — no DHCPv6 client, no `rdisc6`, no IPv6
address of its own assignment. What the guest ends up with comes from the kernel and
whatever the hypervisor's network advertises:

| Protocol | Interface | Address | Assigned by |
|:---|:---|:---|:---|
| IPv4 | `lo` | `127.0.0.1/8` | the init, explicitly |
| IPv4 | NIC | whatever DHCP offers | kernel's built-in autoconfig (`ip=dhcp`) |
| IPv6 | `lo` | `::1/128` | the kernel, when `lo` comes up |
| IPv6 | NIC | `fe80::<IID>/64` link-local | the kernel, when the link comes up |
| IPv6 | NIC | one global `/64` per advertised prefix | SLAAC, from router advertisements |
| IPv6 | NIC | a fixed address of your choosing | the init, when `[network.ipv6_static]` is set |

**Pin an address with `[network.ipv6_static]`** if you can't read the guest console (the
normal case on a confidential-computing host) and need something to put in DNS beforehand:

```toml
[network]
mode = "ipv6"

[network.ipv6_static]
address = "2001:db8:1:2::1"   # any host part in your /64; ::1 is conventional
prefix_len = 64               # 128 for a single delegated address
# gateway = "fe80::1"         # only if the provider sends no router advertisements
# interface = "eth0"          # only on a multi-NIC guest
```

This is *added to* whatever SLAAC produces, not a replacement — router advertisements still
supply the default route in the common case. `gateway` covers a provider that routes a prefix
to the VM without advertising it; it's installed at metric 2048 (worse than the kernel's 1024
for an advertised route) so the two stay separate routes rather than merging into a
load-balanced multipath entry if a router advertisement does show up. Failures here are
logged and boot continues — the guest still has its SLAAC address, and not booting is worse
than an unplanned address. Config-time validation catches unparseable/link-local/loopback
addresses and bad prefix lengths, since on a console-less guest a bad value otherwise
produces an image that boots, looks healthy, and is silently unreachable.

**Finding the address:** with `[network.ipv6_static]` set, it's what you configured.
Otherwise the init logs every address it finds once the network settles, scope labelled:

```
[INIT] eth0: IPv6 2001:db8:1:2:5054:ff:fe12:3456 (global)
[INIT] eth0: IPv6 fe80::5054:ff:fe12:3456 (link-local)
```

The `(global)` one is the address — there's only ever one per advertised prefix, no
privacy/temporary addresses. To compute it before booting: `<the /64> + EUI-64(MAC)` (Linux
defaults `addr_gen_mode` to EUI-64) — split the MAC in half, insert `ff:fe`, flip bit `0x02`
of the first octet:

```
prefix  2001:db8:1:2::/64
MAC     52:54:00:12:34:56
           ↓ flip 0x02 in 52 → 50, insert ff:fe
IID     5054:00ff:fe12:3456
result  2001:db8:1:2:5054:ff:fe12:3456
```

Stable for as long as the MAC is, so it's fine to put in DNS. If the log says **`no global
IPv6 address`**, nothing advertised a prefix on the link — usually because the provider
routes the /64 rather than advertising it. Set `[network.ipv6_static]` with a `gateway`.

<details>
<summary>Why a /64 and never a /48, and who picks the interface identifier</summary>

SLAAC (RFC 4862) concatenates the advertised prefix with a 64-bit interface identifier, so
the prefix must be exactly 64 bits (RFC 7421) — a Prefix Information Option of any other
length is simply not used for autoconfiguration. A provider "giving you a /48" is either
advertising a /64 out of it on your link (works as above; the other 65535 /64s are none of
this guest's business), or routing the whole /48 to your VM via DHCPv6-PD or a static route —
which autoconfiguration does *not* pick up, since there's no DHCPv6 client. Use
`[network.ipv6_static]` for the latter.

The interface identifier itself — in both the link-local and SLAAC address — is derived from
the NIC's MAC (`addr_gen_mode = eui64`, the default), which the hypervisor chose. Privacy
extensions are off (`use_tempaddr = 0`), so nothing rotates it. On sev-snp this is worth
stating plainly: the host already sees every packet's source address, and it also *chose*
that address, stable for as long as the MAC is — a host-controlled correlator across boots,
outside what SEV-SNP protects (memory, not network). Change it via
`net.ipv6.conf.<iface>.addr_gen_mode` in `[hardening].extra_sysctls`, or add an address from
the app.

One non-obvious interaction: `[hardening.runtime].network_spoofing_protection` sets
`net.ipv6.conf.all.forwarding=0`. That's also what keeps SLAAC working — Linux ignores router
advertisements on a forwarding interface, so turning the guest into a router would silently
cost it its address.

</details>

## Build pipeline (host)

`cargo unikernel build` (`src/pipeline/`):

1. **Config resolution** — explicit `-c`, else `./cargo-unikernel.toml`, else zero-config
   auto-detection (`Cargo.toml` → casual Mode A `path="."`; `--binary <path>` → Mode B).
2. **`app_source`** — resolves `[app]` into a `LocalSource` (`path`, confirming a
   `Cargo.toml` is there) or a verified binary (Mode B).
3. **`ovmf`** (sev-snp only) — resolves `[sev_snp.ovmf]`, stages non-preset firmware into
   `dist/.ovmf-cache/` host-side.
4. **`docker`** — builds `Dockerfile.reproducible`, runs one generated in-container script:
   builds the kernel, builds the app (`"rust"` → `cargo build`; `"generic"` → your
   `build_command`), then cross-compiles `cargo-unikernel-init` (app build first, so its
   sha256 bakes into the init via `build.rs`). `readelf` then checks `$APP_BIN` for dynamic
   linking regardless of mode, failing the build with missing-library names rather than
   shipping a crash-looping image — see [`toolchains.md`](toolchains.md). The pipeline then
   assembles the rootfs/cpio and produces every requested output format.
5. **`image::{cpio,iso,uki}`** — every format is produced inside the container; this just
   confirms it landed in `dist/` and reports it.
6. **`measurement`** (sev-snp only) — reads `dist/sev_measurement.txt`, writes a JSON sidecar
   recording every input (vcpus, cmdline, kernel/initrd identity, OVMF source).

Shells out to pinned tools (`ukify`, `xorriso`+Limine, `sev-snp-measure.py`) rather than
reimplementing PE/ISO assembly or kernel measurement.

## GitHub integration

- **`cargo unikernel github init`** writes a workflow that, on every `v*`-glob tag push, installs
  `cargo-unikernel`, builds, then `release --tag <tag> --no-build`. The same build also runs
  (build-only) on pushes to `main`, keeping a warm `actions/cache` entry available since
  cache scopes are otherwise isolated per tag. `--attest-provenance` adds a Sigstore-backed
  `actions/attest-build-provenance` step, gated to tag pushes — build-provenance attestation
  of the release artifacts — a supply-chain claim about the bytes, distinct from an app's own
  SEV-SNP report about a *running guest*. Off by default.
- **`cargo unikernel release`** builds (unless `--no-build`) and publishes `dist/` via `gh` —
  the same path the generated workflow uses. What's attached and the release
  title/notes/draft come from `[release]`, so editing it changes both local and CI releases.

## Image formats

| Format | Tooling | Notes |
|:---|:---|:---|
| `.cpio` + `bzImage` | `cpio --reproducible`, zeroed timestamps, `LC_ALL=C sort` | The measured path for sev-snp; most direct for QEMU. |
| `.iso` | `xorriso -as mkisofs` + Limine | Hybrid BIOS+UEFI; Limine over GRUB for a smaller trusted codebase. Convenience-only for sev-snp — not what's measured. |
| UKI (`.efi`) | `systemd-ukify` | Single UEFI-bootable PE; cmdline shared with `sev-snp-measure.py`. |
| `binary` (`.bin`) | plain `cp` of `$APP_BIN` | Raw app binary alongside any other requested formats. |

`assets/scripts/make_iso.sh` takes the cmdline as an argument so every format from one build
boots with exactly the same cmdline — one source of truth, no drift. See
[`reproducible_builds.md`](reproducible_builds.md) and [`threat_model.md`](threat_model.md)
for the determinism and threat stories.

## Kernel cmdline rationale

Every flag earns its place, in either direction:

| Flag | Why included |
|:---|:---|
| `quiet` | Suppresses routine boot chatter on the serial console; `loglevel=3` below still lets failures through. |
| `loglevel=3` | A boot failure prints to serial instead of failing silently. |
| `panic=-1` | Reboots on kernel panic instead of hanging — extends the init's watchdog to the kernel level. |
| `random.trust_cpu=off`, `random.trust_bootloader=off` | Don't credit RDRAND/RDSEED or the bootloader handoff toward CRNG init — matches Kicksecure's default. Safe here because `CONFIG_HW_RANDOM_VIRTIO` (base.config) gives a fast alternate source fed by the host, which this profile already trusts, and `entropy::wait_for_entropy` hard-fails boot rather than silently starting on an unseeded pool. **sev-snp diverges and keeps `trust_cpu=on`** (see `examples/cargo-unikernel.sev-snp.toml`): that profile's threat model doesn't trust the hypervisor, so host-fed virtio-rng entropy is adversarial there, while RDRAND/RDSEED execute on real silicon inside the encrypted guest, outside the hypervisor's reach. RDRAND/RDSEED output is still mixed into the pool either way — the flag only controls whether it's *credited* as entropy on its own. |
| `page_alloc.shuffle=1` | Activates page-allocator shuffling, which the kernel otherwise leaves inert on a VM with no memory-side-cache to detect. |
| `lockdown=integrity`/`confidentiality` | Lockdown LSM; `confidentiality` (sev-snp) adds no-raw-`/dev/mem`/no-MSR-writes at no extra cost. |
| `transparent_hugepage=madvise` | Opt-in per allocation — avoids the kernel's `always` compaction overhead while keeping the win for large heaps/JITs; no security trade-off, so it's a default. |
| `init_on_alloc=1`, `init_on_free=1` | Zeroes kernel heap memory on allocation and free, closing use-after-free/uninitialized-read info leaks; small, well-understood cost for a security-first default. |

`CONFIG_PREEMPT_NONE` and `CONFIG_TCP_CONG_BBR` (Kconfig, not cmdline) give the same
no-security-cost throughput wins.

**Deliberately excluded:** `mitigations=auto,nosmt`/explicit `spectre_v2=`/etc. (redundant
with the kernel's own safe default; `nosmt` costs 30-50% throughput for little gain in a
single-tenant VM); `mitigations=off` (not exposed as a config knob — use
`extra_kernel_config` if you really need it); `pti=on` (already default); `fips=1`
(compliance opt-in, add yourself if needed); `amd_iommu=*`/`iommu.*` (SEV-SNP's DMA
protection is the hardware Reverse Map Table, not a vIOMMU that isn't there).

**A warning you'll see and can ignore:** every ISO build prints `xorriso ... WARNING: EFI
boot equipment is provided but no directory /EFI/BOOT`. Expected — `make_iso.sh` embeds the
EFI boot image via a real El Torito boot catalog entry (Limine's documented recipe) instead
of a `/EFI/BOOT/BOOTX64.EFI` file; UEFI firmware still finds it as a proper ESP either way. A
literal `/EFI/BOOT` tree would silence the warning but produce an ISO nothing can boot.
</content>
