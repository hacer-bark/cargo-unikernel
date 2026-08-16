<div align="center">
  <h1>cargo-unikernel</h1>
  <p><strong>Turn a Rust project, another language's static build, or a pre-built binary into a minimal, hardened bootable unikernel image — ISO, cpio+kernel, UKI, with an optional AMD SEV-SNP confidential-computing profile.</strong></p>

  [![Crates.io](https://img.shields.io/crates/v/cargo-unikernel.svg?style=for-the-badge&color=fc8d62)](https://crates.io/crates/cargo-unikernel)
  [![Docs.rs](https://img.shields.io/docsrs/cargo-unikernel?style=for-the-badge&color=66c2a5)](https://docs.rs/cargo-unikernel)
  [![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-8da0cb.svg?style=for-the-badge)](#license)
  [![CI](https://img.shields.io/github/actions/workflow/status/hacer-bark/cargo-unikernel/ci.yml?label=CI&style=for-the-badge&color=e78ac3)](https://github.com/hacer-bark/cargo-unikernel/actions/workflows/ci.yml)
</div>

<br/>

> **0.0.1, pre-release.** Config schema, CLI flags, and the generated GitHub Actions workflow
> can change between versions without warning. Pin an exact version
> (`project.cargo_unikernel_version` in `cargo-unikernel.toml`) and re-verify on upgrade.

```sh
cargo install cargo-unikernel
cd my-server/
cargo unikernel build
```

No config file, no template repo — `cargo install` puts the binary on `PATH`, Cargo's
external-subcommand convention picks it up, and it drops into any project. Output is
`.iso`, `.cpio`+kernel, UKI, or a raw app binary, with an optional AMD SEV-SNP profile.

**Any language works.** Rust is zero-config. Bring a pre-built binary in anything, or point
the tool at a build command (Go, Zig, C, ...) for the same reproducible source build Rust
gets. See [Bringing your app in](#bringing-your-app-in).

## What it is

The output is a Linux kernel, a tiny init binary, and your app — nothing else. No systemd,
bash, coreutils, package manager, SSH daemon, or dynamic linker. Init mounts a few
filesystems, applies hardening, execs the app unprivileged, watches it, and powers off the
instant anything looks wrong. Full boot sequence: [`docs/architecture.md`](docs/architecture.md).

## Why this over a container or a hand-built VM image

A container or a general-purpose-distro VM image still carries a shell, a package manager,
and a dynamic linker for an attacker to pivot to post-compromise. `cargo-unikernel` strips
those out rather than locking them down — which also means no live debugging, no runtime
patching, and a RAM-only filesystem with no local durable state (full list:
[Is cargo-unikernel right for your app?](#is-cargo-unikernel-right-for-your-app)). In exchange:


|:---|:---|
| **Performance** | Nothing else runs on the kernel — no container runtime, no other tenant. `CONFIG_PREEMPT_NONE`, BBR congestion control, opt-in transparent hugepages, boot that polls instead of sleeping for timeouts. Small image, fast boot. Details: [architecture.md#kernel-cmdline-rationale](docs/architecture.md#kernel-cmdline-rationale). |
| **Security** | Zero trust in the OS, because there's effectively none to trust. Read-only rootfs, `noexec` elsewhere, empty capability set before exec, a mandatory seccomp filter blocking `ptrace`/module-loading/`mount`/`kexec`/`reboot`/etc., `setrlimit` ceilings. None of it opt-in. Full catalog: [threat_model.md](docs/threat_model.md). |
| **Confidential computing** | `profile.kind = "sev-snp"` gets a hardware root of trust: AMD's Secure Processor measures kernel+init+app before execution, memory is hardware-encrypted per-VM, `/dev/sev-guest` lets the app prove to a remote party this exact image is running. Puts the cloud provider and hypervisor outside the trust boundary. Details: [Confidential computing (SEV-SNP)](#confidential-computing-sev-snp). |

## How it works

Your project directory is mounted into a pinned build container — nothing cloned or copied.
Inside: the kernel builds from pinned source with a curated hardening profile, the app
compiles (or, for a pre-built binary, is verified and staged) and is checked for static
linking, the guest init cross-compiles alongside it, everything assembles into a rootfs and
packs into the requested formats. Every build dependency beyond your own project —
Dockerfile, kernel Kconfig, ISO/UKI tooling, guest init source — is embedded in the
`cargo-unikernel` binary itself.

Full pipeline stage by stage: [`docs/architecture.md`](docs/architecture.md).

## Is cargo-unikernel right for your app?

Hard requirements, checked before committing to the tool:

- **A fully static `x86_64-unknown-linux-musl` binary.** Build fails immediately, naming
  missing libraries, on any dynamic linker segment or `DT_NEEDED` dependency. Rust's default
  target already qualifies; other languages need `CGO_ENABLED=0` (Go), `-Dtarget=...-musl`
  (Zig), `cc -static` (C).
- **x86_64 only.**
- **Everything the app needs is baked in at build time.** No package manager, no runtime
  fetch — the app is in the image before it's ever measured or booted.
- **A single embedded app binary**, free to be multi-threaded or multi-process (ordinary
  `fork`/`clone`/`execve` are untouched by seccomp).

**Best fits:** standalone web/API servers, RAM-only workloads (caches, stream processors,
ephemeral compute), apps whose persistent state already lives off-box, anything that already
ships as a static binary, confidential-computing workloads that need the infra operator
outside the trust boundary.

**Not a good fit:** apps expecting a full OS at runtime (shelling out, cron, systemd units),
anything that can't be statically linked or loads plugins at runtime, non-x86_64 targets,
databases needing durable local disk, GUI apps.

## Bringing your app in

| | How it works | Trust model | Setup |
|:---|:---|:---|:---|
| **Rust source build** | `cargo build`, cross-compiled to musl | Compiler never sees pre-built bytes | Zero-config, or `toolchain = "rust"` |
| **Generic source build** | A `build_command` runs in the same reproducible container | Same as Rust — nothing pre-built touches the image | `toolchain = "generic"` + `build_command`/`output_binary` |
| **Bring your own binary** | A local file — never fetched over the network | Trust whatever produced the binary | `[app.binary]` |

The first two are the same pipeline with a different last-mile build step — see
`examples/cargo-unikernel.casual.toml`'s `[app.source]` for a worked Go example. The third
works with anything, at the cost of trusting pre-built bytes over a verified build. Trade-offs
in depth: [`docs/toolchains.md`](docs/toolchains.md).

## Customizing with cargo-unikernel.toml

Zero-config always builds the `casual` profile with the Rust toolchain. To pick SEV-SNP, a
generic build command, specific output formats, a pre-built binary, or tuned hardening:

```sh
cargo unikernel init # writes ./cargo-unikernel.toml
nano cargo-unikernel.toml
cargo unikernel build
```

`cargo unikernel init --profile <casual|sev-snp>` picks the starting point. See
`examples/cargo-unikernel.casual.toml` and `examples/cargo-unikernel.sev-snp.toml` — each is
a fully-commented reference covering all three app-acquisition modes.

## Granular control

Every knob is documented inline in the example configs (`examples/cargo-unikernel.casual.toml`
has the full field reference). Highlights:

| Section | Controls |
|:---|:---|
| `[kernel]` | Pin the exact Linux kernel `version` (and optionally `sha256`). |
| `[hardening.kernel]` | Build-time Kconfig toggles — legacy subsystems, debug interfaces, KSPP + Lockdown LSM, exploit mitigations, seccomp. On by default, independently toggleable. |
| `[hardening.runtime]` | Boot-time sysctl toggles — spoofing protection, ICMP/TCP hardening, info-leak restriction, ptrace/BPF restriction, kexec/filesystem protection. Same default-on shape. |
| `extra_sysctls` / `extra_kernel_config` | Raw escape hatches beyond the curated categories. |
| `[app.runtime.limits]` | `setrlimit` ceilings (open files, processes, memory, locked memory) applied pre-exec. Generous defaults; optional. |
| `[app.runtime.danger]` | Off by default, named to be hard to enable by accident. `allow_write_execute` is the one opt-out from "no writable+executable path anywhere in the guest." |

**Always on, not configurable:** a seccomp denylist blocking `ptrace`, module loading,
`mount`/`kexec`/`reboot`, and similar syscalls with no legitimate use in a single-purpose
server — the app is killed on any attempt, which the watchdog turns into a full reboot. The
capability bounding set is unconditionally dropped to empty before exec. See
[`docs/architecture.md`](docs/architecture.md).

**Caching.** The kernel source tarball and the compiled bzImage (per kernel version +
hardening config) are cached under `~/.cache/cargo-unikernel/` — an app-only change skips the
kernel step entirely. `ccache` covers everything else. `cargo unikernel github init`'s
workflow caches the same directory across CI runs, and also builds (never publishes) on every
push to `main` so a tag-triggered release always inherits a warm cache (GitHub Actions cache
scopes are isolated per tag).

**Clean output.** `dist/` only ever contains the requested build artifacts; scratch files
live under `~/.cache/cargo-unikernel/last-build/`, inspectable if a build fails.

The app binary is compiled/verified and baked into the image **at build time** — the guest
never fetches it over the network at boot. No runtime dependency, no signing-key management,
no TOCTOU gap, and for SEV-SNP the launch measurement already covers the exact app bytes.

## CLI

- `cargo unikernel build` — build the image(s); zero-config or from a config file.
- `cargo unikernel init` — scaffold a `cargo-unikernel.toml` when customization is needed.
- `cargo unikernel measure` — recompute the SEV-SNP launch measurement from already-built
  artifacts without a full rebuild (`sev-snp` profile only).
- `cargo unikernel doctor` — check the host toolchain (Docker, git, gh).
- `cargo unikernel github init` — write `.github/workflows/cargo-unikernel.yml`: a `v*` tag
  push builds and publishes a GitHub Release automatically.
- `cargo unikernel release` — build (unless `--no-build`) and publish a GitHub Release via
  `gh` right now. Attached artifacts and release title/notes/draft/prerelease are
  configurable via `[release]` in `cargo-unikernel.toml`.

## CI/CD via GitHub Actions

`cargo unikernel github init` writes a workflow that, on every `v*`-glob tag push, installs
`cargo-unikernel`, builds, and publishes a GitHub Release. It also builds (never publishes) on
every push to `main`, purely to keep the cache warm.

If `cargo-unikernel.toml` pins `project.cargo_unikernel_version`, the generated workflow
installs that exact version instead of latest — `cargo unikernel build` also fails closed
(`ValidationError::ToolVersionMismatch`) if a different version ever runs against it. Re-run
`github init` after changing the pin.

> [!IMPORTANT]
> **The first build in a fresh environment compiles a full Linux kernel from source — expect
> around 25 minutes.** Not a hang. Every build after that shares the kernel/bzImage cache and
> typically finishes in a few minutes, as long as the kernel version and hardening config
> haven't changed.

`--attest-provenance` adds a GitHub build-provenance attestation step
(`actions/attest-build-provenance`) — a Sigstore-backed, GitHub-verifiable proof that this
exact workflow run produced these exact bytes. Off by default (requires
`id-token: write`/`attestations: write`). This is supply-chain provenance about the released
bytes — distinct from an app's own SEV-SNP report about a *running* guest.

## Confidential computing (SEV-SNP)

Set `profile.kind = "sev-snp"` and a `[sev_snp]` section (`vcpus`, `vcpu_type`,
`kernel_cmdline`). This is the only profile where `project.cargo_unikernel_version` is
mandatory — a different CLI version can bundle a different pinned kernel/Dockerfile, which
would silently change the launch measurement. `build`/`measure` refuse to run unpinned or
under a mismatched version. `cargo unikernel init --profile sev-snp` sets this automatically.

`cargo unikernel build` then:

1. Builds the kernel with the SEV-SNP attestation Kconfig fragment on top of the hardening
   baseline.
2. Computes the launch measurement with `virtee/sev-snp-measure`, using the exact vcpu
   count/type and kernel cmdline configured — the same cmdline is baked into the UKI, so what's
   measured and what boots can't drift.
3. Writes `dist/sev_measurement.txt` and `dist/sev_measurement.json` (every input, plus
   per-component sha256 hashes for diffing two divergent builds).
4. Leaves `/dev/sev-guest` readable to the app. Proving the measurement to a remote peer is
   the app's protocol — see [`docs/threat_model.md`](docs/threat_model.md#remote-attestation-is-the-apps-job).

**Bring your own OVMF.** `preset = "builtin"` (default) uses the AMD SEV-SNP firmware baked
into the binary, hash-pinned, never fetched over the network. Different cloud providers ship
different OVMF builds — `[sev_snp.ovmf]` also accepts a local `path` (never a URL). See
`examples/cargo-unikernel.sev-snp.toml`.

Build sev-snp via a tagged release workflow so the measurement corresponds to an immutable
commit rather than uncommitted local state. ISO output works for sev-snp too as a
convenience/testing artifact — the measured artifact is always cpio+bzImage or UKI. A benign
`xorriso ... WARNING: EFI boot equipment is provided but no directory /EFI/BOOT` may appear
during ISO builds — see [`docs/architecture.md`](docs/architecture.md) if that looks alarming.

## Minimum supported Rust version

**Rust 1.88+** — config-validation code relies on `if let` chains, stabilized in 1.88. This
is what's needed to build `cargo-unikernel` itself; it has no bearing on your app's own
toolchain, pinned independently inside the build container (see
[`docs/reproducible_builds.md`](docs/reproducible_builds.md)). MSRV bumps are minor-version
changes while the crate stays pre-1.0.

## Project layout

```
Cargo.toml    the published CLI crate itself — `cargo install cargo-unikernel`
src/          CLI, config schema, build pipeline
assets/       Dockerfile, kernel build script + Kconfig, ISO script,
              baked-in SEV-SNP OVMF firmware — embedded into the binary
guest/        SEPARATE nested workspace: cargo-unikernel-init (the
              guest PID-1) + cargo-unikernel-common (shared mount/
              hardening logic). Not a Cargo dependency of the CLI —
              only ever embedded as source text, cross-compiled inside
              the build container for every user's build.
examples/     fully-commented starting configs for each profile x
              app-acquisition mode (rust source / generic source /
              pre-built binary)
docs/         architecture, toolchain trade-offs, threat model,
              reproducible-builds notes
```

## Documentation

Start at [`docs/README.md`](docs/README.md) for the full index. Direct links:

- [`docs/architecture.md`](docs/architecture.md) — how the pieces fit together: host CLI,
  build container, guest init, boot sequence, kernel cmdline rationale.
- [`docs/toolchains.md`](docs/toolchains.md) — the three ways to bring an app in, compared.
- [`docs/threat_model.md`](docs/threat_model.md) — what is and isn't defended against under
  each profile.
- [`docs/reproducible_builds.md`](docs/reproducible_builds.md) — the determinism story, and
  how to verify a build independently.

## License

Licensed under either of

- [Apache License, Version 2.0](https://github.com/hacer-bark/cargo-unikernel/blob/main/LICENSE-APACHE)
- [MIT license](https://github.com/hacer-bark/cargo-unikernel/blob/main/LICENSE-MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
</content>
