# Reproducible Builds

*[docs index](README.md) · [project README](../README.md)*

A reproducible build means anyone building the same inputs gets the same output, byte for
byte. This matters two ways: for **sev-snp**, the launch measurement is only meaningful if
you can reproduce it independently, not just trust `cargo-unikernel`'s own run. For **Mode A**
on any profile, it's what lets you confirm the embedded app was really compiled from the
source you think it was.

## Pinned toolchain (`assets/docker/Dockerfile.reproducible`)

| Component | How it's pinned | Overridable? |
|:---|:---|:---|
| Base OS | Ubuntu 26.04, locked by SHA-256 digest | No |
| `apt` packages (gcc, binutils, musl-tools, …) | Frozen `snapshot.ubuntu.com` mirror timestamp, not the live archive | `[toolchain].apt_snapshot` |
| Rust compiler | Fixed version via `rustup --default-toolchain` | `[toolchain].rust_version` |
| musl libc | Ubuntu's `musl-tools`, same pinned snapshot | Via `apt_snapshot` |
| Rust dependencies | `Cargo.lock` | No |
| `toolchain = "generic"` build command | Runs in the pinned container; its determinism is on the config author | N/A |
| ISO tooling | `xorriso` (via `apt_snapshot`) + Limine, pinned release + checksum | `limine_version`/`limine_sha256` |
| UKI tooling | `systemd-ukify`, pinned systemd package | Via `apt_snapshot` |
| OVMF firmware (`preset`) | Baked into the binary (`assets/ovmf/`), no network fetch; a unit test checks embedded bytes against pinned hashes | Via `[sev_snp.ovmf].path` |

The host's `$HOME/.cargo`/`target` are never mounted in — only explicit cache volumes
(`~/.cache/cargo-unikernel/{cargo,ccache,target}`) — so a host Rust install can never leak
into the pinned toolchain.

## Overriding a pin

Most rows above are overridable in `[toolchain]` (`examples/Cargo-Unikernel.casual.toml` has
the full field list), so a CVE fix doesn't have to wait for a new `cargo-unikernel` release.
`apt_snapshot` is the highest-leverage field — one timestamp moves the entire apt-sourced
toolchain together. **An override changes what "reproducible" means**: the build is
reproducible given that exact pin, but won't match this CLI version's own defaults, even with
identical source. `apt_snapshot = "latest"` (casual only) resolves to the current instant
instead — current, at the cost of reproducibility.

A digest-pinned base image only freezes what's already baked in — every `apt-get install` on
top still resolves against the *live* archive at build time, so two builds of an identical
Dockerfile weeks apart can silently link a different `gcc`/`binutils` with no warning. The apt
snapshot fixes that: one timestamp across all four suites, so resolution is identical
anywhere, any day.

## Sources of nondeterminism this pipeline eliminates

- **Timestamps** — every rootfs file is set to epoch zero (`touch -h -d @0`) before packing.
- **File ordering** — `find | LC_ALL=C sort` before `cpio`.
- **Kernel build variables** — `KBUILD_BUILD_TIMESTAMP`/`_USER`/`_HOST`/`_VERSION` and
  `SOURCE_DATE_EPOCH` are fixed (`assets/kernel/build_kernel.sh`).
- **Cargo target directory** — `CARGO_TARGET_DIR=/tmp/cargo-target` in-container, so no
  host-side cache leaks in.
- **Rust codegen-unit parallelism** — `RUSTFLAGS="-C codegen-units=1"` for
  `cargo-unikernel-init` and the app (Mode A, `"rust"`); racing LLVM codegen threads otherwise
  make section/symbol order nondeterministic on identical source. The kernel (C/Kbuild) is
  unaffected.
- **Kernel struct-layout randomization seed** — a fixed public seed replaces
  `CONFIG_GCC_PLUGIN_RANDSTRUCT`'s fresh-per-build default (`gen-randstruct-seed.sh`).
- **Python hash randomization** — `PYTHONHASHSEED=0` for `ukify`, since unseeded hashing
  randomizes dict/set iteration order in its section-assembly code.

## Provenance across app-acquisition modes

- **Mode A** (`path`) builds whatever's on disk right now — as reproducible as your working
  tree. For third-party verification (e.g. a trusted sev-snp measurement), build via a tagged
  CI release instead (`cargo unikernel github init` triggers on any `v*` tag), so "the input"
  is an immutable, publicly-inspectable commit rather than an uncommitted local tree.
- **Mode B**: `[app.binary].path` is always a local file — never fetched over the network, so
  there's no download step to authenticate. Provenance is whatever produced that file on your
  machine; `cargo-unikernel` can only verify the same bytes get embedded, not where they came
  from.
- **SEV-SNP OVMF firmware**: `preset = "builtin"` has no network fetch and no reproducibility
  question beyond the hash test above. A provider-supplied `path` is your own trust decision —
  always a local file, so verify the provider's published hash against it yourself.

## Per-format determinism notes

- **cpio+bzImage** — fully deterministic given the pinned toolchain and the
  timestamp/sort discipline above. The most-exercised path.
- **UKI** — deterministic given a pinned `ukify`/systemd and no "current time" defaults during
  PE assembly. Its embedded cmdline shares one source of truth with `sev-snp-measure.py`, so
  the two can't drift.
- **ISO** — deterministic given pinned Limine and explicit `xorriso` flags. For sev-snp it's a
  convenience/testing artifact, not what gets measured (always cpio+bzImage or UKI).

## Verifying a build yourself

```bash
git clone <this-app-repo>
git checkout <the-tagged-release-you're-verifying>
# run the equivalent build inside assets/docker/Dockerfile.reproducible yourself,
# or just re-run `cargo unikernel build` against the same config at that commit.
```

For sev-snp, compare the resulting `dist/sev_measurement.txt` (and inspect
`sev_measurement.json` for the vcpu/type/cmdline/OVMF inputs that produced it) against the
value published alongside the image you're verifying.
