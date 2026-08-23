# sev-snp-server-example

A minimal HTTP server that shows off `cargo-unikernel`'s `sev-snp` profile end to end. It
serves `Hello, world!` on `/`, and on `/attestation` (optionally `?nonce=<hex>`) it opens
`/dev/sev-guest` directly and returns the raw AMD SEV-SNP attestation report — proof, to
whatever remote party is talking to it, that this exact measured image is what's running.

Not a library, not a dependency of the `cargo-unikernel` binary — a standalone crate with its
own `Cargo.lock`, built the same way any user's app would be: `cargo-unikernel` compiles it
inside the pinned reproducible-build container and cross-compiles it to
`x86_64-unknown-linux-musl`. Kept out of the root workspace for the same reason `guest/` is —
so nothing here can leak into, or be constrained by, the CLI crate's own toolchain or lints
(this one needs `unsafe` for the `ioctl` call; the CLI denies it).

## Building it yourself

```sh
cd sev-snp-server-example
cargo unikernel build --config cargo-unikernel.toml
cat dist/sev_measurement.txt
```

## Release pipeline

[`.github/workflows/sev-snp-server-example-release.yml`](../.github/workflows/sev-snp-server-example-release.yml)
builds this image on every push to `main` (keeps the kernel-build cache warm — GitHub Actions
cache scopes don't cross tags) and publishes a GitHub Release — the UKI, `sev_measurement.txt`/
`.json`, and the OVMF firmware — whenever a `sev-snp-server-v*` tag is pushed. One build per
trigger; the kernel compile is the expensive part of this pipeline, so nothing here doubles it.

## Verifying a release

Don't just trust that `cargo-unikernel`'s own build produced what it says it did — check it
one of two ways:

**1. Rebuild it yourself.** Same source, same pinned toolchain (see
[`docs/reproducible_builds.md`](../docs/reproducible_builds.md)) — you should get the same
measurement.

```sh
git clone https://github.com/hacer-bark/cargo-unikernel.git
cd cargo-unikernel
git checkout sev-snp-server-vX.Y.Z   # the tag you're verifying
cargo unikernel build --config sev-snp-server-example/cargo-unikernel.toml
diff sev-snp-server-example/dist/sev_measurement.txt \
  <(gh release download sev-snp-server-vX.Y.Z -p sev_measurement.txt -O -)
```

**2. Compare against the live server.** The latest tagged release runs on real AMD SEV-SNP
hardware at `192.209.63.52` (IPv4) / `[2602:f992:60:a4::1]` (IPv6), port 8000 — this exact
binary, this exact measurement, not a simulator. Pull a fresh report and check its embedded
`measurement` field (offset/layout per AMD's SEV-SNP ABI `ATTESTATION_REPORT` structure)
against the hex in the release's `sev_measurement.txt`:

```sh
curl "http://192.209.63.52:8000/attestation?nonce=$(openssl rand -hex 32)" -o report.bin
```

Use a maintained parser/verifier (e.g. [`virtee/snpguest`](https://github.com/virtee/snpguest))
rather than hand-decoding offsets — it also walks AMD's signing chain (VCEK → ASK → ARK). A
byte-matching measurement alone only proves *someone* built identical bytes; the signature
chain is what proves *this* report came off real SEV-SNP silicon rather than a replay or a
software fake. See
[`docs/threat_model.md#remote-attestation-is-the-apps-job`](../docs/threat_model.md#remote-attestation-is-the-apps-job)
for what this app's own `/attestation` endpoint does and doesn't guarantee on its own.
