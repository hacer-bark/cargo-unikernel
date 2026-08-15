# Documentation

Design, security, and build documentation for `cargo-unikernel`. The
[project README](../README.md) covers installation, quick start, and the CLI — start there
for day-to-day usage. These documents go deeper.

| Document | Covers |
|:---|:---|
| [`architecture.md`](architecture.md) | How the pieces fit together: host CLI, build container, guest init, boot sequence, build pipeline |
| [`toolchains.md`](toolchains.md) | The three ways to get an app into the image, and the trust trade-off each makes |
| [`threat_model.md`](threat_model.md) | Trust boundaries, attack/mitigation catalog, what's out of scope |
| [`reproducible_builds.md`](reproducible_builds.md) | What's pinned, what nondeterminism is eliminated, how to verify a build |
| [`attestation_api.md`](attestation_api.md) | The SEV-SNP attestation HTTP server's wire protocol |

**New to the project?** Read `architecture.md`, then `toolchains.md`.
**Evaluating security posture?** Read `threat_model.md`, then `init_security.md`.
**Verifying a build or measurement?** Read `reproducible_builds.md`.
**Integrating with remote attestation?** Read `attestation_api.md`.
