#!/bin/bash
# Checks the pinned toolchain versions this project builds against (Ubuntu base image, apt
# snapshot, Rust, e2fsprogs, and the guest kernel) against upstream, and optionally rewrites
# the pins in place. "bump" always means pin to a new exact value plus its verified checksum
# — never a loose version range. (`cryptography`'s pip install is deliberately unpinned
# instead — see the Dockerfile — so it's not tracked here.)
#
# Usage:
#   bump_toolchain_versions.sh                    # report only
#   bump_toolchain_versions.sh --write            # report and rewrite outdated pins in place
#   bump_toolchain_versions.sh --write --snapshot # also refresh SNAPSHOT_TS to "now"
set -euo pipefail

WRITE=0
BUMP_SNAPSHOT=0
for arg in "$@"; do
    case "$arg" in
        --write) WRITE=1 ;;
        --snapshot) BUMP_SNAPSHOT=1 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DOCKERFILE="$ROOT/assets/docker/Dockerfile.reproducible"
SCHEMA="$ROOT/src/schema.rs"

for bin in curl jq sha256sum; do
    command -v "$bin" >/dev/null || { echo "missing required tool: $bin" >&2; exit 1; }
done

OUTDATED=0

EXAMPLE_FILES=(
    "$ROOT/examples/Cargo-Unikernel.casual.toml"
    "$ROOT/examples/Cargo-Unikernel.sev-snp.toml"
    "$ROOT/sev-snp-server-example/cargo-unikernel.toml"
)

# sync_example_docs <sed-pattern> — applied to the commented-out example values in
# examples/*.toml and sev-snp-server-example/cargo-unikernel.toml, which otherwise silently
# drift out of sync with this CLI's real defaults.
sync_example_docs() {
    local pattern="$1" f
    for f in "${EXAMPLE_FILES[@]}"; do
        [ -f "$f" ] && sed -i "$pattern" "$f"
    done
}

# report_status <name> <current> <latest>; returns 0 (outdated) or 1 (up to date) via $?
report_status() {
    local name="$1" current="$2" latest="$3"
    if [ "$current" = "$latest" ]; then
        printf '%-14s up to date (%s)\n' "$name" "$current"
        return 1
    fi
    printf '%-14s %s -> %s\n' "$name" "$current" "$latest"
    OUTDATED=1
    return 0
}

# ---- Ubuntu base image digest ----------------------------------------------------------
# Only re-resolves the digest for the release already pinned — bumping the Ubuntu release
# itself (26.04 -> 28.04) is a separate, deliberate migration, not something this does.
check_ubuntu() {
    local current latest token tag
    tag="$(grep -m1 '^FROM ubuntu:' "$DOCKERFILE" | sed -E 's/^FROM ubuntu:([0-9.]+)@sha256:.*/\1/')"
    current="$(grep -m1 '^FROM ubuntu:' "$DOCKERFILE" | sed -E 's/.*@sha256:([0-9a-f]+).*/\1/')"
    token="$(curl -fsS --max-time 10 \
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/ubuntu:pull" \
        | jq -r .token)"
    latest="$(curl -fsS --max-time 10 -H "Authorization: Bearer $token" \
        -H 'Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json' \
        -D - -o /dev/null \
        "https://registry-1.docker.io/v2/library/ubuntu/manifests/$tag" \
        | grep -i '^docker-content-digest:' | sed -E 's/.*sha256:([0-9a-f]+).*/\1/' | tr -d '\r')"
    if report_status "ubuntu" "$current" "$latest" && [ "$WRITE" -eq 1 ]; then
        sed -i "s/^FROM ubuntu:$tag@sha256:$current/FROM ubuntu:$tag@sha256:$latest/" "$DOCKERFILE"
    fi
}

# ---- Rust ------------------------------------------------------------------------------
check_rust() {
    local current latest channel_file
    current="$(grep -m1 '^ARG RUST_VERSION=' "$DOCKERFILE" | cut -d= -f2)"
    channel_file="$(mktemp)"
    trap 'rm -f "$channel_file"' RETURN
    curl -fsS --max-time 15 -o "$channel_file" https://static.rust-lang.org/dist/channel-rust-stable.toml
    latest="$(awk '/^\[pkg\.rust\]/{f=1; next} f && /^version/{print; exit}' "$channel_file" \
        | sed -E 's/version = "([0-9]+\.[0-9]+\.[0-9]+).*/\1/')"
    if report_status "rust" "$current" "$latest" && [ "$WRITE" -eq 1 ]; then
        sed -i "s/^ARG RUST_VERSION=$current/ARG RUST_VERSION=$latest/" "$DOCKERFILE"
        sync_example_docs "s/rust_version = \"$current\"/rust_version = \"$latest\"/"
    fi
}

# ---- e2fsprogs (sha256sums.asc published alongside the tarball) -----------------------
check_e2fsprogs() {
    local current latest latest_sha current_sha sums
    current="$(grep -m1 '^ARG E2FSPROGS_VERSION=' "$DOCKERFILE" | cut -d= -f2)"
    latest="$(curl -fsS --max-time 10 "https://api.github.com/repos/tytso/e2fsprogs/tags?per_page=20" \
        | jq -r '.[].name' | grep -E '^v[0-9]+\.[0-9]+(\.[0-9]+)?$' | sed 's/^v//' | sort -V | tail -1)"
    if report_status "e2fsprogs" "$current" "$latest" && [ "$WRITE" -eq 1 ]; then
        sums="$(curl -fsS --max-time 10 "https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v${latest}/sha256sums.asc")"
        latest_sha="$(echo "$sums" | awk -v f="e2fsprogs-${latest}.tar.gz" '$2==f{print $1}')"
        [ -n "$latest_sha" ] || { echo "  could not find sha256 for e2fsprogs-${latest}.tar.gz, skipping write" >&2; return; }
        current_sha="$(grep -m1 '^ARG E2FSPROGS_SHA256=' "$DOCKERFILE" | cut -d= -f2)"
        sed -i "s/^ARG E2FSPROGS_VERSION=$current/ARG E2FSPROGS_VERSION=$latest/" "$DOCKERFILE"
        sed -i "s/^ARG E2FSPROGS_SHA256=$current_sha/ARG E2FSPROGS_SHA256=$latest_sha/" "$DOCKERFILE"
    fi
}

# ---- Guest kernel (schema.rs default + baked-in sha256) --------------------------------
check_kernel() {
    local current latest latest_sha current_sha major sums
    current="$(grep -m1 'fn default_kernel_version' -A1 "$SCHEMA" | grep -o '"[0-9.]*"' | tr -d '"')"
    latest="$(curl -fsS --max-time 10 https://www.kernel.org/releases.json | jq -r 'first(.releases[] | select(.moniker=="longterm")) | .version')"
    if report_status "kernel" "$current" "$latest" && [ "$WRITE" -eq 1 ]; then
        major="$(echo "$latest" | cut -d. -f1)"
        sums="$(curl -fsS --max-time 10 "https://www.kernel.org/pub/linux/kernel/v${major}.x/sha256sums.asc")"
        latest_sha="$(echo "$sums" | awk -v f="linux-${latest}.tar.xz" '$2==f{print $1}')"
        [ -n "$latest_sha" ] || { echo "  could not find sha256 for linux-${latest}.tar.xz, skipping write" >&2; return; }
        current_sha="$(grep -m1 '^const DEFAULT_KERNEL_SHA256' -A1 "$SCHEMA" | grep -o '"[0-9a-f]*"' | tr -d '"')"
        sed -i "s/\"$current\"\.to_string()/\"$latest\".to_string()/" "$SCHEMA"
        sed -i "s/$current_sha/$latest_sha/" "$SCHEMA"
        sync_example_docs "s/^version = \"$current\"/version = \"$latest\"/"
    fi
}

# ---- apt snapshot (always "outdated" by design — report only unless --snapshot) -------
check_snapshot() {
    local current now
    current="$(grep -m1 '^ARG SNAPSHOT_TS=' "$DOCKERFILE" | cut -d= -f2)"
    now="$(date -u +%Y%m%dT%H%M%SZ)"
    printf '%-14s pinned at %s (refresh anytime with --snapshot; not a "latest" check)\n' "snapshot" "$current"
    if [ "$BUMP_SNAPSHOT" -eq 1 ] && [ "$WRITE" -eq 1 ]; then
        sed -i "s/^ARG SNAPSHOT_TS=$current/ARG SNAPSHOT_TS=$now/" "$DOCKERFILE"
        echo "  -> bumped to $now"
    fi
}

echo "Checking pinned toolchain versions..."
check_ubuntu
check_rust
check_e2fsprogs
check_kernel
check_snapshot

if [ "$OUTDATED" -eq 1 ] && [ "$WRITE" -eq 0 ]; then
    echo
    echo "Some pins are outdated. Re-run with --write to update them in place."
fi
