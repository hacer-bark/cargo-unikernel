#!/bin/bash
# Builds the guest Linux kernel: base.config + the profile fragment + kconfig/network/*.config
# for [network].mode + kconfig/storage/*.config for [storage].mode + enabled category
# fragments + an optional user-supplied extra-kconfig file — then compiles bzImage
# deterministically.
#
# Caching (this is the expensive step in the whole pipeline — the kernel source tarball is
# ~150MB and a from-scratch build takes minutes):
#   - the downloaded source tarball is cached by version+sha256 under $CACHE_DIR/src/
#   - ccache covers the actual compiler invocations across builds with the same toolchain
#   - the *finished* bzImage is cached under $CACHE_DIR/bzimage/<fingerprint>/, where the
#     fingerprint hashes the kernel version + every kconfig fragment that would be applied;
#     if nothing kernel-config-relevant changed since the last build, this whole script
#     short-circuits to a cache hit and copies the prebuilt bzImage out — no download,
#     configure, or compile at all.
set -e

KERNEL_VER="${CARGO_UNIKERNEL_KERNEL_VERSION:-6.18.33}"
KERNEL_SHA256="${CARGO_UNIKERNEL_KERNEL_SHA256:-}"
CARGO_UNIKERNEL_PROFILE="${CARGO_UNIKERNEL_PROFILE:-casual}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${CARGO_UNIKERNEL_KERNEL_CACHE_DIR:-/build/cache}"
EXTRA_KCONFIG_FILE="${CARGO_UNIKERNEL_EXTRA_KCONFIG_FILE:-}"

mkdir -p "$CACHE_DIR/src" "$CACHE_DIR/bzimage"

# --- ccache setup (compiler-level cache; helps whenever a full kernel build IS needed) ---
export PATH="/usr/lib/ccache:$PATH"
export CCACHE_DIR="${CCACHE_DIR:-/root/.cache/ccache}"
ccache -M 5G >/dev/null 2>&1 || true

case "$CARGO_UNIKERNEL_PROFILE" in
    casual) PROFILE_FRAGMENT="casual.config" ;;
    sev-snp) PROFILE_FRAGMENT="sev-snp.config" ;;
    *)
        echo "Unknown CARGO_UNIKERNEL_PROFILE '$CARGO_UNIKERNEL_PROFILE' (expected casual or sev-snp)" >&2
        exit 1
        ;;
esac

# Every optional category fragment, gated by its own env var (default: enabled). Order here
# is the order they're applied in (last write wins per-key, same as scripts/config always).
declare -A CATEGORY_ENV=(
    [legacy-subsystems.config]="CARGO_UNIKERNEL_KHARD_LEGACY_SUBSYSTEMS"
    [debug-interfaces.config]="CARGO_UNIKERNEL_KHARD_DEBUG_INTERFACES"
    [self-protection.config]="CARGO_UNIKERNEL_KHARD_SELF_PROTECTION"
    [exploit-mitigations.config]="CARGO_UNIKERNEL_KHARD_EXPLOIT_MITIGATIONS"
    [seccomp.config]="CARGO_UNIKERNEL_KHARD_SECCOMP"
)
CATEGORY_ORDER=(legacy-subsystems.config debug-interfaces.config self-protection.config exploit-mitigations.config seccomp.config)

FRAGMENTS=("$SCRIPT_DIR/kconfig/base.config" "$SCRIPT_DIR/kconfig/$PROFILE_FRAGMENT")

# Networking: entirely driven by `[network].mode`, one fragment per protocol so a disabled
# protocol has no NIC driver/IP stack compiled in at all — not category-gated like the
# fragments below, since "neither selected" needs its own fragment (explicitly disabling
# virtio-net) rather than just omitting the others. See kconfig/network/*.config. Both env
# vars default to "0" (unlike every CATEGORY_ENV entry below, which defaults to enabled) —
# the host CLI always sets them explicitly either way, this is just the safe fallback.
NET_IPV4="${CARGO_UNIKERNEL_NET_IPV4:-0}"
NET_IPV6="${CARGO_UNIKERNEL_NET_IPV6:-0}"
if [ "$NET_IPV4" = "1" ]; then
    FRAGMENTS+=("$SCRIPT_DIR/kconfig/network/ipv4.config")
fi
if [ "$NET_IPV6" = "1" ]; then
    FRAGMENTS+=("$SCRIPT_DIR/kconfig/network/ipv6.config")
fi
if [ "$NET_IPV4" != "1" ] && [ "$NET_IPV6" != "1" ]; then
    FRAGMENTS+=("$SCRIPT_DIR/kconfig/network/none.config")
fi

for cat in "${CATEGORY_ORDER[@]}"; do
    env_name="${CATEGORY_ENV[$cat]}"
    if [ "${!env_name:-1}" != "0" ]; then
        FRAGMENTS+=("$SCRIPT_DIR/kconfig/categories/$cat")
    fi
done

# FIPS defaults to *disabled* (opposite of every category above) — a compliance-specific
# opt-in, not something every build should pay kernel size/attack surface for.
if [ "${CARGO_UNIKERNEL_KHARD_FIPS:-0}" = "1" ]; then
    FRAGMENTS+=("$SCRIPT_DIR/kconfig/categories/fips.config")
fi

if [ "${CARGO_UNIKERNEL_STORAGE_PERSISTENT:-0}" = "1" ]; then
    FRAGMENTS+=("$SCRIPT_DIR/kconfig/storage/persistent.config")
else
    FRAGMENTS+=("$SCRIPT_DIR/kconfig/storage/ram.config")
fi

if [ -n "$EXTRA_KCONFIG_FILE" ] && [ -f "$EXTRA_KCONFIG_FILE" ]; then
    FRAGMENTS+=("$EXTRA_KCONFIG_FILE")
fi

# --- Fingerprint: kernel version + every fragment's content, in application order ---
FINGERPRINT=$( { echo "$KERNEL_VER"; cat "${FRAGMENTS[@]}"; } | sha256sum | cut -d' ' -f1)
CACHED_BZIMAGE="$CACHE_DIR/bzimage/$FINGERPRINT/bzImage"

mkdir -p linux-kernel/arch/x86/boot
if [ -f "$CACHED_BZIMAGE" ]; then
    echo "Kernel config fingerprint $FINGERPRINT matches a cached build — skipping download/compile."
    cp "$CACHED_BZIMAGE" linux-kernel/arch/x86/boot/bzImage
    echo "Done! Kernel is at: linux-kernel/arch/x86/boot/bzImage (from cache)"
    exit 0
fi

# --- Download (cached by version; sha256-verified if provided) ---
TARBALL="$CACHE_DIR/src/linux-${KERNEL_VER}.tar.xz"
if [ -f "$TARBALL" ]; then
    echo "Using cached kernel source tarball: $TARBALL"
else
    echo "Downloading Linux kernel source v$KERNEL_VER..."
    wget -qO "$TARBALL.partial" "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VER}.tar.xz"
    mv "$TARBALL.partial" "$TARBALL"
fi
if [ -n "$KERNEL_SHA256" ]; then
    echo "$KERNEL_SHA256  $TARBALL" | sha256sum -c - || {
        echo "Kernel tarball sha256 mismatch for v$KERNEL_VER — refusing to build" >&2
        rm -f "$TARBALL"
        exit 1
    }
fi

rm -rf linux-kernel
tar -xf "$TARBALL"
mv "linux-${KERNEL_VER}" linux-kernel
cd linux-kernel

# CONFIG_GCC_PLUGIN_RANDSTRUCT (self-protection.config) otherwise draws a fresh seed from
# /dev/urandom on every from-scratch build via this script, producing a genuinely different
# bzImage each time — even from byte-identical source+config on the same machine. That
# silently breaks every measurement comparison (local-vs-CI, or just rebuild-vs-rebuild).
# Replace the seed generator with one that emits a fixed, public seed instead: this is the
# same trade-off Debian's reproducible-builds project makes for this exact plugin. The
# structure-layout hardening it buys is against generic/offset-reuse exploitation of a
# stock kernel, not against an attacker who already has the source and build recipe — which
# this project's whole measurement/verification model assumes anyway. Must land before the
# first `make` invocation below (scripts/basic/randstruct.seed is generated lazily, the
# first time anything triggers it, not necessarily during the final `make bzImage`).
cat > scripts/gen-randstruct-seed.sh <<'RANDSTRUCT_SEED_EOF'
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Fixed, public seed — see build_kernel.sh. Deterministic structure-layout randomization,
# not a security secret; reproducible builds require this to be constant across runs.
SEED="c0ffee00d15ea5e0feedface0d15c0deba5eba11c0ffee00d15ea5e0feedface0d15c0deb"
echo "$SEED" > "$1"
HASH=$(echo -n "$SEED" | sha256sum | cut -d" " -f1)
echo "#define RANDSTRUCT_HASHED_SEED \"$HASH\"" > "$2"
RANDSTRUCT_SEED_EOF

echo "Configuring minimal KVM guest kernel..."
make defconfig
make kvm_guest.config

echo "Applying kconfig fragments: ${FRAGMENTS[*]}"
for fragment_path in "${FRAGMENTS[@]}"; do
    while IFS='=' read -r key directive; do
        # Skip blank lines and comments
        [[ -z "$key" || "$key" == \#* ]] && continue
        case "$directive" in
            enable) scripts/config --enable "$key" ;;
            disable) scripts/config --disable "$key" ;;
            set-str:*) scripts/config --set-str "$key" "${directive#set-str:}" ;;
            set-val:*) scripts/config --set-val "$key" "${directive#set-val:}" ;;
            *)
                echo "Unrecognized directive '$directive' for $key in $fragment_path" >&2
                exit 1
                ;;
        esac
    done < "$fragment_path"
done

echo "Resolving dependencies and finalizing configuration..."
make olddefconfig

echo "Compiling the kernel (this will take a few minutes; ccache speeds up repeat builds)..."
export KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00"
export KBUILD_BUILD_USER="builder"
export KBUILD_BUILD_HOST="buildhost"
export KBUILD_BUILD_VERSION="1"
export SOURCE_DATE_EPOCH=0
make -j"$(nproc)" bzImage
ccache -s || true

mkdir -p "$(dirname "$CACHED_BZIMAGE")"
cp arch/x86/boot/bzImage "$CACHED_BZIMAGE"

echo ""
echo "Done! Kernel is at: linux-kernel/arch/x86/boot/bzImage (cached as $FINGERPRINT for next time)"
