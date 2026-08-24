#!/bin/bash
# Builds the guest Linux kernel: base.config + the profile fragment + kconfig/network/*.config
# for [network].mode + kconfig/storage/*.config for [storage].mode + enabled category
# fragments + an optional user-supplied extra-kconfig file — then compiles bzImage
# deterministically.
#
# Every requested option is verified to have survived `make olddefconfig` before anything is
# compiled (see verify_config below) — olddefconfig silently drops any symbol that was renamed,
# removed upstream, has no prompt, or has an unmet dependency, so an unchecked config can claim
# hardening the built kernel doesn't have.
#
# Caching (the expensive step in the pipeline — ~150MB source, minutes to build):
#   - the downloaded source tarball is cached by version+sha256 under $CACHE_DIR/src/
#   - ccache covers compiler invocations across builds with the same toolchain
#   - the finished bzImage is cached under $CACHE_DIR/bzimage/<fingerprint>/, fingerprinted
#     on everything that can change the output bytes — a hit skips download/configure/compile.
set -euo pipefail

# CONFIG_GCC_PLUGIN_RANDSTRUCT's tie-breaking order is influenced by GCC's own ASLR'd
# process layout, so two from-scratch builds of identical source+config can silently produce
# different struct layouts even with the fixed seed below. Re-exec with ASLR disabled so
# every `make`/gcc-plugin invocation runs in a fixed address space.
if [ -z "${CARGO_UNIKERNEL_ASLR_DISABLED:-}" ]; then
    export CARGO_UNIKERNEL_ASLR_DISABLED=1
    exec setarch "$(uname -m)" -R bash "$0" "$@"
fi

KERNEL_VER="${CARGO_UNIKERNEL_KERNEL_VERSION:-6.18.33}"
KERNEL_SHA256="${CARGO_UNIKERNEL_KERNEL_SHA256:-}"
CARGO_UNIKERNEL_PROFILE="${CARGO_UNIKERNEL_PROFILE:-casual}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${CARGO_UNIKERNEL_KERNEL_CACHE_DIR:-/build/cache}"
EXTRA_KCONFIG_FILE="${CARGO_UNIKERNEL_EXTRA_KCONFIG_FILE:-}"

# An absent checksum is a hard failure, not a warning — the host CLI already resolves
# `[kernel].sha256` (or its baked-in default) before generating this script.
if [ -z "$KERNEL_SHA256" ]; then
    echo "CARGO_UNIKERNEL_KERNEL_SHA256 is not set — refusing to build an unverified kernel." >&2
    echo "Pin \`kernel.sha256\` for version $KERNEL_VER (see kernel.org's sha256sums.asc)." >&2
    exit 1
fi

# --- ccache setup (compiler-level cache; helps whenever a full kernel build IS needed) ---
export PATH="/usr/lib/ccache:$PATH"
export CCACHE_DIR="${CCACHE_DIR:-/root/.cache/ccache}"
# Hash compiler contents, not mtime+size — the randstruct GCC plugin is rebuilt per source
# tree, and a path-only match could serve objects built against a stale plugin.
export CCACHE_COMPILERCHECK="${CCACHE_COMPILERCHECK:-content}"
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

# Networking: one fragment per protocol so a disabled protocol has no NIC driver/IP stack
# compiled in at all. "Neither selected" gets its own fragment (explicitly disabling
# virtio-net) rather than just omitting the others — see kconfig/network/*.config. Both env
# vars default to "0" (the host CLI always sets them explicitly; this is just the fallback).
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

# FIPS defaults to disabled (opposite of every category above) — a compliance opt-in.
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

# --- Parse every fragment up front, into one "last write wins" directive map ---
#
# Parsed once (not streamed straight into `scripts/config`) so verify_config below can check
# against the same resolved map; a later fragment overriding an earlier one is normal.
declare -A DIRECTIVES=()
DIRECTIVE_ORDER=()

parse_fragment() {
    local fragment_path="$1" line key directive
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        if [[ "$line" != *=* ]]; then
            echo "Malformed line (expected KEY=directive) in $fragment_path: $line" >&2
            exit 1
        fi
        key="${line%%=*}"
        directive="${line#*=}"
        case "$directive" in
            enable|disable|set-str:*|set-val:*) ;;
            *)
                echo "Unrecognized directive '$directive' for $key in $fragment_path" >&2
                exit 1
                ;;
        esac
        if [ -z "${DIRECTIVES[$key]+set}" ]; then
            DIRECTIVE_ORDER+=("$key")
        fi
        DIRECTIVES["$key"]="$directive"
    done < "$fragment_path"
}

for fragment_path in "${FRAGMENTS[@]}"; do
    parse_fragment "$fragment_path"
done

# --- Fingerprint ---
#
# Covers this script and the toolchain versions too, not just the config — otherwise editing
# the randstruct seed below, or bumping the compiler, would cache-hit a stale bzImage.
fingerprint_input() {
    echo "$KERNEL_VER"
    echo "$KERNEL_SHA256"
    sha256sum "${BASH_SOURCE[0]}"
    gcc --version 2>/dev/null | head -1 || echo "gcc unknown"
    ld --version 2>/dev/null | head -1 || echo "ld unknown"
    make --version 2>/dev/null | head -1 || echo "make unknown"
    for key in "${DIRECTIVE_ORDER[@]}"; do
        echo "$key=${DIRECTIVES[$key]}"
    done
}
FINGERPRINT=$(fingerprint_input | sha256sum | cut -d' ' -f1)
CACHED_BZIMAGE="$CACHE_DIR/bzimage/$FINGERPRINT/bzImage"

mkdir -p "$CACHE_DIR/src" "$CACHE_DIR/bzimage" linux-kernel/arch/x86/boot
if [ -f "$CACHED_BZIMAGE" ]; then
    echo "Kernel config fingerprint $FINGERPRINT matches a cached build — skipping download/compile."
    cp "$CACHED_BZIMAGE" linux-kernel/arch/x86/boot/bzImage
    echo "Done! Kernel is at: linux-kernel/arch/x86/boot/bzImage (from cache)"
    exit 0
fi

# --- Download (cached by version, always sha256-verified) ---
TARBALL="$CACHE_DIR/src/linux-${KERNEL_VER}.tar.xz"
if [ -f "$TARBALL" ]; then
    echo "Using cached kernel source tarball: $TARBALL"
else
    echo "Downloading Linux kernel source v$KERNEL_VER..."
    wget -qO "$TARBALL.partial" "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${KERNEL_VER}.tar.xz"
    mv "$TARBALL.partial" "$TARBALL"
fi
# Verified on the cached path too — otherwise one poisoned cache entry is trusted forever.
echo "$KERNEL_SHA256  $TARBALL" | sha256sum -c - || {
    echo "Kernel tarball sha256 mismatch for v$KERNEL_VER — refusing to build" >&2
    rm -f "$TARBALL"
    exit 1
}

rm -rf linux-kernel
tar -xf "$TARBALL"
mv "linux-${KERNEL_VER}" linux-kernel
cd linux-kernel

# CONFIG_GCC_PLUGIN_RANDSTRUCT (self-protection.config) otherwise draws a fresh seed from
# /dev/urandom on every from-scratch build, breaking every measurement comparison. Replace
# the seed generator with a fixed, public one instead (same trade-off Debian's
# reproducible-builds project makes for this plugin). Must land before the first `make`
# below — the seed file is generated lazily, not necessarily during the final bzImage build.
cat > scripts/gen-randstruct-seed.sh <<'RANDSTRUCT_SEED_EOF'
#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
# Fixed, public seed — not a secret, just needed constant for reproducible builds.
# randomize_layout_plugin.c expects exactly 64 hex chars (sha256 output fits that shape).
SEED=$(echo -n "unikarnel-fixed-randstruct-seed" | sha256sum | cut -d" " -f1)
echo "$SEED" > "$1"
HASH=$(echo -n "$SEED" | sha256sum | cut -d" " -f1)
echo "#define RANDSTRUCT_HASHED_SEED \"$HASH\"" > "$2"
RANDSTRUCT_SEED_EOF

echo "Configuring minimal KVM guest kernel..."
make defconfig
make kvm_guest.config

echo "Applying ${#DIRECTIVE_ORDER[@]} kconfig directives from: ${FRAGMENTS[*]}"
for key in "${DIRECTIVE_ORDER[@]}"; do
    directive="${DIRECTIVES[$key]}"
    case "$directive" in
        enable) scripts/config --enable "$key" ;;
        disable) scripts/config --disable "$key" ;;
        set-str:*) scripts/config --set-str "$key" "${directive#set-str:}" ;;
        set-val:*) scripts/config --set-val "$key" "${directive#set-val:}" ;;
    esac
done

echo "Resolving dependencies and finalizing configuration..."
make olddefconfig

# --- Verify every directive actually took ---
#
# `make olddefconfig` silently discards anything it can't satisfy — a renamed symbol, an
# upstream removal, or a missed dependency all show up as nothing at all. Fail the build
# rather than warn: these are security options.
verify_config() {
    local key directive expected actual failures=0
    for key in "${DIRECTIVE_ORDER[@]}"; do
        directive="${DIRECTIVES[$key]}"
        actual="$(grep -E "^($key=|# $key is not set)" .config || true)"
        case "$directive" in
            enable)
                # `y` or `m` both count. CONFIG_MODULES=n means nothing ends up `m` in
                # practice, but that distinction isn't this check's to enforce.
                expected="$key=y or $key=m"
                [[ "$actual" == "$key=y" || "$actual" == "$key=m" ]] && continue
                ;;
            disable)
                # Absent counts as disabled — a symbol removed upstream is dead weight, not a
                # security hole.
                expected="# $key is not set (or absent)"
                [[ -z "$actual" || "$actual" == "# $key is not set" ]] && continue
                ;;
            set-val:*)
                expected="$key=${directive#set-val:}"
                [[ "$actual" == "$expected" ]] && continue
                ;;
            set-str:*)
                expected="$key=\"${directive#set-str:}\""
                [[ "$actual" == "$expected" ]] && continue
                ;;
        esac
        echo "  $key: requested '$directive', expected '$expected', got '${actual:-<absent>}'" >&2
        failures=$((failures + 1))
    done

    if [ "$failures" -gt 0 ]; then
        cat >&2 <<VERIFY_EOF

$failures kconfig option(s) above did not survive 'make olddefconfig' — refusing to build.

Each one was requested by a fragment in assets/kernel/kconfig/ and then dropped, which means
the built kernel would NOT have had it. Usual causes, in rough order of likelihood:
  - the symbol was renamed or removed in Linux $KERNEL_VER (drop the line, or use the new name)
  - a dependency is unmet, often disabled by an earlier fragment (grep the Kconfig 'depends on')
  - the symbol has no prompt in this configuration (CONFIG_EXPERT in base.config unlocks many)
  - it is 'select'ed by something else and not directly settable
VERIFY_EOF
        exit 1
    fi
    echo "All ${#DIRECTIVE_ORDER[@]} requested kconfig options verified present in .config."
}
verify_config

echo "Compiling the kernel (this will take a few minutes; ccache speeds up repeat builds)..."
export KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00"
export KBUILD_BUILD_USER="builder"
export KBUILD_BUILD_HOST="buildhost"
export KBUILD_BUILD_VERSION="1"
export SOURCE_DATE_EPOCH=0

# CONFIG_GCC_PLUGIN_LATENT_ENTROPY reads /dev/urandom directly at compile time unless GCC
# gets `-frandom-seed` — a separate mechanism from the randstruct seed file above, and the
# ASLR re-exec doesn't help it either. This pins it to a fixed, deterministic value instead.
export KCFLAGS="${KCFLAGS:-} -frandom-seed=unikarnel-fixed-latent-entropy-seed"
make -j"$(nproc)" bzImage
ccache -s || true

mkdir -p "$(dirname "$CACHED_BZIMAGE")"
cp arch/x86/boot/bzImage "$CACHED_BZIMAGE"

echo ""
echo "Done! Kernel is at: linux-kernel/arch/x86/boot/bzImage (cached as $FINGERPRINT for next time)"
