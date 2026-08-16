//! `cargo-unikernel.toml` config schema + validation.
//!
//! This is a plain module of the CLI crate (not a shared library) — the guest init never
//! reads this schema at runtime, so there's no reason to publish/depend on it as a separate
//! crate. See `guest/` for the (separately embedded) guest-side source.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The full parsed and validated contents of a `cargo-unikernel.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// `[project]` — the project's name and optional pinned CLI version.
    pub project: Project,
    /// `[profile]` — `casual` or `sev-snp`.
    pub profile: Profile,
    /// `[app]` — how the app binary is acquired (source build or pre-built binary) and its
    /// runtime settings.
    pub app: App,
    /// `[network]` — guest network configuration.
    #[serde(default)]
    pub network: Network,
    /// `[storage]` — RAM-only vs. persistent `/var`.
    #[serde(default)]
    pub storage: Storage,
    /// `[kernel]` — which Linux kernel version to build.
    #[serde(default)]
    pub kernel: Kernel,
    /// `[toolchain]` — pins for the reproducible build toolchain itself.
    #[serde(default)]
    pub toolchain: ToolchainPins,
    /// `[hardening]` — build-time and runtime hardening toggles.
    #[serde(default)]
    pub hardening: Hardening,
    /// `[sev_snp]` — confidential-computing profile settings (sev-snp only).
    pub sev_snp: Option<SevSnp>,
    /// `[output]` — which image formats to produce and where.
    pub output: Output,
    /// `[release]` — which `dist/` assets a GitHub Release includes.
    #[serde(default)]
    pub release: Release,
}

/// `[project]` — identifies the project and, optionally, pins it to an exact CLI version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    /// Used verbatim in generated file paths, shell commands, and output filenames — see
    /// `ValidationError::InvalidProjectName` for the allowed character set.
    pub name: String,
    /// The `cargo-unikernel` CLI version this config is pinned to. When set,
    /// `Config::validate` rejects any run under a different version, since that can bundle a
    /// different kernel/Dockerfile/hardening defaults and change the built image's bytes.
    /// Optional for `casual`; required for `sev-snp` (`Config::validate` rejects an unset
    /// value there — an unpinned CLI version means an unpinned launch measurement).
    #[serde(default)]
    pub cargo_unikernel_version: Option<String>,
}

/// The running binary's own version — what `project.cargo_unikernel_version` is checked
/// against.
pub const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Which build profile: the default, no-frills `Casual` profile, or the AMD SEV-SNP
/// confidential-computing `SevSnp` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileKind {
    /// The default, no-frills profile: no measurement, no confidential-computing guarantees.
    Casual,
    /// AMD SEV-SNP confidential computing: measured boot, encrypted guest memory.
    SevSnp,
}

/// `[profile]` — selects `ProfileKind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// `casual` or `sev-snp`.
    pub kind: ProfileKind,
}

/// How the app gets into the image: compiled from source, or a pre-built binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppMode {
    /// `[app.source]` is compiled (or run through a generic `build_command`) inside the
    /// build container.
    Source,
    /// `[app.binary]` — a local file or a URL — is verified and embedded as-is.
    Binary,
}

/// `[app]` — how the app binary is acquired and how it runs once booted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    /// `source` or `binary` — selects which of `source`/`binary` below is used.
    pub mode: AppMode,
    /// Required when `mode = "source"`.
    pub source: Option<AppSource>,
    /// Required when `mode = "binary"`.
    pub binary: Option<AppBinary>,
    /// `[app.runtime]` — env vars, uid/gid, resource limits, and danger opt-outs applied to
    /// the app process before exec.
    #[serde(default)]
    pub runtime: AppRuntime,
}

/// How the app in `[app.source]` gets built inside the container.
///
/// `Rust` is the flagship path — `cargo build`, cross-compiled to musl, zero extra config.
/// `Generic` covers everything else: any language/build system whose output is a single
/// (ideally statically-linked) binary, driven by a user-supplied `build_command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Toolchain {
    /// `cargo build`, cross-compiled to `x86_64-unknown-linux-musl`. Zero extra config.
    Rust,
    /// A user-supplied `build_command`/`output_binary` — any language/build system that
    /// produces a single static binary.
    Generic,
}

/// `[app.source]` — where the app's source comes from and how it's built.
///
/// Builds the project directory itself (mounted as `/workspace`) — no git involved at all,
/// the project directory itself is the source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSource {
    /// Build the project directory itself (mounted as `/workspace`) — no git involved.
    /// Required.
    pub path: Option<String>,
    /// `rust` or `generic` — see `Toolchain`.
    pub toolchain: Toolchain,
    /// Subdirectory (relative to `path`) containing the actual package to build — for
    /// monorepos where the buildable project isn't at the path root.
    #[serde(default = "default_package_path")]
    pub package_path: String,
    /// `toolchain = "rust"` only: the `--profile` passed to `cargo build`.
    #[serde(default = "default_cargo_profile")]
    pub cargo_profile: String,
    /// `toolchain = "rust"` only: `cargo build --features` list.
    #[serde(default)]
    pub features: Vec<String>,
    /// `toolchain = "generic"` only: shell command, cwd'd at `package_path`, that produces
    /// the app binary. Must be statically linked — no dynamic linker in the minimal rootfs.
    pub build_command: Option<String>,
    /// `toolchain = "generic"` only: path to the built binary, relative to `package_path`.
    pub output_binary: Option<String>,
    /// `toolchain = "generic"` only: extra `apt-get install` packages for a toolchain not
    /// already in `assets/docker/Dockerfile.reproducible`.
    #[serde(default)]
    pub extra_apt_packages: Vec<String>,
}

fn default_package_path() -> String {
    ".".to_string()
}

fn default_cargo_profile() -> String {
    "release".to_string()
}

/// `[app.binary]` — a pre-built app binary, already on disk. Required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBinary {
    /// A local file already on disk, inside the project directory.
    pub path: Option<String>,
}

/// `[app.runtime]` — env vars, uid/gid, and resource limits applied to the app process
/// before exec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRuntime {
    /// Environment variables set on the app process.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// uid the app process runs as after exec (dropped from root). Must not be `0` — the drop
    /// is a `setuid` call, which succeeds and changes nothing when asked for root.
    #[serde(default = "default_uid")]
    pub uid: u32,
    /// gid the app process runs as after exec (dropped from root). Must not be `0`, for the
    /// same reason as `uid`.
    #[serde(default = "default_gid")]
    pub gid: u32,
    /// `[app.runtime.danger]` — opt-in escape hatches from the default lockdown.
    #[serde(default)]
    pub danger: DangerRuntime,
    /// `[app.runtime.limits]` — `setrlimit` ceilings.
    #[serde(default)]
    pub limits: AppLimits,
}

const fn default_uid() -> u32 {
    65534
}
const fn default_gid() -> u32 {
    65534
}

impl Default for AppRuntime {
    fn default() -> Self {
        Self {
            env: BTreeMap::new(),
            uid: default_uid(),
            gid: default_gid(),
            danger: DangerRuntime::default(),
            limits: AppLimits::default(),
        }
    }
}

/// `setrlimit` ceilings applied to the app child process before exec — defense-in-depth
/// against a fork bomb, fd exhaustion, or unbounded memory growth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppLimits {
    /// `RLIMIT_NOFILE` — max open file descriptors.
    #[serde(default = "default_max_open_files")]
    pub max_open_files: u64,
    /// `RLIMIT_NPROC` — max processes/threads for this uid, guards against fork bombs.
    #[serde(default = "default_max_processes")]
    pub max_processes: u64,
    /// `RLIMIT_AS` in MiB. `0` (the default) means no cap.
    #[serde(default)]
    pub max_memory_mb: u64,
    /// `RLIMIT_MEMLOCK` in MiB — how much memory the app may pin with `mlock`/`mlockall`.
    ///
    /// Raised well above the kernel's default so an app can keep key material out of any
    /// future swap, but deliberately finite: an unlimited allowance lets a compromised app pin
    /// all of guest RAM, which is the same resource-exhaustion problem the other fields here
    /// exist to bound.
    #[serde(default = "default_max_locked_memory_mb")]
    pub max_locked_memory_mb: u64,
}

const fn default_max_open_files() -> u64 {
    65536
}
const fn default_max_processes() -> u64 {
    2048
}
const fn default_max_locked_memory_mb() -> u64 {
    64
}

impl Default for AppLimits {
    fn default() -> Self {
        Self {
            max_open_files: default_max_open_files(),
            max_processes: default_max_processes(),
            max_memory_mb: 0,
            max_locked_memory_mb: default_max_locked_memory_mb(),
        }
    }
}

/// Opt-in escape hatches from this project's default lockdown.
///
/// Grouped under `[app.runtime.danger]` so they can't blend in with ordinary config by
/// accident. Every field defaults to `false` — see `docs/architecture.md`'s boot sequence
/// for the default posture this opts out of.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DangerRuntime {
    /// DANGER: mounts `/tmp` executable instead of `noexec`, letting the app write and run
    /// new code at runtime. A compromised app can then persist arbitrary code for the rest
    /// of that boot — still wiped on the next reboot, since only `/tmp` is affected.
    #[serde(default)]
    pub allow_write_execute: bool,
}

/// Which IP protocol(s) the guest supports.
///
/// This is a **compile-time** choice, not a runtime toggle: whichever protocol(s) aren't
/// selected have their guest-side code and kernel config left out of the build entirely
/// (`CONFIG_IPV6`/`CONFIG_VIRTIO_NET`/`CONFIG_IP_PNP*` are only ever enabled for a protocol
/// actually in use) — there's no "networking disabled" branch sitting compiled-in-but-unused
/// anywhere for an attacker to reach through a memory-disclosure bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// IPv4 only, via kernel cmdline `ip=dhcp`. The default (matches this tool's original,
    /// IPv4-only behavior).
    Ipv4,
    /// IPv6 only, via SLAAC (router advertisements) — no kernel cmdline parameter needed.
    Ipv6,
    /// Both IPv4 (`ip=dhcp`) and IPv6 (SLAAC).
    Dual,
    /// No networking at all: no virtio-net device, no IP stack compiled into the kernel, no
    /// network bring-up code in the guest init.
    None,
}

impl NetworkMode {
    /// Whether this mode compiles in IPv4 support.
    #[must_use]
    pub const fn has_ipv4(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Dual)
    }

    /// Whether this mode compiles in IPv6 support.
    #[must_use]
    pub const fn has_ipv6(self) -> bool {
        matches!(self, Self::Ipv6 | Self::Dual)
    }

    /// Whether this mode compiles in any networking at all.
    #[must_use]
    pub const fn has_any(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// `[network]` — guest network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// `ipv4`, `ipv6`, `dual`, or `none` — see [`NetworkMode`].
    #[serde(default = "default_network_mode")]
    pub mode: NetworkMode,
    /// `[network.ipv6_static]` — a fixed IPv6 address instead of relying on SLAAC. Omitted by
    /// default; see [`Ipv6Static`].
    pub ipv6_static: Option<Ipv6Static>,
}

const fn default_network_mode() -> NetworkMode {
    NetworkMode::Ipv4
}

impl Default for Network {
    fn default() -> Self {
        Self {
            mode: default_network_mode(),
            ipv6_static: None,
        }
    }
}

/// `[network.ipv6_static]` — assigns a fixed IPv6 address at boot.
///
/// Exists because SLAAC's address is not knowable in advance: the interface identifier is
/// derived from the virtio-net MAC the hypervisor picked, so the only way to learn the guest's
/// address is to read it off the boot console. A guest you cannot attach a console to — the
/// normal case on a confidential-computing host — therefore has no reachable address you could
/// have put in DNS beforehand. A static address is known before the image ever boots.
///
/// Assigned *in addition to* whatever SLAAC provides, not instead of it: router advertisements
/// are what supply the default route in the common case, and turning `accept_ra` off to suppress
/// the extra address would take the route with it. The app binds the address configured here;
/// the SLAAC one existing alongside costs nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Static {
    /// The address to assign, e.g. `"2001:db8:1:2::1"`. With a `/64` from a provider, any host
    /// part works and `::1` is the conventional pick; with a single `/128`, this is that exact
    /// address.
    pub address: String,
    /// Prefix length of the address above. `64` matches what providers hand out most often;
    /// use `128` for a single delegated address.
    #[serde(default = "default_ipv6_prefix_len")]
    pub prefix_len: u8,
    /// Default-route next hop, for a provider that routes a prefix to the VM without sending
    /// router advertisements — in that setup nothing else installs a default route, and the
    /// address alone leaves the guest unreachable. Usually the provider's link-local
    /// (`"fe80::1"`). Omit when router advertisements are present, which is the common case.
    pub gateway: Option<String>,
    /// Which interface to configure. Omitted means the sole non-loopback interface, which is
    /// what a single-NIC guest always has; set it explicitly only for a multi-NIC guest.
    pub interface: Option<String>,
}

const fn default_ipv6_prefix_len() -> u8 {
    64
}

/// Whether `/var` (and other long-term-storage paths) live only in RAM or persist across
/// reboots on a disk-backed device. Also a compile-time choice: `Ram` compiles no virtio-blk
/// driver in at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageMode {
    /// Everything wiped on every reboot; nothing on disk. The default.
    Ram,
    /// `/var` persists across reboots on a virtio-blk device — see `mounts::storage`.
    Persistent,
}

/// `[storage]` — RAM-only vs. persistent `/var`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Storage {
    /// `ram` or `persistent` — see [`StorageMode`].
    #[serde(default = "default_storage_mode")]
    pub mode: StorageMode,
    /// Size of the persistent disk image, in MiB. Only meaningful for `mode = "persistent"`.
    #[serde(default = "default_storage_size_mib")]
    pub size_mib: u32,
}

const fn default_storage_mode() -> StorageMode {
    StorageMode::Ram
}

const fn default_storage_size_mib() -> u32 {
    4096
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            mode: default_storage_mode(),
            size_mib: default_storage_size_mib(),
        }
    }
}

/// `[kernel]` — which Linux kernel to build.
///
/// The tarball (and, once compiled, the resulting bzImage for this exact kconfig) are cached
/// locally, so changing unrelated things (your app code, output formats) never triggers a
/// redownload or rebuild of the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Kernel {
    /// Exact `kernel.org` version to build, e.g. `"6.18.33"`.
    #[serde(default = "default_kernel_version")]
    pub version: String,
    /// Optional sha256 of the upstream kernel.org tarball, checked before build if set.
    pub sha256: Option<String>,
}

fn default_kernel_version() -> String {
    "6.18.33".to_string()
}

/// sha256 of `linux-6.18.33.tar.xz`, verified against kernel.org's own published
/// `sha256sums.asc` — baked in so the zero-config path (the flagship, most-used path) checks
/// the downloaded kernel tarball's integrity out of the box, without requiring a config file
/// just to pin a hash for the version this tool already defaults to.
const DEFAULT_KERNEL_SHA256: &str =
    "6f16ff302599f6fe34742890322cf0775703105fbd8767449682fca6af0fb782";

impl Default for Kernel {
    fn default() -> Self {
        Self {
            version: default_kernel_version(),
            sha256: Some(DEFAULT_KERNEL_SHA256.to_string()),
        }
    }
}

impl Kernel {
    /// The checksum this build must verify the downloaded tarball against.
    ///
    /// Falls back to the baked-in hash when `sha256` wasn't set and `version` is still the
    /// built-in default, which covers a config that sets `[kernel]` explicitly but partially.
    /// A changed `version` has no default to safely guess and yields `None`, which
    /// `Config::validate` rejects.
    ///
    /// Resolved here rather than filled into the struct during config loading, so there is no
    /// ordering question about whether the fill ran before the value was read: validation and
    /// the build script both ask this one function. The previous arrangement only *warned*
    /// about a missing hash, which meant the config change most likely to be made by someone
    /// who cares about kernel provenance — pinning a different version — was also the one that
    /// silently dropped integrity checking on the download.
    #[must_use]
    pub fn sha256_for_build(&self) -> Option<String> {
        self.sha256.clone().or_else(|| {
            (self.version == default_kernel_version()).then(|| DEFAULT_KERNEL_SHA256.to_string())
        })
    }
}

/// `[toolchain]` — overrides for the reproducible-build toolchain this CLI pins by default.
///
/// Covers the apt package snapshot, Rust, Limine, and e2fsprogs pins — see
/// `docs/reproducible_builds.md`. All optional; omit to use this CLI version's tested
/// defaults. Overriding any of these makes the build reproducible given that exact pin, not
/// comparable to a build using this CLI version's own defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolchainPins {
    /// `snapshot.ubuntu.com` timestamp (`YYYYMMDDTHHMMSSZ`) apt resolves gcc/binutils/
    /// musl-tools/python3/xorriso/systemd-ukify/golang/cpio against. `"latest"` resolves to
    /// right now at build time — casual profile only, rejected for sev-snp.
    pub apt_snapshot: Option<String>,
    /// `rustup --default-toolchain` version used to build `cargo-unikernel-init` and Mode A
    /// Rust apps.
    pub rust_version: Option<String>,
    /// Limine bootloader release tag (ISO output only).
    pub limine_version: Option<String>,
    /// sha256 of the Limine release tarball. Recommended whenever `limine_version` is set —
    /// warns (not rejected) if omitted.
    pub limine_sha256: Option<String>,
    /// `e2fsprogs` release used to build the static `mke2fs` bundled into `storage-persistent`
    /// images (`[storage].mode = "persistent"` only).
    pub e2fsprogs_version: Option<String>,
    /// sha256 of the `e2fsprogs` release tarball. Recommended whenever `e2fsprogs_version` is
    /// set — warns (not rejected) if omitted.
    pub e2fsprogs_sha256: Option<String>,
}

impl ToolchainPins {
    /// Warns (doesn't reject) if `limine_version` was overridden without a matching
    /// `limine_sha256` — mirrors `Kernel::fill_default_sha256_or_warn`, but there's no
    /// baked-in hash to fall back to once the version itself has changed.
    pub fn warn_if_limine_unverified(&self) {
        if self.limine_version.is_some() && self.limine_sha256.is_none() {
            eprintln!(
                "[WARN] toolchain.limine_version is set without toolchain.limine_sha256 — the \
                 downloaded Limine release will NOT be integrity-checked. Pin \
                 `toolchain.limine_sha256` (see the release's published checksum) to verify it."
            );
        }
    }

    /// Same as [`Self::warn_if_limine_unverified`], for `e2fsprogs_version`.
    pub fn warn_if_e2fsprogs_unverified(&self) {
        if self.e2fsprogs_version.is_some() && self.e2fsprogs_sha256.is_none() {
            eprintln!(
                "[WARN] toolchain.e2fsprogs_version is set without toolchain.e2fsprogs_sha256 \
                 — the downloaded e2fsprogs release will NOT be integrity-checked. Pin \
                 `toolchain.e2fsprogs_sha256` (see the release's published sha256sums.asc) to \
                 verify it."
            );
        }
    }
}

/// Coarse hardening preset — currently a placeholder; per-category toggles below are what
/// actually take effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HardeningLevel {
    /// Every category below at its own default (all enabled).
    Default,
    /// Reserved for a future stricter preset — currently behaves the same as `Default`.
    Strict,
}

/// `[hardening.kernel]` — build-time (Kconfig) hardening categories.
///
/// See `assets/kernel/kconfig/categories/*.config` for exactly what each one applies. `None`
/// means enabled (the default for every category regardless of `level`, which is reserved
/// for future presets).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KernelHardening {
    /// Strip sound, USB, DRM/framebuffer, wireless/Bluetooth, legacy network protocols, and
    /// most local filesystem drivers this server almost certainly never touches.
    pub disable_legacy_subsystems: Option<bool>,
    /// Strip debugfs, `SysRq`, kprobes/ftrace, /proc/kcore, and kernel debug symbols.
    pub disable_debug_interfaces: Option<bool>,
    /// KSPP baseline: ASLR, zero-on-alloc/free, hardened usercopy/slab, stack protector,
    /// structure-layout randomization, page poisoning, the Lockdown LSM, disables
    /// userfaultfd/live-patching. Applies to both profiles (not sev-snp-only).
    pub kernel_self_protection: Option<bool>,
    /// Spectre/Meltdown-class CPU mitigations: SMEP/SMAP/UMIP, PTI, retpoline. Small
    /// performance cost (mainly PTI) — disable only after a deliberate trade-off decision.
    pub exploit_mitigations: Option<bool>,
    /// Enables seccomp/seccomp-BPF support (your app still installs its own filter to use
    /// it) and disables a couple of legacy syscall-adjacent interfaces.
    pub seccomp: Option<bool>,
    /// Compiles in `CONFIG_CRYPTO_FIPS` (FIPS 140-2/3 mode capability — `fips_enabled`,
    /// crypto self-tests). Off by default: this is a compliance-specific opt-in, not
    /// something every deployment wants paid for in kernel size/attack surface, so unlike
    /// the other categories above it does NOT default to enabled.
    #[serde(default)]
    pub fips: bool,
}

/// `[hardening.runtime]` — sysctl hardening categories, applied by the guest at boot.
///
/// Each one maps to a Cargo feature compiled into `cargo-unikernel-init` (not a runtime
/// toggle) — see `cargo-unikernel-common::hardening` for exactly what each category applies.
/// Same `None` = default-enabled semantics as `[hardening.kernel]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeHardening {
    /// `rp_filter` + ICMP redirect accept/send/secure — IP spoofing / MITM redirect defense.
    pub network_spoofing_protection: Option<bool>,
    /// Ignore ICMP broadcasts/bogus errors and all ICMP echo (a.k.a. "stealth mode": the
    /// guest never answers pings at all).
    pub icmp_hardening: Option<bool>,
    /// SYN cookies, RFC1337, connection-table/backlog tuning for `DDoS` resilience, and a
    /// throughput tweak (no slow-start reset after idle) for keep-alive-heavy servers.
    pub tcp_hardening: Option<bool>,
    /// `kptr_restrict`, `dmesg_restrict`, `perf_event_paranoid` — restrict kernel info leaks.
    pub info_leak_restriction: Option<bool>,
    /// Disable unprivileged BPF and userfaultfd; lock ptrace down entirely (YAMA scope 3);
    /// harden the (still-enabled, for seccomp's sake) classic-BPF JIT against JIT-spray.
    pub ptrace_and_bpf_restriction: Option<bool>,
    /// Disable kexec loading; protect VFS symlinks/hardlinks/fifos/regular files.
    pub kexec_and_fs_protection: Option<bool>,
}

/// `[hardening]` — build-time and runtime hardening toggles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hardening {
    /// Reserved for future coarse presets; every category below defaults to enabled
    /// regardless of `level` today. Kept so `cargo-unikernel.toml` has a stable place for
    /// this once differentiated presets exist — set explicit per-category toggles below for
    /// control that actually takes effect right now.
    #[serde(default = "default_hardening_level")]
    pub level: HardeningLevel,
    /// `[hardening.kernel]` — build-time (Kconfig) hardening categories.
    #[serde(default)]
    pub kernel: KernelHardening,
    /// `[hardening.runtime]` — boot-time (sysctl) hardening categories.
    #[serde(default)]
    pub runtime: RuntimeHardening,
    /// Extra sysctls applied by the guest at boot, after the named runtime categories
    /// above. Format: `{ "/proc/sys/..." = "value" }` — keys are written verbatim as root, so
    /// anything outside `/proc/sys/` is rejected by `validate_extra_sysctl_paths`.
    #[serde(default)]
    pub extra_sysctls: BTreeMap<String, String>,
    /// Extra raw Kconfig directives applied after every named kernel category above (so
    /// these win any conflict) — one string per entry, in the same
    /// `CONFIG_NAME=enable|disable|set-str:value` format as the built-in fragment files
    /// (e.g. `"CONFIG_DEBUG_INFO=enable"`). The escape hatch for exact, per-flag control
    /// beyond the curated categories.
    #[serde(default)]
    pub extra_kernel_config: Vec<String>,
}

const fn default_hardening_level() -> HardeningLevel {
    HardeningLevel::Default
}

impl Default for Hardening {
    fn default() -> Self {
        Self {
            level: default_hardening_level(),
            kernel: KernelHardening::default(),
            runtime: RuntimeHardening::default(),
            extra_sysctls: BTreeMap::new(),
            extra_kernel_config: Vec::new(),
        }
    }
}

/// Where to get the OVMF/UEFI firmware used for the SEV-SNP launch measurement. Cloud
/// providers ship different OVMF builds, so exactly one of these must be set:
/// - `preset`: `"builtin"` — the AMD SEV-SNP firmware baked directly into this CLI binary
///   (see `pipeline::ovmf`), hash-pinned and never fetched over the network at build time.
/// - `path`: a local file already on disk (e.g. one your hypervisor provider gave you).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OvmfSource {
    /// `"builtin"` — the AMD SEV-SNP firmware baked into this CLI binary.
    pub preset: Option<String>,
    /// A local firmware file already on disk.
    pub path: Option<String>,
}

/// `[sev_snp]` — confidential-computing profile settings, required when
/// `profile.kind = "sev-snp"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SevSnp {
    /// vCPU count — measurement-critical.
    pub vcpus: u32,
    /// vCPU model string passed to QEMU (e.g. `"EPYC"`) — also measurement-critical.
    pub vcpu_type: String,
    /// Kernel cmdline baked into the launch measurement and the UKI's `.cmdline` section.
    pub kernel_cmdline: String,
    /// `[sev_snp.ovmf]` — which OVMF/UEFI firmware to measure and boot.
    pub ovmf: OvmfSource,
    /// Which boot inputs `sev-snp-measure.py` hashes to predict the launch measurement.
    /// Defaults to auto-detecting from `[output].formats`: `uki` if a UKI is being built
    /// (providers that direct-boot the `.efi` via QEMU's `fw_cfg` `SNP_KERNEL_HASHES`
    /// mechanism hash the whole assembled UKI as a single "kernel" blob — e.g. Onidel),
    /// `kernel-initrd` otherwise (the traditional `-kernel`/`-initrd`/`-append` triple,
    /// hashed as three separate inputs). Set explicitly if a provider's actual boot mode
    /// doesn't match what your chosen output formats would otherwise imply.
    #[serde(default)]
    pub measured_boot: Option<MeasuredBoot>,
}

/// Which boot inputs `sev-snp-measure.py` hashes to predict the launch measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MeasuredBoot {
    /// The whole assembled UKI `.efi` is hashed as a single "kernel" blob.
    Uki,
    /// The traditional `-kernel`/`-initrd`/`-append` triple, hashed as three separate inputs.
    KernelInitrd,
}

/// A boot image format `cargo-unikernel build` can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// `cpio` initramfs + `bzImage`, for `-initrd`/`-kernel` style boot.
    Cpio,
    /// A bootable ISO (via Limine), for local testing.
    Iso,
    /// A Unified Kernel Image — kernel + initrd + cmdline assembled into one `.efi`.
    Uki,
    /// The raw app binary (`$APP_BIN`), copied into `dist/` unmodified alongside whatever
    /// image formats are also requested — useful for consumers that want the app binary
    /// itself (e.g. to inspect, sign, or re-embed elsewhere) without extracting it from an
    /// image.
    Binary,
}

/// `[output]` — which image formats to produce and where to write them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Output {
    /// Which `OutputFormat`s to build. Must not be empty.
    pub formats: Vec<OutputFormat>,
    /// Directory (relative to the project directory) build artifacts are written to.
    #[serde(default = "default_output_dir")]
    pub dir: String,
}

fn default_output_dir() -> String {
    "dist/".to_string()
}

/// `[release]` — which `dist/` assets a GitHub Release includes and what its body/metadata
/// say.
///
/// Every field is optional: an absent `[release]` section reproduces the tool's default
/// behavior (every artifact that exists in `dist/` is attached — notes are generated by `gh`
/// from commits/PRs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Release {
    /// Which asset kinds to attach (see `ReleaseAsset`). Omitted = every kind in `dist/`.
    /// An empty list is rejected.
    pub assets: Option<Vec<ReleaseAsset>>,
    /// `gh release create --title`. Defaults to the tag name when unset.
    pub title: Option<String>,
    /// Release body text, passed to `gh release create --notes`. Mutually exclusive with
    /// `notes_file`.
    pub notes: Option<String>,
    /// Path (relative to the project directory) to a file whose contents become the
    /// release body, passed to `gh release create --notes-file`. Mutually exclusive with
    /// `notes`.
    pub notes_file: Option<String>,
    /// `gh release create --draft`.
    #[serde(default)]
    pub draft: bool,
    /// `gh release create --prerelease`.
    #[serde(default)]
    pub prerelease: bool,
}

/// A category of `dist/` artifact a GitHub Release can attach — selected via
/// `Release::assets`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseAsset {
    /// `dist/<name>.bzImage`.
    Bzimage,
    /// `dist/<name>.cpio`.
    Cpio,
    /// `dist/<name>.iso`.
    Iso,
    /// `dist/<name>.efi`.
    Uki,
    /// `dist/<name>.bin` (the raw app binary, `OutputFormat::Binary`).
    Binary,
    /// `dist/sev_measurement.txt` and `dist/sev_measurement.json`.
    Measurement,
    /// The staged OVMF firmware file, if present in `dist/`.
    Ovmf,
}

/// Why a `Config` failed `Config::validate`. Each variant is one specific rejected
/// combination — see each variant's `#[error]` message for the exact user-facing wording.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// `[app.source]` missing while `app.mode = "source"`.
    #[error("`[app.source]` is required when `app.mode = \"source\"`")]
    MissingAppSource,
    /// `[app.source]` didn't set `path`.
    #[error("`[app.source]` must set `path` (build this project directly)")]
    AppSourcePathRequired,
    /// `[app.binary]` missing while `app.mode = "binary"`.
    #[error("`[app.binary]` is required when `app.mode = \"binary\"`")]
    MissingAppBinary,
    /// `[app.binary]` didn't set `path`.
    #[error("`[app.binary]` must set `path` (a local file already on disk)")]
    AppBinaryPathRequired,
    /// `toolchain.apt_snapshot = "latest"` used with `profile.kind = "sev-snp"`.
    #[error(
        "`toolchain.apt_snapshot = \"latest\"` is only allowed when `profile.kind = \"casual\"` \
         — pin a snapshot timestamp for reproducible sev-snp builds"
    )]
    LatestAptSnapshotNotAllowedForSevSnp,
    /// `app.source.toolchain = "generic"` without both `build_command` and `output_binary`.
    #[error(
        "`app.source.toolchain = \"generic\"` requires both `build_command` and `output_binary`"
    )]
    GenericToolchainNeedsBuildCommandAndOutputBinary,
    /// A `toolchain = "generic"`-only field set while `app.source.toolchain = "rust"`.
    #[error(
        "`app.source.build_command`/`output_binary`/`extra_apt_packages` only apply when \
         `toolchain = \"generic\"` — remove them or switch off the rust toolchain"
    )]
    RustToolchainCannotSetGenericFields,
    /// `[sev_snp]` set with `profile.kind = "casual"`.
    #[error("`[sev_snp]` is only valid when `profile.kind = \"sev-snp\"`")]
    SevSnpSectionRequiresSevSnpProfile,
    /// `[sev_snp]` missing while `profile.kind = "sev-snp"`.
    #[error("`[sev_snp]` is required when `profile.kind = \"sev-snp\"`")]
    MissingSevSnpSection,
    /// `[sev_snp.ovmf]` set neither or both of `preset`/`path`.
    #[error("`[sev_snp.ovmf]` must set exactly one of `preset` or `path`")]
    OvmfNeedsExactlyOneSource,
    /// `output.formats` was empty.
    #[error("`output.formats` must not be empty")]
    EmptyOutputFormats,
    /// `release.assets` was set to an empty list.
    #[error(
        "`release.assets`, if set, must not be empty — omit the field to include every produced asset"
    )]
    EmptyReleaseAssets,
    /// `[release]` set both `notes` and `notes_file`.
    #[error("`[release]` must set at most one of `notes` or `notes_file`")]
    ReleaseNotesAndNotesFileBothSet,
    /// `project.cargo_unikernel_version` doesn't match the running CLI's own version.
    #[error(
        "this config is pinned to cargo-unikernel {pinned}, but the running CLI is {running} \
         — install the matching version (`cargo install cargo-unikernel --version {pinned} \
         --locked`) to reproduce this build/measurement exactly, or update \
         `project.cargo_unikernel_version` in your config to \"{running}\" if you've \
         deliberately upgraded (re-verify reproducibility and any sev-snp measurement \
         afterward)"
    )]
    ToolVersionMismatch {
        /// The version `project.cargo_unikernel_version` pinned.
        pinned: String,
        /// The running CLI's actual version.
        running: String,
    },
    /// `project.cargo_unikernel_version` unset while `profile.kind = "sev-snp"`.
    #[error(
        "`project.cargo_unikernel_version` is required when `profile.kind = \"sev-snp\"` — a \
         different CLI version can bundle a different pinned kernel/Dockerfile and silently \
         change the launch measurement, so sev-snp refuses to build unpinned; add \
         `cargo_unikernel_version = \"{running}\"` (the version currently running) to \
         `[project]`, or scaffold a fresh config with `cargo-unikernel init --profile \
         sev-snp`, which sets this automatically"
    )]
    SevSnpRequiresPinnedCliVersion {
        /// The running CLI's actual version, suggested as the value to pin.
        running: String,
    },
    /// `project.name` was empty or contained characters other than letters/digits/`-`/`_`.
    #[error(
        "`project.name` must be a non-empty string of letters, digits, `-`, or `_` only \
         (got {0:?}) — it's used verbatim in generated file paths and shell commands inside \
         the build container"
    )]
    InvalidProjectName(String),
    /// `sev_snp.vcpus` was `0`.
    #[error("`sev_snp.vcpus` must be greater than 0 (got {0})")]
    SevSnpVcpusMustBePositive(u32),
    /// `sev_snp.vcpu_type` was empty (or all whitespace).
    #[error("`sev_snp.vcpu_type` must not be empty")]
    SevSnpVcpuTypeMustNotBeEmpty,
    /// `sev_snp.measured_boot = "uki"` without `uki` in `output.formats`.
    #[error(
        "`sev_snp.measured_boot = \"uki\"` requires `uki` to be included in `output.formats` \
         — there's no assembled .efi to measure otherwise"
    )]
    MeasuredBootUkiNeedsUkiOutputFormat,
    /// `kernel.version` was changed without pinning a matching `kernel.sha256`.
    #[error(
        "`kernel.sha256` must be set when `kernel.version` is not the built-in default \
         ({version}) — the tarball would otherwise be downloaded and built without any \
         integrity check. Take the hash for that version from kernel.org's sha256sums.asc"
    )]
    KernelSha256Required {
        /// The version the config asks for, which has no baked-in checksum.
        version: String,
    },
    /// `[network.ipv6_static]` set while `network.mode` has no IPv6.
    #[error(
        "`[network.ipv6_static]` requires `network.mode` to include IPv6 (\"ipv6\" or \"dual\") \
         — the guest has no IPv6 stack compiled in otherwise"
    )]
    Ipv6StaticRequiresIpv6,
    /// `network.ipv6_static.address` was not an IPv6 address.
    #[error("`network.ipv6_static.address` {0:?} is not a valid IPv6 address")]
    Ipv6StaticAddressUnparseable(String),
    /// `network.ipv6_static.address` was an address nothing can reach from off-link.
    #[error(
        "`network.ipv6_static.address` {0:?} is loopback, link-local, multicast or unspecified \
         — a remote client cannot reach it, and the point of a static address is to be the one \
         you connect to"
    )]
    Ipv6StaticAddressNotRoutable(String),
    /// `network.ipv6_static.prefix_len` was outside 1–128.
    #[error("`network.ipv6_static.prefix_len` must be between 1 and 128 (got {0})")]
    Ipv6StaticPrefixLenOutOfRange(u8),
    /// `network.ipv6_static.gateway` was not an IPv6 address.
    #[error("`network.ipv6_static.gateway` {0:?} is not a valid IPv6 address")]
    Ipv6StaticGatewayUnparseable(String),
    /// `storage.size_mib` was `0`.
    #[error("`storage.size_mib` must be greater than 0 (got {0})")]
    StorageSizeMustBePositive(u32),
    /// A key/value pair contained a character the `';'`-joined wire format can't round-trip.
    #[error(
        "`{table}` entry {key:?} contains a `;` (or a `=` in the key) — these reach the guest \
         as one `;`-joined string of `key=value` pairs, so such an entry cannot be encoded \
         without the guest reading it back as something different"
    )]
    UnrepresentableKvPair {
        /// The config table the offending entry came from.
        table: &'static str,
        /// The offending entry's key.
        key: String,
    },
    /// `app.runtime.uid` or `gid` was `0`.
    #[error(
        "`app.runtime.{field}` must not be 0 — the guest init drops privileges by calling \
         `setuid`/`setgid` before exec, which is a no-op for root, leaving the app owning \
         every root-owned file in the guest (including `/proc/sys`, so it could undo the \
         sysctl hardening applied at boot)"
    )]
    AppRuntimeIdMustNotBeRoot {
        /// Whichever of `uid`/`gid` was `0`.
        field: &'static str,
    },
    /// A `hardening.extra_sysctls` key was not a path under `/proc/sys/`.
    #[error(
        "`hardening.extra_sysctls` key {0:?} must be a path under `/proc/sys/` — the guest \
         init writes each key verbatim as root before the filesystem lockdown, so a key \
         pointing elsewhere writes to that path instead of tuning a sysctl"
    )]
    ExtraSysctlNotUnderProcSys(String),
}

impl Config {
    /// Checks every cross-field invariant `serde`'s own per-field deserialization can't
    /// express — e.g. "`[app.binary]` requires `path`" (binary mode), "`[sev_snp]` only
    /// valid for that profile", uid/gid collisions. Called right after parsing, before
    /// anything in the config is acted on.
    ///
    /// # Errors
    ///
    /// Returns the specific `ValidationError` for the first invariant violated.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.validate_project()?;
        self.validate_storage()?;
        self.validate_kernel()?;
        self.validate_kv_encoding()?;
        self.validate_extra_sysctl_paths()?;
        self.validate_ipv6_static()?;
        self.validate_app()?;
        self.validate_profile()?;
        self.validate_output_and_release()?;
        Ok(())
    }

    /// `[app.runtime].env` and `[hardening].extra_sysctls` both reach the guest as one
    /// `';'`-joined string of `key=value` pairs (see `pipeline::docker::guest_init_script`).
    ///
    /// A `';'` anywhere in a key or value, or a `'='` in a key, splits into a pair the guest
    /// reads back differently than it was written — and the guest treats a malformed pair as an
    /// integrity failure and powers off. Rejecting it here turns an unbootable image into a
    /// config error.
    fn validate_kv_encoding(&self) -> Result<(), ValidationError> {
        let checks = [
            ("app.runtime.env", &self.app.runtime.env),
            ("hardening.extra_sysctls", &self.hardening.extra_sysctls),
        ];
        for (table, pairs) in checks {
            for (key, value) in pairs {
                if key.contains(';') || key.contains('=') || value.contains(';') {
                    return Err(ValidationError::UnrepresentableKvPair {
                        table,
                        key: key.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    /// Confines `[hardening].extra_sysctls` keys to `/proc/sys/`.
    ///
    /// The guest init hands each key straight to `write(2)` as root, before the filesystem
    /// lockdown — so an unconfined key isn't a broken sysctl, it's a write to whatever path it
    /// names. `..` is rejected separately: a prefix check alone would accept
    /// `/proc/sys/../../etc/passwd`.
    fn validate_extra_sysctl_paths(&self) -> Result<(), ValidationError> {
        for key in self.hardening.extra_sysctls.keys() {
            if !key.starts_with("/proc/sys/") || key.split('/').any(|part| part == "..") {
                return Err(ValidationError::ExtraSysctlNotUnderProcSys(key.clone()));
            }
        }
        Ok(())
    }

    /// `[project]` invariants: `name`'s character set, and the pinned-version check.
    fn validate_project(&self) -> Result<(), ValidationError> {
        let name = &self.project.name;
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ValidationError::InvalidProjectName(name.clone()));
        }

        if let Some(pinned) = &self.project.cargo_unikernel_version
            && pinned != CLI_VERSION
        {
            return Err(ValidationError::ToolVersionMismatch {
                pinned: pinned.clone(),
                running: CLI_VERSION.to_string(),
            });
        }

        Ok(())
    }

    /// `[storage]` invariants: `size_mib` must be positive.
    const fn validate_storage(&self) -> Result<(), ValidationError> {
        if self.storage.size_mib == 0 {
            return Err(ValidationError::StorageSizeMustBePositive(
                self.storage.size_mib,
            ));
        }
        Ok(())
    }

    /// `[kernel]` invariants: the tarball this build downloads is always checksum-verified.
    fn validate_kernel(&self) -> Result<(), ValidationError> {
        if self.kernel.sha256_for_build().is_none() {
            return Err(ValidationError::KernelSha256Required {
                version: self.kernel.version.clone(),
            });
        }
        Ok(())
    }

    /// `[network.ipv6_static]` invariants: IPv6 actually compiled in, a parseable and
    /// *routable* address, a sane prefix length, and a parseable gateway if given.
    ///
    /// The address checks matter more than usual here: this exists to serve a guest whose
    /// console cannot be read, so a bad value produces an image that boots, looks healthy, and
    /// is silently unreachable. Catching it at config time is the only place it is cheap.
    fn validate_ipv6_static(&self) -> Result<(), ValidationError> {
        let Some(static_v6) = &self.network.ipv6_static else {
            return Ok(());
        };
        if !self.network.mode.has_ipv6() {
            return Err(ValidationError::Ipv6StaticRequiresIpv6);
        }

        let address: std::net::Ipv6Addr = static_v6.address.parse().map_err(|_| {
            ValidationError::Ipv6StaticAddressUnparseable(static_v6.address.clone())
        })?;
        if address.is_loopback()
            || address.is_multicast()
            || address.is_unspecified()
            || address.segments()[0] & 0xffc0 == 0xfe80
        {
            return Err(ValidationError::Ipv6StaticAddressNotRoutable(
                static_v6.address.clone(),
            ));
        }
        if static_v6.prefix_len == 0 || static_v6.prefix_len > 128 {
            return Err(ValidationError::Ipv6StaticPrefixLenOutOfRange(
                static_v6.prefix_len,
            ));
        }

        if let Some(gateway) = &static_v6.gateway
            && gateway.parse::<std::net::Ipv6Addr>().is_err()
        {
            return Err(ValidationError::Ipv6StaticGatewayUnparseable(
                gateway.clone(),
            ));
        }
        Ok(())
    }

    /// `[app]` invariants: `path` required, whether `[app.source]` (source mode) or
    /// `[app.binary]` (binary mode), plus the toolchain-specific field requirements.
    fn validate_app(&self) -> Result<(), ValidationError> {
        // `setuid(0)`/`setgid(0)` succeed and change nothing, so the guest's privilege drop
        // reports success while leaving the app as root.
        if self.app.runtime.uid == 0 {
            return Err(ValidationError::AppRuntimeIdMustNotBeRoot { field: "uid" });
        }
        if self.app.runtime.gid == 0 {
            return Err(ValidationError::AppRuntimeIdMustNotBeRoot { field: "gid" });
        }

        match self.app.mode {
            AppMode::Source => {
                let source = self
                    .app
                    .source
                    .as_ref()
                    .ok_or(ValidationError::MissingAppSource)?;
                if source.path.is_none() {
                    return Err(ValidationError::AppSourcePathRequired);
                }

                let has_generic_fields = source.build_command.is_some()
                    || source.output_binary.is_some()
                    || !source.extra_apt_packages.is_empty();
                match source.toolchain {
                    Toolchain::Generic => {
                        if source.build_command.is_none() || source.output_binary.is_none() {
                            return Err(
                                ValidationError::GenericToolchainNeedsBuildCommandAndOutputBinary,
                            );
                        }
                    }
                    Toolchain::Rust => {
                        if has_generic_fields {
                            return Err(ValidationError::RustToolchainCannotSetGenericFields);
                        }
                    }
                }
                Ok(())
            }
            AppMode::Binary => {
                let binary = self
                    .app
                    .binary
                    .as_ref()
                    .ok_or(ValidationError::MissingAppBinary)?;
                if binary.path.is_none() {
                    return Err(ValidationError::AppBinaryPathRequired);
                }
                Ok(())
            }
        }
    }

    /// `[profile]` invariants: `[sev_snp]` only valid for the matching profile, and (sev-snp
    /// only) vcpu/ovmf/measured-boot requirements.
    fn validate_profile(&self) -> Result<(), ValidationError> {
        match self.profile.kind {
            ProfileKind::Casual => {
                if self.sev_snp.is_some() {
                    return Err(ValidationError::SevSnpSectionRequiresSevSnpProfile);
                }
                Ok(())
            }
            ProfileKind::SevSnp => {
                if self.project.cargo_unikernel_version.is_none() {
                    return Err(ValidationError::SevSnpRequiresPinnedCliVersion {
                        running: CLI_VERSION.to_string(),
                    });
                }
                if self.toolchain.apt_snapshot.as_deref() == Some("latest") {
                    return Err(ValidationError::LatestAptSnapshotNotAllowedForSevSnp);
                }
                let sev_snp = self
                    .sev_snp
                    .as_ref()
                    .ok_or(ValidationError::MissingSevSnpSection)?;
                if sev_snp.vcpus == 0 {
                    return Err(ValidationError::SevSnpVcpusMustBePositive(sev_snp.vcpus));
                }
                if sev_snp.vcpu_type.trim().is_empty() {
                    return Err(ValidationError::SevSnpVcpuTypeMustNotBeEmpty);
                }
                match (&sev_snp.ovmf.preset, &sev_snp.ovmf.path) {
                    (Some(_), None) | (None, Some(_)) => {}
                    _ => return Err(ValidationError::OvmfNeedsExactlyOneSource),
                }
                if sev_snp.measured_boot == Some(MeasuredBoot::Uki)
                    && !self.output.formats.contains(&OutputFormat::Uki)
                {
                    return Err(ValidationError::MeasuredBootUkiNeedsUkiOutputFormat);
                }
                Ok(())
            }
        }
    }

    /// `[output]`/`[release]` invariants: `output.formats` non-empty, `release.assets` not an
    /// empty list, and `notes`/`notes_file` mutually exclusive.
    const fn validate_output_and_release(&self) -> Result<(), ValidationError> {
        if self.output.formats.is_empty() {
            return Err(ValidationError::EmptyOutputFormats);
        }

        if let Some(assets) = &self.release.assets
            && assets.is_empty()
        {
            return Err(ValidationError::EmptyReleaseAssets);
        }
        if self.release.notes.is_some() && self.release.notes_file.is_some() {
            return Err(ValidationError::ReleaseNotesAndNotesFileBothSet);
        }

        Ok(())
    }
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        crate::pipeline::docker::test_fixtures::casual_config_with_formats(vec![OutputFormat::Cpio])
    }

    fn sev_snp_section() -> SevSnp {
        crate::pipeline::docker::test_fixtures::sev_snp_config_with_formats(vec![
            OutputFormat::Cpio,
        ])
        .sev_snp
        .expect("sev_snp_config_with_formats always sets [sev_snp]")
    }

    /// `base_config()` switched to `profile.kind = "sev-snp"` with a pinned CLI version —
    /// sev-snp now refuses to validate unpinned, so every test that flips the profile needs
    /// this instead of setting `profile.kind` on `base_config()` directly.
    fn sev_snp_base_config() -> Config {
        let mut config = base_config();
        config.profile.kind = ProfileKind::SevSnp;
        config.project.cargo_unikernel_version = Some(CLI_VERSION.to_string());
        config
    }

    #[test]
    fn rust_source_path_is_valid() {
        assert!(base_config().validate().is_ok());
    }

    #[test]
    fn danger_write_execute_defaults_to_disabled() {
        assert!(!AppRuntime::default().danger.allow_write_execute);
        assert!(!base_config().app.runtime.danger.allow_write_execute);
    }

    #[test]
    fn project_name_rejects_shell_metacharacters_and_path_separators() {
        for bad in ["", "my app", "app;rm -rf /", "../escape", "a\"b", "a/b"] {
            let mut config = base_config();
            config.project.name = bad.to_string();
            assert!(
                matches!(
                    config.validate(),
                    Err(ValidationError::InvalidProjectName(_))
                ),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn project_name_accepts_letters_digits_dash_underscore() {
        let mut config = base_config();
        config.project.name = "my-app_v2".to_string();
        assert!(config.validate().is_ok());
    }

    /// Changing `kernel.version` is exactly the change that leaves the baked-in checksum
    /// inapplicable, so it must not be the change that quietly turns verification off.
    #[test]
    fn changed_kernel_version_without_a_pinned_sha256_rejected() {
        let mut config = sev_snp_base_config();
        config.sev_snp = Some(sev_snp_section());
        config.kernel = Kernel {
            version: "6.17.1".to_string(),
            sha256: None,
        };
        assert!(matches!(
            config.validate(),
            Err(ValidationError::KernelSha256Required { .. })
        ));

        config.kernel.sha256 = Some("0".repeat(64));
        assert!(config.validate().is_ok());
    }

    /// The default version carries a checksum without the config having to name one, so the
    /// zero-config path stays verified rather than merely unrejected.
    #[test]
    fn default_kernel_version_resolves_a_checksum_without_config() {
        let kernel = Kernel {
            version: default_kernel_version(),
            sha256: None,
        };
        assert_eq!(
            kernel.sha256_for_build().as_deref(),
            Some(DEFAULT_KERNEL_SHA256)
        );
    }

    fn ipv6_config() -> Config {
        let mut config = base_config();
        config.network.mode = NetworkMode::Ipv6;
        config
    }

    fn static_v6(address: &str) -> Ipv6Static {
        Ipv6Static {
            address: address.to_string(),
            prefix_len: default_ipv6_prefix_len(),
            gateway: None,
            interface: None,
        }
    }

    #[test]
    fn a_routable_static_ipv6_is_accepted() {
        let mut config = ipv6_config();
        config.network.ipv6_static = Some(static_v6("2001:db8:1:2::1"));
        assert!(config.validate().is_ok());

        // A single delegated address, the other shape a provider hands out.
        let mut config = ipv6_config();
        config.network.ipv6_static = Some(Ipv6Static {
            prefix_len: 128,
            ..static_v6("2001:db8::5")
        });
        assert!(config.validate().is_ok());

        // Dual-stack counts as having IPv6.
        let mut config = ipv6_config();
        config.network.mode = NetworkMode::Dual;
        config.network.ipv6_static = Some(static_v6("2001:db8:1:2::1"));
        assert!(config.validate().is_ok());
    }

    /// Every one of these builds an image that boots, looks healthy, and cannot be reached —
    /// which on a guest with no readable console is indistinguishable from a broken app.
    #[test]
    fn an_unreachable_static_ipv6_is_rejected() {
        for address in ["fe80::1", "::1", "::", "ff02::1"] {
            let mut config = ipv6_config();
            config.network.ipv6_static = Some(static_v6(address));
            assert!(
                matches!(
                    config.validate(),
                    Err(ValidationError::Ipv6StaticAddressNotRoutable(_))
                ),
                "{address} should be rejected as unreachable"
            );
        }

        let mut config = ipv6_config();
        config.network.ipv6_static = Some(static_v6("not-an-address"));
        assert!(matches!(
            config.validate(),
            Err(ValidationError::Ipv6StaticAddressUnparseable(_))
        ));

        // An IPv4 address in the IPv6 field is the likeliest typo of all.
        let mut config = ipv6_config();
        config.network.ipv6_static = Some(static_v6("192.0.2.1"));
        assert!(matches!(
            config.validate(),
            Err(ValidationError::Ipv6StaticAddressUnparseable(_))
        ));
    }

    #[test]
    fn static_ipv6_prefix_len_and_gateway_are_checked() {
        for prefix_len in [0, 129] {
            let mut config = ipv6_config();
            config.network.ipv6_static = Some(Ipv6Static {
                prefix_len,
                ..static_v6("2001:db8:1:2::1")
            });
            assert!(matches!(
                config.validate(),
                Err(ValidationError::Ipv6StaticPrefixLenOutOfRange(_))
            ));
        }

        let mut config = ipv6_config();
        config.network.ipv6_static = Some(Ipv6Static {
            gateway: Some("fe80::1".to_string()),
            ..static_v6("2001:db8:1:2::1")
        });
        assert!(
            config.validate().is_ok(),
            "a link-local gateway is normal — that check is only for the address"
        );

        let mut config = ipv6_config();
        config.network.ipv6_static = Some(Ipv6Static {
            gateway: Some("nope".to_string()),
            ..static_v6("2001:db8:1:2::1")
        });
        assert!(matches!(
            config.validate(),
            Err(ValidationError::Ipv6StaticGatewayUnparseable(_))
        ));
    }

    /// The guest compiles no IPv6 stack at all in these modes, so the address would be baked
    /// into an image that can never apply it.
    #[test]
    fn static_ipv6_without_an_ipv6_stack_is_rejected() {
        for mode in [NetworkMode::Ipv4, NetworkMode::None] {
            let mut config = base_config();
            config.network.mode = mode;
            config.network.ipv6_static = Some(static_v6("2001:db8:1:2::1"));
            assert!(matches!(
                config.validate(),
                Err(ValidationError::Ipv6StaticRequiresIpv6)
            ));
        }
    }

    #[test]
    fn kv_pair_that_the_wire_format_cannot_round_trip_is_rejected() {
        let semicolon_cases = [
            ("PATH".to_string(), "/usr/bin;/bin".to_string()),
            ("A;B".to_string(), "value".to_string()),
            ("A=B".to_string(), "value".to_string()),
        ];
        for (key, value) in semicolon_cases {
            let mut config = base_config();
            config.app.runtime.env = BTreeMap::from([(key.clone(), value)]);
            assert!(
                matches!(
                    config.validate(),
                    Err(ValidationError::UnrepresentableKvPair { .. })
                ),
                "{key:?} should not be encodable"
            );
        }

        // extra_sysctls shares the encoding, so it shares the check.
        let mut config = base_config();
        config.hardening.extra_sysctls = BTreeMap::from([(
            "/proc/sys/net/ipv4/tcp_rmem".to_string(),
            "4096;87380".to_string(),
        )]);
        assert!(matches!(
            config.validate(),
            Err(ValidationError::UnrepresentableKvPair { .. })
        ));

        // A value containing '=' is fine: the guest splits on the *first* '=' only.
        let mut config = base_config();
        config.app.runtime.env = BTreeMap::from([("OPTS".to_string(), "a=b".to_string())]);
        assert!(config.validate().is_ok());
    }

    /// `setuid(0)` succeeds and changes nothing, so a root uid here would produce a guest whose
    /// privilege drop reports success while the app keeps owning every root-owned file.
    #[test]
    fn root_app_uid_or_gid_rejected() {
        let mut config = base_config();
        config.app.runtime.uid = 0;
        assert!(matches!(
            config.validate(),
            Err(ValidationError::AppRuntimeIdMustNotBeRoot { field: "uid" })
        ));

        let mut config = base_config();
        config.app.runtime.gid = 0;
        assert!(matches!(
            config.validate(),
            Err(ValidationError::AppRuntimeIdMustNotBeRoot { field: "gid" })
        ));
    }

    #[test]
    fn extra_sysctl_key_outside_proc_sys_rejected() {
        for key in [
            "/etc/passwd",
            "net.ipv4.ip_forward",
            "/proc/sys/../../payload/app",
        ] {
            let mut config = base_config();
            config.hardening.extra_sysctls = BTreeMap::from([(key.to_string(), "1".to_string())]);
            assert!(
                matches!(
                    config.validate(),
                    Err(ValidationError::ExtraSysctlNotUnderProcSys(_))
                ),
                "{key:?} should not be writable as a sysctl"
            );
        }

        let mut config = base_config();
        config.hardening.extra_sysctls =
            BTreeMap::from([("/proc/sys/net/ipv4/ip_forward".to_string(), "0".to_string())]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn zero_sev_snp_vcpus_or_empty_vcpu_type_rejected() {
        let mut config = sev_snp_base_config();
        let mut sev_snp = sev_snp_section();
        sev_snp.vcpus = 0;
        config.sev_snp = Some(sev_snp);
        assert!(matches!(
            config.validate(),
            Err(ValidationError::SevSnpVcpusMustBePositive(0))
        ));

        let mut config = sev_snp_base_config();
        let mut sev_snp = sev_snp_section();
        sev_snp.vcpu_type = "  ".to_string();
        config.sev_snp = Some(sev_snp);
        assert!(matches!(
            config.validate(),
            Err(ValidationError::SevSnpVcpuTypeMustNotBeEmpty)
        ));
    }

    #[test]
    fn measured_boot_uki_without_uki_output_format_rejected() {
        let mut config = sev_snp_base_config();
        let mut sev_snp = sev_snp_section();
        sev_snp.measured_boot = Some(MeasuredBoot::Uki);
        config.sev_snp = Some(sev_snp);
        // base_config()'s output.formats is [Cpio], no Uki.
        assert!(matches!(
            config.validate(),
            Err(ValidationError::MeasuredBootUkiNeedsUkiOutputFormat)
        ));

        config.output.formats.push(OutputFormat::Uki);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn source_requires_path() {
        let mut config = base_config();
        config.app.source.as_mut().unwrap().path = None;
        assert!(matches!(
            config.validate(),
            Err(ValidationError::AppSourcePathRequired)
        ));
    }

    #[test]
    fn generic_toolchain_requires_build_command_and_output_binary() {
        let mut config = base_config();
        config.app.source.as_mut().unwrap().toolchain = Toolchain::Generic;
        assert!(matches!(
            config.validate(),
            Err(ValidationError::GenericToolchainNeedsBuildCommandAndOutputBinary)
        ));

        config.app.source.as_mut().unwrap().build_command = Some("make".to_string());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::GenericToolchainNeedsBuildCommandAndOutputBinary)
        ));

        config.app.source.as_mut().unwrap().output_binary = Some("bin/app".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rust_toolchain_rejects_generic_fields() {
        let mut config = base_config();
        config.app.source.as_mut().unwrap().build_command = Some("make".to_string());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::RustToolchainCannotSetGenericFields)
        ));
    }

    #[test]
    fn empty_output_formats_rejected() {
        let mut config = base_config();
        config.output.formats.clear();
        assert!(matches!(
            config.validate(),
            Err(ValidationError::EmptyOutputFormats)
        ));
    }

    #[test]
    fn empty_release_assets_rejected() {
        let mut config = base_config();
        config.release.assets = Some(Vec::new());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::EmptyReleaseAssets)
        ));
    }

    #[test]
    fn release_notes_and_notes_file_together_rejected() {
        let mut config = base_config();
        config.release.notes = Some("hello".to_string());
        config.release.notes_file = Some("NOTES.md".to_string());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::ReleaseNotesAndNotesFileBothSet)
        ));
    }

    #[test]
    fn release_config_defaults_are_valid() {
        let config = base_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn unpinned_tool_version_is_accepted() {
        let config = base_config();
        assert!(config.project.cargo_unikernel_version.is_none());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn matching_pinned_tool_version_is_accepted() {
        let mut config = base_config();
        config.project.cargo_unikernel_version = Some(CLI_VERSION.to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn mismatched_pinned_tool_version_rejected() {
        let mut config = base_config();
        config.project.cargo_unikernel_version = Some("0.0.0-definitely-not-this".to_string());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::ToolVersionMismatch { .. })
        ));
    }

    #[test]
    fn sev_snp_requires_pinned_cli_version() {
        let mut config = base_config();
        config.profile.kind = ProfileKind::SevSnp;
        config.sev_snp = Some(sev_snp_section());
        assert!(config.project.cargo_unikernel_version.is_none());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::SevSnpRequiresPinnedCliVersion { .. })
        ));

        config.project.cargo_unikernel_version = Some(CLI_VERSION.to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn latest_apt_snapshot_rejected_for_sev_snp() {
        let mut config = sev_snp_base_config();
        config.sev_snp = Some(sev_snp_section());
        config.toolchain.apt_snapshot = Some("latest".to_string());
        assert!(matches!(
            config.validate(),
            Err(ValidationError::LatestAptSnapshotNotAllowedForSevSnp)
        ));
    }

    #[test]
    fn latest_apt_snapshot_accepted_for_casual() {
        let mut config = base_config();
        config.toolchain.apt_snapshot = Some("latest".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn default_toolchain_pins_validate_for_both_profiles() {
        let mut casual = base_config();
        assert!(casual.validate().is_ok());

        casual.profile.kind = ProfileKind::SevSnp;
        casual.project.cargo_unikernel_version = Some(CLI_VERSION.to_string());
        casual.sev_snp = Some(sev_snp_section());
        assert!(casual.validate().is_ok());
    }
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod example_file_tests {
    use super::*;

    #[test]
    fn bundled_examples_parse_and_validate() {
        let casual = include_str!("../examples/cargo-unikernel.casual.toml");
        let config: Config = toml::from_str(casual).expect("casual example parses");
        config.validate().expect("casual example validates");

        // The sev-snp example leaves `cargo_unikernel_version` commented out (like the CLI
        // ships it) — but sev-snp now requires it set, exactly like `cargo-unikernel init
        // --profile sev-snp` sets it, so pin it here the same way before validating.
        let sev_snp = crate::config::scaffold::pin_tool_version(include_str!(
            "../examples/cargo-unikernel.sev-snp.toml"
        ));
        let config: Config = toml::from_str(&sev_snp).expect("sev-snp example parses");
        config.validate().expect("sev-snp example validates");
    }
}
