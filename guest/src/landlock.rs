//! Landlock filesystem sandbox for the app process.
//!
//! `CONFIG_SECURITY_LANDLOCK` and `CONFIG_LSM=lockdown,yama,landlock` were already compiled in
//! before this module existed; nothing used them. This is what turns that into an actual
//! boundary: an unprivileged, inherited, irrevocable allowlist over the guest's (fully
//! build-time-known) filesystem layout. Everything not named below — all of `/sys` bar the CPU
//! topology, `/dev/vda`, `/dev/input/event*`, the payload's own directory for writing — is
//! simply not reachable by the app, whatever the mount flags say.
//!
//! Allowlist here, denylist in `seccomp.rs`, on purpose: the seccomp module's own reasoning is
//! that a wrong syscall allowlist silently breaks every app this tool builds. A *filesystem*
//! allowlist doesn't have that property — the layout is fixed by the image, so the set is
//! knowable, and anything an app legitimately needs beyond it is `[app.runtime.landlock]`'s
//! `extra_read_paths`/`extra_read_write_paths`.
//!
//! Hand-rolled against the three raw syscalls rather than taking the `landlock` crate: it is
//! three syscalls and two structs, and this crate's dependency floor (`libc`, `rustix`,
//! `seccompiler`) is deliberately low.
//!
//! ABI negotiation is deliberately strict. The ruleset is built to whatever the running kernel
//! reports, but a kernel below ABI 5 (`LANDLOCK_ACCESS_FS_IOCTL_DEV`, Linux 6.10) makes
//! `fatal` — silently enforcing a weaker sandbox than the one this image claims is worse than
//! refusing to boot, and the pinned kernel is far newer. Compiling without the `landlock`
//! feature is the supported way to run without this module at all.

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};

/// `LANDLOCK_CREATE_RULESET_VERSION` — asks `landlock_create_ruleset` for the supported ABI
/// rather than actually creating a ruleset.
const CREATE_RULESET_VERSION: u32 = 1;
/// `LANDLOCK_RULE_PATH_BENEATH` — the only rule type this module uses.
const RULE_PATH_BENEATH: libc::c_int = 1;

/// The lowest ABI this module will enforce on: `LANDLOCK_ACCESS_FS_IOCTL_DEV` (Linux 6.10).
/// Below it, device `ioctl`s can't be governed at all, which is most of the point of putting
/// `/dev/sev-guest` in a ruleset.
const MIN_ABI: i32 = 5;

// `LANDLOCK_ACCESS_FS_*` from `linux/landlock.h`, in ABI order.
const FS_EXECUTE: u64 = 1 << 0;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_REMOVE_DIR: u64 = 1 << 4;
const FS_REMOVE_FILE: u64 = 1 << 5;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_DIR: u64 = 1 << 7;
const FS_MAKE_REG: u64 = 1 << 8;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_MAKE_SYM: u64 = 1 << 12;
/// ABI 2.
const FS_REFER: u64 = 1 << 13;
/// ABI 3.
const FS_TRUNCATE: u64 = 1 << 14;
/// ABI 5 — the reason [`MIN_ABI`] is 5.
const FS_IOCTL_DEV: u64 = 1 << 15;

/// `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` / `LANDLOCK_SCOPE_SIGNAL` (ABI 6).
///
/// Scoping is about what the app can reach *outside* the filesystem: connecting to an abstract
/// `AF_UNIX` socket someone else owns, or signalling a process outside its own Landlock domain —
/// PID 1 being the only such process in this guest. Its own children share the domain, so
/// ordinary process-group signalling inside the app is untouched.
const SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const SCOPE_SIGNAL: u64 = 1 << 1;

/// `struct landlock_ruleset_attr`. `handled_access_net` (ABI 4) and `scoped` (ABI 6) are only
/// read by the kernel when the size passed to `landlock_create_ruleset` covers them — see
/// [`ruleset_attr_size`].
#[repr(C)]
#[derive(Debug, Default)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `struct landlock_path_beneath_attr` — **packed** in the uapi header, so this is 12 bytes,
/// not 16. Getting that wrong makes the kernel read `parent_fd` out of padding.
#[repr(C, packed)]
#[derive(Debug)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// How many bytes of [`RulesetAttr`] this ABI understands. Passing more returns `E2BIG`.
const fn ruleset_attr_size(abi: i32) -> usize {
    if abi >= 6 {
        24
    } else if abi >= 4 {
        16
    } else {
        8
    }
}

/// Every `LANDLOCK_ACCESS_FS_*` right this ABI knows about.
///
/// A right absent from `handled_access_fs` is one the ruleset does not govern at all — i.e.
/// *always permitted*. So this has to name everything the kernel supports, and any rule below
/// grants back only the subset a given path needs.
const fn handled_access_fs(abi: i32) -> u64 {
    let mut access = FS_EXECUTE
        | FS_WRITE_FILE
        | FS_READ_FILE
        | FS_READ_DIR
        | FS_REMOVE_DIR
        | FS_REMOVE_FILE
        | FS_MAKE_CHAR
        | FS_MAKE_DIR
        | FS_MAKE_REG
        | FS_MAKE_SOCK
        | FS_MAKE_FIFO
        | FS_MAKE_BLOCK
        | FS_MAKE_SYM
        | FS_REFER
        | FS_TRUNCATE;
    if abi >= 5 {
        access |= FS_IOCTL_DEV;
    }
    access
}

/// Read a file, and list a directory. The floor for anything the app may look at.
const READ: u64 = FS_READ_FILE | FS_READ_DIR;

/// [`READ`] plus running what's there — the payload directory, and nothing else unless
/// `danger-allow-write-execute` is compiled in.
const READ_EXEC: u64 = READ | FS_EXECUTE;

/// Full read/write over a scratch directory: create, rename, truncate and remove ordinary
/// files, directories, sockets, fifos and symlinks.
///
/// `FS_MAKE_CHAR`/`FS_MAKE_BLOCK` are deliberately excluded even here — creating a device node
/// needs `CAP_MKNOD`, which the app doesn't have, so granting it would only ever be noise in
/// the ruleset.
const READ_WRITE: u64 = READ
    | FS_WRITE_FILE
    | FS_TRUNCATE
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SOCK
    | FS_MAKE_FIFO
    | FS_MAKE_SYM
    | FS_REFER;

/// A character device the app both reads and writes — `/dev/null`, `/dev/zero`, `/dev/full`.
const DEV_READ_WRITE: u64 = FS_READ_FILE | FS_WRITE_FILE;

/// A character device the app only reads — `/dev/random`, `/dev/urandom`. Writing to the
/// random devices mixes into the pool without crediting entropy: not an attack, but not
/// something the app has any reason to do either.
const DEV_READ: u64 = FS_READ_FILE;

/// `/dev/sev-guest`: read, write, and — the only one that means anything — `ioctl`.
///
/// The driver registers `.unlocked_ioctl` and nothing else: no `.read`, no `.write`. So both
/// byte-stream rights are inert against it, and exist purely so `open(O_RDWR)` succeeds, which
/// is what every SEV-SNP attestation library does. `FS_IOCTL_DEV` is the real grant, and the
/// win is that no *other* device node in this ruleset has it.
#[cfg(feature = "sev-snp")]
const DEV_ATTESTATION: u64 = FS_READ_FILE | FS_WRITE_FILE | FS_IOCTL_DEV;

/// Whether a path missing at ruleset-build time is a bug or just an absent optional device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    /// The image is malformed if this isn't there — `fatal`.
    Required,
    /// Legitimately absent in some builds (`/dev/sev-guest` off the sev-snp profile, `/etc`
    /// when nothing wrote it) — skipped with a warning.
    Optional,
}

/// One `LANDLOCK_RULE_PATH_BENEATH` rule: `access` granted on everything at or beneath `path`.
#[derive(Debug)]
struct Rule {
    path: &'static str,
    access: u64,
    presence: Presence,
}

const fn required(path: &'static str, access: u64) -> Rule {
    Rule {
        path,
        access,
        presence: Presence::Required,
    }
}
const fn optional(path: &'static str, access: u64) -> Rule {
    Rule {
        path,
        access,
        presence: Presence::Optional,
    }
}

/// Writable scratch directories are `READ_WRITE`, plus `FS_EXECUTE` when
/// `danger-allow-write-execute` is compiled in — the Landlock half of the same opt-in
/// `mounts.rs` expresses with mount flags. Without the matching grant here, that feature's
/// executable `/tmp` would be unreachable anyway and the toggle would be a silent no-op.
#[cfg(feature = "danger-allow-write-execute")]
const SCRATCH: u64 = READ_WRITE | FS_EXECUTE;
#[cfg(not(feature = "danger-allow-write-execute"))]
const SCRATCH: u64 = READ_WRITE;

/// The built-in ruleset, before `[app.runtime.landlock]`'s extra paths are added.
///
/// `/proc` is read-only rather than absent: too many runtimes and allocators read
/// `/proc/self/*` or `/proc/meminfo` at startup for denying it to be a safe default, and it is
/// already `hidepid=2` so the app sees only its own processes. `storage.proc_subset_pid`
/// tightens it further by hiding every non-process entry.
///
/// `/sys` is the opposite call: nothing here legitimately browses it, so only the CPU topology
/// — the one part Go's runtime, jemalloc and friends actually read — is granted, and the rest
/// of the enumeration surface is gone.
fn builtin_rules(payload_dir: &'static str) -> Vec<Rule> {
    #[cfg_attr(not(feature = "sev-snp"), allow(unused_mut))]
    let mut rules = vec![
        required(payload_dir, READ_EXEC),
        required("/tmp", SCRATCH),
        required("/var", SCRATCH),
        required("/var/tmp", SCRATCH),
        required("/run", READ_WRITE),
        required("/dev/shm", SCRATCH),
        optional("/etc", READ),
        required("/proc", READ),
        optional("/sys/devices/system/cpu", READ),
        optional("/dev/null", DEV_READ_WRITE),
        optional("/dev/zero", DEV_READ_WRITE),
        optional("/dev/full", DEV_READ_WRITE),
        optional("/dev/random", DEV_READ),
        optional("/dev/urandom", DEV_READ),
    ];
    #[cfg(feature = "sev-snp")]
    rules.push(optional("/dev/sev-guest", DEV_ATTESTATION));
    rules
}

/// `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` — the supported ABI, or
/// a negative errno if Landlock isn't available at all.
#[allow(clippy::as_conversions)]
fn abi_version() -> i32 {
    // SAFETY: the version query passes a null attribute pointer with a zero size, which is
    // exactly what `LANDLOCK_CREATE_RULESET_VERSION` requires; the return value is an ABI
    // number or -1 with errno set.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            CREATE_RULESET_VERSION,
        )
    };
    i32::try_from(ret).unwrap_or(-1)
}

/// The compiled, ready-to-enforce ruleset.
///
/// Built in PID 1 *before* the fork (like `seccomp::build_baseline_denylist`, and for the same
/// reason: this allocates and opens files, neither of which is sound between `fork()` and
/// `execve()`). All the child does is [`restrict_self`], one syscall on an inherited fd.
#[derive(Debug)]
pub(crate) struct Ruleset {
    fd: OwnedFd,
}

impl Ruleset {
    /// The raw fd for [`restrict_self`].
    ///
    /// Deliberately a plain integer rather than a borrow: this crosses into a `pre_exec`
    /// closure, which must own only trivially-copyable state.
    pub(crate) fn raw_fd(&self) -> libc::c_int {
        self.fd.as_raw_fd()
    }
}

/// Builds the ruleset for this image: the built-in rules plus `extra_read`/`extra_read_write` from
/// `[app.runtime.landlock]`.
///
/// There is no runtime "disabled" path here — only compiling this crate without the
/// `landlock` feature skips enforcement, which also removes this whole module and the three
/// `landlock_*` syscalls from the binary. See `Cargo.toml`'s feature doc for why that's a hard
/// requirement rather than a style choice.
///
/// Calls `fatal` (never returns) if Landlock is unavailable, older than [`MIN_ABI`], or if a
/// [`Presence::Required`] path can't be opened. See the module doc for why that's fatal rather
/// than a warning.
#[allow(clippy::as_conversions)]
pub(crate) fn build(
    payload_dir: &'static str,
    extra_read: &[&str],
    extra_read_write: &[&str],
    log: impl Fn(&str),
    fatal: fn(&str) -> !,
) -> Ruleset {
    let abi = abi_version();
    if abi < MIN_ABI {
        fatal(&format!(
            "Landlock ABI {abi} is below the required {MIN_ABI} (Linux 6.10). This image's \
             kernel is built from a pinned, far newer source, so this means `kernel.version` \
             was lowered or CONFIG_SECURITY_LANDLOCK was turned off. Build without the \
             `landlock` feature to boot without the sandbox."
        ));
    }

    let attr = RulesetAttr {
        handled_access_fs: handled_access_fs(abi),
        handled_access_net: 0,
        scoped: if abi >= 6 {
            SCOPE_ABSTRACT_UNIX_SOCKET | SCOPE_SIGNAL
        } else {
            0
        },
    };

    // SAFETY: `attr` is a live local for the duration of the call, and the size passed is the
    // prefix of it this ABI defines (see `ruleset_attr_size`), never more.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::addr_of!(attr),
            ruleset_attr_size(abi),
            0u32,
        )
    };
    let raw = libc::c_int::try_from(ret).unwrap_or(-1);
    if raw < 0 {
        fatal(&format!(
            "landlock_create_ruleset() failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `raw` is a fresh, owned, non-negative fd the kernel just returned to this
    // process; nothing else holds it.
    let fd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };

    let mut rules = builtin_rules(payload_dir);
    rules.extend(extra_read.iter().map(|p| Rule {
        path: leak_path(p),
        access: READ,
        presence: Presence::Required,
    }));
    rules.extend(extra_read_write.iter().map(|p| Rule {
        path: leak_path(p),
        access: READ_WRITE,
        presence: Presence::Required,
    }));

    for rule in &rules {
        add_rule(&fd, rule, &log, fatal);
    }

    log(&format!(
        "Landlock ruleset built (ABI {abi}, {} paths) — every other path is unreachable by the \
         app.",
        rules.len()
    ));
    Ruleset { fd }
}

/// `[app.runtime.landlock]`'s extra paths arrive as borrows of a baked-in `&'static str` that
/// was already split at runtime, so their lifetime is `'static` in fact but not in type. One
/// leak per configured path, once, in a process that never adds more.
fn leak_path(path: &str) -> &'static str {
    Box::leak(path.to_string().into_boxed_str())
}

/// Adds one `LANDLOCK_RULE_PATH_BENEATH` rule, opening its path `O_PATH` (no read permission
/// needed, and no side effect on a device node — which is why this can safely "open"
/// `/dev/sev-guest` without disturbing it).
#[allow(clippy::as_conversions)]
fn add_rule(ruleset: &OwnedFd, rule: &Rule, log: &impl Fn(&str), fatal: fn(&str) -> !) {
    let Ok(cpath) = CString::new(rule.path) else {
        fatal(&format!(
            "Landlock path {:?} contains a NUL byte",
            rule.path
        ));
    };

    // SAFETY: `cpath` is a live NUL-terminated string for the duration of the call.
    let parent_fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if parent_fd < 0 {
        let err = std::io::Error::last_os_error();
        if rule.presence == Presence::Optional {
            log(&format!(
                "[WARN] Landlock: skipping absent path {} ({err})",
                rule.path
            ));
            return;
        }
        fatal(&format!(
            "Landlock: failed to open required path {} ({err}) — this image was not built \
             correctly, or `[app.runtime.landlock]` names a path that doesn't exist",
            rule.path
        ));
    }

    let attr = PathBeneathAttr {
        allowed_access: rule.access,
        parent_fd,
    };
    // SAFETY: `attr` is a live local whose layout matches the packed uapi struct, and
    // `parent_fd` is the fd just opened above; the kernel copies both in during the call.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            std::ptr::addr_of!(attr),
            0u32,
        )
    };
    // SAFETY: closing an fd this function opened and no longer needs — the kernel has already
    // taken its own reference to the path.
    unsafe {
        libc::close(parent_fd);
    }

    if ret != 0 {
        fatal(&format!(
            "landlock_add_rule() failed for {}: {}",
            rule.path,
            std::io::Error::last_os_error()
        ));
    }
}

/// Enforces `ruleset_fd` (from [`Ruleset::raw_fd`]) on the calling process.
///
/// Call only from inside a `Command::pre_exec` closure. Allocation-free and syscall-only, as
/// anything between `fork()` and `execve()` must be. Sets `PR_SET_NO_NEW_PRIVS` first, which
/// the kernel requires before an unprivileged `landlock_restrict_self`; `seccomp.rs` sets it
/// too, and the flag is one-way and idempotent.
///
/// # Errors
///
/// Returns an error if `no_new_privs` or `landlock_restrict_self` fails — which the caller
/// surfaces through `Command::spawn()` into the wipe-and-power-off path, because an app that
/// starts *outside* the sandbox this image promises is worse than an app that doesn't start.
pub(crate) fn restrict_self(ruleset_fd: libc::c_int) -> std::io::Result<()> {
    // SAFETY: plain integer arguments; both return values are checked.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The uapi struct is `__attribute__((packed))`; at 16 bytes the kernel would read
    /// `parent_fd` out of this struct's padding instead of the field.
    #[test]
    fn path_beneath_attr_is_packed_to_twelve_bytes() {
        assert_eq!(std::mem::size_of::<PathBeneathAttr>(), 12);
    }

    #[test]
    fn ruleset_attr_size_matches_each_abi_generation() {
        assert_eq!(ruleset_attr_size(3), 8);
        assert_eq!(ruleset_attr_size(5), 16);
        assert_eq!(ruleset_attr_size(6), 24);
        assert_eq!(ruleset_attr_size(7), 24);
        assert!(ruleset_attr_size(7) <= std::mem::size_of::<RulesetAttr>());
    }

    /// A right left out of `handled_access_fs` is one the ruleset never governs — i.e. one the
    /// app keeps unconditionally. This is the assertion that a new ABI's rights don't get
    /// silently forgotten.
    #[test]
    fn every_governed_right_is_handled_at_the_minimum_abi() {
        let handled = handled_access_fs(MIN_ABI);
        for (name, right) in [
            ("EXECUTE", FS_EXECUTE),
            ("WRITE_FILE", FS_WRITE_FILE),
            ("READ_FILE", FS_READ_FILE),
            ("READ_DIR", FS_READ_DIR),
            ("REMOVE_DIR", FS_REMOVE_DIR),
            ("REMOVE_FILE", FS_REMOVE_FILE),
            ("MAKE_CHAR", FS_MAKE_CHAR),
            ("MAKE_DIR", FS_MAKE_DIR),
            ("MAKE_REG", FS_MAKE_REG),
            ("MAKE_SOCK", FS_MAKE_SOCK),
            ("MAKE_FIFO", FS_MAKE_FIFO),
            ("MAKE_BLOCK", FS_MAKE_BLOCK),
            ("MAKE_SYM", FS_MAKE_SYM),
            ("REFER", FS_REFER),
            ("TRUNCATE", FS_TRUNCATE),
            ("IOCTL_DEV", FS_IOCTL_DEV),
        ] {
            assert!(
                handled & right != 0,
                "{name} is ungoverned, so always allowed"
            );
        }
    }

    /// `FS_IOCTL_DEV` exists only from ABI 5; requesting it on ABI 4 makes the whole
    /// `landlock_create_ruleset` call fail with `EINVAL`.
    #[test]
    fn ioctl_dev_is_not_requested_below_abi_five() {
        assert_eq!(handled_access_fs(4) & FS_IOCTL_DEV, 0);
        assert_ne!(handled_access_fs(5) & FS_IOCTL_DEV, 0);
    }

    /// Device-node creation needs `CAP_MKNOD`, which the app never has.
    #[test]
    fn scratch_directories_never_grant_device_node_creation() {
        assert_eq!(SCRATCH & (FS_MAKE_CHAR | FS_MAKE_BLOCK), 0);
    }

    /// Only the payload directory is executable by default — that is the same claim
    /// `mounts.rs` makes with `noexec`, restated where Landlock can also enforce it.
    #[test]
    #[cfg(not(feature = "danger-allow-write-execute"))]
    fn only_the_payload_is_executable_by_default() {
        let rules = builtin_rules("/payload");
        for rule in &rules {
            let executable = rule.access & FS_EXECUTE != 0;
            assert_eq!(
                executable,
                rule.path == "/payload",
                "{} unexpectedly {} executable",
                rule.path,
                if executable { "is" } else { "is not" }
            );
        }
    }

    /// The mirror of the mount-flag half: opting into `danger-allow-write-execute` has to
    /// grant `FS_EXECUTE` on the scratch mounts too, or the ruleset silently overrides the
    /// toggle and the executable `/tmp` is unreachable anyway.
    #[test]
    #[cfg(feature = "danger-allow-write-execute")]
    fn danger_allow_write_execute_makes_scratch_executable() {
        assert_ne!(SCRATCH & FS_EXECUTE, 0);
    }

    /// `/sys` as a whole is a free enumeration primitive for an attacker with a foothold; the
    /// CPU topology under it is what real runtimes actually read.
    #[test]
    fn sysfs_is_granted_only_at_the_cpu_topology() {
        let rules = builtin_rules("/payload");
        let sys: Vec<&str> = rules
            .iter()
            .map(|r| r.path)
            .filter(|p| p.starts_with("/sys"))
            .collect();
        assert_eq!(sys, vec!["/sys/devices/system/cpu"]);
    }

    /// Writing to the random devices mixes the pool without crediting entropy — harmless, but
    /// there is no reason for the app to be able to do it.
    #[test]
    fn the_random_devices_are_read_only() {
        assert_eq!(DEV_READ & FS_WRITE_FILE, 0);
        assert_eq!(DEV_READ & FS_IOCTL_DEV, 0);
    }

    /// The whole point of pinning ABI 5: `/dev/sev-guest` is an ioctl-only driver, so `ioctl`
    /// is the only right that does anything — and no other device node gets it.
    #[test]
    #[cfg(feature = "sev-snp")]
    fn only_the_attestation_device_may_issue_ioctls() {
        let rules = builtin_rules("/payload");
        let with_ioctl: Vec<&str> = rules
            .iter()
            .filter(|r| r.access & FS_IOCTL_DEV != 0)
            .map(|r| r.path)
            .collect();
        assert_eq!(with_ioctl, vec!["/dev/sev-guest"]);
    }

    /// The kernel this crate is built and tested against is far newer than [`MIN_ABI`]; if
    /// this fails, the test host is the outlier, not the image.
    #[test]
    fn the_running_kernel_supports_the_minimum_abi() {
        let abi = abi_version();
        assert!(
            abi >= MIN_ABI,
            "test host reports Landlock ABI {abi}, below the required {MIN_ABI}"
        );
    }

    /// End-to-end against the running kernel, the way `spawn_app` uses it: a ruleset that
    /// grants nothing under `/etc` must make an `/etc` read fail after `restrict_self`, and
    /// leave a granted path readable.
    #[test]
    fn an_enforced_ruleset_actually_blocks_an_ungranted_path() {
        let temp = std::env::temp_dir();
        let granted = temp.join("cuk-landlock-granted");
        std::fs::write(&granted, b"ok").unwrap();

        let attr = RulesetAttr {
            handled_access_fs: handled_access_fs(abi_version()),
            handled_access_net: 0,
            scoped: 0,
        };
        // SAFETY: same contract as `build` above — a live local, sized to this ABI.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::addr_of!(attr),
                ruleset_attr_size(4).min(ruleset_attr_size(abi_version())),
                0u32,
            )
        };
        let raw = libc::c_int::try_from(raw).unwrap();
        assert!(raw >= 0, "landlock_create_ruleset failed");
        // SAFETY: a fresh owned fd from the kernel.
        let fd = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(raw) };
        add_rule(
            &fd,
            &Rule {
                path: leak_path(temp.to_str().unwrap()),
                access: READ_WRITE,
                presence: Presence::Required,
            },
            &|_: &str| {},
            |m| panic!("{m}"),
        );

        // SAFETY: the child calls only syscalls and `_exit`; the parent only waits on it.
        let status = unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                if restrict_self(fd.as_raw_fd()).is_err() {
                    libc::_exit(97);
                }
                if std::fs::read(&granted).is_err() {
                    libc::_exit(98);
                }
                if std::fs::read("/etc/hostname").is_ok() {
                    libc::_exit(99);
                }
                libc::_exit(0);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0), pid);
            status
        };
        let _ = std::fs::remove_file(&granted);
        assert!(libc::WIFEXITED(status));
        match libc::WEXITSTATUS(status) {
            0 => {}
            97 => panic!("landlock_restrict_self() failed"),
            98 => panic!("a granted path was unreadable under the ruleset"),
            99 => panic!("an ungranted path stayed readable — the ruleset is inert"),
            other => panic!("unexpected child exit {other}"),
        }
    }
}
