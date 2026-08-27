//! Filesystem mounting and lockdown for the guest init: /proc, /sys, /dev, /tmp, /run, /var
//! and the payload bind mount, plus the read-only/noexec remount that seals them at the end
//! of boot.
//!
//! These functions take a `fatal` callback instead of calling a hardcoded panic/shutdown
//! routine, so this module can decide how a boot-time mount failure terminates the VM without
//! depending on that routine directly.
//!
//! `mount(2)` itself goes through `rustix::mount` rather than a hand-rolled `libc::mount` FFI
//! call: rustix's implementation is the one place that gets the raw-pointer/NUL-terminated
//! argument handling right, audited far beyond what one function in this crate could be.

use rustix::mount::MountFlags;
use std::ffi::CString;

/// tmpfs sizes in MiB, baked in by `build.rs` from `[storage.tmpfs]`. Plain per-deployment
/// data, not a toggle — see `Cargo.toml`'s feature list for the actual on/off switches.
const TMPFS_TMP_MB: &str = env!("CARGO_UNIKERNEL_TMPFS_TMP_MB");
const TMPFS_RUN_MB: &str = env!("CARGO_UNIKERNEL_TMPFS_RUN_MB");
const TMPFS_SHM_MB: &str = env!("CARGO_UNIKERNEL_TMPFS_SHM_MB");
const TMPFS_VAR_TMP_MB: &str = env!("CARGO_UNIKERNEL_TMPFS_VAR_TMP_MB");

/// `data` as a `CString`, for the one argument `rustix::mount::mount` still takes as an
/// `Option<&CStr>` rather than a generic `path::Arg` — every other argument here is a fixed
/// string literal chosen by this crate, so only this one ever needs the conversion.
fn mount_data(data: Option<&str>) -> std::io::Result<Option<CString>> {
    data.map(|d| {
        CString::new(d).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mount() data must not contain a NUL byte",
            )
        })
    })
    .transpose()
}

/// `mount(source, target, fstype, flags, data)`.
pub(crate) fn mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: MountFlags,
    data: Option<&str>,
) -> std::io::Result<()> {
    let data = mount_data(data)?;
    rustix::mount::mount(source, target, fstype, flags, data.as_deref()).map_err(Into::into)
}

/// `mount(source, target, NULL, MS_BIND, NULL)`.
fn bind_mount(source: &str, target: &str) -> std::io::Result<()> {
    rustix::mount::mount_bind(source, target).map_err(Into::into)
}

/// `mount(NULL, target, NULL, MS_REMOUNT | flags, data)`.
fn remount(target: &str, flags: MountFlags, data: &str) -> std::io::Result<()> {
    rustix::mount::mount_remount(target, flags, data).map_err(Into::into)
}

/// `umount2(target, 0)`. Used by `storage.rs` to flush `/var`'s journal before power-off.
#[cfg(feature = "storage-persistent")]
#[must_use]
pub(crate) fn unmount(target: &str) -> bool {
    rustix::mount::unmount(target, rustix::mount::UnmountFlags::empty()).is_ok()
}

const NOSUID_NODEV_NOEXEC: MountFlags = MountFlags::NOSUID
    .union(MountFlags::NODEV)
    .union(MountFlags::NOEXEC);

/// Shared by every path `danger-allow-write-execute` affects (`/tmp`, and `/var` — see
/// `storage.rs` for the persistent-mode ext4 case): `noexec` unless that feature is compiled
/// in, in which case the path is writable AND executable.
///
/// Two separate functions selected by `#[cfg]`, not one function with a runtime `if`: only
/// the flags for whichever build was actually requested exist in the binary.
#[cfg(feature = "danger-allow-write-execute")]
pub(crate) const fn writable_exec_mount_flags() -> MountFlags {
    MountFlags::NOSUID.union(MountFlags::NODEV)
}
#[cfg(not(feature = "danger-allow-write-execute"))]
pub(crate) const fn writable_exec_mount_flags() -> MountFlags {
    MountFlags::NOSUID
        .union(MountFlags::NODEV)
        .union(MountFlags::NOEXEC)
}

/// Whether `danger-allow-write-execute` is compiled in. Only ever consulted to pick a log
/// string — the mount flags themselves go through [`writable_exec_mount_flags`], where the
/// `#[cfg]` split keeps the unrequested build's flags out of the binary entirely.
const ALLOW_WRITE_EXECUTE: bool = cfg!(feature = "danger-allow-write-execute");

fn log_write_execute_danger(log: &impl Fn(&str), path: &str) {
    if ALLOW_WRITE_EXECUTE {
        log(&format!(
            "[DANGER] danger-allow-write-execute is compiled in — {path} will be writable AND executable."
        ));
    }
}

/// Mounts /proc, /sys, /dev(+pts, +shm), /tmp, /run, /var(+tmp) and `payload_dir`, then brings
/// up networking.
///
/// Sysctl hardening is applied separately by the caller via `hardening::apply`. Calls
/// `fatal(msg)` (never returns) on any mount failure.
pub(crate) fn prepare_system_env(payload_dir: &str, log: impl Fn(&str), fatal: fn(&str) -> !) {
    log("Mounting essential filesystems...");
    log_write_execute_danger(&log, "/tmp");

    let tmp_data = format!("size={TMPFS_TMP_MB}m,mode=1777");
    let run_data = format!("size={TMPFS_RUN_MB}m,mode=0755");
    let shm_data = format!("size={TMPFS_SHM_MB}m,mode=1777");

    // Ordered: each entry's target must already exist, which for /dev/pts, /dev/shm and
    // /var/tmp means the filesystem carrying it is mounted by an earlier entry.
    let base: &[(&str, &str, &str, MountFlags, Option<&str>)] = &[
        // `hidepid=2`: the app is the only unprivileged process here, and everything else in
        // /proc belongs to PID 1 — so this hides the init's cmdline (which comes from the
        // host-supplied kernel command line) and its /proc entries from the app entirely,
        // rather than relying on PID 1's non-dumpable bit to cover each one individually.
        (
            "proc",
            "/proc",
            "proc",
            NOSUID_NODEV_NOEXEC,
            Some("hidepid=2"),
        ),
        ("sysfs", "/sys", "sysfs", NOSUID_NODEV_NOEXEC, None),
        (
            "devtmpfs",
            "/dev",
            "devtmpfs",
            MountFlags::NOSUID.union(MountFlags::NOEXEC),
            None,
        ),
        // /tmp — writable scratch; NOEXEC unless danger-allow-write-execute is compiled in.
        // 1777, not 1700: the mount root belongs to root and the app runs as an unprivileged
        // uid, so anything narrower leaves the app unable to write to /tmp at all. The sticky
        // bit is what keeps that from also meaning "any process may unlink another's files".
        (
            "tmpfs",
            "/tmp",
            "tmpfs",
            writable_exec_mount_flags(),
            Some(tmp_data.as_str()),
        ),
        (
            "tmpfs",
            "/run",
            "tmpfs",
            NOSUID_NODEV_NOEXEC,
            Some(run_data.as_str()),
        ),
        // Sized separately from `/tmp` (see `CARGO_UNIKERNEL_TMPFS_SHM_MB`), rather than
        // taking tmpfs's default, which is *half of guest RAM* — without a cap this is one
        // more writable mount an app can grow until the guest OOMs, and one more the shutdown
        // scrub has to zero against its deadline.
        (
            "tmpfs",
            "/dev/shm",
            "tmpfs",
            NOSUID_NODEV_NOEXEC,
            Some(shm_data.as_str()),
        ),
    ];
    for &(source, target, fstype, flags, data) in base {
        let _ = std::fs::create_dir_all(target);
        mount(source, target, fstype, flags, data)
            .unwrap_or_else(|e| fatal(&format!("Failed to mount {target}: {e}")));
    }

    // Best-effort, unlike the table above: a guest with no pty support is fine, nothing here
    // needs one. Carries the same nosuid/noexec floor as everything else regardless — being
    // optional is not a reason for it to be the one mount an app could exec from.
    let _ = std::fs::create_dir("/dev/pts");
    let _ = mount(
        "devpts",
        "/dev/pts",
        "devpts",
        MountFlags::NOSUID.union(MountFlags::NOEXEC),
        Some("mode=0620,ptmxmode=0666"),
    );

    let _ = std::fs::create_dir_all("/var");
    log_write_execute_danger(&log, "/var");
    #[cfg(feature = "storage-persistent")]
    crate::storage::mount_persistent_var(&log, fatal);
    #[cfg(not(feature = "storage-persistent"))]
    mount(
        "tmpfs",
        "/var",
        "tmpfs",
        writable_exec_mount_flags(),
        Some("mode=0755"),
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /var: {e}")));

    let _ = std::fs::create_dir_all("/var/tmp");
    let var_tmp_data = format!("size={TMPFS_VAR_TMP_MB}m,mode=1777");
    mount(
        "tmpfs",
        "/var/tmp",
        "tmpfs",
        NOSUID_NODEV_NOEXEC,
        Some(&var_tmp_data),
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /var/tmp: {e}")));

    // The app binary is already baked into payload_dir by the build pipeline, so a fresh
    // tmpfs mount here would hide it. Bind-mount it onto itself instead: preserves contents
    // while turning it into a distinct mountpoint, which lockdown_filesystem() needs to
    // remount read-only later. No NOEXEC: the app binary must be executable from here.
    bind_mount(payload_dir, payload_dir)
        .unwrap_or_else(|e| fatal(&format!("Failed to bind-mount {payload_dir}: {e}")));
    remount(
        payload_dir,
        MountFlags::BIND
            .union(MountFlags::NOSUID)
            .union(MountFlags::NODEV),
        "",
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to remount {payload_dir}: {e}")));

    #[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
    crate::network::init_networking(&log);
    #[cfg(not(any(feature = "net-ipv4", feature = "net-ipv6")))]
    log("Networking disabled ([network].mode = \"none\") — no NIC, skipping bring-up.");

    log("Filesystem environment ready.");
}

/// `/tmp`'s remount flags for [`lockdown_filesystem`] — mirrors [`writable_exec_mount_flags`],
/// minus the initial mount-only flags. `/var` needs no equivalent remount: it's never
/// remounted read-only or noexec after its initial mount, so whatever
/// [`writable_exec_mount_flags`] gave it at mount time (see `prepare_system_env`) simply
/// persists for the rest of the boot.
const fn tmp_remount_flags() -> MountFlags {
    writable_exec_mount_flags()
}

/// The claim is about *paths*, deliberately: this seals the file-backed routes to executing new
/// code (every writable mount is `noexec`, and `seccomp.rs` denies `memfd_create`/`memfd_secret`
/// so an anonymous file can't be `execveat`'d past those flags). It is not W^X — an app can
/// still `mmap`/`mprotect` anonymous `PROT_WRITE|PROT_EXEC` memory and run whatever it puts
/// there, which no mount flag can see. Filtering `mmap`'s protection argument is the only thing
/// that would close it, and doing so breaks every JIT and several allocators, so it isn't done.
fn log_lockdown_complete(log: &impl Fn(&str)) {
    if ALLOW_WRITE_EXECUTE {
        log(
            "[DANGER] Filesystem lockdown complete, EXCEPT /tmp and /var: \
             danger-allow-write-execute is compiled in, so both remain writable+executable for \
             the rest of this boot.",
        );
    } else {
        log("Filesystem lockdown complete. No writable+executable paths remain.");
    }
}

/// `/proc`'s remount data for [`lockdown_filesystem`] — plain `hidepid=2` (same as the initial
/// mount) by default, or `hidepid=2,subset=pid` when the `proc-subset-pid` feature is compiled
/// in, hiding every non-process entry (`/proc/cpuinfo`, `/proc/meminfo`, `/proc/net/*`, ...)
/// from the app. Two functions selected by `#[cfg]`, matching [`writable_exec_mount_flags`]'s
/// pattern, rather than a baked bool an `if` reads: an app that couldn't reach `subset=pid`'s
/// restriction through a bypassed check can't reach it through absent code either.
#[cfg(feature = "proc-subset-pid")]
const fn proc_remount_data() -> &'static str {
    "hidepid=2,subset=pid"
}
#[cfg(not(feature = "proc-subset-pid"))]
const fn proc_remount_data() -> &'static str {
    "hidepid=2"
}

/// Remounts `/proc` (see [`proc_remount_data`]), `payload_dir` read-only, and (unless
/// `danger-allow-write-execute` is compiled in) `/tmp` noexec, sealing off all
/// writable+executable paths.
///
/// The `/proc` remount runs last among the three, after every sysctl write this crate performs
/// (`hardening::apply`, called by the caller before this function) — `subset=pid` would hide
/// `/proc/sys` from a plain path lookup the same way it hides everything else non-process, and
/// this init still needs to write there itself up to this point in boot.
///
/// `/run` is remounted noexec unconditionally. Calls `fatal(msg)` (never returns) on any
/// remount failure.
pub(crate) fn lockdown_filesystem(payload_dir: &str, log: impl Fn(&str), fatal: fn(&str) -> !) {
    log("Locking down filesystem...");

    remount("/proc", NOSUID_NODEV_NOEXEC, proc_remount_data())
        .unwrap_or_else(|e| fatal(&format!("Failed to remount /proc: {e}")));

    // payload_dir is a bind mount — remounting it read-only requires MS_BIND alongside
    // MS_REMOUNT, or the kernel ignores the flag change.
    remount(
        payload_dir,
        MountFlags::BIND
            .union(MountFlags::RDONLY)
            .union(MountFlags::NOSUID)
            .union(MountFlags::NODEV),
        "",
    )
    .unwrap_or_else(|e| {
        fatal(&format!(
            "Failed to lockdown {payload_dir} to Read-Only: {e}"
        ))
    });

    let tmp_data = format!("size={TMPFS_TMP_MB}m,mode=1777");
    remount("/tmp", tmp_remount_flags(), &tmp_data)
        .unwrap_or_else(|e| fatal(&format!("Failed to remount /tmp: {e}")));

    let run_data = format!("size={TMPFS_RUN_MB}m,mode=0755");
    remount(
        "/run",
        MountFlags::NOSUID
            .union(MountFlags::NODEV)
            .union(MountFlags::NOEXEC),
        &run_data,
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to remount /run noexec: {e}")));

    log_lockdown_complete(&log);
}
