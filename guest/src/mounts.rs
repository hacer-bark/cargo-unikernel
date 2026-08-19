//! Filesystem mounting and lockdown for the guest init: /proc, /sys, /dev, /tmp, /run, /var
//! and the payload bind mount, plus the read-only/noexec remount that seals them at the end
//! of boot.
//!
//! These functions take a `fatal` callback instead of calling a hardcoded panic/shutdown
//! routine, so this module can decide how a boot-time mount failure terminates the VM without
//! depending on that routine directly.

use std::ffi::CString;

/// Thin wrapper over the raw `mount(2)` syscall — kept local rather than pulling in `nix` for
/// one function: every argument here is either `None`/empty or a fixed string literal chosen by
/// this crate, so there's no safety or ergonomics the extra dependency would have bought.
pub(crate) fn mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> std::io::Result<()> {
    let to_cstring = |s: &str| {
        CString::new(s).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mount() argument must not contain a NUL byte",
            )
        })
    };
    let source_c = source.map(to_cstring).transpose()?;
    let target_c = to_cstring(target)?;
    let fstype_c = fstype.map(to_cstring).transpose()?;
    let data_c = data.map(to_cstring).transpose()?;

    let source_ptr = source_c
        .as_deref()
        .map_or(std::ptr::null(), std::ffi::CStr::as_ptr);
    let fstype_ptr = fstype_c
        .as_deref()
        .map_or(std::ptr::null(), std::ffi::CStr::as_ptr);
    let data_ptr = data_c
        .as_deref()
        .map_or(std::ptr::null(), std::ffi::CStr::as_ptr)
        .cast::<libc::c_void>();

    // SAFETY: `source_ptr`/`fstype_ptr`/`data_ptr` are each either null or a valid, live
    // NUL-terminated `CString` pointer owned by a local still in scope for the call;
    // `target_c` likewise outlives the call.
    let ret = unsafe { libc::mount(source_ptr, target_c.as_ptr(), fstype_ptr, flags, data_ptr) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

const NOSUID_NODEV_NOEXEC: libc::c_ulong = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;

/// Shared by every path `danger-allow-write-execute` affects (`/tmp`, and `/var` — see
/// `storage.rs` for the persistent-mode ext4 case): `noexec` unless that feature is compiled
/// in, in which case the path is writable AND executable.
///
/// Two separate functions selected by `#[cfg]`, not one function with a runtime `if`: only
/// the flags for whichever build was actually requested exist in the binary.
#[cfg(feature = "danger-allow-write-execute")]
pub(crate) const fn writable_exec_mount_flags() -> libc::c_ulong {
    libc::MS_NOSUID | libc::MS_NODEV
}
#[cfg(not(feature = "danger-allow-write-execute"))]
pub(crate) const fn writable_exec_mount_flags() -> libc::c_ulong {
    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC
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

    // Ordered: each entry's target must already exist, which for /dev/pts, /dev/shm and
    // /var/tmp means the filesystem carrying it is mounted by an earlier entry.
    let base: &[(&str, &str, &str, libc::c_ulong, Option<&str>)] = &[
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
            libc::MS_NOSUID | libc::MS_NOEXEC,
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
            Some("size=64m,mode=1777"),
        ),
        (
            "tmpfs",
            "/run",
            "tmpfs",
            NOSUID_NODEV_NOEXEC,
            Some("size=16m,mode=0755"),
        ),
        // `size=64m` to match /tmp rather than taking tmpfs's default, which is *half of guest
        // RAM* — without it this is the one writable mount an app can grow until the guest OOMs,
        // and the one the shutdown scrub then has to zero against its deadline.
        (
            "tmpfs",
            "/dev/shm",
            "tmpfs",
            NOSUID_NODEV_NOEXEC,
            Some("size=64m,mode=1777"),
        ),
    ];
    for &(source, target, fstype, flags, data) in base {
        let _ = std::fs::create_dir_all(target);
        mount(Some(source), target, Some(fstype), flags, data)
            .unwrap_or_else(|e| fatal(&format!("Failed to mount {target}: {e}")));
    }

    // Best-effort, unlike the table above: a guest with no pty support is fine, nothing here
    // needs one. Carries the same nosuid/noexec floor as everything else regardless — being
    // optional is not a reason for it to be the one mount an app could exec from.
    let _ = std::fs::create_dir("/dev/pts");
    let _ = mount(
        Some("devpts"),
        "/dev/pts",
        Some("devpts"),
        libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("mode=0620,ptmxmode=0666"),
    );

    let _ = std::fs::create_dir_all("/var");
    log_write_execute_danger(&log, "/var");
    #[cfg(feature = "storage-persistent")]
    crate::storage::mount_persistent_var(&log, fatal);
    #[cfg(not(feature = "storage-persistent"))]
    mount(
        Some("tmpfs"),
        "/var",
        Some("tmpfs"),
        writable_exec_mount_flags(),
        Some("mode=0755"),
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /var: {e}")));

    let _ = std::fs::create_dir_all("/var/tmp");
    mount(
        Some("tmpfs"),
        "/var/tmp",
        Some("tmpfs"),
        NOSUID_NODEV_NOEXEC,
        Some("size=64m,mode=1777"),
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /var/tmp: {e}")));

    // The app binary is already baked into payload_dir by the build pipeline, so a fresh
    // tmpfs mount here would hide it. Bind-mount it onto itself instead: preserves contents
    // while turning it into a distinct mountpoint, which lockdown_filesystem() needs to
    // remount read-only later. No NOEXEC: the app binary must be executable from here.
    mount(
        Some(payload_dir),
        payload_dir,
        None::<&str>,
        libc::MS_BIND,
        None::<&str>,
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to bind-mount {payload_dir}: {e}")));
    mount(
        None::<&str>,
        payload_dir,
        None::<&str>,
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_NOSUID | libc::MS_NODEV,
        None::<&str>,
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
const fn tmp_remount_flags() -> libc::c_ulong {
    libc::MS_REMOUNT | writable_exec_mount_flags()
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

/// Remounts `payload_dir` read-only and (unless `danger-allow-write-execute` is compiled in)
/// `/tmp` noexec, sealing off all writable+executable paths.
///
/// `/run` is remounted noexec unconditionally. Calls `fatal(msg)` (never returns) on any
/// remount failure.
pub(crate) fn lockdown_filesystem(payload_dir: &str, log: impl Fn(&str), fatal: fn(&str) -> !) {
    log("Locking down filesystem...");

    // payload_dir is a bind mount — remounting it read-only requires MS_BIND alongside
    // MS_REMOUNT, or the kernel ignores the flag change.
    mount(
        None::<&str>,
        payload_dir,
        None::<&str>,
        libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None::<&str>,
    )
    .unwrap_or_else(|e| {
        fatal(&format!(
            "Failed to lockdown {payload_dir} to Read-Only: {e}"
        ))
    });

    mount(
        None::<&str>,
        "/tmp",
        None::<&str>,
        tmp_remount_flags(),
        Some("size=64m,mode=1777"),
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to remount /tmp: {e}")));

    mount(
        None::<&str>,
        "/run",
        None::<&str>,
        libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("size=16m,mode=0755"),
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to remount /run noexec: {e}")));

    log_lockdown_complete(&log);
}
