//! Filesystem mounting/lockdown and minimal network bring-up shared by the guest init.
//!
//! These functions take a `fatal` callback instead of calling a hardcoded panic/shutdown
//! routine, so the guest init crate can decide how a boot-time mount failure terminates the
//! VM without this crate depending on that.
//!
//! Network bring-up (this whole module's `net-ipv4`/`net-ipv6`-gated half) compiles to
//! nothing at all when neither feature is enabled — `[network].mode = "none"` means no
//! loopback/interface ioctls, no `/proc/net/route` polling, not just an early return past
//! code that still exists in the binary.

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

    let source_ptr = source_c.as_deref().map_or(std::ptr::null(), std::ffi::CStr::as_ptr);
    let fstype_ptr = fstype_c.as_deref().map_or(std::ptr::null(), std::ffi::CStr::as_ptr);
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

#[cfg(feature = "danger-allow-write-execute")]
fn log_write_execute_danger(log: &impl Fn(&str), path: &str) {
    log(&format!(
        "[DANGER] danger-allow-write-execute is compiled in — {path} will be writable AND executable."
    ));
}
#[cfg(not(feature = "danger-allow-write-execute"))]
const fn log_write_execute_danger(_log: &impl Fn(&str), _path: &str) {}

/// Mounts /proc, /sys, /dev(+pts, +shm), /tmp, /run, /var(+tmp) and `payload_dir`, then brings
/// up networking.
///
/// Sysctl hardening is applied separately by the caller via `hardening::apply`. Calls
/// `fatal(msg)` (never returns) on any mount failure.
pub fn prepare_system_env(payload_dir: &str, log: impl Fn(&str), fatal: fn(&str) -> !) {
    log("Mounting essential filesystems...");
    let nosuid_nodev_noexec = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    log_write_execute_danger(&log, "/tmp");

    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        nosuid_nodev_noexec,
        None::<&str>,
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /proc: {e}")));

    mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        nosuid_nodev_noexec,
        None::<&str>,
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /sys: {e}")));

    mount(
        Some("devtmpfs"),
        "/dev",
        Some("devtmpfs"),
        libc::MS_NOSUID,
        None::<&str>,
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /dev: {e}")));

    let _ = std::fs::create_dir("/dev/pts");
    let _ = mount(Some("devpts"), "/dev/pts", Some("devpts"), 0, None::<&str>);

    // /tmp — writable scratch space; NOEXEC unless danger-allow-write-execute is compiled in.
    mount(
        Some("tmpfs"),
        "/tmp",
        Some("tmpfs"),
        writable_exec_mount_flags(),
        Some("size=64m,mode=1700"),
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /tmp: {e}")));

    let _ = std::fs::create_dir_all("/run");
    mount(
        Some("tmpfs"),
        "/run",
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        Some("size=16m,mode=0755"),
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /run: {e}")));

    let _ = std::fs::create_dir_all("/dev/shm");
    mount(
        Some("tmpfs"),
        "/dev/shm",
        Some("tmpfs"),
        nosuid_nodev_noexec,
        Some("mode=1777"),
    )
    .unwrap_or_else(|e| fatal(&format!("Failed to mount /dev/shm: {e}")));

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
        nosuid_nodev_noexec,
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
    init_networking(&log);
    #[cfg(not(any(feature = "net-ipv4", feature = "net-ipv6")))]
    log("Networking disabled ([network].mode = \"none\") — no NIC, skipping bring-up.");

    log("Filesystem environment ready.");
}

#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
fn init_networking(log: &impl Fn(&str)) {
    log("Initializing network interfaces...");

    #[cfg(feature = "net-ipv4")]
    match configure_loopback_v4() {
        Ok(()) => log("Loopback (lo) IPv4 configured: 127.0.0.1/8"),
        Err(e) => log(&format!("[WARN] Failed to configure IPv4 loopback: {e}")),
    }

    match bring_interface_up("lo") {
        Ok(()) => log("Loopback (lo) is UP."),
        Err(e) => log(&format!("[WARN] Failed to bring up loopback: {e}")),
    }

    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            match ensure_interface_up(&name) {
                Ok(was_down) => {
                    if was_down {
                        log(&format!("Interface {name} brought UP"));
                    } else {
                        log(&format!("Interface {name} already UP"));
                    }
                }
                Err(e) => log(&format!("[WARN] Failed to bring up {name}: {e}")),
            }
        }
    }
}

/// `AF_INET`/`IFF_UP`/`IFF_RUNNING` are small, fixed uapi constants (2, 0x1, 0x40) that always
/// fit their narrower `ifreq`-field types — the narrowing here is exact, never lossy.
#[cfg(feature = "net-ipv4")]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn configure_loopback_v4() -> Result<(), String> {
    // SAFETY: `sock` is checked non-negative before each `ioctl`; `ifr`/`sa` are fixed-size,
    // zero-initialized buffers matching `struct ifreq`'s layout. `sock` is closed on every
    // exit path.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(format!("socket(): {}", std::io::Error::last_os_error()));
        }

        let mut ifr = [0u8; 40];
        ifr[..2].copy_from_slice(b"lo");

        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        sa[4..8].copy_from_slice(&[127, 0, 0, 1]);

        ifr[16..32].copy_from_slice(&sa);
        if libc::ioctl(sock, libc::SIOCSIFADDR as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFADDR: {e}"));
        }

        sa[4..8].copy_from_slice(&[255, 0, 0, 0]);
        ifr[16..32].copy_from_slice(&sa);
        if libc::ioctl(sock, libc::SIOCSIFNETMASK as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFNETMASK: {e}"));
        }

        libc::close(sock);
    }
    Ok(())
}

/// Brings `name` UP (and marks it running) via `SIOCGIFFLAGS`/`SIOCSIFFLAGS` — protocol-
/// agnostic (the control socket's own address family doesn't have to match whatever's
/// actually configured on the interface), so this is shared by both IPv4 and IPv6 bring-up.
///
/// For IPv6 specifically: the kernel auto-assigns `::1/128` to `lo` (and a link-local address
/// to any other interface) the moment it comes UP with `CONFIG_IPV6` compiled in — no manual
/// address ioctl needed the way IPv4's [`configure_loopback_v4`] needs one.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
fn bring_interface_up(name: &str) -> Result<(), String> {
    // SAFETY: `sock` is checked non-negative before each `ioctl`; `ifr` is a fixed-size,
    // zero-initialized buffer matching `struct ifreq`, and `name` is truncated to 15 bytes
    // before copying in, leaving room for the trailing NUL. `sock` is closed on every exit path.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(format!("socket(): {}", std::io::Error::last_os_error()));
        }

        let mut ifr = [0u8; 40];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCGIFFLAGS: {e}"));
        }
        let flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
        let new_flags = flags | libc::IFF_UP as i16 | libc::IFF_RUNNING as i16;
        ifr[16..18].copy_from_slice(&new_flags.to_ne_bytes());
        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFFLAGS: {e}"));
        }

        libc::close(sock);
    }
    Ok(())
}

/// See [`bring_interface_up`]'s cast justification — `IFF_UP` is the same kind of small,
/// fixed uapi constant.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
fn ensure_interface_up(name: &str) -> Result<bool, String> {
    // SAFETY: `sock` is checked non-negative before each `ioctl`; `ifr` is a fixed-size,
    // zero-initialized buffer matching `struct ifreq`, and `name` is truncated to 15 bytes
    // before copying in, leaving room for the trailing NUL. `sock` is closed on every exit path.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return Err(format!("socket(): {}", std::io::Error::last_os_error()));
        }

        let mut ifr = [0u8; 40];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCGIFFLAGS: {e}"));
        }

        let flags = i16::from_ne_bytes([ifr[16], ifr[17]]);
        if flags & (libc::IFF_UP as i16) != 0 {
            libc::close(sock);
            return Ok(false);
        }

        let new_flags = flags | libc::IFF_UP as i16;
        ifr[16..18].copy_from_slice(&new_flags.to_ne_bytes());
        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, ifr.as_ptr()) < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFFLAGS: {e}"));
        }

        libc::close(sock);
    }
    Ok(true)
}

/// Reads back the IPv4 address the kernel's `ip=dhcp` autoconfig (or a static assignment) gave
/// an interface, if any.
///
/// `None` covers both "no address yet" and any other ioctl failure — this is a best-effort
/// diagnostic, not something boot should ever fail on.
#[cfg(feature = "net-ipv4")]
#[allow(clippy::cast_possible_truncation)]
fn interface_ipv4_addr(name: &str) -> Option<String> {
    // SAFETY: same reasoning as `ensure_interface_up`.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            return None;
        }

        let mut ifr = [0u8; 40];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = libc::ioctl(sock, libc::SIOCGIFADDR as _, ifr.as_ptr());
        libc::close(sock);
        if ret < 0 {
            return None;
        }

        // `struct sockaddr_in` starts at ifr_addr (offset 16); the IPv4 address itself is at
        // offset 4 within it (after sin_family, sin_port).
        let octets = &ifr[20..24];
        Some(format!(
            "{}.{}.{}.{}",
            octets[0], octets[1], octets[2], octets[3]
        ))
    }
}

/// Reads back every IPv6 address (SLAAC-assigned or otherwise) currently on `name`, by
/// parsing `/proc/net/if_inet6` — the standard Linux mechanism for this (there is no
/// `SIOCGIFADDR`-style ioctl for IPv6 the way [`interface_ipv4_addr`] uses for v4).
///
/// Each line is `<32-hex-char-address> <netlink-dev-no> <prefix-len-hex> <scope-hex>
/// <flags-hex> <device-name>`. Best-effort: any malformed line is silently skipped rather
/// than failing the whole read.
#[cfg(feature = "net-ipv6")]
fn interface_ipv6_addrs(name: &str) -> Vec<std::net::Ipv6Addr> {
    let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") else {
        return Vec::new();
    };
    content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let addr_hex = fields.next()?;
            let dev_name = fields.nth(4)?;
            if dev_name != name || addr_hex.len() != 32 {
                return None;
            }
            let mut bytes = [0u8; 16];
            for (i, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&addr_hex[i * 2..i * 2 + 2], 16).ok()?;
            }
            Some(std::net::Ipv6Addr::from(bytes))
        })
        .collect()
}

/// Logs the current address(es) (or lack thereof) of every non-loopback interface, for
/// whichever protocol(s) are compiled in.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
fn log_interface_addresses(log: &impl Fn(&str)) {
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue;
        }
        #[cfg(feature = "net-ipv4")]
        match interface_ipv4_addr(&name) {
            Some(addr) => log(&format!("{name}: IPv4 {addr}")),
            None => log(&format!("{name}: no IPv4 address assigned yet")),
        }
        #[cfg(feature = "net-ipv6")]
        {
            let addrs = interface_ipv6_addrs(&name);
            if addrs.is_empty() {
                log(&format!("{name}: no IPv6 address assigned yet"));
            }
            for addr in addrs {
                log(&format!("{name}: IPv6 {addr}"));
            }
        }
    }
}

#[cfg(feature = "net-ipv4")]
fn has_default_route_v4() -> bool {
    let Ok(routes) = std::fs::read_to_string("/proc/net/route") else {
        return false;
    };
    routes.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        fields.next();
        fields.next().is_some_and(|dest| dest == "00000000")
    })
}

/// `/proc/net/ipv6_route` fields: `dest_addr dest_prefixlen src_addr src_prefixlen next_hop
/// metric refcnt use flags devname` — a default route has an all-zero destination and a
/// zero prefix length.
#[cfg(feature = "net-ipv6")]
fn has_default_route_v6() -> bool {
    let Ok(routes) = std::fs::read_to_string("/proc/net/ipv6_route") else {
        return false;
    };
    routes.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let dest = fields.next();
        let prefix_len = fields.next();
        dest == Some("00000000000000000000000000000000") && prefix_len == Some("00")
    })
}

#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
fn has_default_route() -> bool {
    #[cfg(feature = "net-ipv4")]
    if has_default_route_v4() {
        return true;
    }
    #[cfg(feature = "net-ipv6")]
    if has_default_route_v6() {
        return true;
    }
    false
}

/// Polls for a default route instead of unconditionally sleeping for the worst-case settle
/// time.
///
/// Returns as soon as one appears, bounded by `max_wait` so a DHCP/SLAAC that never settles
/// can't hang the boot.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
pub fn wait_for_network_settle(
    max_wait: std::time::Duration,
    poll_interval: std::time::Duration,
    log: impl Fn(&str),
) {
    log("Waiting for network to settle (polling for a default route)...");
    let deadline = std::time::Instant::now() + max_wait;
    while std::time::Instant::now() < deadline {
        if has_default_route() {
            log("Network settled (default route present).");
            log_interface_addresses(&log);
            return;
        }
        std::thread::sleep(poll_interval);
    }
    log("[WARN] No default route after the settle timeout — continuing anyway.");
    log_interface_addresses(&log);
}

/// `/tmp`'s remount flags for [`lockdown_filesystem`] — mirrors [`writable_exec_mount_flags`],
/// minus the initial mount-only flags. `/var` needs no equivalent remount: it's never
/// remounted read-only or noexec after its initial mount, so whatever
/// [`writable_exec_mount_flags`] gave it at mount time (see `prepare_system_env`) simply
/// persists for the rest of the boot.
#[cfg(feature = "danger-allow-write-execute")]
const fn tmp_remount_flags() -> libc::c_ulong {
    libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV
}
#[cfg(not(feature = "danger-allow-write-execute"))]
const fn tmp_remount_flags() -> libc::c_ulong {
    libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC
}

#[cfg(feature = "danger-allow-write-execute")]
fn log_lockdown_complete(log: &impl Fn(&str)) {
    log(
        "[DANGER] Filesystem lockdown complete, EXCEPT /tmp and /var: danger-allow-write-execute \
         is compiled in, so both remain writable+executable for the rest of this boot.",
    );
}
#[cfg(not(feature = "danger-allow-write-execute"))]
fn log_lockdown_complete(log: &impl Fn(&str)) {
    log("Filesystem lockdown complete. No writable+executable paths remain.");
}

/// Remounts `payload_dir` read-only and (unless `danger-allow-write-execute` is compiled in)
/// `/tmp` noexec, sealing off all writable+executable paths.
///
/// `/run` is remounted noexec unconditionally. Calls `fatal(msg)` (never returns) on any
/// remount failure.
pub fn lockdown_filesystem(payload_dir: &str, log: impl Fn(&str), fatal: fn(&str) -> !) {
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
    .unwrap_or_else(|e| fatal(&format!("Failed to lockdown {payload_dir} to Read-Only: {e}")));

    mount(
        None::<&str>,
        "/tmp",
        None::<&str>,
        tmp_remount_flags(),
        Some("size=64m,mode=1700"),
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
