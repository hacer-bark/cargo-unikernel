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
pub fn prepare_system_env(payload_dir: &str, log: impl Fn(&str), fatal: fn(&str) -> !) {
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

    for name in std::iter::once("lo".to_string()).chain(non_loopback_interfaces()) {
        match ensure_interface_up(&name) {
            Ok(true) => log(&format!("Interface {name} brought UP")),
            Ok(false) => log(&format!("Interface {name} already UP")),
            Err(e) => log(&format!("[WARN] Failed to bring up {name}: {e}")),
        }
    }
}

/// Every interface the kernel currently knows about except loopback, which every caller here
/// handles separately.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
fn non_loopback_interfaces() -> impl Iterator<Item = String> {
    std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "lo")
}

/// Assigns a fixed IPv6 address (and, optionally, a default route through `gateway`) to
/// `interface`, or to the sole non-loopback interface when `interface` is `None`.
///
/// `static_v6` is `"address/prefix_len"`, exactly as `[network.ipv6_static]` was baked in by
/// `build.rs`; an empty string means the setting is unset and this does nothing.
///
/// Best-effort, deliberately: a failure here is logged and boot continues. The guest still has
/// its SLAAC address, so refusing to boot would turn "reachable at an address you didn't plan
/// for" into "not running at all", which is strictly worse. The `[WARN]` lines are the signal —
/// and are the reason a guest whose console you *can* read is worth booting once before relying
/// on this in an image whose console you can't.
#[cfg(feature = "net-ipv6")]
pub fn configure_static_ipv6(static_v6: &str, gateway: &str, interface: &str, log: &impl Fn(&str)) {
    if static_v6.is_empty() {
        return;
    }

    let Some((address, prefix_len)) = parse_static_v6(static_v6) else {
        log(&format!(
            "[WARN] Ignoring malformed [network.ipv6_static] {static_v6:?} — expected \
             \"address/prefix_len\""
        ));
        return;
    };

    let name = if interface.is_empty() {
        let mut candidates: Vec<String> = non_loopback_interfaces().collect();
        // Sorted so a multi-NIC guest that didn't name one at least picks the same interface on
        // every boot, rather than whatever order /sys/class/net happened to be read in.
        candidates.sort();
        let Some(name) = candidates.first().cloned() else {
            log("[WARN] [network.ipv6_static] set but the guest has no non-loopback interface");
            return;
        };
        if candidates.len() > 1 {
            log(&format!(
                "[WARN] [network.ipv6_static] didn't name an interface and this guest has \
                 {} — using {name}. Set `interface` to choose deliberately.",
                candidates.len()
            ));
        }
        name
    } else {
        interface.to_string()
    };

    match assign_ipv6_address(&name, address, prefix_len) {
        Ok(()) => log(&format!(
            "{name}: IPv6 {address}/{prefix_len} assigned statically — this is the address to \
             connect to"
        )),
        Err(e) => log(&format!(
            "[WARN] Failed to assign static IPv6 {address}/{prefix_len} to {name}: {e}. The \
             guest is reachable only at its SLAAC address, which this boot's console log names."
        )),
    }

    if gateway.is_empty() {
        return;
    }
    let Ok(gateway_addr) = gateway.parse::<std::net::Ipv6Addr>() else {
        log(&format!(
            "[WARN] Ignoring malformed [network.ipv6_static].gateway {gateway:?}"
        ));
        return;
    };
    match add_ipv6_default_route(&name, gateway_addr) {
        Ok(()) => log(&format!(
            "{name}: IPv6 default route via {gateway_addr} (metric {STATIC_ROUTE_METRIC}, \
             below any router advertisement)"
        )),
        // The configured gateway is only needed where nothing advertises one, so finding the
        // identical route already installed is a no-op, not a failure.
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            log(&format!(
                "{name}: IPv6 default route via {gateway_addr} already present"
            ));
        }
        Err(e) => log(&format!(
            "[WARN] Failed to add IPv6 default route via {gateway_addr} on {name}: {e}"
        )),
    }
}

/// Splits the baked `"address/prefix_len"` string. `None` on anything malformed — the host side
/// validated this (`schema::Config::validate_ipv6_static`), so a failure here means the two
/// sides disagree, not that a user typed something wrong.
#[cfg(feature = "net-ipv6")]
fn parse_static_v6(raw: &str) -> Option<(std::net::Ipv6Addr, u8)> {
    let (address, prefix_len) = raw.split_once('/')?;
    let address = address.parse().ok()?;
    let prefix_len: u8 = prefix_len.parse().ok()?;
    if prefix_len == 0 || prefix_len > 128 {
        return None;
    }
    Some((address, prefix_len))
}

/// `struct in6_ifreq` from `linux/ipv6.h`: a 16-byte address, a `u32` prefix length, and a
/// `c_int` interface index — 24 bytes, no padding.
///
/// The old `SIOCSIFADDR`-with-`in6_ifreq` interface rather than rtnetlink: assigning one address
/// is all this needs, and a netlink socket plus message assembly is a great deal more code (and
/// more `unsafe`) for the same single syscall.
#[cfg(feature = "net-ipv6")]
#[repr(C)]
struct In6IfReq {
    addr: [u8; 16],
    prefix_len: u32,
    ifindex: libc::c_int,
}

/// The interface index the kernel knows `name` by, needed by both `in6_ifreq` and `in6_rtmsg`.
#[cfg(feature = "net-ipv6")]
fn interface_index(name: &str) -> std::io::Result<libc::c_int> {
    let mut ifr = ifreq_for(name);
    ifreq_ioctl(libc::SIOCGIFINDEX, &mut ifr, "SIOCGIFINDEX").map_err(std::io::Error::other)?;
    Ok(libc::c_int::from_ne_bytes([
        ifr[IFR_UNION],
        ifr[IFR_UNION + 1],
        ifr[IFR_UNION + 2],
        ifr[IFR_UNION + 3],
    ]))
}

/// Runs one ioctl on a throwaway `AF_INET6` socket — which, unlike the `AF_INET` one
/// [`ifreq_ioctl`] uses, is required here: the IPv6 address and route ioctls are dispatched by
/// the socket's family, not by the request number.
#[cfg(feature = "net-ipv6")]
///
/// Returns the errno-carrying error untouched rather than wrapping it in a labelled one:
/// `io::Error::new` discards `raw_os_error()`, and the caller distinguishes `EEXIST` from a real
/// failure by exactly that. Callers name the operation in their own message instead.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn inet6_ioctl<T>(request: libc::c_ulong, arg: &mut T) -> std::io::Result<()> {
    // SAFETY: `sock` is checked non-negative before use and closed on every exit path; `arg` is
    // a live, correctly-shaped struct borrowed mutably for the call's duration.
    unsafe {
        let sock = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let ret = libc::ioctl(sock, request as _, std::ptr::from_mut(arg));
        let err = std::io::Error::last_os_error();
        libc::close(sock);
        if ret < 0 {
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(feature = "net-ipv6")]
fn assign_ipv6_address(
    name: &str,
    address: std::net::Ipv6Addr,
    prefix_len: u8,
) -> std::io::Result<()> {
    let mut req = In6IfReq {
        addr: address.octets(),
        prefix_len: u32::from(prefix_len),
        ifindex: interface_index(name)?,
    };
    inet6_ioctl(libc::SIOCSIFADDR, &mut req)
}

/// `struct in6_rtmsg` from `linux/ipv6_route.h`. Field order and the `unsigned long` in the
/// middle (which forces the 4 bytes of padding before it on `x86_64`) are what fix this layout.
#[cfg(feature = "net-ipv6")]
#[repr(C)]
struct In6RtMsg {
    dst: [u8; 16],
    src: [u8; 16],
    gateway: [u8; 16],
    rtmsg_type: u32,
    dst_len: u16,
    src_len: u16,
    metric: u32,
    _pad: u32,
    info: libc::c_ulong,
    flags: u32,
    ifindex: libc::c_int,
}

/// Both structs are passed straight to the kernel, so a layout that drifts from the uapi one
/// wouldn't fail to compile — it would silently write the prefix length into the wrong field.
/// The sizes are the cheap half of pinning that down; the offsets below are the rest. Verified
/// against `linux/ipv6.h` and `linux/ipv6_route.h` on `x86_64`.
#[cfg(feature = "net-ipv6")]
const _: () = {
    assert!(size_of::<In6IfReq>() == 24);
    assert!(size_of::<In6RtMsg>() == 80);
};

/// Deliberately *worse* than the 1024 the kernel gives a router-advertisement default route.
///
/// At equal metric the kernel merges two default routes with different gateways into one
/// multipath entry and load-balances across both — so a configured gateway would silently take
/// half the guest's traffic away from the real router. A higher number keeps the two as separate
/// entries with the advertised one preferred, which makes the configured gateway a fallback for
/// the case it exists for (no advertisements at all) instead of a hazard when it's not needed.
/// The ordering the two arrive in stops mattering, which matters here because this runs before
/// the network has settled.
#[cfg(feature = "net-ipv6")]
const STATIC_ROUTE_METRIC: u32 = 2048;

/// Installs `::/0` via `gateway`, for a provider that routes a prefix without advertising it.
#[cfg(feature = "net-ipv6")]
fn add_ipv6_default_route(name: &str, gateway: std::net::Ipv6Addr) -> std::io::Result<()> {
    const RTF_UP: u32 = 0x0001;
    const RTF_GATEWAY: u32 = 0x0002;

    let mut rt = In6RtMsg {
        dst: [0u8; 16],
        src: [0u8; 16],
        gateway: gateway.octets(),
        rtmsg_type: 0,
        dst_len: 0,
        src_len: 0,
        metric: STATIC_ROUTE_METRIC,
        _pad: 0,
        info: 0,
        flags: RTF_UP | RTF_GATEWAY,
        ifindex: interface_index(name)?,
    };
    inet6_ioctl(libc::SIOCADDRT, &mut rt)
}

/// `struct ifreq` on `x86_64`: a 16-byte `ifr_name` followed by a 24-byte union. Interface
/// bring-up and address readback are the same four steps every time — open a control socket,
/// stamp the name in, run an ioctl, read the union back — so they share this buffer type and
/// the helper below rather than repeating that per ioctl.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
type IfReq = [u8; 40];
/// Offset of the union (`ifr_flags`, `ifr_addr`, …) within [`IfReq`].
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
const IFR_UNION: usize = 16;

/// Builds an [`IfReq`] naming `name`, truncated to 15 bytes so the trailing NUL always fits.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
fn ifreq_for(name: &str) -> IfReq {
    let mut ifr = [0u8; 40];
    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    ifr[..len].copy_from_slice(&bytes[..len]);
    ifr
}

/// Runs one `ifreq`-shaped ioctl on a throwaway `AF_INET` control socket.
///
/// `ifr` is passed by `&mut` and the syscall receives `as_mut_ptr()`, not `as_ptr()`: the `SIOCG*`
/// ioctls *write* their result into the union, and handing the kernel a pointer derived from a
/// shared borrow would be undefined behavior even though the bytes happen to arrive.
///
/// The socket's own address family doesn't have to match what's configured on the interface, so
/// `AF_INET` works for the IPv6 paths too. `label` names the ioctl in the error message.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn ifreq_ioctl(request: libc::c_ulong, ifr: &mut IfReq, label: &str) -> Result<(), String> {
    // SAFETY: `sock` is checked non-negative before use and closed on every exit path; `ifr` is
    // a live, fixed-size buffer matching `struct ifreq`'s layout, borrowed mutably for the
    // call's duration.
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if sock < 0 {
            return Err(format!("socket(): {}", std::io::Error::last_os_error()));
        }
        let ret = libc::ioctl(sock, request as _, ifr.as_mut_ptr());
        let err = std::io::Error::last_os_error();
        libc::close(sock);
        if ret < 0 {
            return Err(format!("{label}: {err}"));
        }
    }
    Ok(())
}

/// `AF_INET` is a small, fixed uapi constant (2) that always fits `sa_family_t` — the narrowing
/// here is exact, never lossy.
#[cfg(feature = "net-ipv4")]
#[allow(clippy::cast_possible_truncation)]
fn configure_loopback_v4() -> Result<(), String> {
    let mut ifr = ifreq_for("lo");

    let mut sa = [0u8; 16];
    sa[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());

    sa[4..8].copy_from_slice(&[127, 0, 0, 1]);
    ifr[IFR_UNION..IFR_UNION + 16].copy_from_slice(&sa);
    ifreq_ioctl(libc::SIOCSIFADDR, &mut ifr, "SIOCSIFADDR")?;

    sa[4..8].copy_from_slice(&[255, 0, 0, 0]);
    ifr[IFR_UNION..IFR_UNION + 16].copy_from_slice(&sa);
    ifreq_ioctl(libc::SIOCSIFNETMASK, &mut ifr, "SIOCSIFNETMASK")
}

/// Brings `name` UP (and marks it running) via `SIOCGIFFLAGS`/`SIOCSIFFLAGS`, returning whether
/// it had to be changed — `Ok(false)` means it was already UP.
///
/// For IPv6 specifically, bringing the link up is the *whole* of this crate's addressing: the
/// kernel auto-assigns `::1/128` to `lo` and an `fe80::/64` link-local to any other interface
/// the moment it comes UP with `CONFIG_IPV6` compiled in, and a global address then arrives via
/// SLAAC from a router advertisement. No manual address ioctl the way IPv4's
/// [`configure_loopback_v4`] needs one — and no `DHCPv6` client either, so a prefix delegated
/// rather than advertised (a routed /48 or /56) yields no global address at all. See
/// `docs/architecture.md#network-addressing`.
///
/// `IFF_UP`/`IFF_RUNNING` are small, fixed uapi constants (0x1, 0x40) that always fit
/// `ifr_flags`' narrower type — the narrowing here is exact, never lossy.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn ensure_interface_up(name: &str) -> Result<bool, String> {
    let mut ifr = ifreq_for(name);
    ifreq_ioctl(libc::SIOCGIFFLAGS, &mut ifr, "SIOCGIFFLAGS")?;

    let flags = i16::from_ne_bytes([ifr[IFR_UNION], ifr[IFR_UNION + 1]]);
    if flags & libc::IFF_UP as i16 != 0 {
        return Ok(false);
    }

    let new_flags = flags | libc::IFF_UP as i16 | libc::IFF_RUNNING as i16;
    ifr[IFR_UNION..IFR_UNION + 2].copy_from_slice(&new_flags.to_ne_bytes());
    ifreq_ioctl(libc::SIOCSIFFLAGS, &mut ifr, "SIOCSIFFLAGS")?;
    Ok(true)
}

/// Reads back the IPv4 address the kernel's `ip=dhcp` autoconfig (or a static assignment) gave
/// an interface, if any.
///
/// `None` covers both "no address yet" and any other ioctl failure — this is a best-effort
/// diagnostic, not something boot should ever fail on.
#[cfg(feature = "net-ipv4")]
fn interface_ipv4_addr(name: &str) -> Option<String> {
    let mut ifr = ifreq_for(name);
    ifreq_ioctl(libc::SIOCGIFADDR, &mut ifr, "SIOCGIFADDR").ok()?;
    // `struct sockaddr_in` starts at the union; the IPv4 address itself is at offset 4 within
    // it (after sin_family, sin_port).
    let o = &ifr[IFR_UNION + 4..IFR_UNION + 8];
    Some(format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3]))
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

/// Whether `addr` is routable off-link, i.e. something a remote client could connect to.
///
/// Hand-rolled rather than `Ipv6Addr::is_unicast_link_local`, which is still unstable. Excludes
/// `fe80::/10` (link-local) and `fec0::/10` (deprecated site-local), plus loopback/multicast/
/// unspecified — everything left is a prefix a router advertised.
#[cfg(feature = "net-ipv6")]
const fn is_global_unicast_v6(addr: &std::net::Ipv6Addr) -> bool {
    let first = addr.segments()[0];
    first & 0xffc0 != 0xfe80
        && first & 0xffc0 != 0xfec0
        && !addr.is_loopback()
        && !addr.is_multicast()
        && !addr.is_unspecified()
}

/// Logs the current address(es) (or lack thereof) of every non-loopback interface, for
/// whichever protocol(s) are compiled in.
#[cfg(any(feature = "net-ipv4", feature = "net-ipv6"))]
fn log_interface_addresses(log: &impl Fn(&str)) {
    for name in non_loopback_interfaces() {
        #[cfg(feature = "net-ipv4")]
        match interface_ipv4_addr(&name) {
            Some(addr) => log(&format!("{name}: IPv4 {addr}")),
            None => log(&format!("{name}: no IPv4 address assigned yet")),
        }
        #[cfg(feature = "net-ipv6")]
        {
            let addrs = interface_ipv6_addrs(&name);
            if !addrs.iter().any(is_global_unicast_v6) {
                log(&format!(
                    "[WARN] {name}: no global IPv6 address — nothing advertised a prefix here, \
                     so this interface is not reachable over IPv6"
                ));
            }
            for addr in addrs {
                let scope = if is_global_unicast_v6(&addr) {
                    "global"
                } else {
                    "link-local"
                };
                log(&format!("{name}: IPv6 {addr} ({scope})"));
            }
        }
    }
}

/// `/proc/net/route` fields: `Iface Destination Gateway Flags …` — a default route has an
/// all-zero destination, and `RTF_UP` (0x1) set in the hex flags. Checking the flags too, since
/// a route the kernel is still holding down reads exactly like a settled one without them.
#[cfg(feature = "net-ipv4")]
fn has_default_route_v4() -> bool {
    const RTF_UP: u32 = 0x1;
    let Ok(routes) = std::fs::read_to_string("/proc/net/route") else {
        return false;
    };
    routes.lines().skip(1).any(|line| {
        let mut fields = line.split_whitespace();
        fields.next();
        if fields.next() != Some("00000000") {
            return false;
        }
        fields.next();
        fields
            .next()
            .and_then(|flags| u32::from_str_radix(flags, 16).ok())
            .is_some_and(|flags| flags & RTF_UP != 0)
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

#[cfg(all(test, feature = "net-ipv6"))]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ipv6_tests {
    use super::*;

    /// Offsets, not just sizes: two structs of the right total size with fields in the wrong
    /// places would compile, pass the `const` size assertions, and quietly misconfigure the
    /// network of a guest whose console nobody can read. Values are from `linux/ipv6.h` and
    /// `linux/ipv6_route.h` on `x86_64`.
    #[test]
    fn kernel_struct_field_offsets_match_the_uapi_layout() {
        let ifreq = In6IfReq {
            addr: [0u8; 16],
            prefix_len: 0,
            ifindex: 0,
        };
        let base = std::ptr::from_ref(&ifreq) as usize;
        assert_eq!(std::ptr::from_ref(&ifreq.addr) as usize - base, 0);
        assert_eq!(std::ptr::from_ref(&ifreq.prefix_len) as usize - base, 16);
        assert_eq!(std::ptr::from_ref(&ifreq.ifindex) as usize - base, 20);

        let rt = In6RtMsg {
            dst: [0u8; 16],
            src: [0u8; 16],
            gateway: [0u8; 16],
            rtmsg_type: 0,
            dst_len: 0,
            src_len: 0,
            metric: 0,
            _pad: 0,
            info: 0,
            flags: 0,
            ifindex: 0,
        };
        let base = std::ptr::from_ref(&rt) as usize;
        for (offset, actual) in [
            (0, std::ptr::from_ref(&rt.dst) as usize),
            (16, std::ptr::from_ref(&rt.src) as usize),
            (32, std::ptr::from_ref(&rt.gateway) as usize),
            (48, std::ptr::from_ref(&rt.rtmsg_type) as usize),
            (52, std::ptr::from_ref(&rt.dst_len) as usize),
            (54, std::ptr::from_ref(&rt.src_len) as usize),
            (56, std::ptr::from_ref(&rt.metric) as usize),
            (64, std::ptr::from_ref(&rt.info) as usize),
            (72, std::ptr::from_ref(&rt.flags) as usize),
            (76, std::ptr::from_ref(&rt.ifindex) as usize),
        ] {
            assert_eq!(actual - base, offset, "in6_rtmsg field moved");
        }
    }

    #[test]
    fn static_ipv6_spec_parses_or_is_rejected() {
        let (addr, len) = parse_static_v6("2001:db8:1:2::1/64").unwrap();
        assert_eq!(
            addr,
            "2001:db8:1:2::1".parse::<std::net::Ipv6Addr>().unwrap()
        );
        assert_eq!(len, 64);
        assert_eq!(parse_static_v6("2001:db8::5/128").unwrap().1, 128);

        for bad in [
            "2001:db8::1",
            "2001:db8::1/0",
            "2001:db8::1/129",
            "/64",
            "x/64",
        ] {
            assert!(parse_static_v6(bad).is_none(), "{bad} should not parse");
        }
    }

    /// The distinction the boot log leans on to tell an operator which address to connect to.
    #[test]
    fn only_routable_addresses_count_as_global() {
        let global: std::net::Ipv6Addr = "2001:db8:1:2:5054:ff:fe12:3456".parse().unwrap();
        assert!(is_global_unicast_v6(&global));
        // Unique-local (fc00::/7) is routable within an organization, and a provider that hands
        // one out means it to be connected to — it is not the link-local case this separates.
        assert!(is_global_unicast_v6(&"fd00::1".parse().unwrap()));

        for not_global in ["fe80::5054:ff:fe12:3456", "fec0::1", "::1", "::", "ff02::1"] {
            assert!(
                !is_global_unicast_v6(&not_global.parse().unwrap()),
                "{not_global} must not read as connectable"
            );
        }
    }
}
