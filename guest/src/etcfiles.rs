//! The guest's `/etc`.
//!
//! There wasn't one before this module, and that was a bug rather than a hardening decision:
//! a static musl binary resolving a hostname reads `/etc/resolv.conf`, and with the file
//! *absent* musl falls back to `127.0.0.1` as its resolver — so every outbound DNS lookup in
//! every image failed unless the app hardcoded a nameserver. The kernel's own DHCP client
//! (`ip=dhcp`, `CONFIG_IP_PNP_DHCP`) already learned the right answer and left it in
//! `/proc/net/pnp`; nothing was copying it anywhere musl would look.
//!
//! Four more files ride along for the same "make the mini OS sane" reason: `getpwuid` on the
//! app's own uid failing is a surprising way for a program to break, and `/etc/hosts` without
//! `localhost` is a worse one.
//!
//! Everything here is written by PID 1 before the app exists, onto the image's own root
//! filesystem — which `mounts::lockdown_filesystem` then remounts read-only (best-effort; see
//! `mounts::seal_rootfs`) and which the app, an unprivileged uid facing root-owned 0755
//! directories, cannot write to either way. So this is not writable state the app can turn into
//! a persistence mechanism, and the shutdown scrub has nothing to do here.

/// Where the kernel's IP autoconfiguration publishes what DHCP told it, in `resolv.conf`
/// syntax already. Only exists on an `ip=dhcp` boot.
const KERNEL_PNP: &str = "/proc/net/pnp";

/// The `resolv.conf` directives worth copying out of [`KERNEL_PNP`]. It also contains
/// `bootserver`/`rootserver`/`rootpath` lines, which mean nothing to a resolver.
const PNP_DIRECTIVES: [&str; 3] = ["nameserver", "domain", "search"];

/// Writes `/etc/{hosts,passwd,group,nsswitch.conf}` and, if a resolver can be determined,
/// `/etc/resolv.conf`.
///
/// `nameservers` is `[network].nameservers` — a `';'`-joined list that, when non-empty, wins
/// over whatever DHCP said. Configuring resolvers explicitly is the only option on an
/// IPv6-only guest: SLAAC alone carries no DNS, and this image ships no `DHCPv6` client.
///
/// Best-effort throughout: a failed write is logged and boot continues, because a guest that
/// can't resolve names is still a guest that runs, and an app that doesn't use DNS shouldn't
/// be stopped by this.
pub(crate) fn write_etc(uid: u32, gid: u32, nameservers: &str, search: &str, log: &impl Fn(&str)) {
    write_file("/etc/hosts", HOSTS, log);
    write_file("/etc/nsswitch.conf", NSSWITCH, log);
    write_file("/etc/passwd", &passwd(uid, gid), log);
    write_file("/etc/group", &group(gid), log);
    write_resolv_conf(nameservers, search, log);
}

const HOSTS: &str = "\
127.0.0.1\tlocalhost
::1\tlocalhost ip6-localhost ip6-loopback
";

/// musl ignores this file entirely (its resolver is `files` then `dns`, always). It is here
/// for everything else that might end up in the image — Go's pure-Go resolver reads it, and
/// so do several language runtimes' native-resolver shims.
const NSSWITCH: &str = "\
hosts: files dns
passwd: files
group: files
";

/// `/etc/passwd`: root, the uid the app actually runs as, and `nobody` — the last dropped
/// when the app already runs as 65534, so the file never carries two entries for one uid.
///
/// The shell field is `/dev/null`, not `/bin/false` — there is no `/bin` in this image, and a
/// path that doesn't exist reads as an oversight rather than a decision.
fn passwd(uid: u32, gid: u32) -> String {
    let mut s = format!("root:x:0:0:root:/:/dev/null\napp:x:{uid}:{gid}:app:/var:/dev/null\n");
    if uid != NOBODY_ID {
        s.push_str("nobody:x:65534:65534:nobody:/:/dev/null\n");
    }
    s
}

/// The conventional anonymous uid/gid, and this image's own default for the app — which is
/// exactly why both files below have to check for the collision.
const NOBODY_ID: u32 = 65534;

/// Mirrors [`passwd`]. The `nobody` line is dropped when the app's own gid already is 65534,
/// so the file never carries two entries for one gid.
fn group(gid: u32) -> String {
    let mut s = format!("root:x:0:\napp:x:{gid}:\n");
    if gid != NOBODY_ID {
        s.push_str("nobody:x:65534:\n");
    }
    s
}

/// Writes `/etc/resolv.conf` from [`resolv_conf_body`], or warns and writes nothing.
///
/// An empty `resolv.conf` and a missing one mean the same thing to musl (fall back to
/// `127.0.0.1`), so the file's absence is the honest state and the warning is the useful part.
fn write_resolv_conf(nameservers: &str, search: &str, log: &impl Fn(&str)) {
    let pnp = std::fs::read_to_string(KERNEL_PNP).unwrap_or_default();
    let body = resolv_conf_body(nameservers, search, &pnp);
    if body.is_empty() {
        log(
            "[WARN] No DNS resolver could be determined (no [network].nameservers, and the \
             kernel's DHCP client published none) — /etc/resolv.conf not written, so hostname \
             lookups will fail. Set [network].nameservers if the app resolves names.",
        );
        return;
    }
    write_file("/etc/resolv.conf", &body, log);
}

/// The `resolv.conf` this boot should have, given `[network].nameservers`, `[network].search`,
/// and the contents of [`KERNEL_PNP`]. Empty means "no resolver could be determined".
///
/// Configured nameservers win over DHCP outright rather than being appended: a deployment that
/// names its resolvers is usually doing so *because* it doesn't trust the network's, and a
/// silent fallback entry would defeat that. Explicit config is also the only option on an
/// IPv6-only guest — SLAAC carries no DNS and this image ships no `DHCPv6` client.
///
/// Pure, so the precedence and filtering rules are testable without a `/proc` or a real `/etc`.
fn resolv_conf_body(nameservers: &str, search: &str, pnp: &str) -> String {
    let mut body = String::new();

    if nameservers.is_empty() {
        for line in pnp.lines().filter(|line| is_resolver_directive(line)) {
            body.push_str(line);
            body.push('\n');
        }
    } else {
        for server in nameservers.split(';').filter(|s| !s.is_empty()) {
            body.push_str("nameserver ");
            body.push_str(server);
            body.push('\n');
        }
    }

    if !body.contains("nameserver ") {
        return String::new();
    }
    if !search.is_empty() && !body.contains("search ") {
        body.push_str("search ");
        body.push_str(search);
        body.push('\n');
    }
    body
}

/// Whether a [`KERNEL_PNP`] line is one of [`PNP_DIRECTIVES`]. The file also carries
/// `bootserver`/`rootserver`/`rootpath` lines, which mean nothing to a resolver.
fn is_resolver_directive(line: &str) -> bool {
    line.split_whitespace()
        .next()
        .is_some_and(|first| PNP_DIRECTIVES.contains(&first))
}

/// 0444: every file here describes the system to the app, and none of them is the app's to
/// change. The read-only remount at lockdown is the real enforcement; this is what keeps the
/// window before it from being writable.
fn write_file(path: &str, contents: &str, log: &impl Fn(&str)) {
    use std::os::unix::fs::PermissionsExt as _;

    if let Err(e) = std::fs::write(path, contents) {
        log(&format!("[WARN] Failed to write {path}: {e}"));
        return;
    }
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)) {
        log(&format!("[WARN] Failed to set permissions on {path}: {e}"));
    }
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn passwd_carries_the_configured_uid() {
        let p = passwd(1000, 1000);
        assert!(p.contains("app:x:1000:1000:"));
        assert!(p.starts_with("root:x:0:0:"));
        assert!(p.contains("nobody:x:65534:"));
    }

    /// 65534 is this image's own default app uid, so the collision is the common case, not an
    /// edge one — and `getpwuid(65534)` answering differently per implementation is exactly
    /// the surprise this module exists to remove.
    #[test]
    fn passwd_never_lists_one_uid_twice() {
        assert_eq!(passwd(65534, 65534).lines().count(), 2);
        assert_eq!(passwd(65534, 65534).matches(":65534:").count(), 1);
    }

    /// Two entries for one gid is the kind of thing that makes `getgrgid` answer differently
    /// depending on which implementation reads the file first.
    #[test]
    fn group_never_lists_one_gid_twice() {
        assert_eq!(group(65534).matches("65534").count(), 1);
        assert!(group(1000).contains("nobody:x:65534:"));
    }

    const PNP: &str = "domain example.com\nnameserver 10.0.2.3\nbootserver 10.0.2.2\n\
                       rootserver 10.0.2.2\nrootpath \n";

    /// A deployment that names its resolvers is usually distrusting the network's, so a
    /// DHCP-supplied entry must not survive alongside them.
    #[test]
    fn configured_nameservers_replace_the_dhcp_ones() {
        let body = resolv_conf_body("9.9.9.9;149.112.112.112", "", PNP);
        assert_eq!(body, "nameserver 9.9.9.9\nnameserver 149.112.112.112\n");
        assert!(!body.contains("10.0.2.3"));
    }

    /// The whole reason this module exists: with no config, DHCP's answer has to reach musl.
    #[test]
    fn dhcp_supplies_the_resolver_when_nothing_is_configured() {
        let body = resolv_conf_body("", "", PNP);
        assert!(body.contains("nameserver 10.0.2.3"));
        assert!(body.contains("domain example.com"));
    }

    /// `/proc/net/pnp` also carries bootserver/rootserver/rootpath lines, which are not
    /// resolver directives and would be garbage in a `resolv.conf`.
    #[test]
    fn only_resolver_directives_are_copied_from_the_kernel() {
        let body = resolv_conf_body("", "", PNP);
        assert!(!body.contains("bootserver"));
        assert!(!body.contains("rootserver"));
        assert!(!body.contains("rootpath"));
    }

    /// No resolver anywhere must produce no file, not an empty one that reads as a decision.
    #[test]
    fn no_resolver_anywhere_writes_nothing() {
        assert_eq!(resolv_conf_body("", "", ""), "");
        assert_eq!(
            resolv_conf_body("", "corp.example", "rootpath \n"),
            "",
            "a search domain alone is not a resolver"
        );
    }

    #[test]
    fn a_configured_search_domain_is_appended_once() {
        let body = resolv_conf_body("9.9.9.9", "corp.example", "");
        assert!(body.ends_with("search corp.example\n"));
        assert_eq!(body.matches("search ").count(), 1);
    }

    #[test]
    fn hosts_resolves_localhost_on_both_protocols() {
        assert!(HOSTS.contains("127.0.0.1\tlocalhost"));
        assert!(HOSTS.contains("::1\tlocalhost"));
    }
}
