//! Optional SEV-SNP remote attestation HTTP server.
//!
//! Feature-gated (`attestation`), spawned by `main.rs` as an isolated unprivileged child
//! process when `[attestation].enabled` was set at build time. Proves to a remote client that
//! this specific measured image (kernel + initramfs, including the embedded app) is what's
//! actually running.
//!
//! Serves exactly one route (`GET /v1/attestation`); everything else redirects there. The
//! caller's nonce is used verbatim as the SEV-SNP `REPORT_DATA` field (no hashing, no app-hash
//! binding — the launch measurement itself already proves which app bytes are running).
//!
//! Deliberately plain blocking `std` sockets, not an async runtime: a fixed pool of OS threads
//! each loop `accept()` → handle one connection to completion → `accept()` again, which bounds
//! total concurrency to the thread count without a scheduler, task allocations, or a semaphore
//! object. Every per-request buffer (request line, nonce, ioctl request/response, report bytes)
//! is a fixed-size stack array — request content is 99% predictable in shape (a 128-hex-char
//! nonce and a few bytes of HTTP), so there is nothing to grow dynamically. Responses are raw
//! HTTP with a status line and at most a few bytes of plain-text body — no JSON, no per-request
//! string formatting — both to save bandwidth and because a hand-built body is one more thing
//! an attacker-controlled input could theoretically influence.
//!
//! The one heap allocation left in the whole request path is the per-subnet rate-limiter table
//! (a `HashMap`, capped at [`MAX_TRACKED_SUBNETS`] entries) — it must track a key set shaped by
//! the caller's source IPs, so a fixed-size table isn't a good fit without a hand-rolled hash
//! table of its own. It grows lazily up to that cap and never shrinks below its high-water mark,
//! so worst case under a distributed-subnet flood is bounded and small (a few hundred KB), not
//! unbounded.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::panic_shutdown;

const ATTESTATION_PORT: &str = env!("CARGO_UNIKERNEL_ATTESTATION_PORT");
const MAX_CONSECUTIVE_ACCEPT_ERRORS: u32 = 10;

const ATTESTATION_PATH: &str = "/v1/attestation";

/// The SEV-SNP `REPORT_DATA` field is exactly 64 raw bytes — the nonce is used verbatim as
/// that field (no hashing), so it must be exactly that size, hex-encoded as 128 characters.
const NONCE_BYTES: usize = 64;
const NONCE_HEX_LEN: usize = NONCE_BYTES * 2;

/// Socket-level ceiling on reading a full request, independent of how many small reads it takes
/// — bounds a slowloris-style trickle. Enforced via `SO_RCVTIMEO`, not an async timer.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Same reasoning, for a slow-reading client on the response side, via `SO_SNDTIMEO`.
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST_BYTES: usize = 8192;

/// Every worker blocks in `accept()` on a shared, `dup()`-ed listener and then handles that one
/// connection to completion before accepting another — this is what bounds total concurrent
/// connections, in place of a global semaphore object. A wedged `/dev/sev-guest` ioctl (see
/// `get_snp_attestation_report`) can only ever cost this pool one worker permanently; there is
/// no cross-thread timeout that could reclaim it (a blocking syscall in another OS thread can't
/// be cancelled from here), so the remaining `WORKER_THREADS - 1` keep serving — bounded
/// degradation instead of an unbounded leak.
const WORKER_THREADS: usize = 64;
/// Hard ceiling on concurrent in-flight `/dev/sev-guest` requests, independent of
/// `WORKER_THREADS`. The PSP firmware serializes report generation in hardware regardless, so a
/// burst beyond a small queue just adds blocked threads without adding throughput.
const MAX_CONCURRENT_REPORTS: usize = 8;

/// Hard ceiling on distinct tracked subnets — see the module doc comment for why this is the
/// one heap-growing structure left in the request path.
const MAX_TRACKED_SUBNETS: usize = 2048;
const SUBNET_MAX_REQUESTS: usize = 10;
const SUBNET_WINDOW: Duration = Duration::from_secs(3);
const SUBNET_MAX_CONCURRENT: u32 = 2;

const SNP_GET_REPORT: libc::c_ulong = 0xC020_5300;

#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    _pad: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

#[repr(C)]
struct SnpReportReq {
    user_data: [u8; 64],
    vmpl: u32,
    _rsvd: [u8; 28],
}

#[repr(C)]
struct SnpReportResp {
    data: [u8; 4000],
}

/// Per AMD's SEV-SNP ABI (`MSG_REPORT_RSP`), the PSP firmware wraps the report in a 32-byte
/// header first (4-byte `STATUS`, 4-byte `REPORT_SIZE`, 24 reserved) — the report itself
/// starts at byte 32.
const HEADER_LEN: usize = 32;
const REPORT_LEN: usize = 1184;

/// Opened exactly once at server startup, not per-request: the ioctl is stateless per-call, so
/// repeated `open()/close()` would only be extra syscalls.
enum SnpDevice {
    Available(std::fs::File),
    Unavailable(String),
}

fn open_snp_device() -> SnpDevice {
    match std::fs::File::open("/dev/sev-guest") {
        Ok(f) => SnpDevice::Available(f),
        Err(e) => SnpDevice::Unavailable(format!("SEV-SNP device not available: {e}")),
    }
}

enum ReportError {
    /// The ioctl itself failed, or the firmware returned a status/size this build doesn't
    /// recognize. Detail is logged to stderr (operator-facing only); the client just gets a
    /// generic 500 — no OS error text crosses the wire.
    Failed,
}

fn get_snp_attestation_report(
    device: &std::fs::File,
    report_data: &[u8; NONCE_BYTES],
) -> Result<[u8; REPORT_LEN], ReportError> {
    let mut req = SnpReportReq {
        user_data: *report_data,
        vmpl: 0,
        _rsvd: [0u8; 28],
    };

    let mut resp = SnpReportResp { data: [0u8; 4000] };

    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: std::ptr::addr_of_mut!(req) as u64,
        resp_data: std::ptr::addr_of_mut!(resp) as u64,
        exitinfo2: 0,
    };

    // `ioctl`'s request parameter type differs across libcs (glibc: `c_ulong`; musl: `c_int`);
    // this crate only targets musl but must still type-check on a glibc host, same reasoning as
    // `mounts.rs`'s `set_rlimit`. `SNP_GET_REPORT` is a small, fixed, non-negative uapi
    // constant, so both casts below are always exact regardless of which libc applies.
    #[allow(clippy::cast_possible_truncation)]
    let request = SNP_GET_REPORT as i32;
    #[allow(clippy::cast_sign_loss)]
    let ret = unsafe { libc::ioctl(device.as_raw_fd(), request as _, &mut ioctl_req) };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        let fw_err = ioctl_req.exitinfo2 & 0xFFFF_FFFF;
        eprintln!("[ATTEST] SNP_GET_REPORT ioctl failed: {errno} (fw_err: {fw_err})");
        return Err(ReportError::Failed);
    }

    // Verifying STATUS/REPORT_SIZE rather than trusting fixed offsets turns a firmware-side
    // surprise into a clean error instead of a silently-wrong report. Built from individual
    // indexes (rather than a `try_into()`'d slice) since `resp.data`'s fixed size makes the
    // conversion infallible, and this avoids an unwrap on that always-Ok result.
    let status = u32::from_le_bytes([resp.data[0], resp.data[1], resp.data[2], resp.data[3]]);
    if status != 0 {
        eprintln!("[ATTEST] PSP firmware returned non-zero status: {status}");
        return Err(ReportError::Failed);
    }
    let report_size =
        u32::from_le_bytes([resp.data[4], resp.data[5], resp.data[6], resp.data[7]]) as usize;
    if report_size != REPORT_LEN {
        eprintln!(
            "[ATTEST] unexpected report size from firmware: {report_size} (expected {REPORT_LEN})"
        );
        return Err(ReportError::Failed);
    }

    let mut out = [0u8; REPORT_LEN];
    out.copy_from_slice(&resp.data[HEADER_LEN..HEADER_LEN + REPORT_LEN]);
    Ok(out)
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Subnet {
    V4([u8; 3]), // /24
    V6([u8; 8]), // /64
}

impl From<IpAddr> for Subnet {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(addr) => {
                let octets = addr.octets();
                Self::V4([octets[0], octets[1], octets[2]])
            }
            IpAddr::V6(addr) => {
                let octets = addr.octets();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&octets[0..8]);
                Self::V6(prefix)
            }
        }
    }
}

/// Fixed-size ring buffer of the subnet's last [`SUBNET_MAX_REQUESTS`] request timestamps — a
/// `Vec`/`VecDeque` would grow on the heap as entries arrive; this is exactly one instance of
/// `SubnetState` per tracked subnet (already sized in the `HashMap`'s own bucket), never
/// resized per request.
struct SubnetState {
    times: [Option<Instant>; SUBNET_MAX_REQUESTS],
    next: usize,
    active_connections: u32,
}

impl SubnetState {
    const fn new() -> Self {
        Self {
            times: [None; SUBNET_MAX_REQUESTS],
            next: 0,
            active_connections: 0,
        }
    }

    fn count_in_window(&self, now: Instant) -> usize {
        self.times
            .iter()
            .filter(|t| t.is_some_and(|t| now.duration_since(t) <= SUBNET_WINDOW))
            .count()
    }

    fn is_idle(&self, now: Instant) -> bool {
        self.active_connections == 0 && self.count_in_window(now) == 0
    }
}

enum RateLimitError {
    TooManySubnets,
    RateExceeded,
    ConcurrencyExceeded,
}

struct SubnetLimiter {
    subnets: Mutex<HashMap<Subnet, SubnetState>>,
}

impl SubnetLimiter {
    fn new() -> Self {
        Self {
            subnets: Mutex::new(HashMap::new()),
        }
    }

    fn acquire(&self, ip: IpAddr) -> Result<SubnetGuard<'_>, RateLimitError> {
        let subnet = Subnet::from(ip);
        let now = Instant::now();
        // A poisoned mutex means some other thread panicked while holding it — a state this
        // codebase's "never panic" discipline says should be unreachable, but the wipe-and-exit
        // protocol is exactly the right response if it somehow happens anyway.
        let mut map = self.subnets.lock().unwrap_or_else(|_| {
            panic_shutdown("attestation subnet limiter mutex poisoned — system integrity compromised")
        });

        if map.len() > MAX_TRACKED_SUBNETS / 2 {
            map.retain(|_, state| !state.is_idle(now));
        }

        // Once at capacity, refuse to start tracking a brand-new subnet — an already-tracked
        // one can still proceed.
        if !map.contains_key(&subnet) && map.len() >= MAX_TRACKED_SUBNETS {
            return Err(RateLimitError::TooManySubnets);
        }

        let state = map.entry(subnet.clone()).or_insert_with(SubnetState::new);

        if state.count_in_window(now) >= SUBNET_MAX_REQUESTS {
            return Err(RateLimitError::RateExceeded);
        }
        if state.active_connections >= SUBNET_MAX_CONCURRENT {
            return Err(RateLimitError::ConcurrencyExceeded);
        }

        state.times[state.next] = Some(now);
        state.next = (state.next + 1) % SUBNET_MAX_REQUESTS;
        state.active_connections += 1;

        drop(map);
        Ok(SubnetGuard {
            limiter: self,
            subnet,
        })
    }
}

struct SubnetGuard<'a> {
    limiter: &'a SubnetLimiter,
    subnet: Subnet,
}

impl Drop for SubnetGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut map) = self.limiter.subnets.lock()
            && let Some(state) = map.get_mut(&self.subnet)
        {
            state.active_connections = state.active_connections.saturating_sub(1);
        }
    }
}

struct ServerState {
    snp_device: SnpDevice,
    subnet_limiter: SubnetLimiter,
    /// Counting limiter for concurrent ioctls, in place of an async semaphore — a plain CAS
    /// loop over a fixed-size counter, no heap.
    report_slots: AtomicUsize,
}

struct ReportPermit<'a> {
    slots: &'a AtomicUsize,
}

impl Drop for ReportPermit<'_> {
    fn drop(&mut self) {
        self.slots.fetch_sub(1, Ordering::SeqCst);
    }
}

fn try_acquire_report_slot(slots: &AtomicUsize) -> Option<ReportPermit<'_>> {
    loop {
        let cur = slots.load(Ordering::SeqCst);
        if cur >= MAX_CONCURRENT_REPORTS {
            return None;
        }
        if slots
            .compare_exchange_weak(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Some(ReportPermit { slots });
        }
    }
}

// Every response below is a fully pre-rendered, `'static` byte string — no per-request
// formatting, no heap. `program_length_matches_denylist_size_plus_five`-style invariant tests
// at the bottom of this file check each Content-Length against its actual body length, since
// hand-counting bytes is the one way this approach can quietly drift out of sync.

const RESP_200_HEADER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 1184\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n\r\n";
const RESP_302_REDIRECT: &[u8] = b"HTTP/1.1 302 Found\r\nLocation: /v1/attestation\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESP_400_BAD_NONCE: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nbad nonce";
const RESP_405_METHOD: &[u8] = b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const RESP_429_RATE_LIMITED: &[u8] = b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nrate limited";
const RESP_500_ERROR: &[u8] = b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nerror";
const RESP_503_BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbusy";

const _: () = assert!(REPORT_LEN == 1184, "RESP_200_HEADER's hardcoded Content-Length must match REPORT_LEN");

fn send_static(stream: &mut TcpStream, resp: &'static [u8]) -> std::io::Result<()> {
    stream.write_all(resp)?;
    stream.flush()
}

/// `[::]` when the `net-ipv6` feature is compiled in — Linux dual-stack sockets accept
/// IPv4-mapped connections on the same wildcard by default, so this alone still serves
/// IPv4-only clients too. Plain IPv4 wildcard otherwise.
#[cfg(feature = "net-ipv6")]
fn bind_address() -> String {
    format!("[::]:{ATTESTATION_PORT}")
}
#[cfg(not(feature = "net-ipv6"))]
fn bind_address() -> String {
    format!("0.0.0.0:{ATTESTATION_PORT}")
}

fn send_success(stream: &mut TcpStream, report: &[u8; REPORT_LEN]) -> std::io::Result<()> {
    stream.write_all(RESP_200_HEADER)?;
    stream.write_all(report)?;
    stream.flush()
}

// `pub(super)`/`pub(crate)` here is a genuine, unresolvable conflict between two denied lints
// in a `--bin`-only crate: `unreachable_pub` forbids plain `pub` (nothing in a binary is ever
// externally reachable), while `redundant_pub_crate` correctly observes that, since `mod
// attestation` is itself private, any crate-visible qualifier is no more permissive than plain
// `pub` would be. There is no third visibility spelling that satisfies both — same root cause
// as the lib+bin split in the host `cargo-unikernel` crate, just not worth a split for one
// cross-module function here.
#[allow(clippy::redundant_pub_crate)]
pub(super) fn run_attestation_server() -> ! {
    let listener = TcpListener::bind(bind_address())
        .unwrap_or_else(|e| panic_shutdown(&format!("Failed to bind attestation port: {e}")));

    println!("[ATTEST] Attestation server bound on :{ATTESTATION_PORT} — this is the independent watchdog.");
    println!("[ATTEST] Any failure or interference with this server triggers immediate shutdown.");

    let state = Arc::new(ServerState {
        snp_device: open_snp_device(),
        subnet_limiter: SubnetLimiter::new(),
        report_slots: AtomicUsize::new(0),
    });

    for _ in 1..WORKER_THREADS {
        let worker_listener = listener.try_clone().unwrap_or_else(|e| {
            panic_shutdown(&format!("Failed to clone attestation listener: {e}"))
        });
        let worker_state = Arc::clone(&state);
        std::thread::spawn(move || worker_loop(&worker_listener, &worker_state));
    }
    worker_loop(&listener, &state)
}

fn worker_loop(listener: &TcpListener, state: &ServerState) -> ! {
    let mut consecutive_errors: u32 = 0;
    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                consecutive_errors = 0;
                handle_connection(stream, addr.ip(), state);
            }
            Err(e) => {
                let kind = e.kind();
                if matches!(
                    kind,
                    ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::BrokenPipe
                        | ErrorKind::Interrupted
                ) {
                    continue;
                }

                if e.raw_os_error() == Some(libc::EMFILE) || e.raw_os_error() == Some(libc::ENFILE)
                {
                    eprintln!(
                        "[ATTEST] Out of file descriptors (EMFILE/ENFILE). Throttling..."
                    );
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }

                consecutive_errors += 1;
                eprintln!(
                    "[ATTEST] Accept error ({consecutive_errors}/{MAX_CONSECUTIVE_ACCEPT_ERRORS}): {e}"
                );
                std::thread::sleep(Duration::from_millis(100));

                if consecutive_errors >= MAX_CONSECUTIVE_ACCEPT_ERRORS {
                    panic_shutdown(&format!(
                        "Attestation server failed {MAX_CONSECUTIVE_ACCEPT_ERRORS} consecutive accepts. \
                         Possible interference detected. System integrity compromised."
                    ));
                }
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream, ip: IpAddr, state: &ServerState) {
    let _ = stream.set_read_timeout(Some(REQUEST_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(RESPONSE_WRITE_TIMEOUT));

    let Ok(_subnet_permit) = state.subnet_limiter.acquire(ip) else {
        let _ = send_static(&mut stream, RESP_429_RATE_LIMITED);
        return;
    };

    serve_request(&mut stream, state);
}

fn serve_request(stream: &mut TcpStream, state: &ServerState) {
    let mut buf = [0u8; MAX_REQUEST_BYTES];
    let Some(request) = read_request(stream, &mut buf) else {
        return;
    };

    let Some((method, path, query)) = parse_request_line(request) else {
        // Not something that looks like HTTP at all — don't dignify it with a response.
        return;
    };

    if method != "GET" {
        let _ = send_static(stream, RESP_405_METHOD);
        return;
    }

    if path != ATTESTATION_PATH {
        let _ = send_static(stream, RESP_302_REDIRECT);
        return;
    }

    handle_attestation_request(stream, query, state);
}

/// Reads until the request headers terminate (`\r\n\r\n`), a size cap is hit, or the read
/// times out (`SO_RCVTIMEO`, set by the caller). Returns `None` for anything not worth
/// responding to (empty read, oversized, timed out) rather than an error — those are routine on
/// an internet-facing socket. `buf` is a fixed stack array; nothing here allocates.
fn read_request<'a>(
    stream: &mut TcpStream,
    buf: &'a mut [u8; MAX_REQUEST_BYTES],
) -> Option<&'a [u8]> {
    let mut len = 0usize;
    // Only rescan the newly-arrived tail (plus a 3-byte overlap, since the terminator can
    // straddle a chunk boundary), keeping header assembly O(bytes read) rather than O(n^2).
    let mut scanned = 0usize;
    loop {
        if len == buf.len() {
            return None;
        }
        let n = match stream.read(&mut buf[len..]) {
            Ok(0) => return None,
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return None; // slowloris-style trickle — just drop it
            }
            Err(_) => return None,
        };
        len += n;
        let scan_from = scanned.saturating_sub(3);
        if buf[scan_from..len].windows(4).any(|w| w == b"\r\n\r\n") {
            return Some(&buf[..len]);
        }
        scanned = len;
    }
}

/// Returns `(method, path, query)` for a well-formed HTTP request line, or `None` for
/// anything that doesn't look like HTTP. Operates on the raw bytes read off the socket —
/// no UTF-8 conversion of the whole request, just the (ASCII, per the HTTP spec) first line.
fn parse_request_line(request: &[u8]) -> Option<(&str, &str, &str)> {
    let line_end = request.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&request[..line_end]).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let path_query = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return None;
    }
    let (path, query) = path_query.split_once('?').unwrap_or((path_query, ""));
    Some((method, path, query))
}

fn handle_attestation_request(stream: &mut TcpStream, query: &str, state: &ServerState) {
    let nonce_hex = extract_query_param(query, "nonce").unwrap_or("");
    let mut report_data = [0u8; NONCE_BYTES];
    if nonce_hex.len() != NONCE_HEX_LEN || !hex_decode(nonce_hex.as_bytes(), &mut report_data) {
        let _ = send_static(stream, RESP_400_BAD_NONCE);
        return;
    }

    let Some(_report_permit) = try_acquire_report_slot(&state.report_slots) else {
        let _ = send_static(stream, RESP_503_BUSY);
        return;
    };

    let device = match &state.snp_device {
        SnpDevice::Unavailable(reason) => {
            eprintln!("[ATTEST] {reason}");
            let _ = send_static(stream, RESP_503_BUSY);
            return;
        }
        SnpDevice::Available(device) => device,
    };

    match get_snp_attestation_report(device, &report_data) {
        Ok(report) => {
            let _ = send_success(stream, &report);
        }
        Err(ReportError::Failed) => {
            let _ = send_static(stream, RESP_500_ERROR);
        }
    }
}

fn extract_query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return Some(v);
        }
    }
    None
}

/// Decodes exactly `NONCE_BYTES` of hex into `out`, hand-rolled rather than pulling in a hex
/// crate for the one place a nonce needs decoding — the nonce isn't secret (it's caller-chosen,
/// echoed nowhere), so this doesn't need to be constant-time.
fn hex_decode(hex: &[u8], out: &mut [u8; NONCE_BYTES]) -> bool {
    if hex.len() != NONCE_HEX_LEN {
        return false;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        let (Some(hi), Some(lo)) = (hex_val(hex[2 * i]), hex_val(hex[2 * i + 1])) else {
            return false;
        };
        *byte = (hi << 4) | lo;
    }
    true
}

const fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn content_length_of(resp: &[u8]) -> usize {
        let text = std::str::from_utf8(resp).unwrap();
        let header_end = text.find("\r\n\r\n").unwrap();
        let headers = &text[..header_end];
        let body_len = text.len() - (header_end + 4);
        let declared: usize = headers
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, body_len, "Content-Length doesn't match actual body length");
        body_len
    }

    #[test]
    fn canned_responses_have_correct_content_length() {
        content_length_of(RESP_302_REDIRECT);
        content_length_of(RESP_400_BAD_NONCE);
        content_length_of(RESP_405_METHOD);
        content_length_of(RESP_429_RATE_LIMITED);
        content_length_of(RESP_500_ERROR);
        content_length_of(RESP_503_BUSY);
        // RESP_200_HEADER has no body of its own (the report bytes are written separately by
        // send_success), so its declared length is checked against REPORT_LEN instead.
        let text = std::str::from_utf8(RESP_200_HEADER).unwrap();
        let declared: usize = text
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(declared, REPORT_LEN);
    }

    #[test]
    fn hex_decode_round_trips_known_bytes() {
        let hex = "00".repeat(63) + "ff";
        let mut out = [0u8; NONCE_BYTES];
        assert!(hex_decode(hex.as_bytes(), &mut out));
        assert_eq!(out[63], 0xff);
        assert_eq!(out[0], 0x00);
    }

    #[test]
    fn hex_decode_rejects_wrong_length_and_bad_chars() {
        let mut out = [0u8; NONCE_BYTES];
        assert!(!hex_decode(b"short", &mut out));
        let bad = "zz".repeat(64);
        assert!(!hex_decode(bad.as_bytes(), &mut out));
    }

    #[test]
    fn parse_request_line_extracts_method_path_query() {
        let req = b"GET /v1/attestation?nonce=abcd HTTP/1.1\r\nHost: x\r\n\r\n";
        let (method, path, query) = parse_request_line(req).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/v1/attestation");
        assert_eq!(query, "nonce=abcd");
    }

    #[test]
    fn parse_request_line_rejects_non_http() {
        assert!(parse_request_line(b"not an http request at all").is_none());
    }

    #[test]
    // `guards` is never read, only held: each entry's `Drop` releases a concurrency slot, so
    // keeping them alive (not the values themselves) is the point of this collection.
    #[allow(clippy::collection_is_never_read)]
    fn subnet_limiter_enforces_concurrency() {
        let limiter = SubnetLimiter::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();

        let mut guards = Vec::new();
        for _ in 0..SUBNET_MAX_CONCURRENT {
            guards.push(limiter.acquire(ip).ok().unwrap());
        }
        assert!(matches!(
            limiter.acquire(ip),
            Err(RateLimitError::ConcurrencyExceeded)
        ));
    }

    #[test]
    fn subnet_limiter_enforces_request_rate() {
        let limiter = SubnetLimiter::new();
        let ip: IpAddr = "203.0.113.8".parse().unwrap();

        // Each acquire()/drop() pair frees its concurrency slot immediately but leaves its
        // timestamp in the ring buffer, so this exercises the rate cap independent of the
        // concurrency cap.
        for _ in 0..SUBNET_MAX_REQUESTS {
            limiter.acquire(ip).ok().unwrap();
        }
        assert!(matches!(limiter.acquire(ip), Err(RateLimitError::RateExceeded)));
    }
}
