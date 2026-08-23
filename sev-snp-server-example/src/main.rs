use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::thread;

use socket2::{Domain, Socket, Type};

const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

// linux/sev-guest.h — SNP_GET_REPORT = _IOWR('S', 0x0, struct snp_guest_request_ioctl).
// libc's `Ioctl` request type is c_ulong on glibc but c_int on musl (this project's guest
// target) — 0xc0205300 doesn't fit in an i32, so it has to come in as the wider type first
// and get truncated to whatever `Ioctl` actually is on the target, bit pattern intact.
const SNP_GET_REPORT: libc::Ioctl = 0xc020_5300u32 as libc::Ioctl;

const SNP_REPORT_USER_DATA_SIZE: usize = 64;

#[repr(C)]
struct SnpReportReq {
    user_data: [u8; SNP_REPORT_USER_DATA_SIZE],
    vmpl: u32,
    rsvd: [u8; 28],
}

#[repr(C)]
struct SnpReportResp {
    // status:u32, report_size:u32, rsvd[24] header, then the ATTESTATION_REPORT itself —
    // opaque past that as far as this server is concerned, since verifying it is the
    // caller's job, not this endpoint's.
    data: [u8; 4000],
}

#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

/// Fetches a fresh SEV-SNP attestation report bound to `report_data` (the caller's nonce,
/// zero-padded to 64 bytes) straight from the guest's own /dev/sev-guest. No parsing beyond
/// what's needed to strip the driver's 32-byte response header — signature and measurement
/// verification is the remote caller's job, done against the raw report bytes returned here.
fn get_attestation_report(report_data: [u8; SNP_REPORT_USER_DATA_SIZE]) -> Result<Vec<u8>, String> {
    let dev = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_DEVICE)
        .map_err(|e| format!("open {SEV_GUEST_DEVICE}: {e}"))?;

    let req = SnpReportReq {
        user_data: report_data,
        vmpl: 0,
        rsvd: [0; 28],
    };
    let mut resp = SnpReportResp { data: [0; 4000] };
    let mut ioctl_arg = SnpGuestRequestIoctl {
        msg_version: 1,
        req_data: &req as *const SnpReportReq as u64,
        resp_data: &mut resp as *mut SnpReportResp as u64,
        exitinfo2: 0,
    };

    let ret = unsafe { libc::ioctl(dev.as_raw_fd(), SNP_GET_REPORT, &mut ioctl_arg) };
    if ret != 0 {
        return Err(format!(
            "SNP_GET_REPORT ioctl failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if ioctl_arg.exitinfo2 != 0 {
        let fw_error = ioctl_arg.exitinfo2 as u32;
        let vmm_error = (ioctl_arg.exitinfo2 >> 32) as u32;
        return Err(format!(
            "SNP_GET_REPORT rejected by platform (fw_error={fw_error:#x}, vmm_error={vmm_error:#x})"
        ));
    }

    // Response header: status:u32, report_size:u32, rsvd[24] — 32 bytes total.
    let status = u32::from_le_bytes(resp.data[0..4].try_into().unwrap());
    let report_size = u32::from_le_bytes(resp.data[4..8].try_into().unwrap()) as usize;
    if status != 0 {
        return Err(format!("firmware returned report status {status:#x}"));
    }
    if report_size == 0 || 32 + report_size > resp.data.len() {
        return Err(format!(
            "implausible report_size {report_size} in response header"
        ));
    }
    Ok(resp.data[32..32 + report_size].to_vec())
}

/// Decodes an even-length hex string into up to `SNP_REPORT_USER_DATA_SIZE` bytes, zero-padded
/// on the right — this becomes the report's REPORT_DATA field, so a caller can bind a nonce
/// into the report and reject a replayed one.
fn parse_nonce(hex: &str) -> Result<[u8; SNP_REPORT_USER_DATA_SIZE], String> {
    if hex.len() > SNP_REPORT_USER_DATA_SIZE * 2 {
        return Err(format!(
            "nonce too long: max {} hex chars ({SNP_REPORT_USER_DATA_SIZE} bytes)",
            SNP_REPORT_USER_DATA_SIZE * 2
        ));
    }
    if hex.len() % 2 != 0 {
        return Err("nonce must be an even number of hex characters".to_string());
    }
    let mut out = [0u8; SNP_REPORT_USER_DATA_SIZE];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).map_err(|_| "nonce is not valid hex")?;
        out[i] = u8::from_str_radix(byte_str, 16).map_err(|_| "nonce is not valid hex")?;
    }
    Ok(out)
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// Reads and discards the request line plus headers (up to the blank line separating them
/// from any body), returning the request target (path + optional `?query`). Bodies aren't
/// read — nothing this server handles needs one.
fn read_request_target(stream: &TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let target = request_line.split_whitespace().nth(1)?.to_string();

    let mut header_line = String::new();
    loop {
        header_line.clear();
        match reader.read_line(&mut header_line) {
            Ok(0) => break,
            Ok(_) if header_line == "\r\n" || header_line == "\n" => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    Some(target)
}

fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}

fn handle_attestation(stream: &mut TcpStream, query: &str) {
    let nonce = match query_param(query, "nonce") {
        Some(hex) => match parse_nonce(hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                write_response(stream, "400 Bad Request", "text/plain", e.as_bytes());
                return;
            }
        },
        None => [0u8; SNP_REPORT_USER_DATA_SIZE],
    };

    match get_attestation_report(nonce) {
        Ok(report) => write_response(stream, "200 OK", "application/octet-stream", &report),
        Err(e) => write_response(
            stream,
            "500 Internal Server Error",
            "text/plain",
            e.as_bytes(),
        ),
    }
}

fn handle_connection(stream: std::io::Result<TcpStream>) {
    let mut stream = match stream {
        Ok(s) => s,
        Err(_) => return,
    };

    let target = match read_request_target(&stream) {
        Some(t) => t,
        None => return,
    };
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));

    if path == "/attestation" {
        handle_attestation(&mut stream, query);
    } else {
        let body = "Hello, world!";
        write_response(&mut stream, "200 OK", "text/plain", body.as_bytes());
    }
}

fn serve(listener: TcpListener) {
    for stream in listener.incoming() {
        handle_connection(stream);
    }
}

/// Binds an IPv6-only listener so it doesn't fight the IPv4 listener over the same port —
/// Linux's dual-stack default (bindv6only=0) would otherwise let `[::]` claim v4 traffic too.
fn bind_ipv6_only(port: &str) -> TcpListener {
    let socket =
        Socket::new(Domain::IPV6, Type::STREAM, None).expect("failed to create IPv6 socket");
    socket.set_only_v6(true).expect("failed to set IPV6_V6ONLY");
    let addr = format!("[::]:{port}")
        .parse::<std::net::SocketAddr>()
        .unwrap();
    socket.bind(&addr.into()).expect("failed to bind IPv6 PORT");
    socket.listen(128).expect("failed to listen on IPv6 socket");
    socket.into()
}

fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    let listener_v4 = TcpListener::bind(format!("0.0.0.0:{port}")).expect("failed to bind PORT");
    let listener_v6 = bind_ipv6_only(&port);
    println!("dumy-server listening on :{port} (IPv4 + IPv6)");

    let v6_thread = thread::spawn(move || serve(listener_v6));
    serve(listener_v4);
    let _ = v6_thread.join();
}
