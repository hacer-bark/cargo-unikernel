# Remote Attestation API (SEV-SNP)

*[docs index](README.md) · [project README](../README.md)*

Wire protocol of the optional SEV-SNP remote-attestation HTTP server (`[attestation]`,
sev-snp profile only). See [`init_security.md`](init_security.md) and
[`architecture.md`](architecture.md) for how it fits into the guest's boot sequence and
privilege model.

## Endpoint

```
GET /v1/attestation?nonce=<128 hex characters>
```

`nonce` decodes to exactly 64 raw bytes and is placed verbatim into the report's
`REPORT_DATA` field — not hashed, not echoed back. The caller must remember the nonce it
sent to check it against the report. Any other path redirects here; any method but `GET` is
rejected.

## Success response

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 1184
Connection: close
X-Content-Type-Options: nosniff
Cache-Control: no-store

<1184 raw bytes>
```

The body is the unmodified `MSG_REPORT_RSP` payload from the SEV-SNP `SNP_GET_REPORT`
firmware call (AMD's `ATTESTATION_REPORT` structure) — no wrapper, no text encoding. Every
real verifier (AMD's own tooling, the `sev` crate) parses this exact binary layout directly,
and raw bytes halve the response size against hex with no per-request encoding step. Pipe it
to a file with `curl -o report.bin ...` rather than a terminal.

## Error responses

No JSON, no per-request string formatting — a status line plus, where useful, a short body.

| Condition | Status | Body |
|:---|:---|:---|
| Path other than `/v1/attestation` | `302 Found` (redirects) | empty |
| Method other than `GET` | `405 Method Not Allowed` | empty |
| `nonce` missing, wrong length, or non-hex | `400 Bad Request` | `bad nonce` |
| Per-subnet rate/concurrency limit exceeded | `429 Too Many Requests` | `rate limited` |
| Hardware report queue full, or `/dev/sev-guest` unavailable | `503 Service Unavailable` | `busy` |
| Firmware ioctl failure or unexpected report shape | `500 Internal Server Error` | `error` |

## Report layout

Fields most relevant to verification (offsets per AMD's SEV-SNP ABI — the full structure,
including reserved ranges and TCB sub-fields, is in AMD's public SNP Firmware ABI spec):

| Offset | Size | Field |
|:---|:---|:---|
| `0x000` | 4 | `VERSION` |
| `0x050` | 64 | `REPORT_DATA` — the caller's nonce, verbatim |
| `0x090` | 48 | `MEASUREMENT` — the launch digest covering kernel + init + app |
| `0x0C0` | 32 | `HOST_DATA` |
| `0x180` | 8 | `REPORTED_TCB` |
| `0x1A0` | 64 | `CHIP_ID` |
| `0x2A0` | 512 | `SIGNATURE` (ECDSA over the preceding bytes, by the platform's VCEK) |

`MEASUREMENT` is what a verifier compares against `dist/sev_measurement.txt`/`.json`
produced by `cargo-unikernel build` — a match proves this exact kernel+init+app is what
launched, independent of anything the network path could have altered afterward.

## Concurrency and rate limits

A fixed worker-thread pool accepts connections directly (bounding total concurrency by pool
size, not a dynamic runtime pool); a separate counter bounds concurrent `SNP_GET_REPORT`
firmware calls, since the security processor serializes report generation in hardware
regardless; requests are further rate/concurrency-limited per source `/24` (IPv4) or `/64`
(IPv6) subnet, so one source can't exhaust the queue for everyone else. Every limit rejects
immediately (`429`/`503`) rather than queuing.

## Verifying a report

1. **`REPORT_DATA` equals the nonce sent** — confirms freshness, not a replay.
2. **`MEASUREMENT` equals the expected value** from that image's `sev_measurement.txt`/
   `.json` — confirms this exact build, not a tampered or different one.
3. **`SIGNATURE` verifies against the platform's VCEK**, chained to AMD's root of trust
   (ARK → ASK → VCEK) fetched from AMD's Key Distribution Service by `CHIP_ID` and
   `REPORTED_TCB` — confirms genuine AMD SEV-SNP hardware, not a forgery.

### Example: verifying with the `sev` crate

```rust
// Cargo.toml: sev = "<current version — check docs.rs/sev for the exact API surface>"
use sev::firmware::guest::AttestationReport;
use sev::certs::snp::{Chain, Verifiable};

const EXPECTED_MEASUREMENT: &str = "…"; // from that image's sev_measurement.txt

fn verify_report(report_bytes: &[u8], nonce: &[u8; 64]) -> anyhow::Result<()> {
    let report = AttestationReport::try_from(report_bytes)?;

    anyhow::ensure!(report.report_data == *nonce, "REPORT_DATA does not match the nonce sent");

    let measurement_hex = hex::encode(report.measurement);
    anyhow::ensure!(
        measurement_hex == EXPECTED_MEASUREMENT,
        "measurement does not match the expected build: got {measurement_hex}"
    );

    // Fetch the VCEK for this chip/TCB from AMD's KDS, build the ARK -> ASK -> VCEK chain,
    // and verify. Exact constructor names differ between `sev` crate versions — see its
    // guest-attestation example on docs.rs.
    let chain: Chain = fetch_and_build_chain(&report)?;
    (&chain, &report).verify()?;

    Ok(())
}
```

Fetching a report to feed this function:

```sh
NONCE=$(openssl rand -hex 64)
curl -s -o report.bin "http://127.0.0.1:8080/v1/attestation?nonce=${NONCE}"
```

(Replace `127.0.0.1:8080` with the guest's actual address and `[attestation].port`.)
