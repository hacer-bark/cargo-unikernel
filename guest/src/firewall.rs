//! Default-deny inbound packet filter, installed by PID 1 before any interface comes up.
//!
//! The guest answers nothing it was not configured to answer: no `RST` on a closed TCP port, no
//! ICMP port-unreachable, no echo reply. A scanner sees `filtered`, which is what it would see
//! if the address were dark. Outbound is untouched — this filters the `input` hook only, and
//! return traffic for connections the guest itself opened is admitted by conntrack state rather
//! than by opening ports for it.
//!
//! ## Why nftables rather than eBPF/XDP
//!
//! XDP would need `CONFIG_BPF_SYSCALL` and the eBPF verifier/JIT in the TCB — which
//! `legacy-subsystems.config` deliberately removes, `seccomp.rs` denies to the app, and
//! `hardening.rs` restricts twice over. Trading that surface for a filter is the wrong
//! direction. It would also be stateless: "outbound unrestricted" means admitting the replies,
//! which without conntrack means hand-rolling connection tracking in BPF maps — precisely the
//! part that is easy to get subtly wrong, in the place where getting it wrong fails open.
//!
//! ## Why hand-rolled netlink rather than a bundled `nft`
//!
//! The ruleset this image needs is fixed in shape and tiny — one table, one chain, a dozen
//! rules whose only variable part is a port list. Bundling `nft` would mean four more pinned
//! source tarballs in the build container (libmnl, libnftnl, gmp, nftables) and a C parser
//! running as root in the guest, to emit netlink this module emits directly. Every syscall here
//! goes through `rustix`, so unlike `landlock.rs` or `seccomp.rs` this module contains no
//! `unsafe` at all.
//!
//! The encoding is verified two ways: [`tests`] asserts the exact bytes of the constructed
//! messages, and `nftables_accepts_the_ruleset_and_prints_it_back` installs the real ruleset in
//! a throwaway network namespace and diffs the reference implementation's rendering of it.

use std::io;

// ---------------------------------------------------------------------------------------------
// Netlink and nf_tables constants — `linux/netlink.h`, `linux/netfilter/nfnetlink.h`,
// `linux/netfilter/nf_tables.h`. Written out here rather than taken from `libc` (which exports
// almost none of them) or a crate; each is a long-stable uapi number.
// ---------------------------------------------------------------------------------------------

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
/// Without this, `nf_tables` inserts each new rule at the *head* of the chain, so the ruleset
/// below would end up in reverse — and reverse order is not merely untidy here: the
/// `ct state invalid drop` rule would sit behind the port accepts it is meant to precede.
const NLM_F_APPEND: u16 = 0x0800;

const NLMSG_ERROR: u16 = 0x0002;
const NLMSG_HDR_LEN: usize = 16;
const NLA_HDR_LEN: usize = 4;
/// `NLA_F_NESTED` — advisory (the kernel masks it off when reading an attribute's type), set
/// because every other `nf_tables` producer sets it and a dump that lacks it reads as suspect.
const NLA_F_NESTED: u16 = 0x8000;

const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_RANGE_SREG: u16 = 1;
const NFTA_RANGE_OP: u16 = 2;
const NFTA_RANGE_FROM_DATA: u16 = 3;
const NFTA_RANGE_TO_DATA: u16 = 4;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;

const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;
const NFT_RANGE_EQ: u32 = 0;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_L4PROTO: u32 = 16;
const NFT_CT_STATE: u32 = 0;

/// `NF_DROP` / `NF_ACCEPT`, the verdicts an `immediate` expression writes to the verdict register.
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;

const NFPROTO_INET: u8 = 1;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
/// `NF_INET_LOCAL_IN` — the only hook this module registers. Nothing filters `output` or
/// `forward`: outbound is unrestricted by design, and `ip_forward=0` already means this guest
/// does not route.
const NF_INET_LOCAL_IN: u32 = 1;
/// `NF_IP_PRI_FILTER` — where a filter chain conventionally sits.
const FILTER_PRIORITY: u32 = 0;

/// `IP_CT_ESTABLISHED_BIT`/`RELATED_BIT`/`INVALID_BIT` as the bitmask `ct state` yields.
const CT_STATE_INVALID: u32 = 0x01;
const CT_STATE_ESTABLISHED: u32 = 0x02;
const CT_STATE_RELATED: u32 = 0x04;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

/// `IFNAMSIZ` — an interface name compares as a fixed 16-byte, NUL-padded field.
const IFNAMSIZ: usize = 16;

/// The table and chain this module owns. Named rather than anonymous so an operator reading
/// `nft list ruleset` on a debug build sees where the policy came from.
const TABLE: &str = "cargo-unikernel";
const CHAIN: &str = "input";

/// `ICMPv6` types admitted regardless of configuration, because IPv6 does not work without them.
///
/// Dropping these is the classic way a default-deny ruleset "works" in testing and then fails in
/// production: without router advertisement (134) there is no SLAAC address at all, without
/// neighbour solicit/advert (135/136) the guest is unreachable at L2, and without packet-too-big
/// (2) every response larger than the path MTU vanishes into a PMTUD black hole. Router
/// solicitation (133) is included because the guest sends one and the reply arrives as its own
/// message rather than as conntrack-`related` traffic; MLD query (130) because a switch doing
/// MLD snooping stops delivering the solicited-node multicast that NDP depends on if the guest
/// never answers one.
///
/// Echo request (128) is deliberately absent: "does not answer a ping" is the point. So is
/// redirect (137) — `accept_redirects=0` already ignores it, and admitting it would only hand an
/// on-link attacker a route-steering primitive to aim at that.
const ICMPV6_ALLOWED_TYPES: [u8; 6] = [2, 130, 133, 134, 135, 136];

/// `ICMPv4` destination-unreachable, which carries `fragmentation needed` — the IPv4 half of the
/// PMTUD problem described above. Conntrack admits the ones that match a tracked flow as
/// `related`; this covers the rest, at the cost of accepting an unsolicited error packet the
/// kernel then validates against its own socket table anyway.
const ICMPV4_DEST_UNREACH: u8 = 3;

/// One `[network.firewall].inbound` entry: a protocol and an inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rule {
    protocol: u8,
    first_port: u16,
    last_port: u16,
}

/// Parses the baked `CARGO_UNIKERNEL_FIREWALL_RULES` string: `';'`-joined `proto:ports` entries,
/// where `ports` is either `443` or `8000-8100` (inclusive). An empty string is a valid,
/// meaningful configuration — the guest answers nothing at all.
///
/// The host tool validates this same grammar when it bakes the string in
/// (`schema::Config::validate_firewall`); a failure here therefore means the two sides disagree
/// about the encoding, which `fatal` treats the way every other such disagreement is treated.
pub(crate) fn parse_rules(raw: &str, fatal: fn(&str) -> !) -> Vec<Rule> {
    raw.split(';')
        .filter(|entry| !entry.is_empty())
        .map(|entry| parse_rule(entry, fatal))
        .collect()
}

fn parse_rule(entry: &str, fatal: fn(&str) -> !) -> Rule {
    let malformed = || -> ! {
        fatal(&format!(
            "Malformed [network.firewall].inbound entry {entry:?} — expected \"tcp:443\" or \
             \"udp:8000-8100\""
        ))
    };

    let Some((protocol, ports)) = entry.split_once(':') else {
        malformed()
    };
    let protocol = match protocol {
        "tcp" => IPPROTO_TCP,
        "udp" => IPPROTO_UDP,
        _ => malformed(),
    };
    let (first, last) = ports.split_once('-').unwrap_or((ports, ports));
    let (Ok(first_port), Ok(last_port)) = (first.parse::<u16>(), last.parse::<u16>()) else {
        malformed()
    };
    if first_port == 0 || last_port < first_port {
        malformed()
    }
    Rule {
        protocol,
        first_port,
        last_port,
    }
}

// ---------------------------------------------------------------------------------------------
// Netlink message construction
// ---------------------------------------------------------------------------------------------

/// A netlink message buffer.
///
/// Every length field is patched in once its content is known, so nesting is expressed as
/// `begin`/`end` pairs rather than by pre-computing sizes. `overflowed` latches instead of
/// panicking on an impossible length: this crate denies `arithmetic_side_effects`, and a
/// truncated netlink message is a ruleset that means something other than what was asked for —
/// so it is refused whole in [`Self::finish`] rather than sent.
#[derive(Debug, Default)]
struct NlBuf {
    bytes: Vec<u8>,
    overflowed: bool,
}

/// Netlink rounds every header and payload up to a 4-byte boundary.
const fn align4(len: usize) -> usize {
    len.next_multiple_of(4)
}

impl NlBuf {
    fn put(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Pads to the next 4-byte boundary.
    fn pad(&mut self) {
        let padding = align4(self.bytes.len()).saturating_sub(self.bytes.len());
        self.bytes
            .resize(self.bytes.len().saturating_add(padding), 0);
    }

    /// Patches the `u32` length at `at`, or latches [`Self::overflowed`] if the value doesn't fit.
    fn patch_u32(&mut self, at: usize, value: usize) {
        let Ok(value) = u32::try_from(value) else {
            self.overflowed = true;
            return;
        };
        let Some(slot) = self.bytes.get_mut(at..at.saturating_add(4)) else {
            self.overflowed = true;
            return;
        };
        slot.copy_from_slice(&value.to_ne_bytes());
    }

    fn patch_u16(&mut self, at: usize, value: usize) {
        let Ok(value) = u16::try_from(value) else {
            self.overflowed = true;
            return;
        };
        let Some(slot) = self.bytes.get_mut(at..at.saturating_add(2)) else {
            self.overflowed = true;
            return;
        };
        slot.copy_from_slice(&value.to_ne_bytes());
    }

    /// Starts a `struct nlmsghdr`, returning the offset its length field must be patched at.
    fn begin_msg(&mut self, msg_type: u16, flags: u16, seq: u32) -> usize {
        let at = self.bytes.len();
        self.put(&0u32.to_ne_bytes()); // nlmsg_len, patched by end_msg
        self.put(&msg_type.to_ne_bytes());
        self.put(&flags.to_ne_bytes());
        self.put(&seq.to_ne_bytes());
        self.put(&0u32.to_ne_bytes()); // nlmsg_pid: 0, the kernel
        at
    }

    fn end_msg(&mut self, at: usize) {
        self.pad();
        self.patch_u32(at, self.bytes.len().saturating_sub(at));
    }

    /// `struct nfgenmsg`. `res_id` is big-endian, unlike the netlink header's own fields.
    fn put_nfgenmsg(&mut self, family: u8, res_id: u16) {
        self.put(&[family, 0 /* NFNETLINK_V0 */]);
        self.put(&res_id.to_be_bytes());
    }

    /// A `struct nlattr` with a byte payload.
    fn put_attr(&mut self, attr_type: u16, payload: &[u8]) {
        let len = NLA_HDR_LEN.saturating_add(payload.len());
        let Ok(len16) = u16::try_from(len) else {
            self.overflowed = true;
            return;
        };
        self.put(&len16.to_ne_bytes());
        self.put(&attr_type.to_ne_bytes());
        self.put(payload);
        self.pad();
    }

    /// `nf_tables` reads its scalar attributes as big-endian, unlike netlink's own headers.
    fn put_be32(&mut self, attr_type: u16, value: u32) {
        self.put_attr(attr_type, &value.to_be_bytes());
    }

    /// A NUL-terminated string attribute, as `NFTA_*_NAME`-style attributes are defined.
    fn put_str(&mut self, attr_type: u16, value: &str) {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.put_attr(attr_type, &bytes);
    }

    fn begin_nested(&mut self, attr_type: u16) -> usize {
        let at = self.bytes.len();
        self.put(&0u16.to_ne_bytes()); // nla_len, patched by end_nested
        self.put(&(attr_type | NLA_F_NESTED).to_ne_bytes());
        at
    }

    fn end_nested(&mut self, at: usize) {
        self.pad();
        self.patch_u16(at, self.bytes.len().saturating_sub(at));
    }

    fn finish(self) -> io::Result<Vec<u8>> {
        if self.overflowed {
            return Err(io::Error::other(
                "firewall ruleset exceeded netlink's message limits",
            ));
        }
        Ok(self.bytes)
    }
}

// ---------------------------------------------------------------------------------------------
// nf_tables expressions
//
// A rule is a list of expressions evaluated in order against one packet. Each either loads a
// value into a register or tests what a previous one loaded; the last writes a verdict. The
// sequences below are the ones `nft --debug=netlink` emits for the equivalent human syntax,
// which is quoted above each builder.
// ---------------------------------------------------------------------------------------------

impl NlBuf {
    /// One expression: `NFTA_LIST_ELEM { NFTA_EXPR_NAME, NFTA_EXPR_DATA { .. } }`.
    fn expr(&mut self, name: &str, data: impl FnOnce(&mut Self)) {
        let elem = self.begin_nested(NFTA_LIST_ELEM);
        self.put_str(NFTA_EXPR_NAME, name);
        let body = self.begin_nested(NFTA_EXPR_DATA);
        data(self);
        self.end_nested(body);
        self.end_nested(elem);
    }

    /// `meta load <key> => reg 1`
    fn meta_load(&mut self, key: u32) {
        self.expr("meta", |b| {
            b.put_be32(NFTA_META_KEY, key);
            b.put_be32(NFTA_META_DREG, NFT_REG_1);
        });
    }

    /// `ct load state => reg 1`
    fn ct_state_load(&mut self) {
        self.expr("ct", |b| {
            b.put_be32(NFTA_CT_KEY, NFT_CT_STATE);
            b.put_be32(NFTA_CT_DREG, NFT_REG_1);
        });
    }

    /// `payload load <len>b @ transport header + <offset> => reg 1`
    fn payload_load(&mut self, offset: u32, len: u32) {
        self.expr("payload", |b| {
            b.put_be32(NFTA_PAYLOAD_DREG, NFT_REG_1);
            b.put_be32(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
            b.put_be32(NFTA_PAYLOAD_OFFSET, offset);
            b.put_be32(NFTA_PAYLOAD_LEN, len);
        });
    }

    /// `cmp <op> reg 1 <value>`. `value` is raw register bytes: network order for anything
    /// loaded from a packet header, host order for the kernel-internal words `meta`/`ct` yield.
    fn cmp(&mut self, op: u32, value: &[u8]) {
        self.expr("cmp", |b| {
            b.put_be32(NFTA_CMP_SREG, NFT_REG_1);
            b.put_be32(NFTA_CMP_OP, op);
            let data = b.begin_nested(NFTA_CMP_DATA);
            b.put_attr(NFTA_DATA_VALUE, value);
            b.end_nested(data);
        });
    }

    /// `range eq reg 1 <first> <last>`, inclusive.
    fn range(&mut self, first: &[u8], last: &[u8]) {
        self.expr("range", |b| {
            b.put_be32(NFTA_RANGE_SREG, NFT_REG_1);
            b.put_be32(NFTA_RANGE_OP, NFT_RANGE_EQ);
            let from = b.begin_nested(NFTA_RANGE_FROM_DATA);
            b.put_attr(NFTA_DATA_VALUE, first);
            b.end_nested(from);
            let to = b.begin_nested(NFTA_RANGE_TO_DATA);
            b.put_attr(NFTA_DATA_VALUE, last);
            b.end_nested(to);
        });
    }

    /// `bitwise reg 1 = ( reg 1 & <mask> ) ^ 0` — how `ct state` is tested for membership in a
    /// set of bits before the `cmp neq 0` that follows it.
    fn bitwise_mask(&mut self, mask: u32) {
        self.expr("bitwise", |b| {
            b.put_be32(NFTA_BITWISE_SREG, NFT_REG_1);
            b.put_be32(NFTA_BITWISE_DREG, NFT_REG_1);
            b.put_be32(NFTA_BITWISE_LEN, 4);
            let m = b.begin_nested(NFTA_BITWISE_MASK);
            b.put_attr(NFTA_DATA_VALUE, &mask.to_ne_bytes());
            b.end_nested(m);
            let x = b.begin_nested(NFTA_BITWISE_XOR);
            b.put_attr(NFTA_DATA_VALUE, &0u32.to_ne_bytes());
            b.end_nested(x);
        });
    }

    /// `immediate reg 0 <verdict>` — the terminal expression of every rule here.
    fn verdict(&mut self, verdict: u32) {
        self.expr("immediate", |b| {
            b.put_be32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
            let data = b.begin_nested(NFTA_IMMEDIATE_DATA);
            let v = b.begin_nested(NFTA_DATA_VERDICT);
            b.put_be32(NFTA_VERDICT_CODE, verdict);
            b.end_nested(v);
            b.end_nested(data);
        });
    }

    /// Wraps `expressions` in a `NFT_MSG_NEWRULE` appended to this batch.
    fn rule(&mut self, seq: u32, expressions: impl FnOnce(&mut Self)) {
        let msg = self.begin_msg(
            (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
            seq,
        );
        self.put_nfgenmsg(NFPROTO_INET, 0);
        self.put_str(NFTA_RULE_TABLE, TABLE);
        self.put_str(NFTA_RULE_CHAIN, CHAIN);
        let list = self.begin_nested(NFTA_RULE_EXPRESSIONS);
        expressions(self);
        self.end_nested(list);
        self.end_msg(msg);
    }
}

/// The `l4proto` guard every port rule opens with, so a `tcp dport 443` rule cannot be satisfied
/// by a UDP packet whose second header halfword happens to be 443.
fn l4proto_is(buf: &mut NlBuf, protocol: u8) {
    buf.meta_load(NFT_META_L4PROTO);
    buf.cmp(NFT_CMP_EQ, &[protocol]);
}

fn nfproto_is(buf: &mut NlBuf, family: u8) {
    buf.meta_load(NFT_META_NFPROTO);
    buf.cmp(NFT_CMP_EQ, &[family]);
}

/// A built ruleset: the netlink bytes, and how many of the messages in them ask to be
/// acknowledged.
///
/// The count is produced by the same code that emits the messages rather than recomputed from
/// the rule list, so the two cannot drift — [`send_batch`] waits for exactly this many
/// acknowledgements, and a count that was one too low would mean declaring success while a
/// message's verdict was still unread.
#[derive(Debug)]
struct Batch {
    bytes: Vec<u8>,
    ackable: usize,
}

/// Builds the whole ruleset as one netlink batch: a transaction the kernel either commits
/// entirely or rejects entirely, so there is no window in which the chain exists with a
/// `drop` policy but without the rules that make the guest reachable.
fn build_batch(rules: &[Rule]) -> io::Result<Batch> {
    let mut buf = NlBuf::default();
    // One sequence number per message, so an error reply names the exact message it rejected.
    // Every message except the batch's own begin/end markers carries `NLM_F_ACK`, so the last
    // sequence number is also how many acknowledgements to expect, minus those two markers.
    let mut seq: u32 = 0;
    let mut tick = || {
        seq = seq.saturating_add(1);
        seq
    };

    // NFNL_MSG_BATCH_BEGIN, whose res_id names the subsystem the batch belongs to.
    let begin = buf.begin_msg(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, tick());
    buf.put_nfgenmsg(0, NFNL_SUBSYS_NFTABLES);
    buf.end_msg(begin);

    // `add table inet cargo-unikernel`
    let s = tick();
    let table = buf.begin_msg(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        s,
    );
    buf.put_nfgenmsg(NFPROTO_INET, 0);
    buf.put_str(NFTA_TABLE_NAME, TABLE);
    buf.end_msg(table);

    // `add chain ... { type filter hook input priority filter; policy drop; }`
    //
    // The policy is the whole feature: every packet that reaches the end of this chain without
    // matching a rule is dropped silently, with no RST and no ICMP error.
    let s = tick();
    let chain = buf.begin_msg(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        s,
    );
    buf.put_nfgenmsg(NFPROTO_INET, 0);
    buf.put_str(NFTA_CHAIN_TABLE, TABLE);
    buf.put_str(NFTA_CHAIN_NAME, CHAIN);
    let hook = buf.begin_nested(NFTA_CHAIN_HOOK);
    buf.put_be32(NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN);
    buf.put_be32(NFTA_HOOK_PRIORITY, FILTER_PRIORITY);
    buf.end_nested(hook);
    buf.put_be32(NFTA_CHAIN_POLICY, NF_DROP);
    buf.put_str(NFTA_CHAIN_TYPE, "filter");
    buf.end_msg(chain);

    // `iifname "lo" accept` — the app's own localhost traffic, which a drop policy would
    // otherwise sever. Matched on the name rather than the index so it does not depend on
    // loopback having been enumerated first.
    let s = tick();
    buf.rule(s, |b| {
        let mut name = [0u8; IFNAMSIZ];
        if let Some(slot) = name.get_mut(.."lo".len()) {
            slot.copy_from_slice(b"lo");
        }
        b.meta_load(NFT_META_IIFNAME);
        b.cmp(NFT_CMP_EQ, &name);
        b.verdict(NF_ACCEPT);
    });

    // `ct state established,related accept` — this is what makes "outbound is unrestricted"
    // true: replies to connections the guest opened are admitted as state, without any port
    // being open to the network.
    let s = tick();
    buf.rule(s, |b| {
        b.ct_state_load();
        b.bitwise_mask(CT_STATE_ESTABLISHED | CT_STATE_RELATED);
        b.cmp(NFT_CMP_NEQ, &0u32.to_ne_bytes());
        b.verdict(NF_ACCEPT);
    });

    // `ct state invalid drop` — before the accept rules, so a packet conntrack cannot place in
    // any flow never reaches them.
    let s = tick();
    buf.rule(s, |b| {
        b.ct_state_load();
        b.bitwise_mask(CT_STATE_INVALID);
        b.cmp(NFT_CMP_NEQ, &0u32.to_ne_bytes());
        b.verdict(NF_DROP);
    });

    // `meta nfproto ipv6 icmpv6 type <t> accept`, one rule per type — see ICMPV6_ALLOWED_TYPES.
    for icmp_type in ICMPV6_ALLOWED_TYPES {
        let s = tick();
        buf.rule(s, |b| {
            nfproto_is(b, NFPROTO_IPV6);
            l4proto_is(b, IPPROTO_ICMPV6);
            b.payload_load(0, 1);
            b.cmp(NFT_CMP_EQ, &[icmp_type]);
            b.verdict(NF_ACCEPT);
        });
    }

    // `meta nfproto ipv4 icmp type destination-unreachable accept`
    let s = tick();
    buf.rule(s, |b| {
        nfproto_is(b, NFPROTO_IPV4);
        l4proto_is(b, IPPROTO_ICMP);
        b.payload_load(0, 1);
        b.cmp(NFT_CMP_EQ, &[ICMPV4_DEST_UNREACH]);
        b.verdict(NF_ACCEPT);
    });

    // The configured ports — the only part of this ruleset a deployment chooses.
    for rule in rules {
        let s = tick();
        buf.rule(s, |b| {
            l4proto_is(b, rule.protocol);
            // Destination port: 2 bytes at offset 2 of the transport header, same for TCP and
            // UDP. Compared in network order, which is how it sits in the packet.
            b.payload_load(2, 2);
            if rule.first_port == rule.last_port {
                b.cmp(NFT_CMP_EQ, &rule.first_port.to_be_bytes());
            } else {
                b.range(
                    &rule.first_port.to_be_bytes(),
                    &rule.last_port.to_be_bytes(),
                );
            }
            b.verdict(NF_ACCEPT);
        });
    }

    let last = tick();
    let end = buf.begin_msg(NFNL_MSG_BATCH_END, NLM_F_REQUEST, last);
    buf.put_nfgenmsg(0, NFNL_SUBSYS_NFTABLES);
    buf.end_msg(end);

    Ok(Batch {
        bytes: buf.finish()?,
        ackable: usize::try_from(last).unwrap_or(0).saturating_sub(2),
    })
}

// ---------------------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------------------

/// How long to wait for the kernel's acknowledgement of the batch. Generous for a local socket
/// answering a single transaction; bounded so a kernel that never replies can't hang the boot
/// before the app it is protecting even starts.
const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Sends `batch` on a `NETLINK_NETFILTER` socket and reads back one acknowledgement per
/// acknowledgeable message in it.
///
/// `nf_tables` applies a batch as a transaction: an error in any message rejects the whole thing,
/// which is why this can treat "any error reply" as "no ruleset was installed" rather than
/// having to unpick a partial one. Every reply is checked — an unacknowledged batch is a
/// ruleset that may not exist, and this returns `Err` rather than let the caller assume it does.
fn send_batch(batch: &Batch) -> io::Result<()> {
    use rustix::net::{
        AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, bind, netlink, recv, send,
        socket_with,
    };

    let sock = socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(netlink::NETFILTER),
    )?;
    // Port id 0: let the kernel assign one, rather than assuming this process's pid is free.
    bind(&sock, &netlink::SocketAddrNetlink::new(0, 0))?;
    rustix::net::sockopt::set_socket_timeout(
        &sock,
        rustix::net::sockopt::Timeout::Recv,
        Some(ACK_TIMEOUT),
    )?;

    send(&sock, &batch.bytes, SendFlags::empty())?;

    let mut acks = 0usize;
    let mut buf = [0u8; 8192];
    while acks < batch.ackable {
        let (received, _) = recv(&sock, &mut buf[..], RecvFlags::empty())?;
        let Some(mut reply) = buf.get(..received) else {
            return Err(io::Error::other("short netlink read"));
        };
        while let Some((header, rest)) = split_message(reply)? {
            acks = acks.saturating_add(check_reply(header)?);
            reply = rest;
        }
    }
    Ok(())
}

/// Splits one netlink message off the front of `reply`, returning its bytes and the remainder.
/// `None` once nothing further remains.
fn split_message(reply: &[u8]) -> io::Result<Option<(&[u8], &[u8])>> {
    if reply.len() < NLMSG_HDR_LEN {
        return Ok(None);
    }
    let Some(len_bytes) = reply.get(..4) else {
        return Ok(None);
    };
    let mut len = [0u8; 4];
    len.copy_from_slice(len_bytes);
    let len = usize::try_from(u32::from_ne_bytes(len)).unwrap_or(0);
    if len < NLMSG_HDR_LEN || len > reply.len() {
        return Err(io::Error::other("malformed netlink reply length"));
    }
    let (header, rest) = reply.split_at(len.min(reply.len()));
    Ok(Some((header, rest.get(..).unwrap_or_default())))
}

/// Reads one reply message, returning how many acknowledgements it accounts for (1 for a
/// success ack, and never returning at all for a failure — which is reported as `Err`).
///
/// `NLMSG_ERROR` with a zero error code *is* the acknowledgement: netlink has no separate
/// "success" message type.
fn check_reply(message: &[u8]) -> io::Result<usize> {
    let Some(type_bytes) = message.get(4..6) else {
        return Err(io::Error::other("truncated netlink reply header"));
    };
    let mut msg_type = [0u8; 2];
    msg_type.copy_from_slice(type_bytes);
    if u16::from_ne_bytes(msg_type) != NLMSG_ERROR {
        // Anything else in this conversation (NLMSG_DONE, NLMSG_NOOP) carries no verdict on
        // whether the batch applied, so it neither counts nor fails.
        return Ok(0);
    }

    let Some(error_bytes) = message.get(NLMSG_HDR_LEN..NLMSG_HDR_LEN.saturating_add(4)) else {
        return Err(io::Error::other("truncated netlink error reply"));
    };
    let mut code = [0u8; 4];
    code.copy_from_slice(error_bytes);
    let code = i32::from_ne_bytes(code);
    if code == 0 {
        return Ok(1);
    }

    // `struct nlmsgerr` echoes the header of the message it rejects, so the sequence number
    // names which one — the difference between "the ruleset is wrong" and "message 7 is wrong"
    // when this has to be diagnosed from a boot log.
    let rejected = message
        .get(NLMSG_HDR_LEN.saturating_add(12)..NLMSG_HDR_LEN.saturating_add(16))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_ne_bytes);
    Err(io::Error::other(format!(
        "nf_tables rejected message #{rejected}: {}",
        io::Error::from_raw_os_error(code.saturating_neg())
    )))
}

/// Installs the ruleset, or terminates the boot.
///
/// Called before `network::init_networking` brings any interface up, so no packet is ever
/// handled by an unfiltered stack — the guest is silent from the moment it can receive anything
/// at all. (The kernel's own `ip=dhcp` autoconfiguration runs before this init exists and is
/// therefore outside that window; nothing is listening then, but it is documented in
/// `docs/threat_model.md` rather than left implied.)
///
/// A failure is fatal, for the same reason `entropy.rs` and `landlock.rs` are: an image whose
/// config says "only these ports answer" must not boot into a state where every port does. The
/// most likely cause by far is a kernel built without `CONFIG_NF_TABLES`/`CONFIG_NF_CONNTRACK`,
/// which `[network.firewall]` selects automatically — so this failing means the two halves of
/// the build disagree, exactly the case that should stop rather than degrade.
pub(crate) fn install(rules: &[Rule], log: impl Fn(&str), fatal: fn(&str) -> !) {
    log("Installing inbound packet filter (default deny)...");

    let batch = build_batch(rules)
        .unwrap_or_else(|e| fatal(&format!("Failed to build the firewall ruleset: {e}")));
    if let Err(e) = send_batch(&batch) {
        fatal(&format!(
            "Failed to install the firewall ruleset: {e}. The guest would otherwise answer on \
             every port, which is not what this image was configured for."
        ));
    }

    log(&format!(
        "Inbound filter active: default deny, {} configured port rule(s), outbound unrestricted.",
        rules.len()
    ));
}

#[cfg(test)]
// Tests panicking (via unwrap/expect/assert) on failure is the point, not a code
// smell — this is the standard justified exception to these lints.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn no_fatal(message: &str) -> ! {
        panic!("{message}")
    }

    #[test]
    fn ports_and_ranges_parse_and_an_empty_policy_is_legal() {
        assert_eq!(
            parse_rules("tcp:80;udp:443;tcp:8000-8100", no_fatal),
            vec![
                Rule {
                    protocol: IPPROTO_TCP,
                    first_port: 80,
                    last_port: 80
                },
                Rule {
                    protocol: IPPROTO_UDP,
                    first_port: 443,
                    last_port: 443
                },
                Rule {
                    protocol: IPPROTO_TCP,
                    first_port: 8000,
                    last_port: 8100
                },
            ]
        );
        // "answer nothing at all" is a configuration, not an error — a guest that only makes
        // outbound connections is exactly what this feature's default-deny is for.
        assert!(parse_rules("", no_fatal).is_empty());
    }

    /// Every acknowledgement the installer waits for has to correspond to a message that
    /// actually asked for one. If this drifts, a failed rule goes unnoticed (count too low) or
    /// the boot hangs until the timeout and then fails a working ruleset (count too high).
    #[test]
    fn the_acknowledgement_count_matches_the_messages_that_request_one() {
        // The ten fixed rules: loopback, two conntrack, six `ICMPv6`, one `ICMPv4`.
        const FIXED_RULES: usize = 1 + 2 + ICMPV6_ALLOWED_TYPES.len() + 1;

        let rules = parse_rules("tcp:80;tcp:443;udp:443", no_fatal);
        let batch = build_batch(&rules).unwrap();

        let mut remaining = batch.bytes.as_slice();
        let mut requested = 0usize;
        while let Some((message, rest)) = split_message(remaining).unwrap() {
            let flags = u16::from_ne_bytes(message.get(6..8).unwrap().try_into().unwrap());
            if flags & NLM_F_ACK != 0 {
                requested = requested.saturating_add(1);
            }
            remaining = rest;
        }

        assert_eq!(requested, batch.ackable);
        // The fixed rules, the table and the chain, plus one per configured port rule.
        assert_eq!(batch.ackable, FIXED_RULES + 2 + rules.len());
    }

    /// The encoding assertions above only check this module against itself. This one checks it
    /// against the kernel: it installs the real ruleset in a throwaway network namespace, so a
    /// wrong attribute number, register, or expression layout fails here rather than by leaving
    /// a production guest either wide open or unreachable.
    ///
    /// Forks first: `unshare(CLONE_NEWUSER)` is refused in a multi-threaded process, and the
    /// test harness is one. The batch is built *before* the fork, so the child only issues
    /// syscalls — the same rule `spawn_app`'s `pre_exec` chain follows.
    ///
    /// Skips rather than fails where the environment can't support the test: user namespaces
    /// disabled, or a kernel without `nf_tables`. It cannot skip a rejected message, which is
    /// the thing under test.
    #[test]
    fn the_kernel_accepts_the_ruleset() {
        const INSTALLED: i32 = 0;
        const NO_NAMESPACE: i32 = 10;
        const NO_NFTABLES: i32 = 11;
        const REJECTED: i32 = 12;

        let rules = parse_rules("tcp:80;tcp:443;udp:443;tcp:8000-8100", no_fatal);
        let batch = build_batch(&rules).unwrap();

        // SAFETY: the child path issues only syscalls and never returns to the test harness;
        // the parent only waits on the pid it just created.
        let status = unsafe {
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                    libc::_exit(NO_NAMESPACE);
                }
                match send_batch(&batch) {
                    Ok(()) => libc::_exit(INSTALLED),
                    // A kernel with no nf_tables support at all, rather than one that read the
                    // messages and disagreed with them.
                    Err(e)
                        if matches!(
                            e.raw_os_error(),
                            Some(libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT | libc::ENOENT)
                        ) =>
                    {
                        libc::_exit(NO_NFTABLES)
                    }
                    Err(_) => libc::_exit(REJECTED),
                }
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, std::ptr::addr_of_mut!(status), 0), pid);
            status
        };

        assert!(libc::WIFEXITED(status), "the child died instead of exiting");
        match libc::WEXITSTATUS(status) {
            INSTALLED => {}
            NO_NAMESPACE => eprintln!("skipped: this host does not allow user namespaces"),
            NO_NFTABLES => eprintln!("skipped: this kernel has no nf_tables support"),
            _ => panic!(
                "the kernel rejected the ruleset — an attribute, register or expression in \
                 this module does not match what nf_tables expects"
            ),
        }
    }
}
