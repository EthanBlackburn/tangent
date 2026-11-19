//! New connections, for a `macos` source. Endpoint Security reports no
//! network, so they are read from tcpdump, which on macOS tags each packet
//! with the process that sent it (`-k NP` on the `pktap` interface). The
//! filter takes only what starts a connection: TCP SYNs, TLS ClientHellos
//! (whose server name says the host), QUIC's Initial packets, and DNS
//! answers (which name an address the hello did not). They are joined into
//! one line a connection, as the plugin reads it:
//!
//! ```json
//! {"time": "...Z", "net": {"proc": "curl", "pid": 4242, "proto": "tcp",
//!  "dst": "203.0.113.5", "port": 443, "host": "evil.example", "named_by": "tls"}}
//! ```
//!
//! with `eproc` and `epid` when the packet was sent for another process (a
//! system daemon's download for an app). Nothing past a hello is read: no
//! payload, no URL, no bytes sent.

use std::collections::HashMap;
use std::num::NonZeroUsize;

use bytes::BytesMut;
use chrono::DateTime;
use lru::LruCache;
use regex::Regex;
use serde_json::{json, Map, Value};

/// macOS's own tcpdump, by its path: it is started as root.
pub(super) const TCPDUMP: &str = "/usr/sbin/tcpdump";

/// tcpdump's arguments: every interface with each packet's process, no
/// names looked up, a line at a time, the time as a number, the bytes, and
/// the filter.
pub(super) fn arguments() -> Vec<String> {
    let mut arguments: Vec<String> = ["-i", "pktap,all", "-k", "NP", "-n", "-l", "-tt", "-X"]
        .map(String::from)
        .into();
    arguments.push(STARTS.join(" or "));
    arguments
}

/// What starts a connection, for IPv4 and for IPv6 without extension
/// headers (libpcap's `tcp[]` and `udp[]` read IPv4 only).
const STARTS: [&str; 7] = [
    "(tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)",
    "(ip6 and ip6[6] = 6 and ip6[53] & 0x12 = 0x02)",
    "(tcp[((tcp[12] & 0xf0) >> 2)] = 0x16 and tcp[((tcp[12] & 0xf0) >> 2) + 5] = 0x01)",
    "(ip6 and ip6[6] = 6 and ip6[40 + ((ip6[52] & 0xf0) >> 2)] = 0x16 \
     and ip6[40 + ((ip6[52] & 0xf0) >> 2) + 5] = 0x01)",
    "(udp dst port 443 and udp[8] & 0xf0 = 0xc0)",
    "(ip6 and ip6[6] = 17 and ip6[42:2] = 443 and ip6[48] & 0xf0 = 0xc0)",
    "udp src port 53",
];

/// A SYN waits this long (packet time) for its hello before it goes out
/// named by DNS, or not at all.
const WAIT: f64 = 1.0;
/// Flows and names remembered, the longest unused dropped past these.
const FLOWS: usize = 20_000;
const NAMES: usize = 50_000;

/// tcpdump's text in, a line at a time, and the connections out.
pub(super) struct Connections {
    /// A packet's first line: its time, tcpdump's tags, and the addresses,
    /// which end the tags. A process's name is the program's to choose and
    /// is printed as it is, so the tags end only where two addresses
    /// follow: the kernel holds a name to 16 bytes, too few to spell that.
    head: Regex,
    hex: Regex,
    /// The tags whole: `proc <name>:<pid>`, then `eproc <name>:<pid>` when
    /// the packet was sent for another process. Each pid is the number that
    /// ends its tag, whatever the name before it holds (a program named
    /// `x:690, y` is not pid 690), and the last number is always the
    /// kernel's: the pid of the process the connection is counted as.
    tags: Regex,
    /// Tags in another shape (more than the two tcpdump is asked for): each
    /// as it reads.
    tag: Regex,
    /// The packet being read: its time, its tags and its bytes so far, in
    /// hex. It is whole when the next begins.
    packet: Option<(String, String, String)>,
    /// flow -> a connection waiting for its hello
    pending: HashMap<Flow, Connection>,
    /// flows already written
    seen: LruCache<Flow, ()>,
    /// address -> the name DNS answered it for
    names: LruCache<String, String>,
    /// connections so far, for the order they came in
    count: u64,
}

/// A connection's two ends: source address and port, destination's.
type Flow = (String, usize, String, usize);

struct Connection {
    /// when its first packet was sent: seconds, and as the record's time
    at: f64,
    time: String,
    /// `proc` and `pid`, `eproc` and `epid`
    who: Map<String, Value>,
    dst: String,
    port: usize,
    proto: &'static str,
    /// the host, and what named it
    host: Option<(String, &'static str)>,
    order: u64,
}

impl Connections {
    pub(super) fn new() -> Self {
        let re = |re| Regex::new(re).expect("a regex written here");
        Self {
            head: re(r"^([0-9]+\.[0-9]+) \((.*?)\) IP6? [0-9a-f:.]{5,} > [0-9a-f:.]{5,}: "),
            hex: re(r"^\s+0x[0-9a-f]+:"),
            tags: re(r"^proc (.+?):([0-9]+)(?:, eproc (.+?):([0-9]+))?$"),
            tag: re(r"(e?proc) (.+?):([0-9]+)(?:, |$)"),
            packet: None,
            pending: HashMap::new(),
            seen: LruCache::new(NonZeroUsize::new(FLOWS).expect("more than none")),
            names: LruCache::new(NonZeroUsize::new(NAMES).expect("more than none")),
            count: 0,
        }
    }

    /// One line of tcpdump's, and the connections it completes.
    pub(super) fn line(&mut self, line: &str, out: &mut Vec<BytesMut>) {
        if let Some(head) = self.head.captures(line) {
            let next = (head[1].to_string(), head[2].to_string(), String::new());
            if let Some((t, tags, hex)) = self.packet.replace(next) {
                self.read(&t, &tags, &hex, out);
            }
        } else if self.hex.is_match(line) {
            if let Some((_, _, hex)) = self.packet.as_mut() {
                // `0x0010:  4500 0034 ...  E..4`: the bytes end at two spaces
                let bytes = line.split_once(':').map_or("", |(_, bytes)| bytes).trim();
                hex.extend(bytes.split("  ").next().unwrap_or("").split_whitespace());
            }
        }
    }

    /// The end of tcpdump's text: the packet being read, and every
    /// connection still waiting.
    pub(super) fn done(&mut self, out: &mut Vec<BytesMut>) {
        if let Some((t, tags, hex)) = self.packet.take() {
            self.read(&t, &tags, &hex, out);
        }
        self.flush(f64::INFINITY, out);
    }

    /// Whoever sends a packet chooses its bytes: one this cannot read is
    /// passed over, and the capture goes on.
    fn read(&mut self, t: &str, tags: &str, hex: &str, out: &mut Vec<BytesMut>) {
        let (Ok(bytes), Some((at, time))) = (hex::decode(hex), when(t)) else {
            return;
        };
        self.flush(at, out);
        let b = &bytes[..];
        let (ihl, proto, src, dst) = match b.first().map(|v| v >> 4) {
            Some(4) if b.len() >= 20 => (usize::from(b[0] & 15) * 4, b[9], &b[12..16], &b[16..20]),
            Some(6) if b.len() >= 40 => (40, b[6], &b[8..24], &b[24..40]),
            _ => return,
        };
        if b.len() < ihl + 8 {
            return;
        }
        let (sport, dport) = (int(b, ihl, 2), int(b, ihl + 2, 2));
        let flow = (addr(src), sport, addr(dst), dport);
        let who = self.tagged(tags);
        let new = |proto, order| Connection {
            at,
            time,
            who,
            dst: addr(dst),
            port: dport,
            proto,
            host: None,
            order,
        };
        if proto == 17 {
            if sport == 53 {
                let (asked, answers) = dns_answers(&b[ihl + 8..]);
                if let Some(asked) = asked.filter(|name| !name.is_empty()) {
                    for ip in answers {
                        self.names.put(ip, asked.clone());
                    }
                }
            } else if !self.seen.contains(&flow) {
                let c = new("quic", self.count);
                self.sent(flow, c, out);
            }
            return;
        }
        if proto != 6 || b.len() < ihl + 20 {
            return;
        }
        let flags = b[ihl + 13];
        let payload = slice(b, ihl + usize::from(b[ihl + 12] >> 4) * 4, b.len());
        if flags & 0x02 != 0 && flags & 0x10 == 0 {
            if !self.seen.contains(&flow) {
                // a SYN sent again waits from its latest, in its first's place
                let order = self.pending.get(&flow).map_or(self.count, |c| c.order);
                let c = new("tcp", order);
                self.count += 1;
                self.pending.insert(flow, c);
            }
            return;
        }
        let host = server_name(payload);
        let mut c = match self.pending.remove(&flow) {
            Some(c) => c,
            None if self.seen.contains(&flow) => return,
            None => new("tcp", self.count),
        };
        if let Some(host) = host {
            c.host = Some((host, "tls"));
        }
        self.sent(flow, c, out);
    }

    /// The connections that have waited long enough at `now`, in the order
    /// they came.
    fn flush(&mut self, now: f64, out: &mut Vec<BytesMut>) {
        let mut due: Vec<(u64, Flow)> = self
            .pending
            .iter()
            .filter(|(_, c)| now - c.at >= WAIT)
            .map(|(flow, c)| (c.order, flow.clone()))
            .collect();
        due.sort();
        for (_, flow) in due {
            if let Some(c) = self.pending.remove(&flow) {
                self.sent(flow, c, out);
            }
        }
    }

    /// A flow's connection, written once: a SYN sent again, or a hello that
    /// comes after its SYN went out, is the same connection.
    fn sent(&mut self, flow: Flow, mut c: Connection, out: &mut Vec<BytesMut>) {
        self.count += 1;
        self.seen.put(flow, ());
        if c.host.is_none() {
            c.host = self.names.peek(&c.dst).map(|name| (name.clone(), "dns"));
        }
        let mut net = c.who;
        net.insert("dst".into(), json!(c.dst));
        net.insert("port".into(), json!(c.port));
        net.insert("proto".into(), json!(c.proto));
        if let Some((host, named_by)) = c.host {
            net.insert("host".into(), json!(host));
            net.insert("named_by".into(), json!(named_by));
        }
        let mut line = BytesMut::from(json!({"time": c.time, "net": net}).to_string().as_bytes());
        line.extend_from_slice(b"\n");
        out.push(line);
    }

    /// Who sent a packet, from tcpdump's tags: proc and pid, eproc and epid.
    fn tagged(&self, tags: &str) -> Map<String, Value> {
        let mut who = Map::new();
        let mut tag = |kind: &str, name: &str, pid: &str| {
            if let Ok(pid) = pid.parse::<u64>() {
                who.insert(kind.to_string(), json!(name));
                who.insert(
                    if kind == "proc" { "pid" } else { "epid" }.to_string(),
                    json!(pid),
                );
            }
        };
        if let Some(m) = self.tags.captures(tags) {
            tag("proc", &m[1], &m[2]);
            if let (Some(name), Some(pid)) = (m.get(3), m.get(4)) {
                tag("eproc", name.as_str(), pid.as_str());
            }
        } else {
            for m in self.tag.captures_iter(tags) {
                tag(&m[1], &m[2], &m[3]);
            }
        }
        who
    }
}

/// tcpdump's time, seconds and a fraction: as a number, and as a record's
/// time, to the nanosecond.
fn when(t: &str) -> Option<(f64, String)> {
    let (seconds, fraction) = t.split_once('.')?;
    let day = DateTime::from_timestamp(seconds.parse().ok()?, 0)?;
    let nanos: String = fraction
        .chars()
        .chain("000000000".chars())
        .take(9)
        .collect();
    Some((
        t.parse().ok()?,
        format!("{}.{nanos}Z", day.format("%Y-%m-%dT%H:%M:%S")),
    ))
}

/// `b[from..to]`, as much of it as there is.
fn slice(b: &[u8], from: usize, to: usize) -> &[u8] {
    let to = to.min(b.len());
    &b[from.min(to)..to]
}

/// The `len` bytes at `at` as a number, as many of them as there are.
fn int(b: &[u8], at: usize, len: usize) -> usize {
    slice(b, at, at.saturating_add(len))
        .iter()
        .fold(0, |n, byte| n << 8 | usize::from(*byte))
}

/// A name's bytes as text; one that is not ASCII is shown as unreadable.
fn text(b: &[u8]) -> String {
    b.iter()
        .map(|byte| {
            if byte.is_ascii() {
                char::from(*byte)
            } else {
                char::REPLACEMENT_CHARACTER
            }
        })
        .collect()
}

/// An address as it is written: four bytes dotted, sixteen as eight groups.
fn addr(b: &[u8]) -> String {
    if b.len() == 4 {
        return b.iter().map(u8::to_string).collect::<Vec<_>>().join(".");
    }
    (0..16)
        .step_by(2)
        .map(|i| format!("{:x}", int(b, i, 2)))
        .collect::<Vec<_>>()
        .join(":")
}

/// A DNS name at `q`, following compression: the name, and where it ends.
fn name_at(b: &[u8], mut q: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    while q < b.len() && jumps < 20 {
        let n = usize::from(b[q]);
        if n == 0 {
            q += 1;
            break;
        }
        if n & 0xC0 == 0xC0 {
            if q + 1 >= b.len() {
                // a pointer cut off by the packet's end
                q = b.len();
                break;
            }
            end.get_or_insert(q + 2);
            q = (n & 0x3F) << 8 | usize::from(b[q + 1]);
            jumps += 1;
            continue;
        }
        labels.push(text(slice(b, q + 1, q + 1 + n)));
        q += 1 + n;
    }
    (labels.join("."), end.unwrap_or(q))
}

/// A DNS response's question name and the addresses it answered with.
fn dns_answers(b: &[u8]) -> (Option<String>, Vec<String>) {
    if b.len() < 12 {
        return (None, Vec::new());
    }
    let (questions, answers) = (int(b, 4, 2), int(b, 6, 2));
    let mut q = 12;
    let mut asked = None;
    for _ in 0..questions {
        let (name, end) = name_at(b, q);
        asked = Some(name);
        q = end + 4;
    }
    let mut ips = Vec::new();
    for _ in 0..answers {
        q = name_at(b, q).1;
        if q + 10 > b.len() {
            break;
        }
        let (kind, len) = (int(b, q, 2), int(b, q + 8, 2));
        let data = slice(b, q + 10, q + 10 + len);
        if (kind == 1 && data.len() == 4) || (kind == 28 && data.len() == 16) {
            ips.push(addr(data));
        }
        q += 10 + len;
    }
    (asked, ips)
}

/// A ClientHello's server name, from as much of it as one segment holds:
/// one with a post-quantum key share spans two, and the name may be in the
/// second.
fn server_name(p: &[u8]) -> Option<String> {
    if p.len() < 44 || p[0] != 0x16 || p[5] != 1 {
        return None;
    }
    // past the record's and the handshake's headers, the version and the random
    let mut q = 5 + 4 + 2 + 32;
    q += 1 + usize::from(p[q]); // the session id
    q += 2 + int(p, q, 2); // the cipher suites
    if q >= p.len() {
        return None;
    }
    q += 1 + usize::from(p[q]); // the compression methods
    let end = (q + 2 + int(p, q, 2)).min(p.len());
    q += 2;
    while q + 4 <= end {
        let (kind, len) = (int(p, q, 2), int(p, q + 2, 2));
        if kind == 0 && q + 9 <= p.len() {
            let name = text(slice(p, q + 9, q + 9 + int(p, q + 7, 2)));
            return (!name.is_empty()).then_some(name);
        }
        q += 4 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: [u8; 4] = [10, 0, 0, 2];
    const EVIL: [u8; 4] = [203, 0, 113, 5];
    const CDN: [u8; 4] = [198, 51, 100, 7];

    /// A packet as `tcpdump -k NP -n -tt -X` prints it.
    fn dump(t: &str, tags: &str, packet: &[u8]) -> Vec<String> {
        let mut lines = vec![format!(
            "{t} ({tags}) IP 10.0.0.2.50000 > 203.0.113.5.443: ..."
        )];
        for (row, bytes) in packet.chunks(16).enumerate() {
            let groups: Vec<String> = bytes.chunks(2).map(hex::encode).collect();
            lines.push(format!(
                "\t0x{:04x}:  {}  ................",
                row * 16,
                groups.join(" ")
            ));
        }
        lines
    }

    fn be(n: usize) -> [u8; 2] {
        (n as u16).to_be_bytes()
    }

    fn ip4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0x45, 0];
        b.extend(be(20 + payload.len()));
        b.extend([0, 0, 0, 0, 64, proto, 0, 0]);
        b.extend(src);
        b.extend(dst);
        b.extend(payload);
        b
    }

    fn tcp(sport: usize, dport: usize, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(be(sport));
        b.extend(be(dport));
        b.extend([
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            5 << 4,
            flags,
            0xff,
            0xff,
            0,
            0,
            0,
            0,
        ]);
        b.extend(payload);
        b
    }

    fn udp(sport: usize, dport: usize, payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(be(sport));
        b.extend(be(dport));
        b.extend(be(8 + payload.len()));
        b.extend([0, 0]);
        b.extend(payload);
        b
    }

    /// A ClientHello naming `host`, after `before` bytes of another extension.
    fn hello(host: &str, before: usize) -> Vec<u8> {
        let mut extensions = Vec::new();
        if before > 0 {
            extensions.extend([0, 0x15]);
            extensions.extend(be(before));
            extensions.extend(vec![0; before]);
        }
        extensions.extend([0, 0]);
        extensions.extend(be(host.len() + 5));
        extensions.extend(be(host.len() + 3));
        extensions.push(0);
        extensions.extend(be(host.len()));
        extensions.extend(host.bytes());
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0]);
        body.extend(be(extensions.len()));
        body.extend(extensions);
        let mut handshake = vec![1, 0];
        handshake.extend(be(body.len()));
        handshake.extend(body);
        let mut record = vec![0x16, 3, 1];
        record.extend(be(handshake.len()));
        record.extend(handshake);
        record
    }

    fn dns(asked: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut b = vec![0, 7, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for label in asked.split('.') {
            b.push(label.len() as u8);
            b.extend(label.bytes());
        }
        b.extend([0, 0, 1, 0, 1]);
        b.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        b.extend(ip);
        b
    }

    /// The `net` of each connection the lines make, and each record's time.
    fn run(lines: &[Vec<String>]) -> Vec<Value> {
        let mut connections = Connections::new();
        let mut out = Vec::new();
        for line in lines.iter().flatten() {
            connections.line(line, &mut out);
        }
        connections.done(&mut out);
        out.iter()
            .map(|line| {
                assert!(line.ends_with(b"\n"), "a line ends");
                serde_json::from_slice(line).unwrap()
            })
            .collect()
    }

    #[test]
    fn a_connection_is_named_by_its_hello() {
        let rows = run(&[
            dump(
                "1762735140.000001",
                "proc curl:4242",
                &ip4(6, ME, EVIL, &tcp(50000, 443, 0x02, &[])),
            ),
            dump(
                "1762735140.020000",
                "proc curl:4242",
                &ip4(
                    6,
                    ME,
                    EVIL,
                    &tcp(50000, 443, 0x18, &hello("evil.example", 0)),
                ),
            ),
        ]);
        assert_eq!(
            rows,
            [json!({"time": "2025-11-10T00:39:00.000001000Z", "net": {
                "proc": "curl", "pid": 4242, "dst": "203.0.113.5", "port": 443,
                "proto": "tcp", "host": "evil.example", "named_by": "tls",
            }})]
        );
    }

    #[test]
    fn a_name_past_the_first_segment_comes_from_dns() {
        let chrome = "proc Google Chrome Helper:700, eproc Google Chrome:690";
        let long = hello("cdn.example", 2000);
        let rows = run(&[
            dump(
                "1762735140.000000",
                "proc mDNSResponder:90",
                &ip4(
                    17,
                    [9, 9, 9, 9],
                    ME,
                    &udp(53, 6000, &dns("cdn.example", CDN)),
                ),
            ),
            dump(
                "1762735140.100000",
                chrome,
                &ip4(6, ME, CDN, &tcp(50001, 443, 0x02, &[])),
            ),
            dump(
                "1762735140.110000",
                chrome,
                &ip4(6, ME, CDN, &tcp(50001, 443, 0x18, &long[..1400])),
            ),
        ]);
        assert_eq!(rows.len(), 1);
        let net = &rows[0]["net"];
        assert_eq!(
            (&net["host"], &net["named_by"]),
            (&json!("cdn.example"), &json!("dns"))
        );
        assert_eq!(
            (&net["proc"], &net["pid"]),
            (&json!("Google Chrome Helper"), &json!(700))
        );
        assert_eq!(
            (&net["eproc"], &net["epid"]),
            (&json!("Google Chrome"), &json!(690))
        );
    }

    #[test]
    fn a_syn_without_a_hello_goes_out_after_a_second() {
        let mut connections = Connections::new();
        let mut out = Vec::new();
        let lines = [
            dump(
                "1762735140.000000",
                "proc ssh:5",
                &ip4(6, ME, EVIL, &tcp(50002, 22, 0x02, &[])),
            ),
            dump(
                "1762735142.000000",
                "proc ssh:5",
                &ip4(6, ME, EVIL, &tcp(50003, 22, 0x02, &[])),
            ),
            dump(
                "1762735142.100000",
                "proc ssh:5",
                &ip4(6, ME, EVIL, &tcp(50004, 22, 0x02, &[])),
            ),
        ];
        for line in lines.iter().flatten() {
            connections.line(line, &mut out);
        }
        // the first went out when the second was read, two seconds on, and
        // the others wait
        assert_eq!(out.len(), 1);
        let first: Value = serde_json::from_slice(&out[0]).unwrap();
        assert_eq!(first["net"]["port"], json!(22));
        assert_eq!(first["net"].get("host"), None);
        connections.done(&mut out);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn quic_is_one_connection_a_flow() {
        let mut initial = vec![0xc3];
        initial.extend([0; 40]);
        let initial = ip4(17, ME, CDN, &udp(50004, 443, &initial));
        let rows = run(&[
            dump("1762735140.0", "proc Google Chrome:690", &initial),
            dump("1762735140.1", "proc Google Chrome:690", &initial),
        ]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["net"]["proto"], json!("quic"));
    }

    #[test]
    fn a_syn_sent_again_is_the_same_connection() {
        let syn = ip4(6, ME, EVIL, &tcp(50005, 443, 0x02, &[]));
        let rows = run(&[
            dump("1762735140.0", "proc curl:4242", &syn),
            dump("1762735142.0", "proc curl:4242", &syn),
            dump(
                "1762735142.1",
                "proc curl:4242",
                &ip4(
                    6,
                    ME,
                    EVIL,
                    &tcp(50005, 443, 0x18, &hello("evil.example", 0)),
                ),
            ),
        ]);
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn a_pid_is_the_number_that_ends_its_tag() {
        let syn = ip4(6, ME, EVIL, &tcp(50006, 22, 0x02, &[]));
        for (tags, want) in [
            (
                "proc x:690, y:4242",
                json!({"proc": "x:690, y", "pid": 4242}),
            ),
            (
                "proc a:69) IP b:4242",
                json!({"proc": "a:69) IP b", "pid": 4242}),
            ),
            (
                "proc nsurlsessiond:300, eproc y:1, z:4242",
                json!({"proc": "nsurlsessiond", "pid": 300, "eproc": "y:1, z", "epid": 4242}),
            ),
        ] {
            let rows = run(&[dump("1762735140.0", tags, &syn)]);
            for (key, value) in want.as_object().unwrap() {
                assert_eq!(&rows[0]["net"][key], value, "{tags}");
            }
        }
    }

    #[test]
    fn a_packet_it_cannot_read_is_passed_over() {
        // a hello's first 43 bytes
        let mut short = vec![0x16, 3, 1, 0, 0x26, 1];
        short.extend([0; 37]);
        // a name's pointer, its second byte gone
        let mut cut = dns("cdn.example", CDN)[..12].to_vec();
        cut.extend(b"\x03cdn\xc0");
        let rows = run(&[
            dump(
                "1762735140.0",
                "proc x:7",
                &ip4(6, ME, EVIL, &tcp(50007, 443, 0x18, &short)),
            ),
            dump(
                "1762735140.1",
                "proc x:7",
                &ip4(17, [9, 9, 9, 9], ME, &udp(53, 6001, &cut)),
            ),
            // half a byte
            vec![
                "1762735140.2 (proc x:7) IP 10.0.0.2.5 > 203.0.113.5.443: ...".to_string(),
                "\t0x0000:  450  ...".to_string(),
            ],
            dump(
                "1762735140.3",
                "proc curl:4242",
                &ip4(6, ME, EVIL, &tcp(50008, 22, 0x02, &[])),
            ),
        ]);
        assert_eq!(rows.last().unwrap()["net"]["pid"], json!(4242));
    }

    #[test]
    fn an_address_is_written_as_net_py_wrote_it() {
        assert_eq!(addr(&[203, 0, 113, 5]), "203.0.113.5");
        let mut six = [0u8; 16];
        six[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        six[15] = 1;
        assert_eq!(addr(&six), "2001:db8:0:0:0:0:0:1");
    }
}
