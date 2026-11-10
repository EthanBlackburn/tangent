"""net.py: tcpdump's view of new connections, one JSON line each, for packs/macos.

Endpoint Security reports no network, so the pack reads it from tcpdump, which
on macOS tags each packet with the process that sent it (`-k NP` on the
`pktap` interface). The filter takes only what starts a connection: TCP SYNs,
TLS ClientHellos (whose server name says the host), QUIC's Initial packets,
and DNS answers (which name an address the hello did not). This script joins
them into one line per connection:

  {"time": "...Z", "net": {"proc": "curl", "pid": 4242, "proto": "tcp",
   "dst": "203.0.113.5", "port": 443, "host": "evil.example", "named_by": "tls"}}

with `eproc`/`epid` when the packet was sent for another process (a system
daemon's download for an app). Nothing past a hello is read: no payload, no
URL, no bytes sent.

  sudo tcpdump -i pktap,all -k NP -n -l -tt -X "$(python3 net.py --filter)" \\
    | python3 net.py | nc -U net.sock

Standard library only, so it runs on the Python macOS ships.
"""

import json
import re
import sys
from datetime import datetime, timezone

# What starts a connection, for IPv4 and for IPv6 without extension headers
# (libpcap's tcp[] and udp[] read IPv4 only).
FILTER = " or ".join([
    "(tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0)",
    "(ip6 and ip6[6] = 6 and ip6[53] & 0x12 = 0x02)",
    "(tcp[((tcp[12] & 0xf0) >> 2)] = 0x16 and tcp[((tcp[12] & 0xf0) >> 2) + 5] = 0x01)",
    "(ip6 and ip6[6] = 6 and ip6[40 + ((ip6[52] & 0xf0) >> 2)] = 0x16"
    " and ip6[40 + ((ip6[52] & 0xf0) >> 2) + 5] = 0x01)",
    "(udp dst port 443 and udp[8] & 0xf0 = 0xc0)",
    "(ip6 and ip6[6] = 17 and ip6[42:2] = 443 and ip6[48] & 0xf0 = 0xc0)",
    "udp src port 53",
])

# A SYN waits this long (packet time) for its hello before it goes out named
# by DNS, or not at all.
WAIT = 1.0
# Flows and names remembered, the oldest dropped past these.
FLOWS = 20000
NAMES = 50000

HEAD = re.compile(r"^(\d+\.\d+) \((.*?)\) IP6? ")
HEX = re.compile(r"\s+0x[0-9a-f]+:")
TAG = re.compile(r"(e?proc) (.+?):(\d+)(?=, |$)")


def iso(t):
    s, _, frac = t.partition(".")
    d = datetime.fromtimestamp(int(s), tz=timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + (frac + "000000000")[:9] + "Z"


def addr(b):
    if len(b) == 4:
        return ".".join(str(x) for x in b)
    return ":".join(f"{int.from_bytes(b[i:i + 2], 'big'):x}" for i in range(0, 16, 2))


def name_at(b, q, depth=0):
    """A DNS name at `q`, following compression; the name and where it ends."""
    labels = []
    end = None
    while q < len(b) and depth < 20:
        n = b[q]
        if n == 0:
            q += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = q + 2
            q = ((n & 0x3F) << 8) | b[q + 1]
            depth += 1
            continue
        labels.append(b[q + 1:q + 1 + n].decode("ascii", "replace"))
        q += 1 + n
    return ".".join(labels), (end if end is not None else q)


def dns_answers(b):
    """A DNS response's question name and the addresses it answered with."""
    if len(b) < 12:
        return None, []
    qd, an = int.from_bytes(b[4:6], "big"), int.from_bytes(b[6:8], "big")
    q = 12
    qname = None
    for _ in range(qd):
        qname, q = name_at(b, q)
        q += 4
    ips = []
    for _ in range(an):
        _, q = name_at(b, q)
        if q + 10 > len(b):
            break
        typ = int.from_bytes(b[q:q + 2], "big")
        rdlen = int.from_bytes(b[q + 8:q + 10], "big")
        rd = b[q + 10:q + 10 + rdlen]
        if typ == 1 and rdlen == 4 or typ == 28 and rdlen == 16:
            ips.append(addr(rd))
        q += 10 + rdlen
    return qname, ips


def server_name(p):
    """A ClientHello's server name, from as much of it as one segment holds:
    one with a post-quantum key share spans two, and the name may be in the
    second."""
    if len(p) < 43 or p[0] != 0x16 or p[5] != 1:
        return None
    q = 5 + 4 + 2 + 32
    q += 1 + p[q]
    q += 2 + int.from_bytes(p[q:q + 2], "big")
    if q >= len(p):
        return None
    q += 1 + p[q]
    end = min(q + 2 + int.from_bytes(p[q:q + 2], "big"), len(p))
    q += 2
    while q + 4 <= end:
        et = int.from_bytes(p[q:q + 2], "big")
        el = int.from_bytes(p[q + 2:q + 4], "big")
        if et == 0 and q + 9 <= len(p):
            n = int.from_bytes(p[q + 7:q + 9], "big")
            return p[q + 9:q + 9 + n].decode("ascii", "replace") or None
        q += 4 + el
    return None


class Joiner:
    def __init__(self, out):
        self.out = out
        self.pending = {}  # flow -> connection waiting for its hello
        self.seen = {}  # flows already written
        self.names = {}  # address -> the name DNS answered it for

    def write(self, c):
        if not c.get("host") and c["dst"] in self.names:
            c["host"], c["named_by"] = self.names[c["dst"]], "dns"
        self.out.write(json.dumps({"time": iso(c.pop("t")), "net": c}) + "\n")
        self.out.flush()

    def remember(self, d, k, v, limit):
        d[k] = v
        if len(d) > limit:
            del d[next(iter(d))]

    def flush(self, now):
        for f in [f for f, c in self.pending.items() if now - float(c["t"]) >= WAIT]:
            self.write(self.pending.pop(f))

    def packet(self, t, tags, b):
        self.flush(float(t))
        v = b[0] >> 4 if b else 0
        if v == 4:
            ihl, proto, src, dst = (b[0] & 15) * 4, b[9], b[12:16], b[16:20]
        elif v == 6:
            ihl, proto, src, dst = 40, b[6], b[8:24], b[24:40]
        else:
            return
        if len(b) < ihl + 8:
            return
        sport = int.from_bytes(b[ihl:ihl + 2], "big")
        dport = int.from_bytes(b[ihl + 2:ihl + 4], "big")
        flow = (addr(src), sport, addr(dst), dport)
        who = {}
        for kind, name, pid in TAG.findall(tags):
            who[kind] = name
            who["pid" if kind == "proc" else "epid"] = int(pid)
        conn = {"t": t, **who, "dst": addr(dst), "port": dport}
        if proto == 17:
            if sport == 53:
                qname, ips = dns_answers(b[ihl + 8:])
                for ip in ips:
                    if qname:
                        self.remember(self.names, ip, qname, NAMES)
            elif flow not in self.seen:
                self.remember(self.seen, flow, True, FLOWS)
                self.write({**conn, "proto": "quic"})
            return
        if proto != 6 or len(b) < ihl + 20:
            return
        flags = b[ihl + 13]
        payload = b[ihl + (b[ihl + 12] >> 4) * 4:]
        if flags & 0x02 and not flags & 0x10:
            if flow not in self.seen:
                self.pending[flow] = {**conn, "proto": "tcp"}
            return
        host = server_name(payload)
        c = self.pending.pop(flow, None)
        if c is None:
            if flow in self.seen:
                return
            c = {**conn, "proto": "tcp"}
        if host:
            c["host"], c["named_by"] = host, "tls"
        self.remember(self.seen, flow, True, FLOWS)
        self.write(c)

    def done(self):
        for c in list(self.pending.values()):
            self.write(c)
        self.pending.clear()


def run(lines, out):
    j = Joiner(out)
    cur = None
    for line in lines:
        m = HEAD.match(line)
        if m:
            if cur:
                j.packet(cur[0], cur[1], bytes.fromhex(cur[2]))
            cur = [m.group(1), m.group(2), ""]
        elif cur and HEX.match(line):
            cur[2] += "".join(line.split(":", 1)[1].strip().split("  ")[0].split())
    if cur:
        j.packet(cur[0], cur[1], bytes.fromhex(cur[2]))
    j.done()


if __name__ == "__main__":
    if sys.argv[1:] == ["--filter"]:
        print(FILTER)
    else:
        run(sys.stdin, sys.stdout)
