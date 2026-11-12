"""net.py on packets built here, in tcpdump -X's text: python3 -m unittest net_test"""

import io
import json
import struct
import unittest

import net


def dump(t, tags, pkt, text="IP 10.0.0.2.50000 > 203.0.113.5.443: ..."):
    """A packet as `tcpdump -k NP -n -tt -X` prints it."""
    lines = [f"{t} ({tags}) {text}"]
    for off in range(0, len(pkt), 16):
        chunk = pkt[off:off + 16].hex()
        groups = " ".join(chunk[i:i + 4] for i in range(0, len(chunk), 4))
        lines.append(f"\t0x{off:04x}:  {groups}  ................")
    return lines


def ip4(proto, src, dst, payload):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                       bytes(src), bytes(dst)) + payload


def tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def hello(host, before=0):
    """A ClientHello naming `host`, after `before` bytes of another extension."""
    name = host.encode()
    sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    pad = struct.pack("!HH", 0x0015, before) + b"\0" * before if before else b""
    exts = pad + sni
    body = b"\x03\x03" + b"\0" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def dns(qname, ip):
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\0"
    head = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(ip)
    return head + q + struct.pack("!HH", 1, 1) + ans


ME, EVIL, CDN = [10, 0, 0, 2], [203, 0, 113, 5], [198, 51, 100, 7]


def run(lines):
    out = io.StringIO()
    net.run(lines, out)
    return [json.loads(l) for l in out.getvalue().splitlines()]


class Net(unittest.TestCase):
    def test_a_connection_is_named_by_its_hello(self):
        rows = run(
            dump("1762735140.000001", "proc curl:4242", ip4(6, ME, EVIL, tcp(50000, 443, 0x02)))
            + dump("1762735140.020000", "proc curl:4242",
                   ip4(6, ME, EVIL, tcp(50000, 443, 0x18, hello("evil.example")))))
        self.assertEqual(len(rows), 1)
        n = rows[0]["net"]
        self.assertEqual((n["proc"], n["pid"], n["dst"], n["port"]), ("curl", 4242, "203.0.113.5", 443))
        self.assertEqual((n["host"], n["named_by"], n["proto"]), ("evil.example", "tls", "tcp"))
        self.assertEqual(rows[0]["time"], "2025-11-10T00:39:00.000001000Z")

    def test_a_name_past_the_first_segment_comes_from_dns(self):
        rows = run(
            dump("1762735140.000000", "proc mDNSResponder:90", ip4(17, [9, 9, 9, 9], ME, udp(53, 6000, dns("cdn.example", CDN))))
            + dump("1762735140.100000", "proc Google Chrome Helper:700, eproc Google Chrome:690",
                   ip4(6, ME, CDN, tcp(50001, 443, 0x02)))
            + dump("1762735140.110000", "proc Google Chrome Helper:700, eproc Google Chrome:690",
                   ip4(6, ME, CDN, tcp(50001, 443, 0x18, hello("cdn.example", before=2000)[:1400]))))
        n = rows[0]["net"]
        self.assertEqual((n["host"], n["named_by"]), ("cdn.example", "dns"))
        self.assertEqual((n["eproc"], n["epid"]), ("Google Chrome", 690))

    def test_a_syn_without_a_hello_goes_out_after_a_second(self):
        rows = run(
            dump("1762735140.000000", "proc ssh:5", ip4(6, ME, EVIL, tcp(50002, 22, 0x02)))
            + dump("1762735142.000000", "proc ssh:5", ip4(6, ME, EVIL, tcp(50003, 22, 0x02))))
        self.assertEqual([r["net"]["port"] for r in rows], [22, 22])
        self.assertNotIn("host", rows[0]["net"])

    def test_quic_is_one_connection_a_flow(self):
        initial = udp(50004, 443, b"\xc3" + b"\0" * 40)
        rows = run(dump("1762735140.0", "proc Google Chrome:690", ip4(17, ME, CDN, initial))
                   + dump("1762735140.1", "proc Google Chrome:690", ip4(17, ME, CDN, initial)))
        self.assertEqual([r["net"]["proto"] for r in rows], ["quic"])

    def test_a_syn_sent_again_is_the_same_connection(self):
        syn = ip4(6, ME, EVIL, tcp(50005, 443, 0x02))
        rows = run(dump("1762735140.0", "proc curl:4242", syn)
                   + dump("1762735142.0", "proc curl:4242", syn)
                   + dump("1762735142.1", "proc curl:4242",
                          ip4(6, ME, EVIL, tcp(50005, 443, 0x18, hello("evil.example")))))
        self.assertEqual(len(rows), 1)

    def test_a_pid_is_the_number_that_ends_its_tag(self):
        syn = ip4(6, ME, EVIL, tcp(50006, 22, 0x02))
        for tags, want in [
            ("proc x:690, y:4242", {"proc": "x:690, y", "pid": 4242}),
            ("proc a:69) IP b:4242", {"proc": "a:69) IP b", "pid": 4242}),
            ("proc nsurlsessiond:300, eproc y:1, z:4242", {"proc": "nsurlsessiond", "pid": 300, "eproc": "y:1, z", "epid": 4242}),
        ]:
            n = run(dump("1762735140.0", tags, syn))[0]["net"]
            self.assertEqual({k: n.get(k) for k in want}, want, tags)

    def test_a_packet_it_cannot_read_is_passed_over(self):
        short = b"\x16\x03\x01\x00\x26\x01" + b"\0" * 37          # a hello's first 43 bytes
        cut = dns("cdn.example", CDN)[:12] + b"\x03cdn\xc0"          # a name's pointer, its second byte gone
        rows = run(
            dump("1762735140.0", "proc x:7", ip4(6, ME, EVIL, tcp(50007, 443, 0x18, short)))
            + dump("1762735140.1", "proc x:7", ip4(17, [9, 9, 9, 9], ME, udp(53, 6001, cut)))
            + ["1762735140.2 (proc x:7) IP 10.0.0.2.5 > 203.0.113.5.443: ...", "\t0x0000:  450  ..."]   # half a byte
            + dump("1762735140.3", "proc curl:4242", ip4(6, ME, EVIL, tcp(50008, 22, 0x02))))
        self.assertEqual(rows[-1]["net"]["pid"], 4242)


if __name__ == "__main__":
    unittest.main()
