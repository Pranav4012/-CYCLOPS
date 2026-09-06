"""
Real PCAP I/O — turn CYCLOPS from an in-memory simulation into a tool that
ingests actual capture files (the artifact a passive tap / data diode produces).

`read_pcap(path)` parses genuine link-layer bytes — Ethernet / raw-IP / Linux
cooked, IPv4, TCP/UDP, the TCP timestamp option, DNS questions and partial-HTTP
requests — into `halfsight.types.Packet`. Pure standard library, so it runs
anywhere; if `dpkt` or `scapy` is installed it is used as a more permissive
backend for exotic captures (pcapng, unusual link types).

`write_pcap(path, packets)` emits a real, Wireshark-openable classic pcap from
`Packet` objects, so labeled lab traffic can be round-tripped through the exact
ingestion path a production deployment would use.
"""
from __future__ import annotations

import struct
from typing import Iterator, List, Optional

from .types import (Packet, FLAG_FIN, FLAG_SYN, FLAG_RST, FLAG_PSH, FLAG_ACK)

# ---- link-layer / protocol constants --------------------------------------
DLT_EN10MB = 1      # Ethernet
DLT_RAW = 101       # raw IPv4/IPv6
DLT_LINUX_SLL = 113 # Linux cooked
PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D

QTYPE_NUM = {"A": 1, "NS": 2, "CNAME": 5, "NULL": 10, "MX": 15, "TXT": 16, "AAAA": 28}
QTYPE_STR = {v: k for k, v in QTYPE_NUM.items()}
HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE")


# =============================================================================
# DNS helpers (question section only — no compression pointers in questions)
# =============================================================================
def _encode_dns_query(qname: str, qtype: str) -> bytes:
    hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)  # RD set, 1 question
    q = b"".join(bytes([len(l)]) + l.encode() for l in qname.strip(".").split(".") if l)
    q += b"\x00"
    q += struct.pack("!HH", QTYPE_NUM.get(qtype.upper(), 1), 1)   # qtype, IN
    return hdr + q


def _parse_dns_question(payload: bytes):
    if len(payload) < 12:
        return None, None
    qd = struct.unpack("!H", payload[4:6])[0]
    if qd < 1:
        return None, None
    i = 12
    labels = []
    while i < len(payload):
        ln = payload[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0:          # a pointer should not appear in a question
            return None, None
        labels.append(payload[i + 1:i + 1 + ln].decode("latin-1", "replace"))
        i += 1 + ln
    if i + 4 > len(payload):
        return ".".join(labels) or None, "A"
    qtype = struct.unpack("!H", payload[i:i + 2])[0]
    return ".".join(labels) or None, QTYPE_STR.get(qtype, str(qtype))


# =============================================================================
# Writer — real classic pcap from Packet objects
# =============================================================================
def _ip_checksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        s += (hdr[i] << 8) + hdr[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return (~s) & 0xFFFF


def _ip_to_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def _build_l4_payload(p: Packet) -> bytes:
    if p.proto == "UDP" and (p.dst_port == 53 or p.src_port == 53) and p.dns_qname:
        return _encode_dns_query(p.dns_qname, p.dns_qtype or "A")
    if p.http_partial:                       # a real, incomplete HTTP request
        return b"GET / HTTP/1.1\r\nHost: x\r\nX-a: " + b"a" * max(0, p.length - 26)
    n = max(0, p.length)
    return b"\x00" * min(n, 1400)


def _build_tcp(p: Packet, payload: bytes) -> bytes:
    opts = b""
    if p.tcp_tsval is not None:
        opts = b"\x01\x01" + struct.pack("!BBII", 8, 10, p.tcp_tsval & 0xFFFFFFFF,
                                         (p.tcp_tsecr or 0) & 0xFFFFFFFF)
    while len(opts) % 4:
        opts += b"\x00"
    offset = (20 + len(opts)) // 4
    seq = (p.tcp_seq or 0) & 0xFFFFFFFF
    ack = (p.tcp_ack or 0) & 0xFFFFFFFF
    hdr = struct.pack("!HHIIBBHHH", p.src_port, p.dst_port, seq, ack,
                      (offset << 4), p.tcp_flags & 0xFF, 65535, 0, 0)
    return hdr + opts + payload


def _build_udp(p: Packet, payload: bytes) -> bytes:
    return struct.pack("!HHHH", p.src_port, p.dst_port, 8 + len(payload), 0) + payload


def _build_frame(p: Packet) -> bytes:
    payload = _build_l4_payload(p)
    if p.proto == "TCP":
        l4 = _build_tcp(p, payload); proto = 6
    elif p.proto == "UDP":
        l4 = _build_udp(p, payload); proto = 17
    else:
        l4 = payload; proto = 0
    total = 20 + len(l4)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0x4000, 64, proto, 0,
                     _ip_to_bytes(p.src_ip), _ip_to_bytes(p.dst_ip))
    ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip + l4


def write_pcap(path: str, packets: List[Packet]) -> int:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, 65535, DLT_EN10MB))
        for p in packets:
            frame = _build_frame(p)
            ts = max(0.0, p.ts)
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1_000_000),
                                len(frame), len(frame)))
            f.write(frame)
    return len(packets)


# =============================================================================
# Reader — pure python, with optional dpkt/scapy backend
# =============================================================================
def _parse_ipv4(data: bytes, ts: float) -> Optional[Packet]:
    if len(data) < 20 or (data[0] >> 4) != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    src = ".".join(str(b) for b in data[12:16])
    dst = ".".join(str(b) for b in data[16:20])
    l4 = data[ihl:]
    if proto == 6 and len(l4) >= 20:           # TCP
        sport, dport = struct.unpack("!HH", l4[0:4])
        seq, ack = struct.unpack("!II", l4[4:12])
        off = (l4[12] >> 4) * 4
        flags = l4[13]
        tsval = tsecr = None
        opts = l4[20:off]
        i = 0
        while i < len(opts):
            k = opts[i]
            if k == 0:
                break
            if k == 1:
                i += 1; continue
            if i + 1 >= len(opts):
                break
            ln = opts[i + 1]
            if k == 8 and ln == 10 and i + 10 <= len(opts):
                tsval, tsecr = struct.unpack("!II", opts[i + 2:i + 10])
            i += max(2, ln)
        payload = l4[off:]
        http_partial = (dport in (80, 8080) and payload[:4] in HTTP_METHODS
                        and b"\r\n\r\n" not in payload)
        return Packet(ts, src, dst, sport, dport, "TCP", len(payload), tcp_flags=flags,
                      tcp_tsval=tsval, tcp_tsecr=tsecr, tcp_seq=seq, tcp_ack=ack,
                      http_partial=http_partial)
    if proto == 17 and len(l4) >= 8:           # UDP
        sport, dport = struct.unpack("!HH", l4[0:4])
        payload = l4[8:]
        qn = qt = None
        if dport == 53 or sport == 53:
            qn, qt = _parse_dns_question(payload)
        return Packet(ts, src, dst, sport, dport, "UDP", len(payload),
                      dns_qname=qn, dns_qtype=qt)
    return None


def _link_to_ipv4(linktype: int, frame: bytes):
    if linktype == DLT_EN10MB:
        if len(frame) < 14:
            return None
        etype = struct.unpack("!H", frame[12:14])[0]
        off = 14
        while etype == 0x8100 and len(frame) >= off + 4:      # VLAN tag(s)
            etype = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
        return frame[off:] if etype == 0x0800 else None
    if linktype == DLT_RAW:
        return frame
    if linktype == DLT_LINUX_SLL:
        if len(frame) < 16:
            return None
        return frame[16:] if struct.unpack("!H", frame[14:16])[0] == 0x0800 else None
    return None


def _read_pcap_pure(path: str) -> Iterator[Packet]:
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[0:4])[0]
        if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian = "<"; nano = magic == PCAP_MAGIC_NS
        elif struct.unpack(">I", gh[0:4])[0] in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            endian = ">"; nano = struct.unpack(">I", gh[0:4])[0] == PCAP_MAGIC_NS
        else:
            raise ValueError("not a classic pcap file (pcapng? install scapy/dpkt)")
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        rh = struct.Struct(endian + "IIII")
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            ts_sec, ts_frac, incl, _orig = rh.unpack(h)
            frame = f.read(incl)
            if len(frame) < incl:
                break
            ts = ts_sec + (ts_frac / 1e9 if nano else ts_frac / 1e6)
            ipd = _link_to_ipv4(linktype, frame)
            if ipd:
                pkt = _parse_ipv4(ipd, ts)
                if pkt:
                    yield pkt


def _read_pcap_dpkt(path: str) -> Iterator[Packet]:
    import dpkt
    with open(path, "rb") as f:
        try:
            reader = dpkt.pcapng.Reader(f) if path.endswith((".pcapng", ".ntar")) else dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0); reader = dpkt.pcap.Reader(f)
        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
            except Exception:
                continue
            if not isinstance(ip, dpkt.ip.IP):
                continue
            data = bytes(ip.pack())
            pkt = _parse_ipv4(data, ts)
            if pkt:
                yield pkt


def read_pcap(path: str, backend: str = "auto") -> Iterator[Packet]:
    """Yield Packet objects from a real capture. backend: 'auto'|'pure'|'dpkt'."""
    if backend in ("auto", "dpkt"):
        try:
            import dpkt  # noqa: F401
            yield from _read_pcap_dpkt(path)
            return
        except ImportError:
            if backend == "dpkt":
                raise
    yield from _read_pcap_pure(path)
