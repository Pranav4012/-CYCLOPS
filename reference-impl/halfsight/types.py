"""
Core data structures for one-directional (passive / data-diode) traffic.

Everything downstream assumes we only ever observe ONE direction of a link.
A ``UniFlow`` is therefore a *half-flow*: we may see client -> server OR
server -> client, but almost never both. This asymmetry is a first-class
part of the model rather than an inconvenience to be papered over.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
import math


@dataclass
class Packet:
    """A single passively observed packet (subset of fields a diode can copy)."""
    ts: float                 # capture timestamp (seconds, monotonic at the tap)
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str                # 'TCP' | 'UDP' | 'ICMP' | ...
    length: int               # L3 payload length in bytes
    tcp_flags: int = 0        # bitmask; see FLAG_* below
    tcp_tsval: Optional[int] = None   # TCP timestamp option TSval (RFC 7323)
    tcp_tsecr: Optional[int] = None   # TCP timestamp option TSecr
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    # Application metadata a passive parser can lift without a handshake:
    dns_qname: Optional[str] = None
    dns_qtype: Optional[str] = None
    sni: Optional[str] = None
    http_partial: bool = False   # saw partial/incomplete HTTP request line/headers


# TCP flag bits
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10


@dataclass
class UniFlow:
    """
    A unidirectional flow key + the observations we have for it.

    Deliberately stores only what a NetFlow/IPFIX exporter or a light packet
    parser can produce in one direction. The *return* direction is unknown and
    must be inferred (see halfflow.HalfFlowReconstructor).
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str

    start_ts: float = 0.0
    last_ts: float = 0.0
    packets: int = 0
    bytes: int = 0

    # flag counters (observed direction only)
    syn: int = 0
    synack: int = 0
    fin: int = 0
    rst: int = 0
    ack: int = 0
    psh: int = 0

    # timing series for spectral / periodicity analysis
    arrival_ts: List[float] = field(default_factory=list)
    payload_sizes: List[int] = field(default_factory=list)

    # TCP timestamp samples for passive RTT
    tsval_samples: List[tuple] = field(default_factory=list)   # (ts, tsval)
    tsecr_samples: List[tuple] = field(default_factory=list)   # (ts, tsecr)
    retransmits: int = 0

    # cumulative-ACK progression — GHOSTFLOW reconstructs the UNSEEN peer's byte
    # volume from these: each ACK is a receipt for bytes the peer sent back.
    ack_first: Optional[int] = None
    ack_last: Optional[int] = None
    ack_samples: int = 0

    # application observations
    dns_qnames: List[str] = field(default_factory=list)
    dns_qtypes: List[str] = field(default_factory=list)
    sni_names: List[str] = field(default_factory=list)
    http_partial_count: int = 0

    @property
    def key(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.proto}"

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.start_ts)

    @property
    def byte_rate(self) -> float:
        d = self.duration
        return self.bytes / d if d > 0 else 0.0

    @property
    def mean_pkt_size(self) -> float:
        return self.bytes / self.packets if self.packets else 0.0

    def update(self, p: Packet) -> None:
        if self.packets == 0:
            self.start_ts = p.ts
        self.last_ts = p.ts
        self.packets += 1
        self.bytes += p.length
        self.arrival_ts.append(p.ts)
        self.payload_sizes.append(p.length)

        if p.proto == "TCP":
            f = p.tcp_flags
            if f & FLAG_SYN and f & FLAG_ACK:
                self.synack += 1
            elif f & FLAG_SYN:
                self.syn += 1
            if f & FLAG_FIN:
                self.fin += 1
            if f & FLAG_RST:
                self.rst += 1
            if f & FLAG_ACK:
                self.ack += 1
            if f & FLAG_PSH:
                self.psh += 1
            if p.tcp_tsval is not None:
                self.tsval_samples.append((p.ts, p.tcp_tsval))
            if p.tcp_tsecr is not None and p.tcp_tsecr != 0:
                self.tsecr_samples.append((p.ts, p.tcp_tsecr))
            # track cumulative-ACK progression (monotone; guard against wrap/dupes)
            if p.tcp_ack is not None and (f & FLAG_ACK):
                if self.ack_first is None:
                    self.ack_first = p.tcp_ack
                if self.ack_last is None or p.tcp_ack >= self.ack_last:
                    self.ack_last = p.tcp_ack
                self.ack_samples += 1

        if p.http_partial:
            self.http_partial_count += 1
        if p.dns_qname:
            self.dns_qnames.append(p.dns_qname)
            self.dns_qtypes.append(p.dns_qtype or "A")
        if p.sni:
            self.sni_names.append(p.sni)


@dataclass
class Alert:
    """Labelled, scored, evidence-bearing intelligence — the pipeline's output."""
    ts: float
    detector: str
    threat: str                 # canonical threat class
    severity: str               # 'info' | 'low' | 'medium' | 'high' | 'critical'
    confidence: float           # calibrated [0,1]
    flow_key: str
    title: str
    evidence: dict = field(default_factory=dict)     # human + machine readable
    contributions: dict = field(default_factory=dict)  # feature -> attribution (explainability)

    def to_record(self) -> dict:
        return {
            "ts": round(self.ts, 6),
            "detector": self.detector,
            "threat": self.threat,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "flow_key": self.flow_key,
            "title": self.title,
            "evidence": self.evidence,
            "contributions": self.contributions,
        }


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of a string — reused by DGA/DNS detectors."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
