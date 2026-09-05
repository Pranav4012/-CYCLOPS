"""
Labeled, parameterised, one-directional traffic generators with ground truth.

Each attack generator returns ``(packets, gt)`` where ``gt`` names the threat
class and target so the harness can score precision/recall honestly. Benign
generators return ``(packets, None)`` and must NOT trip any detector — they are
the base-rate battle. All randomness is seeded per call for reproducibility.
"""
from __future__ import annotations

import random
import string
from typing import List, Tuple, Optional

from halfsight.types import Packet, FLAG_SYN, FLAG_ACK, FLAG_PSH, FLAG_FIN

B32 = string.ascii_lowercase + "234567"
REAL_DOMAINS = ["google.com", "cloudflare.com", "github.com", "wikipedia.org",
                "microsoft.com", "apple.com", "amazon.com", "office.com",
                "windowsupdate.com", "akamai.net", "fastly.net", "ubuntu.com"]


def _rng(seed): return random.Random(seed)


# --------------------------------------------------------------------------- #
# Benign background — the hard part: it must stay silent.
# --------------------------------------------------------------------------- #
def benign_background(t0: float, seed: int, n_hosts: int = 16) -> Tuple[List[Packet], None]:
    r = _rng(seed); pk = []
    servers = ["93.184.216.34", "140.82.121.4", "151.101.1.140", "13.107.42.14"]
    for i in range(n_hosts):
        host = f"10.0.{r.randint(0,4)}.{r.randint(2,250)}"
        t = t0 + r.uniform(0, 20)
        # a couple of real DNS lookups
        for _ in range(r.randint(1, 3)):
            pk.append(Packet(t + r.uniform(0, 5), host, "8.8.8.8", r.randint(1024, 65535), 53,
                             "UDP", 62, dns_qname=r.choice(REAL_DOMAINS), dns_qtype="A"))
        # a healthy, completing web session (coherent TCP timestamps + ACK growth)
        srv = r.choice(servers); sp = r.randint(1024, 65535); ack = r.randint(1000, 9000)
        for k in range(r.randint(8, 16)):
            ack += r.randint(1000, 2800)
            pk.append(Packet(t + k * 0.05, host, srv, sp, 443, "TCP", r.randint(400, 1400),
                             tcp_flags=FLAG_ACK | FLAG_PSH, tcp_ack=ack,
                             tcp_tsval=100000 + int((t + k * 0.05) * 1000)))
    return pk, None


def benign_cdn(t0: float, seed: int) -> Tuple[List[Packet], None]:
    """A busy but LEGIT CDN client: many hostnames under one 2LD, but STRUCTURED
    (short, low-entropy, reused) — must not read as a DNS tunnel."""
    r = _rng(seed); pk = []
    host = f"10.0.7.{r.randint(2,250)}"
    names = [f"{p}-{r.randint(0,40)}" for p in ("img", "static", "cache", "edge", "cdn", "assets")]
    for i in range(45):
        lbl = r.choice(names)   # reused, structured labels
        pk.append(Packet(t0 + i * 0.3, host, "8.8.8.8", 40000 + i, 53, "UDP", 64,
                         dns_qname=f"{lbl}.akamai-cdn.net", dns_qtype="A"))
    return pk, None


def benign_periodic(t0: float, seed: int) -> Tuple[List[Packet], None]:
    """A legit periodic service (NTP every ~64s) — periodic by design, must not
    read as a C2 beacon (handled by the known-good-service guard)."""
    r = _rng(seed); pk = []
    host = f"10.0.8.{r.randint(2,250)}"; ntp = "132.163.96.1"
    base = t0
    for i in range(14):
        pk.append(Packet(base, host, ntp, 123, 123, "UDP", 76))
        base += 64.0 + r.uniform(-1, 1)
    return pk, None


def flash_crowd(t0: float, victim: str, seed: int, n_clients: int = 120) -> Tuple[List[Packet], None]:
    """A legit traffic spike: many REAL clients that complete handshakes and ACK.
    Must be told apart from a spoofed SYN flood (PULSE liveness) — so NOT flagged."""
    r = _rng(seed); pk = []
    for i in range(n_clients):
        src = f"203.0.{r.randint(0,255)}.{r.randint(1,254)}"
        t = t0 + r.uniform(0, 8); sp = r.randint(1024, 65535); ack = r.randint(1000, 5000)
        # completing connections with coherent timestamps + growing ACKs
        for k in range(r.randint(4, 8)):
            ack += r.randint(800, 1600)
            pk.append(Packet(t + k * 0.03, src, victim, sp, 443, "TCP", r.randint(200, 900),
                             tcp_flags=(FLAG_SYN if k == 0 else FLAG_ACK | FLAG_PSH),
                             tcp_ack=(0 if k == 0 else ack),
                             tcp_tsval=500000 + int((t + k * 0.03) * 1000)))
    return pk, None


# --------------------------------------------------------------------------- #
# Attacks
# --------------------------------------------------------------------------- #
def syn_flood(t0: float, victim: str, seed: int, rate_total: int = 600,
              spoofed: bool = True) -> Tuple[List[Packet], dict]:
    r = _rng(seed); pk = []
    for i in range(rate_total):
        src = f"198.18.{r.randint(0,255)}.{r.randint(1,254)}"
        t = t0 + r.uniform(0, 8)
        # spoofed floods carry no coherent TCP timestamp option
        ts = None if spoofed else 700000 + int(t * 1000)
        pk.append(Packet(t, src, victim, r.randint(1024, 65535), 80, "TCP", 60,
                         tcp_flags=FLAG_SYN, tcp_tsval=ts))
    return pk, {"threats": {"syn_flood"}, "target": victim}


def udp_flood(t0: float, victim: str, seed: int, n_sources: int = 250,
              per_src: int = 26) -> Tuple[List[Packet], dict]:
    r = _rng(seed); pk = []
    dport = r.randint(1024, 65535)
    for s in range(n_sources):
        src = f"198.51.{r.randint(0,255)}.{r.randint(1,254)}"; sp = r.randint(1024, 65535)
        for _ in range(per_src):   # reuse the 5-tuple so flow count stays bounded
            pk.append(Packet(t0 + r.uniform(0, 8), src, victim, sp, dport, "UDP",
                             r.randint(28, 64)))
    return pk, {"threats": {"udp_flood"}, "target": victim}


def reflection(t0: float, victim: str, seed: int, amp_port: int = 53,
               n_reflectors: int = 40, per_refl: int = 30) -> Tuple[List[Packet], dict]:
    r = _rng(seed); pk = []
    dport = r.randint(1024, 65535)   # the victim's spoofed source port for the queries
    for i in range(1, n_reflectors + 1):
        refl = f"192.0.2.{i}"
        for _ in range(per_refl):
            pk.append(Packet(t0 + r.uniform(0, 8), refl, victim, amp_port, dport, "UDP",
                             r.randint(1400, 4000)))
    return pk, {"threats": {"reflection_amplification"}, "target": victim}


def slowloris(t0: float, victim: str, seed: int, n_conns: int = 30) -> Tuple[List[Packet], dict]:
    r = _rng(seed); pk = []
    for i in range(n_conns):
        sp = 30000 + i; base = t0 + r.uniform(0, 2)
        src = f"172.16.{r.randint(0,255)}.{r.randint(1,254)}"   # one src per connection
        for k in range(8):
            t = base + k * 6.0
            pk.append(Packet(t, src, victim, sp, 80, "TCP", 24,
                             tcp_flags=FLAG_ACK | FLAG_PSH, http_partial=True,
                             tcp_tsval=200000 + int(t * 1000)))
    return pk, {"threats": {"slowloris"}, "target": victim}


def dns_tunnel(t0: float, domain: str, seed: int, n_queries: int = 40,
               label_len: int = 30) -> Tuple[List[Packet], dict]:
    r = _rng(seed); pk = []
    host = f"10.0.0.{r.randint(2,250)}"
    for i in range(n_queries):
        label = "".join(r.choice(B32) for _ in range(label_len))
        pk.append(Packet(t0 + i * 0.7, host, "8.8.8.8", 51000 + i, 53, "UDP", 90,
                         dns_qname=f"{label}.{domain}", dns_qtype="TXT"))
    return pk, {"threats": {"dns_tunnelling"}, "target": domain}


def dga_lookups(t0: float, infected: str, seed: int, n: int = 16,
                label_len: int = 16) -> Tuple[List[Packet], dict]:
    r = _rng(seed); pk = []
    for i in range(n):
        dga = "".join(r.choice(string.ascii_lowercase) if r.random() > 0.3
                      else r.choice("0123456789") for _ in range(label_len))
        pk.append(Packet(t0 + i * 2.0, infected, "8.8.8.8", 52000 + i, 53, "UDP", 70,
                         dns_qname=f"{dga}.info", dns_qtype="A"))
    return pk, {"threats": {"dga_domain"}, "target": ".info"}


def c2_beacon(t0: float, c2_ip: str, infected: str, seed: int, period: float = 60.0,
              jitter: float = 0.13, n: int = 15) -> Tuple[List[Packet], dict]:
    r = _rng(seed); pk = []
    base = t0
    for i in range(n):
        t = base + (r.random() * 2 - 1) * period * jitter
        sp = 45000 + i
        for k in range(3):
            pk.append(Packet(t + k * 0.03, infected, c2_ip, sp, 443, "TCP", 512,
                             tcp_flags=FLAG_ACK | FLAG_PSH, tcp_tsval=300000 + int(t * 1000)))
        base += period
    return pk, {"threats": {"c2_beaconing"}, "target": c2_ip}


# --------------------------------------------------------------------------- #
# Encrypted-transport variants — for the graceful-degradation evaluation.
# --------------------------------------------------------------------------- #
def doh_beacon(t0: float, resolver: str, infected: str, seed: int, period: float = 60.0,
               jitter: float = 0.12, n: int = 15) -> Tuple[List[Packet], dict]:
    """C2/DGA hidden inside DNS-over-HTTPS: periodic TCP/443 to a DoH resolver,
    NO plaintext qnames. Lexical DGA/tunnel detection is blind; beacon TIMING
    (SPECTER) survives, and TCP ACKs still allow GHOSTFLOW reconstruction."""
    r = _rng(seed); pk = []
    base = t0; ack = r.randint(1000, 9000)
    for i in range(n):
        t = base + (r.random() * 2 - 1) * period * jitter; sp = 47000 + i
        for k in range(4):
            ack += r.randint(400, 1400)
            pk.append(Packet(t + k * 0.02, infected, resolver, sp, 443, "TCP", r.randint(200, 900),
                             tcp_flags=FLAG_ACK | FLAG_PSH, tcp_ack=ack,
                             tcp_tsval=400000 + int((t + k * 0.02) * 1000)))
        base += period
    return pk, {"threats": {"c2_beaconing"}, "target": resolver, "transport": "DoH"}


def quic_beacon(t0: float, c2: str, infected: str, seed: int, period: float = 60.0,
                jitter: float = 0.12, n: int = 15) -> Tuple[List[Packet], dict]:
    """C2 over QUIC / HTTP-3: periodic UDP/443 flows, no TCP handshake / ACK /
    timestamps. GHOSTFLOW & PULSE degrade to the prior; beacon TIMING survives."""
    r = _rng(seed); pk = []
    base = t0
    for i in range(n):
        t = base + (r.random() * 2 - 1) * period * jitter; sp = 48000 + i
        for k in range(3):
            pk.append(Packet(t + k * 0.02, infected, c2, sp, 443, "UDP", 640))
        base += period
    return pk, {"threats": {"c2_beaconing"}, "target": c2, "transport": "QUIC"}


# --------------------------------------------------------------------------- #
# Reconstruction ground truth — a client->server flow whose ACK numbers encode
# a KNOWN reverse-byte volume; the harness withholds the truth and reconstructs.
# --------------------------------------------------------------------------- #
def recon_flow(t0: float, true_reverse_bytes: int, seed: int) -> Tuple[List[Packet], dict]:
    r = _rng(seed); pk = []
    host = f"10.0.0.{r.randint(2,250)}"; sp = r.randint(1024, 65535)
    isn = r.randint(1_000_000, 4_000_000_000 - 10_000_000)  # server ISN
    n_acks = max(4, min(80, true_reverse_bytes // 1400 + r.randint(2, 6)))  # delayed-ACK cadence
    # realistic imperfection: we may join a little late and/or the flow is cut
    # before the final ACK — both bias the estimate low, as in the field.
    start_frac = r.uniform(0.0, 0.04)
    end_frac = r.uniform(0.0, 0.05)
    lo = int(true_reverse_bytes * start_frac)
    hi = int(true_reverse_bytes * (1 - end_frac))
    for k in range(n_acks):
        frac = k / (n_acks - 1)
        cum = int(lo + (hi - lo) * frac)
        ack = isn + 1 + cum
        t = t0 + k * 0.04 + r.uniform(0, 0.01)
        pk.append(Packet(t, host, "93.184.216.34", sp, 443, "TCP", r.randint(40, 200),
                         tcp_flags=FLAG_ACK | (FLAG_PSH if r.random() > 0.5 else 0),
                         tcp_ack=ack, tcp_tsval=100000 + int(t * 1000)))
    return pk, {"true_reverse_bytes": true_reverse_bytes, "host": host}
