#!/usr/bin/env python3
"""
Self-contained demo: synthesize one-directional traffic containing benign load
plus every threat class in the brief, run the passive pipeline, and show the
tamper-evident evidence ledger catching a post-hoc edit.

Run:  python3 demo.py
Deps: numpy  (pip install -r requirements.txt)
"""
import random
import string

from halfsight import Pipeline, FlowTable, Packet
from halfsight.types import FLAG_SYN, FLAG_ACK, FLAG_PSH

random.seed(1337)
B32 = string.ascii_lowercase + "234567"


def synth_packets():
    pkts = []
    t0 = 1000.0

    # ---- benign: a few normal web sessions + normal DNS -------------------
    for i in range(8):
        sp = 40000 + i
        t = t0 + i * 3
        # normal DNS lookup of a real domain
        pkts.append(Packet(t, f"10.0.0.{20+i}", "8.8.8.8", 50000 + i, 53, "UDP", 60,
                           dns_qname=random.choice(["google.com", "cloudflare.com",
                                                    "github.com", "wikipedia.org"]),
                           dns_qtype="A"))
        # a healthy request/response-sized flow (coherent TCP timestamps => live host)
        for k in range(12):
            pkts.append(Packet(t + k * 0.05, f"10.0.0.{20+i}", "93.184.216.34", sp, 443, "TCP",
                               1200, tcp_flags=FLAG_ACK | FLAG_PSH,
                               tcp_tsval=100000 + int((t + k * 0.05) * 1000),
                               tcp_ack=1))

    # ---- SYN flood: 600 spoofed sources, 1 SYN each, no timestamps --------
    victim = "203.0.113.10"
    for i in range(600):
        src = f"198.18.{random.randint(0,255)}.{random.randint(1,254)}"
        t = t0 + random.uniform(0, 8)          # inside a 10s window
        pkts.append(Packet(t, src, victim, random.randint(1024, 65535), 80, "TCP",
                           60, tcp_flags=FLAG_SYN))   # SYN only, never completes

    # ---- Slowloris: 30 slow, partial-header conns to a web server ---------
    web = "203.0.113.20"
    for i in range(30):
        sp = 30000 + i
        base = t0 + random.uniform(0, 2)
        for k in range(8):                     # dribble tiny partial headers over ~48s
            t = base + k * 6.0
            pkts.append(Packet(t, f"172.16.0.{i+1}", web, sp, 80, "TCP", 24,
                               tcp_flags=FLAG_ACK | FLAG_PSH, http_partial=True,
                               tcp_tsval=200000 + int(t * 1000)))

    # ---- DNS tunnelling: long high-entropy TXT subdomains -----------------
    tun = "tunnel-c2.net"
    for i in range(40):
        label = "".join(random.choice(B32) for _ in range(30))
        t = t0 + i * 0.7
        pkts.append(Packet(t, "10.0.0.77", "8.8.8.8", 51000 + i, 53, "UDP", 90,
                           dns_qname=f"{label}.{tun}", dns_qtype="TXT"))

    # ---- DGA + C2 beaconing: periodic check-ins (60s, 30% jitter) ---------
    c2 = "203.0.113.66"
    infected = "10.0.0.5"
    for i in range(16):
        t = t0 + i * 60.0 + random.uniform(-9, 9)     # 60s beacon, heavy jitter
        sp = 45000 + i
        # DGA rendezvous lookup just before the beacon
        dga = "".join(random.choice(string.ascii_lowercase) if random.random() > 0.3
                      else random.choice("0123456789") for _ in range(16))
        pkts.append(Packet(t - 0.2, infected, "8.8.8.8", 52000 + i, 53, "UDP", 70,
                           dns_qname=f"{dga}.info", dns_qtype="A"))
        # the near-constant-size encrypted check-in
        for k in range(3):
            pkts.append(Packet(t + k * 0.03, infected, c2, sp, 443, "TCP",
                               512, tcp_flags=FLAG_ACK | FLAG_PSH,
                               tcp_tsval=300000 + int(t * 1000)))
    return pkts


def main():
    print("=" * 74)
    print("  CYCLOPS · HalfSight engine — unidirectional-first passive threat detection")
    print("  one eye on the wire · reference core (SIH 2026 · PS 26145 · NTRO)")
    print("=" * 74)

    ft = FlowTable()
    for p in synth_packets():
        ft.ingest(p)
    flows = ft.snapshot()
    print(f"\nIngested one-directional traffic -> {len(flows)} half-flows assembled.\n")

    pipe = Pipeline()
    alerts = pipe.run_window(flows, now=2000.0, window_s=30.0)
    # flush remaining evidence into a final block and anchor it
    for i in range(2):
        pipe.seal_and_anchor(2000.0 + i)

    alerts.sort(key=lambda a: -a.confidence)
    print(f"ALERTS ({len(alerts)}) — ranked by confidence")
    print("-" * 74)
    for a in alerts:
        print(f"[{a.severity.upper():8}] {a.confidence:5.2f}  {a.threat:22} {a.title}")
        top = list(a.evidence.items())[:3]
        if top:
            print("            evidence: " + ", ".join(f"{k}={v}" for k, v in top))
    print()

    # ---- forensic chain-of-custody ---------------------------------------
    print("EVIDENCE LEDGER")
    print("-" * 74)
    print("  ", pipe.ledger.summary())
    ok, _ = pipe.ledger.verify_chain()
    print(f"   chain verification: {'INTACT ✓' if ok else 'BROKEN ✗'}")

    # tamper with a sealed block to prove detection
    if len(pipe.ledger.blocks) > 1:
        pipe.ledger.blocks[1].merkle_root = "deadbeef" * 8
        ok2, broken = pipe.ledger.verify_chain()
        print(f"   after tampering with block #1: "
              f"{'INTACT ✓' if ok2 else f'TAMPER DETECTED ✗ at block #{broken}'}")
    print()


if __name__ == "__main__":
    main()
