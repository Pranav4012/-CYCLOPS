#!/usr/bin/env python3
"""
Run the CYCLOPS pipeline on a REAL packet capture.

    python3 -m halfsight.ingest path/to/capture.pcap
    python3 -m halfsight.ingest capture.pcap --json out.json --backend pure

Reads real link-layer bytes (Ethernet/raw-IP/Linux-cooked, IPv4, TCP/UDP, DNS,
partial-HTTP), assembles one-directional half-flows, runs every detector bank,
and prints ranked, evidence-sealed alerts. This is the same pipeline the eval
harness measures — pointed at a file instead of synthetic packets.
"""
from __future__ import annotations

import argparse
import json
import sys

from .pcap import read_pcap
from .pipeline import FlowTable, Pipeline


def run(path: str, backend: str = "auto", window_s: float = 60.0):
    ft = FlowTable()
    n = 0
    first_ts = last_ts = None
    for p in read_pcap(path, backend=backend):
        ft.ingest(p)
        n += 1
        if first_ts is None:
            first_ts = p.ts
        last_ts = p.ts
    flows = ft.snapshot()
    now = (last_ts or 0.0) + 1.0
    pipe = Pipeline(sensor_id="pcap-ingest")
    alerts = pipe.run_window(flows, now=now, window_s=window_s)
    pipe.seal_and_anchor(now)
    span = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else 0.0
    return {"packets": n, "flows": len(flows), "span_s": round(span, 2),
            "alerts": alerts, "ledger": pipe.ledger.summary()}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run CYCLOPS on a real pcap capture")
    ap.add_argument("pcap", help="path to a .pcap (classic) or .pcapng (needs dpkt/scapy)")
    ap.add_argument("--json", help="also write the full result as JSON to this path")
    ap.add_argument("--backend", default="auto", choices=["auto", "pure", "dpkt"])
    ap.add_argument("--window", type=float, default=60.0, help="analysis window seconds")
    args = ap.parse_args(argv)

    try:
        r = run(args.pcap, backend=args.backend, window_s=args.window)
    except FileNotFoundError:
        print(f"error: no such file: {args.pcap}", file=sys.stderr); return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr); return 2

    print("=" * 72)
    print(f"  CYCLOPS · pcap ingest — {args.pcap}")
    print("=" * 72)
    print(f"  {r['packets']} packets · {r['flows']} half-flows · {r['span_s']}s span\n")
    alerts = sorted(r["alerts"], key=lambda a: -a.confidence)
    if not alerts:
        print("  no threats detected.")
    else:
        print(f"  ALERTS ({len(alerts)}) — ranked by confidence")
        print("  " + "-" * 68)
        for a in alerts:
            print(f"  [{a.severity.upper():8}] {a.confidence:5.2f}  {a.threat:22} {a.title}")
            ev = list(a.evidence.items())[:3]
            if ev:
                print("             " + ", ".join(f"{k}={v}" for k, v in ev))
    led = r["ledger"]
    print(f"\n  WIRESEAL: {led['blocks']} blocks · chain "
          f"{'INTACT ✓' if led['chain_intact'] else 'BROKEN ✗'} · head {led['head']}")
    print("=" * 72)

    if args.json:
        out = dict(r); out["alerts"] = [a.to_record() for a in r["alerts"]]
        with open(args.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"  wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
