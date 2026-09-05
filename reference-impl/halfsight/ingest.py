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
from .pipeline import FlowTable, Pipeline, severity_for
from .types import Alert


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


def run_streaming(path: str, backend: str = "auto", window_s: float = 600.0,
                  max_channels: int = 200_000):
    """Bounded-memory ingest for VERY large captures.

    Processes tumbling time-windows of `window_s` seconds — only one window of
    flows is ever held in memory — running every detector per window and deduping
    alerts across windows into a single hash-chained ledger. Beacons whose period
    is short relative to the window are caught in-window; to also catch long-period
    beacons split across windows, a tiny per-channel list of flow-start times is
    accumulated across the whole capture (just timestamps) and SPECTER runs once
    over it at the end.
    """
    pipe = Pipeline(sensor_id="pcap-stream")
    ft = FlowTable()
    win_start = first_ts = last_ts = None
    packets = windows = 0
    alerts, seen = [], set()
    chan_ev, chan_by = {}, {}   # (src,dst) -> [start_ts...] / [bytes...]  (bounded)

    def collect(a):
        k = (a.threat, a.flow_key)
        if k not in seen:
            seen.add(k); alerts.append(a)

    def flush(now):
        nonlocal ft, windows
        snap = ft.snapshot()
        if snap:
            for a in pipe.run_window(snap, now=now, window_s=window_s):
                collect(a)
            windows += 1
            for f in snap:                              # accumulate lightweight beacon series
                if f.dst_port == 53 or len(chan_ev) >= max_channels:
                    continue
                key = (f.src_ip, f.dst_ip)
                chan_ev.setdefault(key, []).append(f.start_ts)
                chan_by.setdefault(key, []).append(f.bytes)
                if len(chan_ev[key]) > 256:
                    chan_ev[key] = chan_ev[key][-256:]; chan_by[key] = chan_by[key][-256:]
        ft = FlowTable()

    for p in read_pcap(path, backend=backend):
        if first_ts is None:
            first_ts = win_start = p.ts
        last_ts = p.ts
        if p.ts - win_start >= window_s:
            flush(win_start + window_s); win_start = p.ts
        ft.ingest(p); packets += 1
    now = (last_ts or 0.0) + 1.0
    flush(now)

    # global beacon pass — catches long-period beacons split across windows
    for (src, dst), ev in chan_ev.items():
        if len(ev) < 8:
            continue
        br = pipe.beacon.analyze(sorted(ev), chan_by[(src, dst)])
        if br.is_beacon:
            collect(Alert(now, "beaconing", "c2_beaconing", severity_for(br.confidence),
                          br.confidence, f"{src}->{dst}",
                          f"C2 beacon {src} -> {dst} every ~{br.period_s}s (jitter {br.jitter_pct}%)",
                          evidence={**br.evidence, "period_s": br.period_s, "jitter_pct": br.jitter_pct}))
    pipe.seal_and_anchor(now)
    span = (last_ts - first_ts) if (first_ts is not None) else 0.0
    return {"packets": packets, "windows": windows, "window_s": window_s,
            "span_s": round(span, 2), "alerts": alerts, "ledger": pipe.ledger.summary()}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run CYCLOPS on a real pcap capture")
    ap.add_argument("pcap", help="path to a .pcap (classic) or .pcapng (needs dpkt/scapy)")
    ap.add_argument("--json", help="also write the full result as JSON to this path")
    ap.add_argument("--backend", default="auto", choices=["auto", "pure", "dpkt"])
    ap.add_argument("--window", type=float, default=None, help="analysis window seconds")
    ap.add_argument("--stream", action="store_true",
                    help="bounded-memory streaming mode (tumbling windows) for very large captures")
    args = ap.parse_args(argv)

    window = args.window if args.window is not None else (600.0 if args.stream else 60.0)
    try:
        r = (run_streaming(args.pcap, backend=args.backend, window_s=window) if args.stream
             else run(args.pcap, backend=args.backend, window_s=window))
    except FileNotFoundError:
        print(f"error: no such file: {args.pcap}", file=sys.stderr); return 2
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr); return 2

    print("=" * 72)
    print(f"  CYCLOPS · pcap ingest — {args.pcap}" + ("  [streaming]" if args.stream else ""))
    print("=" * 72)
    flows_line = (f"{r['windows']} windows × {int(r['window_s'])}s" if args.stream
                  else f"{r['flows']} half-flows")
    print(f"  {r['packets']} packets · {flows_line} · {r['span_s']}s span\n")
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
