# `halfsight` — the CYCLOPS reference engine

A small, **runnable** Python core that ingests one-directional (passive / data-diode)
IP traffic and emits scored, evidence-anchored alerts. It exists to prove the CYCLOPS
concept is buildable — the detection maths runs, it is not a mock.

Only hard dependency: **numpy**.

```bash
pip install -r requirements.txt
python3 demo.py
```

## What the demo does

`demo.py` synthesises **one-directional** traffic containing benign load plus every threat
class in PS 26145, assembles it into half-flows, runs the pipeline, prints ranked alerts,
then flips one byte of a sealed evidence block to demonstrate tamper-detection.

## Module map

```
halfsight/
├── types.py                 # Packet, UniFlow (a half-flow), Alert; shannon_entropy
├── halfflow.py              # ★ HalfFlowReconstructor — GHOSTFLOW + PULSE + VANTAGE
│                            #   passive RTT, TCP-timestamp clock recovery (liveness),
│                            #   half-open ratio, return-direction posterior with variance
├── detectors/
│   ├── beaconing.py         # SpectralBeaconDetector (SPECTER) — Rayleigh/Lomb-Scargle
│   │                        #   periodogram over event times; FAP as confidence
│   ├── dga.py               # DGAClassifier (BABEL) — training-free FANCI-style char model
│   ├── dns_tunnel.py        # DNSTunnelDetector (BABEL) — per-domain entropy/length/uniqueness
│   └── floods.py            # FloodSlowlorisDetector (FLOODLIGHT + HOURGLASS)
│                            #   SYN/UDP flood, reflection/amplification, Slowloris
├── evidence/
│   └── ledger.py            # WIRESEAL — Merkle tree + hash-chained, signed evidence ledger
├── caliber.py               # CALIBER — split-conformal calibrator (coverage guarantee)
├── pcap.py                  # REAL pcap read/write (Ethernet/IP/TCP/UDP/DNS/partial-HTTP)
├── ingest.py                # CLI: run the pipeline on a real .pcap  (python3 -m halfsight.ingest)
├── dga_families.py          # published DGA algorithms + real benign top-domains list
├── dga_model.py             # trained char-n-gram MLP (BABEL's DGA brain) — numpy only
├── dga_model.npz            # committed trained weights (~8MB, float16) — loads at runtime
└── pipeline.py              # FlowTable + Pipeline: packets → detectors → alerts → ledger

eval/
├── labeled.py               # labeled, seeded, ground-truth traffic generators
├── metrics.py               # precision/recall/F1, relative error, summary stats
├── make_pcaps.py            # write labeled real .pcap files to pcaps/
├── train_dga.py             # train + evaluate the DGA model on the real 25-family dataset
├── run_eval.py              # the harness — 7 evaluations, writes results/metrics.json
└── results/metrics.json     # last run's measured numbers

datasets/                    # (gitignored) real data — ./datasets/fetch_datasets.sh to pull
```

★ = the flagship. `halfflow.py` treats the unseen return direction as a latent variable and
recovers three signals without ever touching the return path: a TCP-timestamp clock (host
liveness / spoofing tell), an RTO-proxy passive RTT, and a return-traffic posterior.

## How each detector works one-directionally

| Detector | Signal it keys on (observed direction only) |
|---|---|
| **SPECTER** (`beaconing.py`) | Point-process periodicity via a Rayleigh/Lomb-Scargle-style periodogram over flow-initiation times. Confidence = `1 − exp(−N·R²)` false-alarm probability. Robust to jitter. |
| **BABEL / DGA** (`dga.py`) | Per-label entropy, n-gram "englishness", digit/vowel ratios, consonant runs, dictionary-DGA word hits → hand-calibrated logistic with per-feature attributions. |
| **BABEL / tunnel** (`dns_tunnel.py`) | Per registrable domain: subdomain entropy, label length, unique-subdomain ratio, TXT/NULL qtype mix, uplink byte estimate. |
| **FLOODLIGHT** (`floods.py`) | SYN half-open ratio + source-IP entropy + **HalfSight liveness** (spoofed sources have no coherent TCP-timestamp clock); UDP pps/reflection from amplifier source ports. |
| **HOURGLASS** (`floods.py`) | Clusters of long-duration, low-byte-rate, partial-HTTP flows to one server. |
| **WIRESEAL** (`evidence/ledger.py`) | Each alert → evidence bundle (alert + flow record + packet-hash Merkle root + feature vector + model version), batched into hash-chained, signed blocks; `verify_chain()` localises any tamper. |

## Evaluation

```bash
python3 -m eval.run_eval 30        # 30 trials/class, seeded, ~3s
```

Measures (never asserts) the claims on labeled, ground-truth, one-directional traffic and writes `eval/results/metrics.json`:

1. **Detection** — per-class recall (overt + low-signal stealth tiers), false-alarm rate on benign/flash-crowd/CDN/NTP, a confusion matrix, and macro P/R/F1.
2. **Reconstruction** — GHOSTFLOW reverse-byte error vs withheld ground truth.
3. **Conformal** — CALIBER interval coverage vs nominal 1−α (marginal over 200 splits).
4. **Jitter** — SPECTER beacon detection vs jitter at two observation depths, plus the Poisson false-positive rate.
5. **Spoof vs flash-crowd** — separation from inbound-only data via PULSE liveness.
6. **Custody** — WIRESEAL tamper-localisation accuracy.

Headline (30 trials/class): macro **F1 0.967**, overt recall **100%** / stealth **90%**, **0%** benign false-alarm, reconstruction **±4.3%** median, conformal coverage **0.90 → 0.90**, Poisson beacon FP **0%**, tamper localisation **100%**, trained DGA model **AUC 0.970** / F1 0.90.

## Validated on REAL attack captures — 8/8

```bash
./pcaps/real/fetch_real_captures.sh   # pull real DDoS / DNS-tunnel / Slowloris / Cobalt-Strike captures (public)
python3 -m eval.validate_real         # run CYCLOPS on each -> 8/8 detected
```

Real captures — one per threat class — from StopDDoS (real DDoS), ggyggy666/DNS-Tunnel-Datasets (iodine + dnscat2), abastin99/PCAP_files (Slowloris), and malware-traffic-analysis.net (**real Cobalt Strike C2**). On the Cobalt Strike capture SPECTER recovers the **120s beacon interval at R=0.9997** and the trained DGA model flags the generated domains. Finding real data exposed & fixed 5 detector bugs (O(n²) DNS blowup, reflection FP on resolver traffic, missing amplifier ports, TCP SYN-ACK reflection, actual-span rate).

## DGA model — trained on real data

```bash
./datasets/fetch_datasets.sh        # public: chrmor 25-family DGA dataset + OpenDNS top-10k
python3 -m eval.train_dga           # ~2 min → halfsight/dga_model.npz + results/dga_model_metrics.json
```

`dga_model.py` is a character-n-gram (1–4) **embedding-bag MLP** trained in pure numpy on **337k domains across 25 real DGA families** (conficker, cryptolocker, gozi, matsnu, necurs, ranbyus, suppobox, tinba…) vs real Alexa/OpenDNS legit. Held-out test: **ROC-AUC 0.970**, F1 0.90 @0.5, recall 94% (vs the hand-tuned heuristic's 54%), **1% FPR** operating point. BABEL (`detectors/dga.py`) loads the committed model automatically and falls back to the heuristic if it's absent. Arithmetic families score 95–99%; dictionary families (nymaim, suppobox) are the known-hard case that needs cross-host correlation, and per-**host** detection stays near-total because a bot cycles through many domains.

## Real `.pcap` ingestion

```bash
python3 -m eval.make_pcaps                     # write labeled real pcaps to pcaps/
python3 -m halfsight.ingest pcaps/mixed.pcap   # run the pipeline on a real capture
python3 -m halfsight.ingest any.pcap --json out.json
```

`pcap.py` parses real link-layer bytes (Ethernet / raw-IP / Linux-cooked, IPv4, TCP/UDP, the TCP timestamp option, DNS questions, partial-HTTP) into `Packet` objects — pure standard library, with `dpkt`/`scapy` used automatically if present for pcapng or exotic link types. `write_pcap` emits Wireshark-openable classic pcaps, so labeled lab traffic round-trips through the exact ingestion path a diode deployment would use. Point `ingest` at your own tap dump or a public sample capture.

## Using it programmatically on real traffic

Replace the synthetic packets in `demo.py` with a PCAP/NetFlow reader (scapy / pyshark / a
YAF-IPFIX parser) that emits `halfsight.types.Packet` objects into a `FlowTable`, then call
`Pipeline.run_window(...)`. The detector APIs are stable and each returns a structured result
with `evidence` and (for DGA) per-feature `contributions`.

> This is a reference core sized for clarity, not line rate. The production path (AF_XDP capture,
> Flink stream processing, online models, conformal calibration, HSM signing, ledger anchoring)
> is laid out in the [Dossier](../product/cyclops-dossier.html).
