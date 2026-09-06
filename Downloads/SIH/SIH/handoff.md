# HANDOFF — CYCLOPS (SIH 2026 · PS 26145)

Read this to pick up the project cold. Pair it with `decisions.md` (why) and
`progress.md` (what's done / next). Keep it updated when files or URLs change.

---

## 1. What this is

**CYCLOPS** — a *unidirectional-first* passive NDR for data-diode monitoring
enclaves, built for Smart India Hackathon 2026, Problem Statement **26145**
(NTRO, theme "Blockchain & Cybersecurity"). The enclave sees a **one-way** copy
of a link (data diode): it can never probe, complete a handshake, or push
mitigation back. CYCLOPS treats the **unseen return half as an inference target**
(reconstruct it from ACK/timestamp bits), detects in the **timing & information
domains**, and seals alerts into **tamper-evident, reproducible custody**.

Threats in scope: SYN/UDP flood, reflection/amplification, Slowloris, DNS
tunnelling, DGA, C2 beaconing.

## 2. Repo map

```
SIH/
├── README.md                 # front door: thesis, deliverables, measured results, 8 cores
├── decisions.md              # every decision + rationale (D1..D23)
├── progress.md               # done / next / limitations / how-to-demo
├── handoff.md                # this file
├── .gitignore
├── product/                  # the 3 published HTML artifacts (self-contained)
│   ├── cyclops-console.html  # LIVE SOC console (canvas sim + real in-page maths). ~950 lines.
│   ├── cyclops-dossier.html  # editorial brief (thesis, 8 cores, arch, scope, roadmap)
│   └── cyclops-eval.html     # measured evaluation report (charts from real metrics)
└── reference-impl/           # the REAL, runnable engine + eval harness (numpy only)
    ├── requirements.txt       # numpy
    ├── demo.py                # `python3 demo.py` — detects all 4 threats + tamper demo
    ├── README.md
    ├── halfsight/
    │   ├── __init__.py        # exports Packet, UniFlow, Alert, Pipeline, FlowTable
    │   ├── types.py           # Packet, UniFlow (a half-flow), Alert, shannon_entropy
    │   ├── halfflow.py        # GHOSTFLOW + PULSE + VANTAGE (the flagship)
    │   ├── caliber.py         # CALIBER split-conformal calibrator
    │   ├── pcap.py            # REAL pcap read/write (pure-python + optional dpkt/scapy)
    │   ├── ingest.py          # CLI: python3 -m halfsight.ingest <file.pcap>
    │   ├── dga_families.py    # published DGA algorithms + real benign list (offline fallback)
    │   ├── dga_model.py       # trained char-n-gram MLP (BABEL's DGA brain, numpy)
    │   ├── dga_model.npz      # committed trained weights (~8MB float16) — loads at runtime
    │   ├── pipeline.py        # FlowTable + Pipeline (glue)
    │   ├── detectors/
    │   │   ├── beaconing.py   # SPECTER (spectral, look-elsewhere-corrected)
    │   │   ├── dga.py         # BABEL/DGA (FANCI-style, real-data-calibrated, length-gated)
    │   │   ├── dns_tunnel.py  # BABEL/tunnel
    │   │   └── floods.py      # FLOODLIGHT (flood/reflection) + HOURGLASS (slowloris)
    │   └── evidence/
    │       └── ledger.py      # WIRESEAL (Merkle + hash-chained signed ledger)
    ├── eval/
    │   ├── labeled.py         # seeded ground-truth traffic generators
    │   ├── metrics.py         # P/R/F1, relative error, stats
    │   ├── make_pcaps.py      # write labeled real .pcap files to pcaps/
    │   ├── train_dga.py       # train + eval the DGA model on the real 25-family dataset
    │   ├── validate_real.py   # run the pipeline on REAL downloaded attack captures (8/8)
    │   ├── run_eval.py        # the harness (7 evals) → results/metrics.json
    │   └── results/{metrics.json, dga_model_metrics.json, real_pcap_validation.json}
    ├── pcaps/                 # generated labeled .pcaps (gitignored; make_pcaps regenerates)
    │   └── real/              # REAL downloaded captures + fetch_real_captures.sh (gitignored)
    └── datasets/              # real DGA + benign corpora (gitignored; fetch_datasets.sh pulls)
```

## 3. Run it

```bash
cd reference-impl
pip install -r requirements.txt        # numpy only
python3 demo.py                        # end-to-end detection + tamper demo
python3 -m eval.run_eval 30            # measured evaluation (7 evals) → eval/results/metrics.json
python3 -m eval.make_pcaps             # write labeled real .pcap files to pcaps/
python3 -m halfsight.ingest pcaps/mixed.pcap   # run the pipeline on a REAL pcap (or any capture)
./datasets/fetch_datasets.sh           # (optional) pull the real DGA + benign corpora
python3 -m eval.train_dga              # (optional) retrain the DGA model → halfsight/dga_model.npz
./pcaps/real/fetch_real_captures.sh    # (optional) pull REAL attack captures (public sources)
python3 -m eval.validate_real          # (optional) run CYCLOPS on them → 8/8 detected
```
Everything is deterministic/seeded. `demo`/`run_eval`/`ingest` need no network — the
trained DGA model (`dga_model.npz`) is committed. Only `fetch_datasets.sh` +
`train_dga` need the internet. `ingest` accepts classic `.pcap` (pcapng needs dpkt/scapy).

## 4. Published artifacts (private; user shares from the page)

| Artifact | URL |
|---|---|
| Console  | https://claude.ai/code/artifact/9d977882-6f5b-4be5-9f34-ddaaaf6b8540 |
| Dossier  | https://claude.ai/code/artifact/18b25c6e-2ea3-4ba9-a747-04258c4fd1de |
| Evaluation | https://claude.ai/code/artifact/81beb59b-05f1-451f-9aff-626cd23ba36f |

To update an artifact: edit its file in `product/`, then re-publish **the same
file path** (Artifact tool) to keep the URL. The console `#ff` URL fragment
fast-forwards the simulation to a fully-active frame (used for screenshots).

## 5. The eight cores → where they live

| Core | Does | File |
|---|---|---|
| GHOSTFLOW | reverse-byte reconstruction (ACK deltas) | `halfflow.py: reconstruct_reverse_bytes` |
| PULSE | liveness/RTT (TS-clock, RTO) | `halfflow.py: recover_ts_clock / passive_rtt` |
| VANTAGE | which-half routing | `halfflow.py: infer_role` |
| SPECTER | spectral beaconing | `detectors/beaconing.py` |
| BABEL | DGA + DNS tunnel | `detectors/dga.py`, `detectors/dns_tunnel.py` |
| BACKLOG ORACLE | SYN backlog / DoS | `detectors/floods.py` |
| CALIBER | conformal confidence | `caliber.py` |
| WIRESEAL | Merkle custody | `evidence/ledger.py` |

## 6. Measured results (from `eval/results/metrics.json`, 30 trials/class)

- Detection macro **F1 0.951**; overt recall **100%**, stealth **85%**; **0%** benign false-alarm (90 scenarios).
- Confusion is clean: errors are attack→benign misses only, **no wrong-class mis-attribution**.
- GHOSTFLOW reconstruction **±4.3%** median error (p90 7.0%).
- CALIBER conformal coverage **0.95/0.90/0.80 → 0.95/0.90/0.80** (tracks nominal).
- SPECTER **0% Poisson FP**; detects to ~20% jitter (15 beacons) / ~30% (40 beacons); period err <1%.
- Spoof-vs-flash-crowd **100%**; WIRESEAL tamper localisation **100%**.
- **DGA model (trained on real data):** char-n-gram MLP on 25 real families — ROC-**AUC 0.970**, F1 0.90, recall 94%
  (vs heuristic 54%), 1% FPR operating point. Arithmetic families 95–99%; dictionary families low (per-domain), but
  per-**host** detection ~100% (bot cycles many domains). Metrics in `eval/results/dga_model_metrics.json`.
- **Real pcap ingestion verified:** `make_pcaps` → `ingest` detects all 4 threats from real pcap bytes; `benign.pcap` clean.
- **ALL 6 threat classes validated on REAL downloaded captures (8/8):** real DDoS (StopDDoS), iodine+dnscat2 tunnels,
  real Slowloris, and a **real Cobalt Strike C2 beacon** (SPECTER recovered the 120s interval at R=0.9997 + DGA model
  flagged the domains). See `eval/validate_real.py` and `results/real_pcap_validation.json`. Detection macro F1 (synthetic) = **0.967**.

## 7. Conventions & gotchas

- **UniFlow is ONE direction.** Never assume you can see the return path; that's
  the whole point. New features must be computable one-way.
- **Detector thresholds** live in each detector's `__init__` (e.g. SPECTER
  `max_fap=0.01, min_cycles=4`, floods `syn_rate_thr`, tunnel `min_queries`).
  Changing them shifts the eval numbers — re-run `run_eval` and update the KPI
  figures in all three `product/*.html` files + the READMEs if you do.
- **KPI numbers appear in 4 places:** `product/cyclops-console.html` (KPI tiles +
  MEASURED RECALL panel + footer), `product/cyclops-dossier.html` (section 08),
  `product/cyclops-eval.html` (the embedded `const M = {...}` — the source of the
  charts, incl. `dgaReal`), and both READMEs + `decisions.md`/`progress.md`. Keep
  them in sync with `eval/results/metrics.json` if you retune anything.
- **BABEL's DGA brain is the trained model** (`dga_model.npz`), loaded via
  `dga_model.load_cached()`. `DGAClassifier(use_model=False)` forces the heuristic.
  The model scores the **leftmost** label; the pipeline runs tunnel detection FIRST
  and excludes tunnel 2LDs from DGA (else a tunnel's subdomains score as DGA). The
  1% FPR threshold is baked into the npz (`model.threshold`). If you change
  features/n-grams/`DEFAULT_DIM`, retrain (`eval.train_dga`) — inference and the
  saved weights must match. The heuristic (`detectors/dga.py`) stays as fallback.
- **Flood/tunnel detectors are calibrated against REAL captures** (`floods.py`,
  `dns_tunnel.py`): reflection needs high byte-rate + ≥10 reflectors (else normal
  DNS false-fires); rate uses the actual per-dst span; the tunnel score leans on
  query VOLUME (real tunnels reuse subdomains). If you retune, re-run BOTH
  `eval.run_eval` (synthetic) AND `eval.validate_real` (the 8 real captures) — they
  pull in opposite directions and both must stay green. Pipeline aggregates DNS
  per-2LD (never per flow×qname — that was an O(n²) hang on real high-volume DNS).
- **pcap round-trip:** `write_pcap` encodes DNS qnames as real DNS messages and
  partial-HTTP as real payload; the reader re-derives `dns_qname`/`http_partial`
  from bytes. If you add a Packet field the detectors need, teach both ends.
- **Artifact canvas rule:** size canvases lazily at draw time via `fit()` — do
  NOT capture width once at load (causes squished charts). See console `fit()`.
- **Artifacts are committed dark-theme** (single visual world) with explicit
  backgrounds; fonts are Google Fonts (Archivo + IBM Plex Mono + IBM Plex Sans).
- **Workflow scripts** (`Date.now`/`Math.random` unavailable) do NOT apply here —
  `run_eval.py`/`demo.py` are normal Python and use `random`/`time` freely.
- **WIRESEAL** uses hashlib/hmac as an ed25519 stand-in — documented; don't ship
  the HMAC key as real signing.

## 8. Good next tasks (see progress.md)

Real PCAP adapter (scapy → `Packet`) · pitch deck · GHOSTFLOW wrap/PAWS
hardening · pytest suite · DoH/QUIC degradation eval scenario. If you change any
detector, **re-run the eval and re-sync the KPI numbers everywhere** (§7).
