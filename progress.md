# PROGRESS — CYCLOPS (SIH 2026 · PS 26145)

Status snapshot. Update the checkboxes and "Last updated" whenever state changes.

**Last updated:** 2026-09-05 · **State:** submission-ready · **ALL 6 threat classes validated on real public attack captures (8/8)** · DGA ML model on 25 real families (AUC 0.970) · macro F1 0.967, 0% FP

---

## Done ✅

### Concept & research
- [x] 13-agent design/research workflow → synthesized product **CYCLOPS** with 8 named cores.
- [x] Full concept: thesis, pillars, architecture, differentiation, honest scope, roadmap.

### Reference engine (`reference-impl/halfsight/`) — runs, `python3 demo.py`
- [x] `types.py` — Packet / UniFlow (half-flow) / Alert; ACK-progression tracking.
- [x] `halfflow.py` — GHOSTFLOW (ACK-derivative reverse-byte reconstruction) + PULSE
      (TS-clock liveness, passive RTT) + VANTAGE (role inference) + return posterior.
- [x] `detectors/beaconing.py` — SPECTER, Rayleigh periodogram **with look-elsewhere correction**.
- [x] `detectors/dga.py` — BABEL/DGA FANCI-style classifier with per-feature attributions.
- [x] `detectors/dns_tunnel.py` — BABEL/tunnel per-domain entropy/length/uniqueness.
- [x] `detectors/floods.py` — FLOODLIGHT (SYN/UDP/reflection) + HOURGLASS (slowloris).
- [x] `evidence/ledger.py` — WIRESEAL Merkle + hash-chained signed ledger + tamper detection.
- [x] `caliber.py` — CALIBER split-conformal calibrator.
- [x] `pipeline.py` — FlowTable + Pipeline (packets → detectors → alerts → sealed evidence).
- [x] `demo.py` — synthesizes benign + all 4 threats, detects all, proves tamper detection.

### Real inputs — PCAP ingestion & real DGA data
- [x] `halfsight/pcap.py` — real pcap read/write (Ethernet/IP/TCP/UDP/DNS/partial-HTTP; pure-python + optional dpkt/scapy).
- [x] `halfsight/ingest.py` — CLI `python3 -m halfsight.ingest <file.pcap>` runs the pipeline on any real capture.
- [x] `halfsight/dga_families.py` — published DGA algorithms + real benign top-domains (fallback/offline).
- [x] `eval/make_pcaps.py` — writes labeled real .pcap sample files (Wireshark-openable).
- [x] **Verified round-trip:** write labeled traffic → real pcap → read back → all 4 threats detected; `benign.pcap` clean.

### Real attack captures — ALL classes validated (8/8)
- [x] `pcaps/real/fetch_real_captures.sh` — pulls real captures from public sources (StopDDoS, DNS-Tunnel-Datasets, abastin99, MTA).
- [x] `eval/validate_real.py` — runs the pipeline on each real capture, checks detection → `results/real_pcap_validation.json`.
- [x] **8/8 detected:** SYN flood, TCP/ISAKMP/DNS reflection, iodine + dnscat2 tunnels, Slowloris, **real Cobalt Strike C2 beacon (120s, R=0.9997) + DGA**.
- [x] Real data found & fixed 5 bugs: O(n²) DNS blowup, reflection FP on resolver traffic, missing amplifier ports, TCP SYN-ACK reflection, actual-span rate.
- [x] Tunnel detector recalibrated for real tunnels (volume feature) → synthetic tunnel recall 75%→90%, macro F1 0.951→0.967.

### Real labeled dataset + trained DGA ML model
- [x] `datasets/fetch_datasets.sh` — pulls chrmor 25-family DGA dataset (674k domains) + OpenDNS top-10k (public).
- [x] `halfsight/dga_model.py` — char-n-gram embedding-bag MLP (numpy); `dga_model.npz` committed (float16, ~8MB).
- [x] `eval/train_dga.py` — trains + evaluates on the real dataset (stratified split, per-family, heuristic comparison).
- [x] **Trained-model metrics:** ROC-AUC **0.970**, F1 0.90 @0.5, recall **94%** (vs heuristic 54%), 1% FPR operating point.
- [x] Wired into BABEL (cached load); pipeline reordered so tunnel 2LDs are excluded from DGA scoring.

### Evaluation (`reference-impl/eval/`) — runs, `python3 -m eval.run_eval 30`
- [x] `labeled.py` — seeded ground-truth generators (attacks + benign/flash-crowd/CDN/NTP + recon flows).
- [x] `metrics.py` — P/R/F1, relative error, summary stats.
- [x] `run_eval.py` — **7** evaluations, writes `results/metrics.json`.
- [x] **Measured results:** macro F1 0.951 · overt recall 100% / stealth 85% · **0% benign FP** ·
      recon ±4.3% median · conformal coverage 0.90→0.90 · SPECTER 0% Poisson FP · spoof 100% · tamper 100% ·
      real-data DGA 85.5% @ 0.7% FPR.

### Artifacts (published, private, share-ready)
- [x] **Console** — live SOC demo · https://claude.ai/code/artifact/9d977882-6f5b-4be5-9f34-ddaaaf6b8540
- [x] **Dossier** — editorial brief · https://claude.ai/code/artifact/18b25c6e-2ea3-4ba9-a747-04258c4fd1de
- [x] **Evaluation** — measured report · https://claude.ai/code/artifact/81beb59b-05f1-451f-9aff-626cd23ba36f
- [x] KPIs across console + dossier updated to **measured** numbers; cross-linked to the eval report.

### Bugs fixed
- [x] Console canvas squish (lazy-fit width at draw time).
- [x] Slowloris eval generator shattered flows (src randomized per-packet → per-connection).
- [x] SPECTER 92.5% Poisson false-positive → 0% (look-elsewhere correction + cycle/FAP gates).
- [x] Conformal degeneracy + exchangeability (moved to reconstruction intervals, randomized+shuffled, marginal-over-splits).

### Docs
- [x] Top-level `README.md`, `reference-impl/README.md` (with eval section), `.gitignore`.
- [x] `decisions.md`, `progress.md`, `handoff.md` (this set).

## In progress / next 🔜
- [x] ~~Real PCAP ingestion adapter~~ — **done** (`halfsight/pcap.py` + `ingest` CLI).
- [x] ~~Ingest genuinely external public captures~~ — **done** (8/8 real captures incl. real Cobalt Strike C2).
- [x] ~~Streaming ingest (chunked windows)~~ — **done** (`ingest.run_streaming` / `--stream`, bounded memory + global beacon pass).
- [x] ~~Harden GHOSTFLOW for seq/TSval wrap, PAWS, delayed-ACK/Nagle~~ — **done** (serial arithmetic + TSval unwrap + PAWS filter).
- [x] ~~Expand eval: PR curves + DoH/QUIC degradation~~ — **done** (DGA PR curve + avg-precision; measured degradation matrix).
- [x] ~~Unit tests (`pytest`) + CI~~ — **done** (30 tests in `reference-impl/tests/`, GitHub Actions + `eval/ci_gate.py` regression gate).
- [ ] (optional) Slide deck / 3-min pitch script for the on-stage demo.
- [ ] (optional) Thin FastAPI backend wrapping the engine (for a live SOC UI).

## Known limitations (honest)
- Traffic is synthetic/lab-generated; not a NIST-grade benchmark.
- Baseline comparison (Zeek/Suricata/RITA) is architectural, not head-to-head measured.
- Encrypted-transport (QUIC/HTTP-3) and DoH/DoT erode specific detectors — handled by graceful degradation, not solved.
- Console is a scripted live *simulation* (maths computed in-page); the engine is the real detector.

## How to demo (90s)
One-way banner → Ghost-Half timeline → SYN-flood backlog + cookie-flip → click a CALIBER alert →
hit Tamper (inclusion proof fails) → point at the Evaluation report for measured numbers.
(Console `#ff` deep-link jumps to a fully-active frame.)
