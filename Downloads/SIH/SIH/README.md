<div align="center">

# 👁 CYCLOPS
### One eye on the wire. No blind spot it won't admit to.

**A unidirectional-first passive NDR for data-diode enclaves.**
Smart India Hackathon 2026 · Problem Statement **26145** · **NTRO** · Theme: *Blockchain & Cybersecurity*

</div>

---

## The problem (PS 26145)

Critical-infrastructure operators watch their gateway/peering links through a **hardware data diode**: traffic is copied **one way** into a monitoring enclave that has *no physical path back*. The enclave can see everything crossing the link but can **never send a probe, complete a handshake, or push a mitigation**. It must work purely from passively observed PCAP, exported flow records (NetFlow/IPFIX/sFlow) and derived metadata — detecting, classifying and scoring **SYN/UDP floods, Slowloris, DNS tunnelling, and DGA/C2 beaconing** in near real time, as labelled alerts with confidence scores and supporting evidence.

## The bet

Almost every detector ever shipped is **bidirectional-first** — it secretly assumes a round trip (the SYN-ACK, the request/response ratio, the RTT). On a diode you often see only *one direction*, and that assumption quietly breaks. Halving a two-sided model doesn't half-work; it **fails**, because the missing return half isn't missing at random — **its very absence is the signal.**

CYCLOPS is built the other way around. It treats the unseen return half as an **inference target**: TCP leaks the far side into the headers you *do* see (cumulative-ACK receipts, timestamp echoes, retransmit backoff), so we reconstruct a **phantom bi-flow** with a calibrated uncertainty band, then detect in the **timing and information domains** that survive one-way visibility *and* encryption — and seal every probabilistic alert into **diode-rooted, court-reproducible evidence.**

> CYCLOPS doesn't degrade gracefully on one-way input. It gets **stronger** by inferring the half everyone else throws away.

---

## What's in this repo

| Deliverable | What it is | Where |
|---|---|---|
| 🖥️ **Live SOC console** | Interactive command console — watch CYCLOPS detect all four threats in sequence, with the Ghost-Half reconstruction, a real in-page Lomb-Scargle periodogram, explainable CALIBER alert cards, and a WIRESEAL tamper demo. | [`product/cyclops-console.html`](product/cyclops-console.html) · **[open ▶](https://claude.ai/code/artifact/9d977882-6f5b-4be5-9f34-ddaaaf6b8540)** |
| 📄 **Dossier** | The editorial brief: the one-way thesis, all eight novel cores, architecture, honest differentiation, KPIs and roadmap. | [`product/cyclops-dossier.html`](product/cyclops-dossier.html) · **[open ▶](https://claude.ai/code/artifact/18b25c6e-2ea3-4ba9-a747-04258c4fd1de)** |
| 📊 **Evaluation report** | The **measured** results (recall, calibration coverage, reconstruction error, jitter robustness, custody) rendered from a real eval run. | [`product/cyclops-eval.html`](product/cyclops-eval.html) · **[open ▶](https://claude.ai/code/artifact/81beb59b-05f1-451f-9aff-626cd23ba36f)** |
| ⚙️ **Reference engine** | A **real, runnable** Python core (`halfsight`) that ingests one-directional traffic and produces scored, evidence-anchored alerts, plus a seeded eval harness. Not a mock — the detection maths runs. | [`reference-impl/`](reference-impl/) |

### Run the engine in 30 seconds

```bash
cd reference-impl
pip install -r requirements.txt      # numpy only
python3 demo.py
```

It synthesises benign + all four attack classes over **one-directional** traffic and prints ranked alerts, then flips one byte of sealed evidence to prove tamper-detection. Sample output:

```
[CRITICAL] 0.92  c2_beaconing    C2 beacon 10.0.0.5 -> 203.0.113.66 every ~59.7s (jitter 13.0%)
[CRITICAL] 0.89  syn_flood       SYN flood against 203.0.113.10  (60 SYN/s, 599 spoofed src, cookie-flip)
[HIGH]     0.74  dns_tunnelling  DNS tunnel over tunnel-c2.net: ~720 B uplink encoded
[MEDIUM]   0.66  slowloris       Slowloris against 203.0.113.20  (30 conns, 4.6 B/s)
   chain verification: INTACT ✓
   after tampering with block #1: TAMPER DETECTED ✗ at block #1
```

### Run it on a real `.pcap` capture

Not a simulation — the pipeline parses genuine Ethernet/IP/TCP/UDP/DNS bytes (pure Python; optional `scapy`/`dpkt` for pcapng):

```bash
python3 -m eval.make_pcaps                        # write labeled real .pcap files to pcaps/
python3 -m halfsight.ingest pcaps/mixed.pcap      # run CYCLOPS on a real capture
python3 -m halfsight.ingest your_own_capture.pcap # ...or point it at any capture / tap dump
```

Point it at any capture from your own tap, Wireshark's sample set, or a diode. `benign.pcap` → *no threats detected*; `mixed.pcap` → all four threats, evidence sealed.

### Retrain the DGA model on the real dataset

The trained model (`halfsight/dga_model.npz`, ~8 MB) ships committed, so it works out of the box. To reproduce it from the real corpus:

```bash
./datasets/fetch_datasets.sh        # pulls the chrmor 25-family DGA dataset + OpenDNS top-10k (public)
python3 -m eval.train_dga           # trains the char-n-gram MLP, ~2 min, held-out test report
```

---

### Measured results (not asserted)

Run `python3 -m eval.run_eval 30` in `reference-impl/` — seeded, labeled, one-directional traffic, ~3s:

| Metric | Result | Notes |
|---|---|---|
| **Detection macro F1** | **0.967** | 7 threat classes; overt recall **100%**, stealth **90%** |
| **False-alarm rate** | **0%** | 90 benign scenarios incl. flash-crowd, CDN, NTP — zero false alarms |
| **GHOSTFLOW reconstruction** | **±4.3%** median | reverse-byte error vs withheld ground truth (200 flows) |
| **CALIBER coverage** | **0.90 → 0.90** | empirical conformal coverage tracks nominal 1−α exactly |
| **SPECTER robustness** | **0% Poisson FP** | look-elsewhere-corrected; detects to ~20–30% jitter (scales with observation) |
| **Spoof vs flash-crowd** | **100%** | separated from inbound-only data via PULSE liveness |
| **WIRESEAL tamper localisation** | **100%** | exact leaf/alert identified |
| **DGA model (trained on real data)** | **AUC 0.970** · F1 0.90 | char-n-gram MLP on **25 real DGA families** (337k domains) vs real Alexa/OpenDNS legit — ~2× the heuristic's recall (54%→94%); arithmetic families 95–99%, dictionary families need cross-host WordGraph |

Confusion is clean: every error is an attack scored *benign* (a stealth miss) — **never a wrong-class mis-attribution**. Full breakdown in the [evaluation report](https://claude.ai/code/artifact/81beb59b-05f1-451f-9aff-626cd23ba36f).

### Validated on REAL attack captures — 8/8

Not just synthetic. CYCLOPS is run on **genuinely-real public captures**, one per threat class, and detects **all of them**:

```bash
./pcaps/real/fetch_real_captures.sh    # pull the real captures (public sources)
python3 -m eval.validate_real          # run CYCLOPS on each, check detection
```

| Real capture | Threat | Detected | Source |
|---|---|---|---|
| spoofed SYN flood (37k pkts) | `syn_flood` | ✓ 0.89 | [StopDDoS/packet-captures](https://github.com/StopDDoS/packet-captures) |
| TCP SYN-ACK reflection | `reflection_amplification` | ✓ 0.90 | StopDDoS |
| IPsec/ISAKMP amplification | `reflection_amplification` | ✓ 0.90 | StopDDoS |
| DNS-ANY amplification (20k pps) | `reflection_amplification` | ✓ 0.90 | StopDDoS |
| iodine DNS tunnel (17k queries) | `dns_tunnelling` | ✓ 0.81 | [DNS-Tunnel-Datasets](https://github.com/ggyggy666/DNS-Tunnel-Datasets) |
| dnscat2 DNS tunnel (C2) | `dns_tunnelling` | ✓ 0.94 | DNS-Tunnel-Datasets |
| Slowloris (500 slow conns) | `slowloris` | ✓ 0.90 | [abastin99/PCAP_files](https://github.com/abastin99/PCAP_files) |
| **Cobalt Strike C2 beacon + DGA** | `c2_beaconing` + `dga_domain` | ✓ 1.00 | [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/) |

On the real Cobalt Strike capture, SPECTER recovered the **120s beacon interval at R=0.9997** and the trained model flagged the generated domains — both threats, one real malware pcap. Finding real data exposed and fixed **5 real bugs** (an O(n²) blowup on high-volume DNS, a reflection false-positive on normal resolver traffic, missing amplifier ports, TCP SYN-ACK reflection, and a tunnel detector over-tuned to synthetic subdomains).

## The eight cores

Each only makes sense *because* the wire speaks one direction. The moat is an **inference-and-honesty layer** no bidirectional NDR has.

| Core | Role | The one-way trick |
|---|---|---|
| **GHOSTFLOW** | Half-flow reconstruction | Cumulative-ACK deltas recover the peer's return byte volume; a shadow TCP FSM tracks the unseen side → a phantom bi-flow with a variance band. |
| **PULSE** | Liveness oracle | TSecr echo + RTO backoff + a visible third-ACK *prove* the peer answered without a round trip — kills the biggest one-way false positive (asymmetric routing ≠ half-open flood). |
| **VANTAGE** | Which-half routing | Infers whether you see client→server or server→client and routes to a detector bank built for that vantage. |
| **SPECTER** | Spectral beaconing | Lomb-Scargle periodogram over egress flow-initiations; its analytic false-alarm probability *is* the confidence. Survives jitter; needs no completeness. |
| **BABEL** | DNS language + covert-capacity | Char/word models for DGAs + an information bound that **meters exfil throughput** ("~N kbps"), asserting a live tunnel from poll cadence alone. |
| **BACKLOG ORACLE** | DoS mechanism | Little's-Law "SYN-RECV backlog % / ETA-to-exhaustion" + the victim's own SYN-cookie regime-flip — the actual mechanism, not a pps proxy. |
| **CALIBER** | Honest confidence | Conformal coverage guarantee with reconstruction variance propagated in — the band **widens when it leaned on inference**. Observed / Inferred / Assumed + TreeSHAP. |
| **WIRESEAL** | Custody + federation | Diode-rooted Merkle chain-of-custody sealing the *inference chain*; opposite-half federation lets two enclaves attest a bi-flow event without sharing raw PCAP. |

---

## Architecture

```
CAPTURE ─▶ STREAM ─▶ HALFSIGHT ─▶ DETECTORS ─▶ CALIBER ─▶ WIRESEAL
AF_XDP     Redpanda   GHOSTFLOW    FLOODLIGHT   conformal   Merkle +
ns-stamp   → Flink    PULSE        HOURGLASS    confidence  HSM-signed
drop-acct  sketches   VANTAGE      BABEL·SPECTER +TreeSHAP  ledger
```

Every stage runs on **one direction only**, deterministic and replayable for forensic use. See the [Dossier](product/cyclops-dossier.html) for the full layer detail and the graceful-degradation matrix (QUIC/HTTP-3, DoH/DoT, sampled sFlow).

## Honest about scope

DGA lexical scoring, beacon periodicity, entropy-based tunnelling and volumetric flood detection are table-stakes — we don't claim to have invented them. Our contribution is the **unidirectional-first** reframing and the honesty layer around them, and we route around our own limits (encrypted transport, sampled feeds) with explicit graceful degradation rather than overselling.

---

<div align="center">
<sub>Built for SIH 2026 · PS 26145 · NTRO. KPI figures are targets/illustrative on the reference trace; the detection maths is genuinely computed.</sub>
</div>
