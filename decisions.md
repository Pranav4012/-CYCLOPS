# DECISIONS — CYCLOPS (SIH 2026 · PS 26145)

A running log of every non-trivial decision and its rationale. Newest section last.
Keep this updated whenever an approach, name, threshold, or claim changes.

---

## Product framing

- **D1 — Product = CYCLOPS ("one eye on the wire").** The problem's defining
  feature is *unidirectional* visibility (data diode). One-eye/one-direction is
  the whole identity. Chosen over MONOCLE/TIRESIAS/PERISCOPE/SIMPLEX/ARGUS-1
  (kept as `naming_alternatives`). The half-flow engine keeps the sub-name
  **HalfSight**.
- **D2 — Central thesis: "unidirectional-first."** Instead of retraining a
  bidirectional NDR on halved data (a missing-not-at-random covariate-shift
  failure), treat the unseen return half as an *inference target*. This is the
  moat and the demo's emotional core. Everything else serves it.
- **D3 — Eight named cores.** GHOSTFLOW (reconstruction), PULSE (liveness),
  VANTAGE (which-half routing), SPECTER (spectral beaconing), BABEL (DNS
  language + covert-capacity), BACKLOG ORACLE (Little's-Law DoS), CALIBER
  (conformal honest confidence), WIRESEAL (Merkle custody + federation). Named
  so each is memorable and maps to a concrete mechanism.
- **D4 — Blockchain theme is load-bearing, not decorative.** The diode is
  reframed as the first cryptographic link of chain-of-custody; WIRESEAL seals
  the *inference chain* (model hash + features + reconstruction), which is the
  one thing that genuinely needs a ledger (reproducible, admissible, federable).
- **D5 — Honesty as a feature.** We explicitly state what we did NOT invent
  (DGA lexical scoring, beacon periodicity, entropy tunnelling, volumetric
  flood) and where we degrade (QUIC/HTTP-3, DoH/DoT, sampled sFlow). This is
  what earns a skeptical NTRO panel's trust — and it shaped the eval design.

## Deliverables

- **D6 — Three artifacts + a runnable engine + an eval report**, not slides.
  (1) Live SOC console, (2) editorial Dossier, (3) Evaluation report — all HTML
  artifacts; plus `reference-impl/` (real Python) and `eval/` (real harness).
  Rationale: judges are impressed by *seeing it work* and by *measured* numbers.
- **D7 — Visual identity: dark SIGINT/oscilloscope instrument.** Palette:
  near-black blue ground, signal-cyan accent (observed), ghost-violet (inferred),
  slate (assumed); semantic ok/warn/crit separate from accent. Type: Archivo
  (display) + IBM Plex Mono (telemetry) + IBM Plex Sans (body). Deliberately
  single-theme (committed dark) — a SIGINT console is inherently dark; all colors
  painted explicitly so it holds on any host ground. Avoids the generic
  "AI cream + serif" / "purple gradient" looks.
- **D8 — Color is semantic doctrine:** Observed = cyan solid, Inferred = violet
  dashed, Assumed = grey. Used consistently in the Ghost-Half timeline and the
  CALIBER Observed/Inferred/Assumed alert card.

## Engine (reference-impl/halfsight)

- **D9 — Dependency-light (numpy only), stdlib crypto.** Runs anywhere in an
  enclave incl. constrained sensors. WIRESEAL uses hashlib/hmac (documented to
  swap for ed25519 + Fabric/QLDB in production). Pure-python linear algebra in
  halfflow.py.
- **D10 — Half-flow is a UniFlow (one direction), by design.** All features are
  what a NetFlow/IPFIX exporter or light parser can produce one-way. The return
  direction is inferred, never stored as truth.
- **D11 — GHOSTFLOW reconstruction = cumulative-ACK delta.** `reverse_bytes ≈
  ack_last − ack_first` (each ACK is a receipt for the peer's bytes). Chosen over
  the earlier prior-ratio heuristic because it is a *measurement*, not a guess —
  and it is what makes the reconstruction-error claim real (measured ±4.3%).
  Prior-ratio kept as fallback when ACK progression isn't visible.
- **D12 — PULSE liveness = TCP-timestamp clock coherence.** A real host's TSval
  increments at a fixed Hz; fit ts→TSval, use R². Spoofed flood sources lack a
  coherent clock → low liveness. This is the spoof-vs-flash-crowd discriminant
  (measured 100%).
- **D13 — SPECTER uses a Rayleigh/phase periodogram over event times**, not
  Lomb-Scargle on sampled values, because beacons are a *point process*. Framed
  as the point-process analogue of Lomb-Scargle. FAP = exp(−N·R²).
- **D14 — SPECTER look-elsewhere correction (BUG FIX).** The naive single-period
  FAP false-fired on aperiodic Poisson traffic **92.5%** of the time (scanning
  thousands of periods inflates max R). Fixed with `M_eff = (1/pmin − 1/pmax)·span`
  independent frequencies → `global_fap = min(1, M_eff·exp(−N·R²))`, plus a
  `min_cycles ≥ 4` gate and `max_fap = 0.01`. Result: **0% Poisson FP**, detection
  scales honestly with observation (15 beacons → 20% jitter, 40 → 30%).
- **D15 — DGA classifier is training-free (FANCI-style logistic).** Hand-
  calibrated weights over entropy/n-gram/digit/vowel/consonant features + a
  dictionary-DGA tell. Documented to swap for a trained char-LSTM in production.
  Chosen so the reference runs with zero training data.
- **D16 — Pipeline guards to avoid obvious false positives:** skip beacon
  detection on known-good periodic service channels (DNS 53, NTP 123/323);
  dedup DGA alerts by registrable label. Documented as a cheap allowlist that a
  production build swaps for 2LD/ASN reputation.

## Evaluation

- **D17 — Measure, don't assert.** Every headline KPI is produced by
  `eval/run_eval.py` on seeded labeled traffic. Replaced the earlier asserted
  figures (±3.1%, "8–12 cycles", illustrative bake-off) with measured ones.
- **D18 — Difficulty tiers for credibility.** A flat 100%/1.000 macro reads as
  rigged. Added an overt + **stealth** tier (near-threshold tunnels, short DGA
  labels, high-jitter/few-cycle beacons) → honest spread (overt 100%, stealth
  85%). Added borderline-benign (flash-crowd, structured CDN, NTP) to test
  precision honestly → 0% FP.
- **D19 — CALIBER conformal on the reconstruction, not detection scores.**
  Detector confidences cluster into point masses (degenerate conformal). The
  reconstruction relative error is *continuous*, so split-conformal intervals on
  it track nominal coverage exactly (0.95/0.90/0.80). Also on-message: CALIBER =
  reconstruction-calibrated confidence. Coverage reported *marginal over 200
  splits* (the guarantee is marginal), fixing single-split variance.
- **D20 — Bake-off numbers dropped from the console.** Fabricated competitor
  recall (RITA 0.58 etc.) risked looking dishonest. Replaced with **real measured
  per-class recall**; baseline comparison kept *qualitative/architectural* in the
  Dossier (they consume biflow features a diode doesn't provide).
- **D21 — Reconstruction sizes randomized + shuffled before conformal split** to
  restore exchangeability (the earlier index-structured sizes broke it → 6%
  undercoverage).

## Process / tracking

- **D22 — Concept depth came from a 13-agent workflow** (4 vision lenses + 8
  research dossiers + synthesis, ~717k tokens) grounded in real named techniques
  (Lomb-Scargle, FANCI, Little's Law, conformal prediction, Certificate-
  Transparency anchoring).
- **D23 — Maintain `decisions.md` / `progress.md` / `handoff.md`** and update at
  each milestone (user request).

## From simulation to real inputs

- **D24 — Real PCAP ingestion (`halfsight/pcap.py`).** The step from simulation
  to real is parsing actual capture bytes. Pure-python reader (Ethernet / raw-IP /
  Linux-cooked, IPv4, TCP/UDP, TCP timestamp option, DNS questions, partial-HTTP)
  so it needs no deps; auto-uses `dpkt`/`scapy` if present for pcapng/exotic link
  types. `write_pcap` emits Wireshark-openable classic pcaps for a real round-trip.
  Verified: write labeled traffic → read back → **all four threats detected from
  real pcap bytes**, incl. Slowloris via real partial-HTTP payload inspection and
  DGA/tunnel via real DNS message parsing.
- **D25 — Real domain data (`halfsight/dga_families.py`).** The problem asks for
  "DGA samples from published algorithms." Implemented the real **Cryptolocker**
  (date-seeded xorshift, Bader reference form) and a **dictionary DGA**
  (suppobox/matsnu style), scored against a **real benign top-domains list**
  (Tranco/Umbrella-style). This makes the DGA benchmark authentic and verifiable.
- **D26 — DGA classifier recalibrated ON real data (BUG FIX).** Real domains
  exposed an **8% false-positive rate** — the classifier flagged brandable names
  (windowsupdate, nvidia, npmjs, slack). Two root causes fixed: (a) the "shape"
  penalties (englishness/vowel/consonant) are now **length-gated** so short
  brandables don't accrue them; (b) the common-bigram table was too small, so real
  compound words scored as random — **expanded** it. Re-tuned weights vs the real
  benign set → **85.5% Cryptolocker recall at 0.7% FPR** (from 83.7% @ 8%).
- **D27 — Dictionary DGA is honestly low-recall (~1%) single-domain.** By design:
  dictionary DGAs use real words, so a per-domain classifier can't catch them —
  they need BABEL's cross-host WordGraph (not implemented in the reference). We
  **report the gap** in the eval rather than hiding it — the honesty is the point.
- **D28 — `ingest` CLI + labeled real pcaps.** `python3 -m halfsight.ingest
  <file.pcap>` runs the full pipeline on any real capture. `eval/make_pcaps.py`
  writes labeled sample pcaps (gitignored — regenerable, 2 MB binary). Added a
  7th eval (`eval_dga_realdata`) so `metrics.json` carries the real-data numbers.

## Real labeled dataset + a trained ML model

- **D29 — Real labeled DGA dataset.** Fetched the public **chrmor DGA_domains_dataset**
  (674,898 domains: 337k DGA across **25 real families** — conficker, cryptolocker,
  gozi, matsnu, necurs, ranbyus, suppobox, tinba… — + 337k Alexa legit) and the
  OpenDNS top-10k benign list, from public GitHub raw (netlab360 was unreachable).
  This is genuinely observed/real-algorithm data with family labels. Datasets are
  gitignored (20 MB); `datasets/fetch_datasets.sh` re-pulls them.
- **D30 — Trained ML model replaces hand weights (accuracy "up to the mark").**
  `dga_model.py` is a char-n-gram (1–4) **embedding-bag MLP** trained in pure numpy
  (dense-batch SGD, BLAS-accelerated — the sparse `np.add.at` version was too slow).
  Held-out test: **ROC-AUC 0.970, F1 0.90 @0.5, recall 94%** vs the heuristic's 54%.
  Committed as `dga_model.npz`, **float16-quantized to 7.7 MB** (from 15.5 MB;
  negligible loss) so it ships and runs out of the box.
- **D31 — 1% FPR operating point + per-host framing.** Calibrated the model
  threshold to 1% FPR on real legit (recall then 73% per-domain). Framed honestly:
  a bot cycles through many rendezvous domains, so **per-host detection is
  near-total** (the pipeline's dga scenario recall is 100%) even where per-domain
  dips. Arithmetic families 95–99%; dictionary families (nymaim/suppobox) are the
  known-hard per-domain case (need cross-host WordGraph) — reported, not hidden.
- **D32 — Wired the trained model into BABEL + pipeline reorder (BUG-guard).**
  `DGAClassifier` loads the model via a module-level cache (`load_cached`, so
  repeated `Pipeline()` builds don't re-read the 8 MB file). The model scores the
  *leftmost* label, which would flag a tunnel's high-entropy subdomains — so the
  pipeline now runs **DNS-tunnel detection first** and excludes detected tunnel
  2LDs from DGA scoring. Verified: demo + eval unchanged, 0% benign false-alarm.

## Real attack captures for EVERY threat class

- **D33 — All 6 threat classes validated on genuinely-real public captures (8/8).**
  Downloaded real DDoS (StopDDoS/packet-captures — real one-way DDoS traffic),
  real iodine + dnscat2 DNS tunnels (ggyggy666/DNS-Tunnel-Datasets), a real
  Slowloris capture (abastin99/PCAP_files), and a **real Cobalt Strike C2 beacon**
  (malware-traffic-analysis.net). `eval/validate_real.py` runs the pipeline on each
  and confirms detection. On the CS capture SPECTER recovered the **120s beacon
  interval (R=0.9997)** AND the trained DGA model flagged the generated domains.
- **D34 — Real data exposed & fixed 5 real detector bugs** (this is the value of
  real data): (1) an **O(n²) blowup** — `dns_by_domain` appended the flow once per
  qname, so a 17k-query tunnel built ~10^8 qnames and hung; fixed to aggregate per
  2LD. (2) A **reflection false-positive** on a normal client↔resolver DNS chat;
  fixed by requiring high byte-rate + many distinct reflectors. (3) **Missing
  amplifier ports** (ISAKMP/IPsec-NAT-T 4500, chargen, RIP, SNMP, …). (4) **TCP
  SYN-ACK reflection** wasn't handled at all — added a branch. (5) Rate was
  computed over a fixed window; now over the capture's **actual per-dst span** so
  sub-second real bursts score correctly.
- **D35 — Tunnel detector recalibrated for REAL tunnels.** The old gate required
  `unique_ratio > 0.7`, calibrated to synthetic 100%-unique subdomains. Real iodine
  **reuses** subdomains (52% unique) but hammers one 2LD 17k times, so added a
  query-**volume** feature and relaxed the gate. Bonus: synthetic tunnel recall
  rose 75% → 90% and macro F1 0.951 → 0.967.
- **D36 — MTA password scheme.** malware-traffic-analysis.net zips are AES with
  password `infected_YYYYMMDD` (scheme shown only as an image — read it via the
  browser). Extracted with `pyzipper`; macOS `unzip` can't do AES.
- **D37 — `validate_real.py` + `fetch_real_captures.sh`.** Reproducible: the fetch
  script pulls every capture from its public source; the validator ingests each and
  writes `results/real_pcap_validation.json`. Captures are gitignored (binary,
  large); the scripts + cited sources make them one command away.

## Roadmap Phase-1 hardening (post-validation)

- **D38 — GHOSTFLOW/PULSE hardened for 32-bit wrap + PAWS.** `types.py` now tracks
  ACK progression with RFC 1982 serial arithmetic and counts wraparounds
  (`ack_wraps`), so a long/high-volume flow crossing 2^32 reconstructs exactly (test:
  0.00% error across a wrap). `recover_ts_clock` unwraps the TSval series and applies
  a **PAWS-style filter** that drops old/reordered TSvals before fitting the clock
  (test: 1000 Hz recovered exactly across a TSval wrap). Documented that delayed-ACK /
  Nagle coarsen the ACK cadence but not the cumulative total, so the estimate stays an
  accurate lower bound. No eval regression (recon still ±4.3%).
- **D39 — Streaming chunked ingest for very large captures.** `ingest.run_streaming`
  (`--stream`) processes tumbling `window_s` windows — only one window of flows in
  memory at a time — into one hash-chained ledger, deduping alerts across windows. A
  tiny per-channel list of flow-start times is accumulated across the whole capture
  (just timestamps, bounded) and SPECTER runs over it at the end, so **long-period
  beacons split across windows are still caught**. Verified on real captures (dnscat2
  → 8 windows, synflood → 3 windows @5s, Cobalt Strike beacon caught across 300s windows).
- **D40 — Eval expansion: PR curve + graceful-degradation matrix.** `train_dga` now
  emits a precision-recall curve + **average precision** for the DGA model.
  `eval_degradation` measures the honest encrypted-transport matrix: **DoH** blinds
  lexical DGA/tunnel (qnames encrypted) but beacon TIMING survives 100%; **QUIC**
  removes ACK/timestamps so GHOSTFLOW degrades to the prior, but beacon timing
  survives. This turns the dossier's "graceful degradation" claim into measured data.
- **D41 — pytest suite + CI regression gate (the anti-regression guardrail).** 30
  tests in `reference-impl/tests/` cover every module (incl. the wrap-hardening and
  the Poisson-FP guard) and run in ~0.5s using the committed model + self-generated
  pcaps (no downloads). `.github/workflows/ci.yml` runs pytest + a synthetic eval and
  then `eval/ci_gate.py`, which **fails the build** if macro F1 < 0.90, false-alarm
  rate > 0.05, or DGA AUC < 0.93 — so a teammate's engine change that regresses the
  top-tier numbers is caught automatically. Floors sit below measured (0.967 / 0 /
  0.970) with margin for normal variance.
