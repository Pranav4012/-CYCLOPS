# SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Smart India Hackathon 2026 · PS 26145 · Sponsoring Organisation: National Technical Research Organisation (NTRO)

An AI/ML pipeline that ingests a one-directional (read-only) stream of IP traffic and detects,
classifies, and scores cyber-security threats in near real time — without ever being able to
contact the traffic's source, complete a handshake, decrypt payload, or send anything back
across the ingest path.

## Problem summary

Critical-infrastructure operators monitor gateway/peering links using passive mirroring or
hardware data diodes: traffic flows into a monitoring enclave in one direction only. The
enclave sees everything but can never talk back. This system must work purely from what it
can passively observe — packet captures, flow records (NetFlow/IPFIX/sFlow), and derived
metadata.

### Threats detected

| # | Threat | Signal |
|---|--------|--------|
| a | Volumetric/protocol DDoS | Flow-level rate + source-IP entropy |
| b | Botnet C2 beaconing | Periodicity / inter-arrival time analysis |
| c | DGA domains & DNS tunnelling | Entropy/n-gram analysis of DNS query names |
| d | Malware in encrypted sessions | JA3/JA3S/JA4 fingerprints, packet size/timing (no decryption) |
| e | Reconnaissance / port scanning | Fan-out across destination ports/hosts |
| f | Data exfiltration | Outbound-to-inbound byte ratio anomalies |

### Hard constraints

- **Read-only ingest** — no return path, no live query to the source, no inline blocking.
- **No payload decryption** — TLS/QUIC analysed from metadata only.
- **Streaming, not batch** — incremental processing, bounded latency, not an end-of-run report.
- **Defined throughput target** — must state and demonstrate tested flows/sec or Mbps.
- **Standardized alert schema** — timestamp, flow ID, threat class, confidence score, evidence.

## Architecture

```
Synthetic/replayed traffic (PCAP or flow records)
        |  (read-only ingest)
        v
Feature extraction  (rate, entropy, periodicity, fan-out, byte ratios, JA3 fingerprints)
        v
Detection engine  (rule thresholds + ML models)
        v
Structured alerts  (JSON: timestamp, flow_id, threat_class, confidence, evidence)
        v
Streaming API  (FastAPI + WebSocket)
        v
Dashboard  (React)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the detailed data flow and
[`schemas/`](schemas/) for the exact contracts between stages.

## Repo structure

```
SIH26145/
├── README.md                  <- you are here
├── docs/
│   ├── ARCHITECTURE.md        <- pipeline + data flow detail
│   └── BENCHMARKS.md          <- throughput/latency results (fill in after testing)
├── schemas/
│   ├── flow.schema.json       <- output of ingest
│   ├── feature_vector.schema.json  <- output of feature extraction
│   └── alert.schema.json      <- output of detection engine
├── backend/
│   ├── requirements.txt
│   └── src/sih_detector/
│       ├── ingest/            <- Track A: traffic replay + flow parsing
│       ├── features/          <- Track B: feature extraction (2 people)
│       ├── detection/         <- Track C: rules + ML models
│       └── api/               <- Track D: FastAPI + WebSocket + benchmarking
├── frontend/
│   ├── package.json
│   └── src/
│       ├── components/        <- Track E: dashboard UI
│       ├── hooks/
│       └── pages/
├── benchmarks/                <- throughput/latency test scripts + results
└── data/samples/               <- sample/synthetic traffic + example flow-schema JSON
```

## Team ownership (6 tracks)

| Track | Folder | Owner(s) |
|---|---|---|
| A — Ingest | `backend/src/sih_detector/ingest/` | Person 1 |
| B — Features (DDoS/Recon/Exfil) | `backend/src/sih_detector/features/` | Person 2 |
| B — Features (C2/DGA/Encrypted) | `backend/src/sih_detector/features/` | Person 3 |
| C — Detection/ML | `backend/src/sih_detector/detection/` | Person 4 |
| D — API/Backend/Streaming | `backend/src/sih_detector/api/` | Person 5 |
| E — Frontend/Dashboard | `frontend/` | Person 6 |

## Getting started

### Backend
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn sih_detector.api.main:app --app-dir src --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## Branching model

- `main` stays stable — nobody pushes directly.
- One feature branch per track: `feat/ingest`, `feat/features-a`, `feat/features-b`,
  `feat/detection`, `feat/api`, `feat/frontend`.
- Everyone builds against the schemas in `schemas/` from minute one, using mocked
  data where needed, so tracks stay unblocked until the integration window.
- Integration merge order: `ingest` → `features-a`/`features-b` → `detection` → `api` → `frontend`.

## Status

- [ ] Schemas locked
- [ ] Ingest working (replay → flows)
- [ ] Feature extraction — DDoS / Recon / Exfil
- [ ] Feature extraction — C2 / DGA / Encrypted malware
- [ ] Detection engine (rules + ML)
- [ ] API + WebSocket streaming
- [ ] Dashboard
- [ ] Benchmarked throughput/latency (`docs/BENCHMARKS.md`)
- [ ] Demo rehearsed
