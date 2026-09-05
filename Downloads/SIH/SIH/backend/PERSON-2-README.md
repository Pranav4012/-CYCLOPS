# Backend Contribution

## Branch

```text
person-2-backend
```

## Role

I am the backend owner for CYCLOPS.

My responsibility is to expose the work of the HalfSight detection engine as a usable, testable service for a future frontend or SIEM consumer.

```text
PCAP
  -> FastAPI
  -> REST / WebSocket
  -> PCAP job queue
  -> FlowTable
  -> HalfSight Pipeline
  -> Detectors
  -> CALIBER
  -> Correlation Engine
  -> WIRESEAL
  -> Alerts / Incidents / Evidence / Metrics
```

## What I Built

### 1. FastAPI application

Implemented the backend application in `backend/app/main.py`.

The API provides:

- REST endpoints for service data.
- WebSocket events for live updates.
- CORS support for a future frontend.
- OpenAPI documentation at `/docs`.
- HTTP validation for PCAP uploads.
- Bounded pagination for collection endpoints.

### 2. PCAP upload service

Implemented PCAP upload handling through:

```text
POST /api/pcap/upload
```

The upload process:

1. Validates `.pcap` and `.pcapng` extensions.
2. Streams the upload in 1 MiB chunks.
3. Writes the capture to a temporary file.
4. Enforces the `CYCLOPS_MAX_UPLOAD_BYTES` limit.
5. Returns HTTP `202 Accepted` immediately.
6. Creates a background processing job.

Example response:

```json
{
  "job_id": "pcap_366b5314bd",
  "status": "queued"
}
```

### 3. Background PCAP workers

Implemented a two-worker `ThreadPoolExecutor` in `backend/app/service.py`.

Jobs support these states:

```text
queued -> processing -> completed
                       -> failed
```

Each job records:

- Job ID.
- Source filename.
- Current status.
- Progress percentage.
- Packets processed.
- Flows detected.
- Processing time.
- Packets per second.
- Flows per second.
- Error details when processing fails.

Job status endpoint:

```text
GET /api/jobs/{job_id}
```

### 4. HalfSight engine integration

Connected the backend to the real engine under `reference-impl/halfsight`.

The backend uses:

- `read_pcap` for packet decoding.
- `FlowTable` for one-directional flow aggregation.
- `Pipeline` for detector execution.
- SPECTER for beaconing detection.
- BABEL for DGA and DNS tunnel detection.
- FLOODLIGHT for flood/reflection detection.
- HOURGLASS for Slowloris detection.
- CALIBER for confidence and alert scoring.
- WIRESEAL for evidence sealing and chain-of-custody.

Each PCAP job receives a new isolated pipeline and ledger.

### 5. Alert API

Implemented:

```text
GET /api/alerts
GET /api/alerts/{alert_id}
```

Alert records include:

- Alert ID.
- Detector.
- Threat type.
- Severity.
- Confidence.
- Source.
- Destination.
- Flow key.
- Evidence ID.
- Detector evidence.
- Feature contributions.

Collection responses support pagination:

```text
GET /api/alerts?limit=50&offset=0
```

### 6. Flow API

Implemented:

```text
GET /api/flows
GET /api/flows/{flow_id}
```

Flow records include:

- One-way flow ID.
- Source endpoint.
- Destination endpoint.
- Protocol.
- Direction.
- Packet count.
- Byte count.
- Duration.
- Start timestamp.
- End timestamp.

### 7. Evidence API

Implemented:

```text
GET /api/evidence
GET /api/evidence/{evidence_id}
GET /api/evidence/{evidence_id}/verify
```

Evidence records include:

- Evidence ID.
- Related alert ID.
- Threat type.
- SHA-256 digest.
- Merkle root.
- Verification state.
- WIRESEAL chain state.

The verification endpoint lets a frontend or SIEM display whether evidence remains intact.

### 8. Correlation engine

Implemented in `backend/app/correlation.py`.

The correlation engine groups alerts by:

- Observed source host.
- Five-minute time bucket.

It combines related detector output into a single incident record instead of presenting every detector alert as an unrelated event.

The engine creates:

- Incident ID.
- Host.
- Related detections.
- Incident confidence.
- Heuristic threat score.
- Severity.
- Timeline.
- Recommendation.
- Explanation reasons.
- Supporting detectors.
- Detection chain.
- Evidence verification state.

### 9. Explainable threat scoring

Implemented in `backend/app/scoring.py`.

The score combines:

- Highest detector confidence.
- Number of independent detectors.
- Detector agreement.

The output is explicitly labelled:

```json
{
  "threat_score": 70,
  "score_type": "heuristic",
  "severity": "high"
}
```

This is a heuristic presentation score. It is not claimed to be a newly calibrated CALIBER score.

### 10. Incident API

Implemented:

```text
GET /api/incidents
GET /api/incidents/{incident_id}
GET /api/incidents/{incident_id}/explanation
```

An incident contains:

- Incident ID.
- Host.
- Severity.
- Heuristic threat score.
- Confidence.
- Related detections.
- Timeline.
- Explanation.
- Recommended action.
- Detection chain.
- Evidence verification status.

Example detection chain:

```json
[
  "PCAP",
  "FLOW",
  "BABEL",
  "SPECTER",
  "CALIBER",
  "CORRELATION",
  "WIRESEAL"
]
```

### 11. Metrics API

Implemented:

```text
GET /api/metrics
```

The metrics response exposes:

- Packets processed.
- Flows created.
- Alerts generated.
- Incidents created.
- Packets per second.
- Flows per second.

The status endpoint also reports:

- Detector health.
- Job counters.
- Storage backend.
- WIRESEAL state.
- Last processing performance.

### 12. Event-driven WebSocket

Implemented:

```text
WS /api/live
```

The WebSocket sends compact event messages instead of repeatedly sending the complete state.

Supported event categories include:

- `READY`
- `HEALTH`
- `JOB_QUEUED`
- `JOB_COMPLETED`
- `JOB_FAILED`
- `ALERTS_UPDATED`

A client can send `ping` or `snapshot` and receive a health response.

### 13. Persistence

Implemented in `backend/app/storage.py`.

The backend supports:

- SQLite automatically for local development.
- PostgreSQL through `DATABASE_URL`.
- SQLAlchemy database access.
- Persistent PCAP jobs.
- Persistent alerts.
- Persistent flows.
- Persistent evidence.
- Persistent incidents.

Local database files are ignored by Git.

PostgreSQL configuration example:

```powershell
$env:DATABASE_URL = "postgresql://cyclops:password@localhost:5432/cyclops"
```

### 14. Package exports

Updated `backend/app/__init__.py` to expose:

```python
from .main import app
from .service import CyclopsService
```

This allows:

```python
from backend.app import app, CyclopsService
```

## Files I Own

```text
backend/
├── .env.example
├── PERSON-2-README.md
├── README.md
├── requirements.txt
└── app/
    ├── __init__.py
    ├── main.py
    ├── service.py
    ├── storage.py
    ├── correlation.py
    └── scoring.py
```

## Dependencies Added

```text
fastapi
uvicorn
python-multipart
SQLAlchemy
psycopg[binary]
httpx2
numpy
```

Python 3.11 or 3.13 should be used. Python 3.15 pre-release builds caused compatibility errors with NumPy and FastAPI dependencies.

## How to Run

From the repository root:

```powershell
cd C:\Users\USER\Downloads\SIH\SIH
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
uvicorn backend.app.main:app --app-dir . --host 127.0.0.1 --port 8000
```

Open the API documentation:

```text
http://127.0.0.1:8000/docs
```

## How to Test PCAP Upload

In another PowerShell window:

```powershell
cd C:\Users\USER\Downloads\SIH\SIH
curl.exe -X POST `
  -F "file=@reference-impl\pcaps\mixed.pcap" `
  http://127.0.0.1:8000/api/pcap/upload
```

Copy the returned job ID and query it:

```powershell
curl.exe http://127.0.0.1:8000/api/jobs/pcap_YOUR_REAL_ID
```

Do not type the literal text `YOUR_REAL_ID`; replace it with the actual returned ID.

## Validation Results

The backend was tested against the repository capture:

```text
Capture: reference-impl/pcaps/mixed.pcap
Packets processed: 1,512
Flows created: 810
Alerts generated: 15
Correlated incidents: 3
Evidence records: 15
WIRESEAL chain: intact
```

Measured local performance varied by run and environment. Representative results were:

```text
Processing time: approximately 0.10 - 0.65 seconds
Packets/sec: approximately 2,300 - 15,100
Flows/sec: approximately 1,200 - 8,000
```

These are local measurements on the included fixture, not universal production benchmarks.

## Tests Completed

- Python compilation.
- Package import validation.
- Real HalfSight PCAP processing.
- Alert count validation.
- Flow count validation.
- Evidence verification.
- SQLite persistence reload.
- REST status endpoint.
- REST pagination.
- PCAP upload response.
- Background job status.
- Incident endpoint.
- Incident explanation endpoint.
- Metrics endpoint.
- WebSocket ready event.
- WebSocket health event.

## Contribution Summary For Presentation

> I built the CYCLOPS backend service that converts uploaded one-way PCAP traffic into usable cybersecurity intelligence. My backend queues PCAP processing, builds one-directional flows, runs the HalfSight detector pipeline, correlates independent alerts into incidents, calculates explainable heuristic threat scores, creates timelines and detection chains, verifies WIRESEAL evidence, persists results, and exposes everything through REST and WebSocket APIs.

## Git Commands

Review the branch:

```powershell
git branch --show-current
git status
```

Expected branch:

```text
person-2-backend
```

Stage and commit the Person 2 work:

```powershell
git add backend .gitignore
git commit -m "feat: complete Person 2 backend intelligence service"
```

Push the branch:

```powershell
git push -u origin person-2-backend
```
