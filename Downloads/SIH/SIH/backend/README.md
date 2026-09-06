# CYCLOPS Backend API

This is the Person 2 deliverable. It is the application bridge between the future UI and the real `reference-impl/halfsight` engine. PCAP uploads are streamed to a temporary file and queued so the HTTP worker is not blocked by CPU-heavy detection.

## Run from the repository root

Use Python 3.11 or 3.13. Python 3.15 pre-release builds are not supported by the current NumPy/FastAPI dependency stack.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload --port 8000
```

API documentation is available at `http://localhost:8000/docs`.

## Endpoints

- `GET /api/status`
- `GET /api/integrations` reports the exact teammate snapshots and active adapters
- `GET /api/alerts` and `GET /api/alerts/{id}`
- `GET /api/flows` and `GET /api/flows/{id}`
- `GET /api/evidence` and `GET /api/evidence/{id}`
- `GET /api/evidence/{id}/verify` verifies the alert digest and WIRESEAL chain
- `GET /api/incidents` and `GET /api/incidents/{id}` return correlated incidents
- `GET /api/incidents/{id}/explanation` returns human-readable detection reasons
- `GET /api/metrics` returns measured packet, flow, alert, incident, and throughput metrics
- `POST /api/pcap/upload` for `.pcap` and `.pcapng`; returns `202` with a `job_id`
- `GET /api/jobs/{job_id}` for queued, processing, completed, or failed status
- `WS /api/live` for compact `job_queued`, `job_completed`, `job_failed`, and alert events

Collection endpoints support bounded pagination: `?limit=50&offset=0` (maximum page size: 200).

`/api/status` reports detector health and measured `processing_seconds`, `packets_per_second`, and `flows_per_second` from the last completed analysis. The default upload limit is 1 GiB and can be changed with `CYCLOPS_MAX_UPLOAD_BYTES`.

## Persistence

The backend uses SQLite automatically for local development. For PostgreSQL, set `DATABASE_URL` before starting the server:

```powershell
$env:DATABASE_URL = "postgresql://cyclops:password@localhost:5432/cyclops"
uvicorn backend.app.main:app --reload --port 8000
```

The service persists PCAP jobs, alerts, flows, and evidence records. PostgreSQL tables are created automatically on startup; production deployments should run migrations instead of relying on automatic table creation.

The service is intentionally in-memory for this first slice. Each job gets an isolated `FlowTable`, `Pipeline`, CALIBER, and WIRESEAL ledger; up to two jobs are processed concurrently. Restarting the process clears the API snapshot and job history.