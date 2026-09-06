# CYCLOPS — Deployment

One container runs everything: the FastAPI backend, the `halfsight` engine, and
the static SOC console (served at `/`).

## Run with Docker (recommended)

```bash
docker compose up --build
```

Open **http://localhost:8000** — upload a `.pcap`, watch alerts + the live feed,
click **verify** on any alert to check its WIRESEAL seal.

## Run without Docker

```bash
pip install -r reference-impl/backend/requirements.txt
cd reference-impl
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

Then open http://localhost:8000.

## What's wired

- `GET  /`                          → SOC console (frontend)
- `GET  /api/status` `/api/metrics`  → engine + detector health, ledger state
- `POST /api/pcap/upload`            → queue a capture (returns `job_id`)
- `GET  /api/jobs/{id}`              → job progress
- `GET  /api/alerts` `/api/flows`    → paginated results
- `GET  /api/evidence/{id}/verify`   → WIRESEAL tamper check
- `WS   /api/live`                    → live event stream (status/alerts)

## Config

| Env var | Default | Meaning |
|---|---|---|
| `CYCLOPS_MAX_UPLOAD_BYTES` | `1073741824` (1 GiB) | max capture upload size |

The SQLite alert/evidence store lives in `reference-impl/backend/` and is
persisted via the `cyclops-data` volume in `docker-compose.yml`.

## Production notes (roadmap, not required for the demo)

- Lock `CORSMiddleware` origins in `backend/app/main.py` to your deployed frontend host.
- The async job queue is in-memory — jobs are lost on restart (fine for demo; use a
  real queue for production).
- Add an auth token in front of `/api/*` if the service is publicly exposed.
- Pin exact dependency versions for reproducible image builds.
