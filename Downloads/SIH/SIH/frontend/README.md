# CYCLOPS Person 6 Frontend and Integration

This is the Person 6 deliverable: frontend engineering plus full-stack integration and validation.

## What it does

The console consumes the real Person 2 backend. It does not use scripted alert data.

- Overview metrics from `GET /api/metrics`.
- Correlated incidents from `GET /api/incidents`.
- Explainable incidents and heuristic threat scores.
- Detector alerts from `GET /api/alerts`.
- WIRESEAL records from `GET /api/evidence`.
- Live evidence status from `/api/evidence/{id}/verify` data.
- Team integration status from `GET /api/integrations`.
- PCAP upload through `POST /api/pcap/upload`.
- Live refresh through `WS /api/live` events.

## Run

Start the backend first:

```powershell
cd C:\Users\USER\Downloads\SIH\SIH
.\.venv\Scripts\Activate.ps1
uvicorn backend.app.main:app --app-dir . --host 127.0.0.1 --port 8000
```

Then serve the frontend in a second terminal:

```powershell
cd C:\Users\USER\Downloads\SIH\SIH\frontend
python -m http.server 3000
```

Open `http://127.0.0.1:3000`.

The frontend uses `http://127.0.0.1:8000` by default. A deployment can set `window.CYCLOPS_API` before loading `app.js` to point at another backend.

## Person 6 integration boundary

```text
Person 4 PCAP / flow input
        -> Person 1 HalfSight inference
        -> Person 3 detectors
        -> Person 5 CALIBER / WIRESEAL
        -> Person 2 REST + WebSocket API
        -> Person 6 console + integration tests
```

The teammate branches were selectively integrated at the API contract. Their branch histories contain incompatible repository layouts, so the current engine and backend were preserved while the frontend consumes the stable outputs they expose.
