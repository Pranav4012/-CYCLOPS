"""CYCLOPS REST and event WebSocket API."""
from __future__ import annotations

import asyncio
import os
import tempfile

from fastapi import FastAPI, File, HTTPException, Query, UploadFile, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .service import CyclopsService

app = FastAPI(title="CYCLOPS API", version="0.2.0",
              description="Queued passive one-way network detection API")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000",
                    "http://127.0.0.1:3000"], allow_credentials=False,
                    allow_methods=["GET", "POST"], allow_headers=["*"])
service = CyclopsService()


@app.get("/api/status")
def get_status():
    return service.status()


@app.get("/api/alerts")
def get_alerts(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return service.page("alerts", limit, offset)


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = next((item for item in service.snapshot()["alerts"]
                  if item["id"] == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return alert


@app.get("/api/flows")
def get_flows(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return service.page("flows", limit, offset)


@app.get("/api/flows/{flow_id:path}")
def get_flow(flow_id: str):
    flow = next((item for item in service.snapshot()["flows"]
                 if item["id"] == flow_id), None)
    if flow is None:
        raise HTTPException(status_code=404, detail="flow not found")
    return flow


@app.get("/api/evidence")
def get_evidence(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return service.page("evidence", limit, offset)


@app.get("/api/evidence/{evidence_id}")
def get_evidence_item(evidence_id: str):
    evidence = next((item for item in service.snapshot()["evidence"]
                     if item["id"] == evidence_id), None)
    if evidence is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return evidence


@app.get("/api/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: str):
    evidence = service.verify_evidence(evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="evidence not found")
    return evidence


@app.get("/api/incidents")
def get_incidents(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    return service.page("incidents", limit, offset)


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    incident = next((item for item in service.snapshot()["incidents"]
                     if item["incident_id"] == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@app.get("/api/incidents/{incident_id}/explanation")
def get_incident_explanation(incident_id: str):
    incident = get_incident(incident_id)
    return {"incident_id": incident_id, **incident["explanation"]}


@app.get("/api/metrics")
def get_metrics():
    return service.status()["metrics"]


@app.post("/api/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)):
    filename = file.filename or "capture.pcap"
    if not filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=415,
                            detail="only .pcap and .pcapng files are supported")
    max_bytes = int(os.getenv("CYCLOPS_MAX_UPLOAD_BYTES", str(1024 * 1024 * 1024)))
    suffix = os.path.splitext(filename)[1].lower()
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as capture:
            temp_path = capture.name
            total = 0
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(status_code=413, detail="capture exceeds upload limit")
                capture.write(chunk)
        if total == 0:
            raise HTTPException(status_code=400, detail="uploaded capture is empty")
        job_id = service.submit_file(temp_path, filename)
        temp_path = None
        return JSONResponse(status_code=202,
                            content={"job_id": job_id, "status": "queued"})
    except HTTPException:
        raise
    except OSError as exc:
        raise HTTPException(status_code=500,
                            detail=f"capture could not be saved: {exc}") from exc
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    job = service.job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job


@app.websocket("/api/live")
async def live(websocket: WebSocket):
    await websocket.accept()
    loop = asyncio.get_running_loop()
    events: asyncio.Queue[dict[str, object]] = asyncio.Queue()

    def receive_event(event: dict[str, object]) -> None:
        loop.call_soon_threadsafe(events.put_nowait, event)

    service.subscribe(receive_event)
    await websocket.send_json({"type": "ready", "event": "READY",
                               "data": {"status": "connected"}})
    try:
        while True:
            receive_task = asyncio.create_task(websocket.receive_text())
            event_task = asyncio.create_task(events.get())
            done, pending = await asyncio.wait({receive_task, event_task},
                                               return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            finished = done.pop().result()
            if isinstance(finished, dict):
                await websocket.send_json(finished)
            elif finished.lower() in {"ping", "snapshot"}:
                await websocket.send_json({"type": "health", "event": "HEALTH",
                                           "data": service.status()})
    except Exception:
        await websocket.close()
    finally:
        service.unsubscribe(receive_event)


# --- Static frontend (served at / so the whole app is one container) -----------
# Mounted LAST so it never shadows the /api/* routes above.
from pathlib import Path  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402

_FRONTEND_DIR = Path(__file__).resolve().parents[3] / "frontend"
if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
