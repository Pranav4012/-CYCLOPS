"""Queued application service adapting the HalfSight engine to API records."""
from __future__ import annotations

import os
import hashlib
import json
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

ENGINE_ROOT = Path(__file__).resolve().parents[2] / "reference-impl"
sys.path.insert(0, str(ENGINE_ROOT))

from halfsight.pcap import read_pcap  # noqa: E402
from halfsight.pipeline import FlowTable, Pipeline  # noqa: E402
from .storage import Storage
from .correlation import correlate

DEMO_PCAP = ENGINE_ROOT / "pcaps" / "mixed.pcap"
DEMO_REPLAY_INTERVAL_S = 45.0


class CyclopsService:
    """Queue PCAP jobs and keep the latest analysis snapshot in memory."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._storage = Storage()
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cyclops-pcap")
        self._jobs: dict[str, dict[str, Any]] = {
            job["job_id"]: job for job in self._storage.load_jobs()}
        self._events: deque[dict[str, Any]] = deque(maxlen=256)
        self._subscribers: set[Callable[[dict[str, Any]], None]] = set()
        self._alerts: list[dict[str, Any]] = []
        self._flows: list[dict[str, Any]] = []
        self._evidence: list[dict[str, Any]] = []
        self._incidents: list[dict[str, Any]] = self._storage.load_records("incidents")
        self._ledger = {"sensor_id": "api-sensor-01", "blocks": 1,
                        "pending": 0, "anchored_blocks": 0,
                        "chain_intact": True, "first_broken_block": None,
                        "head": None}
        self._stats = {"packets": 0, "span_s": 0.0, "source": "empty"}
        self._performance = {"processing_seconds": 0.0,
                             "packets_per_second": 0.0,
                             "flows_per_second": 0.0, "last_job_id": None}
        self._updated_at = time.time()
        self._alerts = self._storage.load_records("alerts")
        self._flows = self._storage.load_records("flows")
        self._evidence = self._storage.load_records("evidence")

        self._demo_autoplay = True
        if DEMO_PCAP.exists():
            if not self._alerts and not self._flows:
                threading.Thread(target=self._seed_demo_data, daemon=True,
                                 name="cyclops-demo-seed").start()
            if os.getenv("CYCLOPS_DEMO_REPLAY", "").strip().lower() in {"1", "true", "yes"}:
                threading.Thread(target=self._demo_replay_loop, daemon=True,
                                 name="cyclops-demo-replay").start()

    def _seed_demo_data(self) -> None:
        try:
            self.analyze_file(str(DEMO_PCAP), source=DEMO_PCAP.name)
        except Exception:
            pass

    def _demo_replay_loop(self) -> None:
        while self._demo_autoplay:
            time.sleep(DEMO_REPLAY_INTERVAL_S)
            if not self._demo_autoplay:
                return
            try:
                self.analyze_file(str(DEMO_PCAP), source=DEMO_PCAP.name)
            except Exception:
                pass

    @staticmethod
    def _flow_record(flow: Any) -> dict[str, Any]:
        return {"id": flow.key, "source": f"{flow.src_ip}:{flow.src_port}",
                "destination": f"{flow.dst_ip}:{flow.dst_port}",
                "protocol": flow.proto, "direction": "OBSERVED",
                "packets": flow.packets, "bytes": flow.bytes,
                "duration_s": round(flow.duration, 3),
                "start_ts": flow.start_ts, "end_ts": flow.last_ts}

    @staticmethod
    def _alert_record(alert: Any, index: int) -> dict[str, Any]:
        record = alert.to_record()
        record.update({"id": f"ALT-{index:04d}",
                       "evidence_id": f"EV-{index:04d}",
                       "source": alert.flow_key.split("->", 1)[0],
                       "destination": alert.flow_key.split("->", 1)[-1]})
        return record

    def _emit(self, event: dict[str, Any]) -> None:
        event.setdefault("event", event.get("type", "event").upper())
        with self._lock:
            self._events.append(event)
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber(event)
            except Exception:
                self.unsubscribe(subscriber)

    def subscribe(self, subscriber: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            self._subscribers.add(subscriber)

    def unsubscribe(self, subscriber: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            self._subscribers.discard(subscriber)

    def submit_file(self, path: str, source: str) -> str:
        self._demo_autoplay = False
        job_id = f"pcap_{uuid.uuid4().hex[:10]}"
        with self._lock:
            self._jobs[job_id] = {"job_id": job_id, "status": "queued",
                                  "progress": 0, "source": source,
                                  "packets_processed": 0, "flows_detected": 0,
                                  "created_at": time.time(), "error": None}
            self._storage.upsert_job(self._jobs[job_id])
        self._emit({"type": "job_queued", "job_id": job_id, "status": "queued"})
        self._executor.submit(self._run_job, job_id, path, source)
        return job_id

    def _set_job(self, job_id: str, **updates: Any) -> None:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].update(updates)
                self._storage.upsert_job(self._jobs[job_id])

    def _run_job(self, job_id: str, path: str, source: str) -> None:
        self._set_job(job_id, status="processing", progress=5)
        try:
            result = self.analyze_file(path, source=source, job_id=job_id)
            self._set_job(job_id, status="completed", progress=100,
                          completed_at=time.time(), result={
                              "alerts": len(result["alerts"]),
                              "flows": len(result["flows"]),
                              "performance": result["performance"],
                          })
            self._emit({"type": "job_completed", "job_id": job_id,
                        "status": "completed", "alerts": len(result["alerts"])})
        except Exception as exc:
            self._set_job(job_id, status="failed", progress=100,
                          completed_at=time.time(), error=str(exc))
            self._emit({"type": "job_failed", "job_id": job_id,
                        "status": "failed", "error": str(exc)})
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def job(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            value = self._jobs.get(job_id)
            return dict(value) if value else None

    def analyze_file(self, path: str, source: str | None = None,
                     job_id: str | None = None) -> dict[str, Any]:
        started = time.perf_counter()
        pipeline = Pipeline(sensor_id="api-sensor-01")
        table = FlowTable()
        packet_count = 0
        first_ts = last_ts = None
        for packet in read_pcap(path, backend="auto"):
            table.ingest(packet)
            packet_count += 1
            first_ts = packet.ts if first_ts is None else first_ts
            last_ts = packet.ts

        flows = table.snapshot()
        if job_id:
            self._set_job(job_id, progress=80, packets_processed=packet_count,
                          flows_detected=len(flows))
        now = (last_ts or time.time()) + 1.0
        alerts = pipeline.run_window(flows, now=now, window_s=60.0)
        pipeline.seal_and_anchor(now)
        span = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0
        elapsed = max(time.perf_counter() - started, 0.000001)
        alert_records = [self._alert_record(alert, i) for i, alert in enumerate(alerts, 1)]

        with self._lock:
            self._alerts = alert_records
            self._flows = [self._flow_record(flow) for flow in flows]
            self._evidence = [{"id": alert["evidence_id"], "alert_id": alert["id"],
                               "threat": alert["threat"], "status": "SEALED",
                               "ts": alert["ts"],
                               "sha256": hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest(),
                               "merkle_root": pipeline.ledger.blocks[-1].merkle_root,
                               "verified": True} for alert in alert_records]
            self._incidents = correlate(alert_records, self._evidence)
            self._storage.replace_records("alerts", self._alerts, "id")
            self._storage.replace_records("flows", self._flows, "id")
            self._storage.replace_records("evidence", self._evidence, "id")
            self._storage.replace_records("incidents", self._incidents, "incident_id")
            self._ledger = pipeline.ledger.summary()
            self._stats = {"packets": packet_count, "span_s": round(span, 2),
                           "source": source or os.path.basename(path)}
            self._performance = {"processing_seconds": round(elapsed, 4),
                                 "packets_per_second": round(packet_count / elapsed, 2),
                                 "flows_per_second": round(len(flows) / elapsed, 2),
                                 "last_job_id": job_id}
            if job_id:
                self._jobs[job_id]["performance"] = dict(self._performance)
            self._updated_at = time.time()
        self._emit({"type": "alerts_updated", "count": len(alert_records)})
        return self.snapshot()

    def analyze_bytes(self, filename: str, payload: bytes) -> dict[str, Any]:
        suffix = Path(filename).suffix.lower() or ".pcap"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as capture:
            capture.write(payload)
            temp_path = capture.name
        try:
            return self.analyze_file(temp_path, source=filename)
        finally:
            os.unlink(temp_path)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {"updated_at": self._updated_at, "stats": dict(self._stats),
                    "alerts": list(self._alerts), "flows": list(self._flows),
                    "evidence": list(self._evidence),
                    "incidents": list(self._incidents),
                    "performance": dict(self._performance),
                    "ledger": dict(self._ledger)}

    def page(self, name: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        limit = max(1, min(limit, 200))
        with self._lock:
            values = list(getattr(self, f"_{name}"))
        return {"items": values[offset:offset + limit], "offset": offset,
                "limit": limit, "total": len(values),
                "next_offset": offset + limit if offset + limit < len(values) else None}

    def verify_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        with self._lock:
            evidence = next((item for item in self._evidence if item["id"] == evidence_id), None)
            if evidence is None:
                return None
            alert = next((item for item in self._alerts if item["id"] == evidence["alert_id"]), None)
            digest = hashlib.sha256(json.dumps(alert or {}, sort_keys=True).encode()).hexdigest()
            verified = digest == evidence.get("sha256") and self._ledger.get("chain_intact", False)
            return {"evidence_id": evidence_id, "sha256": evidence.get("sha256"),
                    "merkle_root": evidence.get("merkle_root"), "verified": verified,
                    "ledger_chain_intact": self._ledger.get("chain_intact", False)}

    def job_counts(self) -> dict[str, int]:
        with self._lock:
            counts = {"queued": 0, "processing": 0, "completed": 0, "failed": 0}
            for job in self._jobs.values():
                counts[job["status"]] = counts.get(job["status"], 0) + 1
            return counts

    def status(self) -> dict[str, Any]:
        state = self.snapshot()
        return {"service": "cyclops-api", "status": "online",
                "engine": "halfsight-ensemble", "engine_version": "0.3.1",
                "sensor_id": state["ledger"]["sensor_id"],
                "updated_at": state["updated_at"], "stats": state["stats"],
                "performance": state["performance"], "jobs": self.job_counts(),
                "metrics": {"packets_processed": state["stats"]["packets"],
                            "flows_created": len(state["flows"]),
                            "alerts_generated": len(state["alerts"]),
                            "incidents_created": len(state["incidents"]),
                            "processing": {"packets_per_second": state["performance"]["packets_per_second"],
                                            "flows_per_second": state["performance"]["flows_per_second"]}},
                "detectors": {"SPECTER": "online", "BABEL": "online",
                               "FLOODLIGHT": "online", "HOURGLASS": "online",
                               "CALIBER": "online", "WIRESEAL": "online"},
                "storage": {"backend": self._storage.backend, "persistent": True},
                "ledger": state["ledger"]}
