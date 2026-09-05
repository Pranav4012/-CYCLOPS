"""Correlate detector alerts into explainable incident records."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .scoring import score_incident


def _host(alert: dict[str, Any]) -> str:
    source = str(alert.get("source", "unknown"))
    return source.split(":", 1)[0] if source not in {"", "*"} else "unknown"


def _timestamp(value: Any) -> str:
    return datetime.fromtimestamp(float(value), timezone.utc).isoformat()


def correlate(alerts: list[dict[str, Any]], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group alerts by observed source and a five-minute analysis window."""
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for alert in alerts:
        bucket = int(float(alert.get("ts", 0)) // 300)
        groups.setdefault((_host(alert), bucket), []).append(alert)

    evidence_ids = {item["id"] for item in evidence}
    incidents = []
    for index, ((host, _bucket), detections) in enumerate(sorted(groups.items()), 1):
        detections.sort(key=lambda item: float(item.get("ts", 0)))
        compact = [{"alert_id": item["id"], "detector": item["detector"],
                    "type": item["threat"], "confidence": item["confidence"],
                    "evidence_id": item.get("evidence_id")} for item in detections]
        scoring = score_incident(compact)
        timeline = [{"timestamp": _timestamp(item["ts"]), "type": item["threat"].upper(),
                     "detector": item["detector"], "alert_id": item["id"]}
                    for item in detections]
        detector_names = {item["detector"] for item in detections}
        reasons = []
        if "beaconing" in detector_names or any(item["threat"] == "c2_beaconing" for item in detections):
            reasons.append("Periodic outbound communication")
        if "dga" in detector_names or any(item["threat"] == "dga_domain" for item in detections):
            reasons.append("Suspicious generated domain")
        if "dns_tunnel" in detector_names or any(item["threat"] == "dns_tunnelling" for item in detections):
            reasons.append("High-capacity DNS naming pattern")
        if not reasons:
            reasons.append("Anomalous network behavior scored by the detection ensemble")
        incident_id = f"INC-{index:04d}"
        incidents.append({
            "incident_id": incident_id,
            "host": host,
            **scoring,
            "confidence": round(max(item["confidence"] for item in compact), 4),
            "detections": compact,
            "timeline": timeline,
            "recommendation": "Investigate and isolate host" if scoring["severity"] in {"high", "critical"} else "Continue monitoring",
            "explanation": {"summary": "Correlated network threat detected",
                            "reasons": reasons,
                            "supporting_detectors": sorted(detector_names)},
            "chain": ["PCAP", "FLOW", *sorted(detector_names), "CALIBER",
                      "CORRELATION", "WIRESEAL"],
            "evidence_verified": all(item.get("evidence_id") in evidence_ids for item in compact),
        })
    return incidents
