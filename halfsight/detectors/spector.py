from __future__ import annotations

import statistics
from datetime import datetime
from typing import Iterable

BEACON_MIN_SAMPLES = 4          # need at least this many connections to judge regularity
BEACON_CV_THRESHOLD = 0.15      # coefficient of variation below this = suspiciously regular
BEACON_SCORE_THRESHOLD = 1.0 - (BEACON_CV_THRESHOLD / 0.6)
BEACON_MIN_INTERVAL_SEC = 5.0   # ignore sub-5s bursts, that's not beaconing, that's a burst


def _parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def interarrival_regularity_score(timestamps: list[str]) -> float:
    """
    Returns 0-1, higher = more periodic/regular.
    Uses coefficient of variation (stdev/mean) of inter-arrival times,
    inverted and clamped so a perfectly regular beacon scores near 1.0
    and bursty/human traffic scores near 0.0.
    """
    if len(timestamps) < BEACON_MIN_SAMPLES:
        return 0.0

    times = sorted(_parse_ts(t) for t in timestamps)
    intervals = [
        (times[i + 1] - times[i]).total_seconds()
        for i in range(len(times) - 1)
    ]
    intervals = [i for i in intervals if i >= BEACON_MIN_INTERVAL_SEC]
    if len(intervals) < BEACON_MIN_SAMPLES - 1:
        return 0.0

    mean = statistics.mean(intervals)
    if mean == 0:
        return 0.0
    stdev = statistics.pstdev(intervals)
    cv = stdev / mean

    # invert: cv=0 (perfectly regular) -> score 1.0; cv>=0.6 -> score ~0
    score = max(0.0, 1.0 - (cv / 0.6))
    return round(min(score, 1.0), 3)


def detect(flows_by_pair: dict[tuple[str, str], list[dict]]) -> list[dict]:
    """
    flows_by_pair: {(src_ip, dst_ip): [flow, flow, ...]} already grouped upstream.
    Returns a list of Alert dicts (schemas/alert.schema.json) for pairs
    that look like C2 beaconing.
    """
    alerts = []
    for (src_ip, dst_ip), flows in flows_by_pair.items():
        timestamps = [f["timestamp"] for f in flows]
        score = interarrival_regularity_score(timestamps)

        if score >= BEACON_SCORE_THRESHOLD:
            alerts.append({
                "timestamp": flows[-1]["timestamp"],
                "flow_id": flows[-1]["flow_id"],
                "threat_class": "botnet_c2_beaconing",
                "confidence": score,
                "severity": "high" if score > 0.8 else "medium",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "evidence": {
                    "interarrival_regularity_score": score,
                    "sample_count": len(flows),
                },
                "detector": "specter:periodicity_v1",
            })
    return alerts