from __future__ import annotations

import math
import re
from collections import Counter

import dga_families
import dga_model

ENTROPY_THRESHOLD = 3.2          # bits/char above this looks randomly generated
QUERY_LEN_THRESHOLD = 50         # chars — legit hostnames are rarely this long
TUNNEL_QUERY_RATE_THRESHOLD = 20 # queries/host in a window — tunnelling repeats a lot

# Common English bigrams, used as a crude "does this look like a real word" check.
# Real domains have DNS-common bigrams like "th", "an", "in"; DGA output doesn't.
_COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
}


def shannon_entropy(s: str) -> float:
    """Bits per character. Random strings score high (~4+), real words score low (~2-3)."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def ngram_score(label: str) -> float:
    """
    0-1, higher = more DGA-like. Counts what fraction of consecutive bigrams
    in the label are NOT common English bigrams. Random strings score near 1.0.
    """
    label = re.sub(r"[^a-z]", "", label.lower())
    if len(label) < 2:
        return 0.0
    bigrams = [label[i:i + 2] for i in range(len(label) - 1)]
    uncommon = sum(1 for b in bigrams if b not in _COMMON_BIGRAMS)
    return round(uncommon / len(bigrams), 3)


def _extract_label(qname: str) -> str:
    """The subdomain/leftmost label is usually where DGA/tunnelling noise lives."""
    parts = qname.split(".")
    return parts[0] if parts else qname


def detect(flows_with_dns: list[dict]) -> list[dict]:
    """
    flows_with_dns: Flow dicts where flow["dns_query"] is not None.
    Returns Alert dicts for queries that look like DGA or tunnelling.
    """
    alerts = []

    # tunnelling needs a per-source query count — build that first
    query_counts: dict[str, int] = {}
    for f in flows_with_dns:
        query_counts[f["src_ip"]] = query_counts.get(f["src_ip"], 0) + 1

    for f in flows_with_dns:
        dns = f.get("dns_query")
        if not dns or not dns.get("qname"):
            continue

        qname = dns["qname"]
        label = _extract_label(qname)
        tld = qname.split(".")[-1] if "." in qname else None

        entropy = round(shannon_entropy(label), 3)
        ngram = ngram_score(label)
        is_long = len(qname) >= QUERY_LEN_THRESHOLD
        is_high_rate = query_counts.get(f["src_ip"], 0) >= TUNNEL_QUERY_RATE_THRESHOLD

        # known-family match is a strong, explainable signal — check it first
        family = dga_families.match_family(label, tld)
        # trained-model score, if dga_model.npz exists; None means fall back to heuristic
        model_prob = dga_model.model_score(label)

        heuristic_dga = entropy >= ENTROPY_THRESHOLD and ngram >= 0.6
        is_dga = bool(family) or heuristic_dga or (model_prob is not None and model_prob >= 0.7)
        is_tunnel = is_long or is_high_rate

        if not (is_dga or is_tunnel):
            continue

        confidence = max(
            0.95 if family else 0.0,
            model_prob if model_prob is not None else 0.0,
            min(entropy / 5.0, 1.0) if heuristic_dga else 0.0,
            0.75 if is_tunnel else 0.0,
        )

        evidence = {
            "qname": qname,
            "entropy": entropy,
            "ngram_score": ngram,
            "query_length": len(qname),
            "queries_from_src": query_counts.get(f["src_ip"], 0),
        }
        if family:
            evidence["dga_family"] = family.name
        if model_prob is not None:
            evidence["model_probability"] = model_prob

        detector_tag = "babel:family_match" if family else (
            "babel:trained_model" if model_prob is not None else "babel:entropy_ngram_v1"
        )

        alerts.append({
            "timestamp": f["timestamp"],
            "flow_id": f["flow_id"],
            "threat_class": "dga_dns_tunnelling",
            "confidence": round(confidence, 3),
            "severity": "high" if confidence > 0.8 else "medium",
            "src_ip": f["src_ip"],
            "dst_ip": f.get("dst_ip", ""),
            "evidence": evidence,
            "detector": detector_tag,
        })
    return alerts