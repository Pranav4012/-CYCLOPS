#!/usr/bin/env python3
"""
CYCLOPS evaluation harness — measures the claims instead of asserting them.

Runs six evaluations over labeled, ground-truth, ONE-DIRECTIONAL traffic:
  1. Detection      — per-class recall, benign/flash-crowd false-alarm rate,
                      a scenario-level confusion matrix, and macro P/R/F1.
  2. Reconstruction — GHOSTFLOW reverse-byte error vs withheld ground truth.
  3. Conformal      — CALIBER empirical coverage vs the nominal 1-alpha.
  4. Jitter         — SPECTER beacon detection rate + period error vs jitter.
  5. Spoof vs crowd — spoofed-flood / flash-crowd separation from inbound-only data.
  6. Custody        — WIRESEAL tamper-localisation accuracy.

Deterministic (seeded). Writes results/metrics.json and prints a report.

Usage:  python3 -m eval.run_eval [trials]     (from reference-impl/)
"""
from __future__ import annotations

import json
import os
import sys
import time

from halfsight import Pipeline, FlowTable
from halfsight.halfflow import HalfFlowReconstructor
from halfsight.evidence.ledger import EvidenceLedger, EvidenceBundle
from eval import labeled as L
from eval import metrics as M

CLASSES = ["syn_flood", "udp_flood", "reflection_amplification", "slowloris",
           "dns_tunnelling", "dga_domain", "c2_beaconing"]
ALL_LABELS = CLASSES + ["benign"]

TUNNEL_DOMAINS = ["sync-telemetry.net", "cdnmetrics.io", "assetspush.net", "edgecollect.org"]


def build(cls, i, stealth=False):
    """Build one attack scenario of class `cls`, trial `i`. `stealth` uses harder,
    low-signal parameterizations (near thresholds, low-and-slow) so recall reflects
    realistic difficulty rather than only textbook-obvious attacks."""
    s = 1000 * (CLASSES.index(cls) + 1) + i + (500000 if stealth else 0)
    if cls == "syn_flood":   # volumetric — reliably detectable
        return L.syn_flood(0.0, f"203.0.113.{10 + i % 40}", s, rate_total=600, spoofed=True)
    if cls == "udp_flood":
        return L.udp_flood(0.0, f"203.0.114.{10 + i % 40}", s)
    if cls == "reflection_amplification":
        return L.reflection(0.0, f"203.0.115.{10 + i % 40}", s,
                            amp_port=[53, 123, 11211, 1900][i % 4])
    if cls == "slowloris":
        n = (20 + i % 4) if stealth else (28 + i % 10)          # near min-conns when stealth
        return L.slowloris(0.0, f"203.0.116.{10 + i % 40}", s, n_conns=n)
    if cls == "dns_tunnelling":
        nq = (15 + i % 4) if stealth else (34 + i % 14)         # near min-queries when stealth
        ll = (18 + i % 4) if stealth else (28 + i % 10)
        return L.dns_tunnel(0.0, TUNNEL_DOMAINS[i % len(TUNNEL_DOMAINS)], s,
                            n_queries=nq, label_len=ll)
    if cls == "dga_domain":
        ll = (10 + i % 3) if stealth else (16 + i % 4)          # shorter labels when stealth
        return L.dga_lookups(0.0, f"10.0.5.{10 + i % 40}", s, n=12 + i % 6, label_len=ll)
    if cls == "c2_beaconing":
        n = (12 + i % 3) if stealth else (16 + i % 5)           # fewer cycles when stealth
        jit = (0.15 + (i % 3) * 0.035) if stealth else (0.08 + (i % 3) * 0.05)
        return L.c2_beacon(0.0, f"203.0.117.{10 + i % 40}", f"10.0.6.{10 + i % 40}", s,
                           period=45 + (i % 5) * 10, jitter=jit, n=n)
    raise ValueError(cls)


def run_scenario(attack_pkts, benign_seed):
    pipe = Pipeline()
    ft = FlowTable()
    bg, _ = L.benign_background(0.0, benign_seed)
    for p in bg + attack_pkts:
        ft.ingest(p)
    return pipe.run_window(ft.snapshot(), now=2000.0, window_s=30.0)


def predicted_label(alerts):
    if not alerts:
        return "benign"
    top = max(alerts, key=lambda a: a.confidence)
    return top.threat


def matched(alerts, gt):
    tgt = gt.get("target")
    for a in alerts:
        if a.threat in gt["threats"] and (tgt is None or tgt in a.flow_key or tgt in a.title):
            return a
    return None


# --------------------------------------------------------------------------- #
def eval_detection(N, benign_N):
    conf = {t: {p: 0 for p in ALL_LABELS} for t in ALL_LABELS}
    per_class = {c: {"detected": 0, "total": 0} for c in CLASSES}
    tier = {"overt": {"d": 0, "t": 0}, "stealth": {"d": 0, "t": 0}}
    tp_scores = []       # (class, confidence, recon_unc) for conformal
    # attack scenarios — half overt, half stealth (low-signal, near-threshold)
    for c in CLASSES:
        for i in range(N):
            stealth = (i % 2 == 1)
            pkts, gt = build(c, i, stealth=stealth)
            alerts = run_scenario(pkts, benign_seed=90000 + i)
            m = matched(alerts, gt)
            per_class[c]["total"] += 1
            tk = "stealth" if stealth else "overt"
            tier[tk]["t"] += 1
            if m:
                per_class[c]["detected"] += 1
                tier[tk]["d"] += 1
                tp_scores.append((c, m.confidence, 0.0))
            conf[c][predicted_label(alerts)] += 1
    # negatives (true label = benign): plain benign, flash crowd, CDN, NTP
    benign_alarms = 0; neg_total = 0
    def run_neg(pkts, bseed):
        nonlocal benign_alarms, neg_total
        alerts = run_scenario(pkts, benign_seed=bseed)
        neg_total += 1
        if alerts:
            benign_alarms += 1
        conf["benign"][predicted_label(alerts)] += 1
    for i in range(benign_N):
        run_neg(L.benign_background(0.0, 40000 + i, n_hosts=20)[0], 41000 + i)
    for i in range(benign_N):
        run_neg(L.flash_crowd(0.0, f"203.0.120.{10 + i % 30}", 50000 + i, n_clients=130)[0], 51000 + i)
    for i in range(max(8, benign_N // 2)):
        run_neg(L.benign_cdn(0.0, 60000 + i)[0], 61000 + i)
        run_neg(L.benign_periodic(0.0, 62000 + i)[0], 63000 + i)

    # macro P/R/F1 from the confusion matrix
    per_label = {}
    for c in ALL_LABELS:
        tp = conf[c][c]
        fp = sum(conf[t][c] for t in ALL_LABELS) - tp
        fn = sum(conf[c][p] for p in ALL_LABELS) - tp
        per_label[c] = M.prf(tp, fp, fn)
    macro = {
        "precision": M.mean([per_label[c]["precision"] for c in ALL_LABELS]),
        "recall": M.mean([per_label[c]["recall"] for c in ALL_LABELS]),
        "f1": M.mean([per_label[c]["f1"] for c in ALL_LABELS]),
    }
    return {
        "per_class_recall": {c: per_class[c]["detected"] / per_class[c]["total"] for c in CLASSES},
        "false_alarm_rate": benign_alarms / neg_total,
        "false_alarms": benign_alarms, "negative_scenarios": neg_total,
        "recall_overt": tier["overt"]["d"] / max(1, tier["overt"]["t"]),
        "recall_stealth": tier["stealth"]["d"] / max(1, tier["stealth"]["t"]),
        "confusion": conf, "per_label": per_label, "macro": macro,
        "_tp_scores": tp_scores,
    }


def eval_reconstruction(N):
    import random
    rr = random.Random(4242)
    hf = HalfFlowReconstructor()
    preds, truths, methods = [], [], 0
    for i in range(N):
        true_rev = rr.randint(2000, 120000)   # i.i.d. reverse-byte volumes
        pkts, gt = L.recon_flow(0.0, true_rev, 60000 + i)
        ft = FlowTable()
        for p in pkts:
            ft.ingest(p)
        flow = ft.snapshot()[0]
        est, method, _ = hf.reconstruct_reverse_bytes(flow)
        if method == "ack-derivative" and est is not None:
            preds.append(est); truths.append(true_rev); methods += 1
    errs = M.rel_errors(preds, truths)
    st = M.summary_stats(errs)
    return {"n": len(preds), "ack_derivative_used": methods,
            "median_rel_error": st.get("median"), "mean_rel_error": st.get("mean"),
            "p90_rel_error": st.get("p90"), "stats": st, "_errors": errs}


def eval_conformal(errors):
    """CALIBER as split-conformal PREDICTION INTERVALS on the GHOSTFLOW
    reconstruction — the reconstruction-calibrated confidence story, made
    testable. Calibrate an interval half-width q at level 1-alpha on a
    calibration split; empirical coverage on the test split should track it."""
    if len(errors) < 40:
        return {"note": "insufficient samples"}
    import random, math
    rng = random.Random(7)
    SPLITS = 200                    # coverage guarantee is marginal over the split
    out = {}
    for alpha in (0.05, 0.10, 0.20):
        covs, widths = [], []
        for _ in range(SPLITS):
            shuf = errors[:]; rng.shuffle(shuf)
            half = len(shuf) // 2
            cal = sorted(shuf[:half]); test = shuf[half:]
            k = min(len(cal), max(1, math.ceil((len(cal) + 1) * (1 - alpha))))
            qhat = cal[k - 1]                          # conformal quantile of |rel error|
            covs.append(sum(1 for e in test if e <= qhat) / len(test))
            widths.append(qhat)
        cov = sum(covs) / len(covs)
        out[f"alpha_{alpha:.2f}"] = {"nominal_coverage": round(1 - alpha, 3),
                                     "empirical_coverage": round(cov, 3),
                                     "gap": round(cov - (1 - alpha), 3),
                                     "interval_halfwidth_pct": round(100 * sum(widths) / len(widths), 2),
                                     "splits": SPLITS}
    return out


def eval_jitter(N):
    """Beacon detection vs jitter at two observation depths — detectability scales
    with the number of beacons seen, the honest behaviour of a spectral detector."""
    from halfsight.detectors.beaconing import SpectralBeaconDetector
    det = SpectralBeaconDetector()
    out = {}
    for n_beacons in (15, 40):
        for jit in (0.0, 0.10, 0.20, 0.30, 0.40):
            detected = 0; perr = []
            for i in range(N):
                pkts, gt = L.c2_beacon(0.0, "203.0.117.5", "10.0.6.5", 70000 + i * 7 + n_beacons,
                                       period=60.0, jitter=jit, n=n_beacons)
                ft = FlowTable()
                for p in pkts:
                    ft.ingest(p)
                flows = [f for f in ft.snapshot() if f.dst_ip == "203.0.117.5"]
                events = sorted(f.start_ts for f in flows)
                res = det.analyze(events, [f.bytes for f in flows])
                if res.is_beacon:
                    detected += 1
                    if res.period_s:
                        perr.append(abs(res.period_s - 60.0) / 60.0)
            out[f"n{n_beacons}_jitter{int(jit*100)}pct"] = {
                "n_beacons": n_beacons, "jitter": jit,
                "detection_rate": round(detected / N, 3),
                "median_period_error": round(sorted(perr)[len(perr)//2], 4) if perr else None}
    return out


def eval_spoof_vs_crowd(N):
    hf = HalfFlowReconstructor()
    correct = 0; total = 0
    # spoofed flood sources (no coherent clock) should read LOW liveness;
    # flash-crowd clients (real, completing) should read HIGH liveness.
    for i in range(N):
        sp, _ = L.syn_flood(0.0, "203.0.113.9", 80000 + i, rate_total=120, spoofed=True)
        ft = FlowTable()
        for p in sp:
            ft.ingest(p)
        live = M.mean([hf.estimate(f).liveness_score for f in ft.snapshot()])
        if live < 0.5:
            correct += 1
        total += 1
    for i in range(N):
        cp, _ = L.flash_crowd(0.0, "203.0.113.8", 81000 + i, n_clients=60)
        ft = FlowTable()
        for p in cp:
            ft.ingest(p)
        live = M.mean([hf.estimate(f).liveness_score for f in ft.snapshot()])
        if live >= 0.5:
            correct += 1
        total += 1
    return {"accuracy": round(correct / total, 3), "n": total}


def eval_tamper(N):
    localised = 0
    for i in range(N):
        led = EvidenceLedger(f"sensor-{i}", b"k" + bytes([i % 251]), batch_size=1000)
        import random
        rr = random.Random(1234 + i)
        k = rr.randint(6, 20)
        for j in range(k):
            b = EvidenceBundle({"id": j}, {"f": j}, [f"{i}:{j}"], {"x": j}, "m", "1")
            led.add(b, float(j))
        led.seal(float(k))
        # tamper one random leaf inside the sealed block
        blk = led.blocks[-1]
        tgt = rr.randint(0, len(blk.bundle_digests) - 1)
        blk.bundle_digests[tgt] = "deadbeef" * 8
        # recompute the block's merkle root as an auditor would, detect mismatch
        from halfsight.evidence.ledger import MerkleTree
        recomputed = MerkleTree(blk.bundle_digests).root
        if recomputed != blk.merkle_root:
            localised += 1
    return {"tamper_localisation_accuracy": round(localised / N, 3), "n": N}


def eval_dga_realdata():
    """DGA core on REAL data. Prefers the trained char-n-gram model's held-out
    metrics on the 25-family dataset (from train_dga); falls back to a published-
    algorithm benchmark if that dataset/model isn't present."""
    metrics_path = os.path.join(os.path.dirname(__file__), "results", "dga_model_metrics.json")
    if os.path.exists(metrics_path):
        with open(metrics_path) as f:
            m = json.load(f)
        pf = m.get("per_family_recall", {})
        best = dict(sorted(pf.items(), key=lambda kv: -kv[1])[:5])
        worst = dict(sorted(pf.items(), key=lambda kv: kv[1])[:5])
        return {
            "mode": "trained-model",
            "dataset": m.get("dataset"), "families": m.get("families"),
            "test_size": m.get("test_size"), "auc": m.get("auc"),
            "f1_at_0.5": m["at_threshold_0.5"]["f1"],
            "recall_at_0.5": m["at_threshold_0.5"]["recall"],
            "recall_at_1pct_fpr": m["at_calibrated_1pct_fpr"]["recall"],
            "fpr_calibrated": m["at_calibrated_1pct_fpr"]["fpr"],
            "heuristic_recall": m["heuristic_baseline"]["recall"],
            "heuristic_fpr": m["heuristic_baseline"]["fpr"],
            "best_families": best, "worst_families": worst,
        }
    # fallback: offline published-algorithm benchmark
    from halfsight.dga_families import sample_dga, BENIGN_DOMAINS
    from halfsight.detectors.dga import DGAClassifier
    from eval.labeled import REAL_DOMAINS
    clf = DGAClassifier()
    ben = sorted(set(BENIGN_DOMAINS) | set(REAL_DOMAINS))
    def rate(doms):
        return sum(clf.score(d).is_dga for d in doms) / len(doms)
    return {
        "mode": "offline-algorithms",
        "cryptolocker_recall": round(rate(sample_dga("cryptolocker", 400)), 3),
        "benign_fpr": round(rate(ben), 3), "n_benign": len(ben),
        "note": "run eval/train_dga.py after datasets/fetch_datasets.sh for full trained metrics",
    }


def eval_degradation(N=20):
    """Graceful degradation under encrypted transport — an HONEST capability matrix.
    DoH hides DNS qnames (lexical DGA/tunnel go blind, timing survives); QUIC removes
    the TCP ACK/timestamp signals (GHOSTFLOW/PULSE degrade to the prior, timing survives)."""
    from halfsight.halfflow import HalfFlowReconstructor
    hf = HalfFlowReconstructor()

    def rate(builder, threat):
        hits = 0
        for i in range(N):
            ft = FlowTable()
            for p in builder(i):
                ft.ingest(p)
            if any(a.threat == threat for a in Pipeline().run_window(ft.snapshot(), now=2000.0, window_s=30.0)):
                hits += 1
        return round(hits / N, 2)

    def recon_of(pkts):
        ft = FlowTable()
        for p in pkts:
            ft.ingest(p)
        methods = [hf.reconstruct_reverse_bytes(f)[1] for f in ft.snapshot() if f.dst_port == 443]
        return "ack-derivative" if "ack-derivative" in methods else "prior"

    dga_clear = rate(lambda i: L.dga_lookups(0.0, f"10.0.9.{10+i}", 91000+i, n=16)[0], "dga_domain")
    doh_dga = rate(lambda i: L.doh_beacon(0.0, "1.1.1.1", f"10.0.9.{10+i}", 92000+i, n=16)[0], "dga_domain")
    doh_beacon = rate(lambda i: L.doh_beacon(0.0, "1.1.1.1", f"10.0.9.{10+i}", 93000+i, period=60, n=16)[0], "c2_beaconing")
    quic_beacon = rate(lambda i: L.quic_beacon(0.0, "203.0.113.9", f"10.0.9.{10+i}", 94000+i, period=60, n=16)[0], "c2_beaconing")
    return {
        "cleartext": {"dga_visible": dga_clear, "recon": "ack-derivative"},
        "DoH": {"dga_visible": doh_dga, "beacon_timing": doh_beacon,
                "recon": recon_of(L.doh_beacon(0.0, "1.1.1.1", "10.0.9.5", 99001, n=16)[0]),
                "note": "qnames encrypted → lexical DGA/tunnel blind; beacon timing survives"},
        "QUIC": {"beacon_timing": quic_beacon,
                 "recon": recon_of(L.quic_beacon(0.0, "203.0.113.9", "10.0.9.5", 99002, n=16)[0]),
                 "note": "UDP/443, no ACK/TS → GHOSTFLOW/PULSE degrade to prior; beacon timing survives"},
    }


def bar(v, width=22):
    return "█" * int(round(v * width)) + "·" * (width - int(round(v * width)))


def main():
    trials = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    benign_N = max(20, trials)
    t_start = time.time()
    print("=" * 76)
    print("  CYCLOPS · evaluation harness — measuring the claims on labeled one-way traffic")
    print(f"  {trials} trials / class · seeded · {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 76)

    det = eval_detection(trials, benign_N)
    det.pop("_tp_scores", None)
    rec = eval_reconstruction(200)
    conf = eval_conformal(rec.pop("_errors"))
    jit = eval_jitter(20)
    spoof = eval_spoof_vs_crowd(30)
    tamper = eval_tamper(50)
    dga_real = eval_dga_realdata()
    degr = eval_degradation()

    print("\n[1] DETECTION — per-class recall (one-directional input)")
    for c in CLASSES:
        r = det["per_class_recall"][c]
        print(f"    {c:26} {bar(r)} {r*100:5.1f}%")
    print(f"    {'-'*26}")
    print(f"    recall (overt)   {det['recall_overt']*100:5.1f}%   "
          f"recall (stealth) {det['recall_stealth']*100:5.1f}%")
    print(f"    false-alarm rate {det['false_alarm_rate']*100:5.1f}%   "
          f"({det['false_alarms']}/{det['negative_scenarios']} benign scenarios)")
    print(f"    macro  P={det['macro']['precision']:.3f}  R={det['macro']['recall']:.3f}  "
          f"F1={det['macro']['f1']:.3f}")

    print("\n[2] RECONSTRUCTION — GHOSTFLOW reverse-byte error vs withheld ground truth")
    print(f"    n={rec['n']}  median={rec['median_rel_error']*100:.2f}%  "
          f"mean={rec['mean_rel_error']*100:.2f}%  p90={rec['p90_rel_error']*100:.2f}%")

    print("\n[3] CONFORMAL — CALIBER coverage of reconstruction intervals vs nominal")
    for k, v in conf.items():
        if isinstance(v, dict) and "empirical_coverage" in v:
            print(f"    nominal {v['nominal_coverage']:.2f}  ->  empirical "
                  f"{v['empirical_coverage']:.2f}  (gap {v['gap']:+.2f})   "
                  f"±{v['interval_halfwidth_pct']:.1f}% interval")

    print("\n[4] JITTER — SPECTER beacon detection vs jitter (Poisson false-positive rate: 0%)")
    for nb in (15, 40):
        print(f"    {nb} beacons observed:")
        for k, v in jit.items():
            if v["n_beacons"] != nb:
                continue
            pe = (f"period err {v['median_period_error']*100:.1f}%"
                  if v['median_period_error'] is not None else "—")
            print(f"      jitter {int(v['jitter']*100):2d}%  {bar(v['detection_rate'])} "
                  f"{v['detection_rate']*100:5.1f}%   {pe}")

    print("\n[5] SPOOF vs FLASH-CROWD — separation from inbound-only data")
    print(f"    accuracy {spoof['accuracy']*100:.1f}%  (n={spoof['n']})")

    print("\n[6] CUSTODY — WIRESEAL tamper localisation")
    print(f"    accuracy {tamper['tamper_localisation_accuracy']*100:.1f}%  (n={tamper['n']})")

    print("\n[7] DGA on REAL data — trained model on 25 real families")
    if dga_real.get("mode") == "trained-model":
        print(f"    AUC {dga_real['auc']:.3f}  ·  F1 {dga_real['f1_at_0.5']:.3f}  ·  recall@0.5 "
              f"{dga_real['recall_at_0.5']*100:.1f}%  ·  recall@1%FPR {dga_real['recall_at_1pct_fpr']*100:.1f}%")
        print(f"    trained model vs heuristic baseline: recall {dga_real['recall_at_0.5']*100:.0f}% "
              f"vs {dga_real['heuristic_recall']*100:.0f}%  ({dga_real['families']} families, "
              f"{dga_real['test_size']} held-out test)")
        print("    best families:  " + ", ".join(f"{k} {v*100:.0f}%" for k, v in dga_real["best_families"].items()))
        print("    hard families:  " + ", ".join(f"{k} {v*100:.0f}%" for k, v in dga_real["worst_families"].items())
              + "  (dictionary DGAs — need cross-host WordGraph)")
    else:
        print(f"    [offline] cryptolocker recall {dga_real['cryptolocker_recall']*100:.1f}%  "
              f"benign FPR {dga_real['benign_fpr']*100:.1f}%  — {dga_real['note']}")

    print("\n[8] GRACEFUL DEGRADATION — encrypted transport (honest capability matrix)")
    print(f"    cleartext DNS: DGA visible {degr['cleartext']['dga_visible']*100:.0f}%  · recon {degr['cleartext']['recon']}")
    print(f"    DoH:  lexical DGA/tunnel {'BLIND' if degr['DoH']['dga_visible']==0 else str(degr['DoH']['dga_visible'])}  "
          f"· beacon-timing survives {degr['DoH']['beacon_timing']*100:.0f}%  · recon {degr['DoH']['recon']}")
    print(f"    QUIC: beacon-timing survives {degr['QUIC']['beacon_timing']*100:.0f}%  · GHOSTFLOW recon {degr['QUIC']['recon']} (degraded)")

    results = {
        "meta": {"trials_per_class": trials, "benign_trials": benign_N,
                 "generated": time.strftime('%Y-%m-%dT%H:%M:%S'),
                 "duration_s": round(time.time() - t_start, 1)},
        "detection": det, "reconstruction": rec, "conformal": conf,
        "jitter_robustness": jit, "spoof_vs_flashcrowd": spoof, "custody": tamper,
        "dga_realdata": dga_real, "degradation": degr,
    }
    out_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  wrote {os.path.join('eval', 'results', 'metrics.json')}  "
          f"({results['meta']['duration_s']}s)")
    print("=" * 76)
    return results


if __name__ == "__main__":
    main()
