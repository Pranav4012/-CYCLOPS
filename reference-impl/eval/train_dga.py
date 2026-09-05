#!/usr/bin/env python3
"""
Train + evaluate the CYCLOPS DGA model on REAL data.

Corpus: chrmor DGA_domains_dataset — 25 real DGA families (conficker, cryptolocker,
gozi, matsnu, necurs, ranbyus, suppobox, tinba, ...) vs real Alexa legit domains.
Trains a char-n-gram logistic model, calibrates the threshold to ~1% FPR, reports
overall + per-family metrics, compares against the hand-tuned heuristic, and saves
the model to halfsight/dga_model.npz (committed, so BABEL runs without the dataset).

    python3 -m eval.train_dga          # after datasets/fetch_datasets.sh

Deterministic (seeded).
"""
from __future__ import annotations

import json
import os

import numpy as np

from halfsight.dga_model import DGAModel, load_dataset, registrable_label
from halfsight.detectors.dga import DGAClassifier

DATA = os.path.join(os.path.dirname(__file__), "..", "datasets", "dga_domains_full.csv")
OUT = os.path.join(os.path.dirname(__file__), "results")
MODEL = os.path.join(os.path.dirname(__file__), "..", "halfsight", "dga_model.npz")


def auc(scores, y):
    order = np.argsort(scores)
    ranks = np.empty(len(scores)); ranks[order] = np.arange(1, len(scores) + 1)
    pos = y == 1; npos = pos.sum(); nneg = len(y) - npos
    if npos == 0 or nneg == 0:
        return 0.5
    return (ranks[pos].sum() - npos * (npos + 1) / 2) / (npos * nneg)


def prf(scores, y, thr):
    pred = scores >= thr
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / len(y)
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "fpr": fpr}


def main(train_per=3000, test_per=800):
    if not os.path.exists(DATA):
        print("dataset missing — run:  ./datasets/fetch_datasets.sh"); return
    rng = np.random.default_rng(7)
    rows = load_dataset(DATA)
    by_fam = {}
    legit = []
    for label, fam, dom in rows:
        if label == "dga":
            by_fam.setdefault(fam, []).append(dom)
        elif label == "legit":
            legit.append(dom)
    families = sorted(by_fam)
    print(f"loaded {len(rows)} rows · {len(families)} DGA families · {len(legit)} legit")

    # stratified split by family
    dtrain, dtest, test_fam = [], [], []
    for fam in families:
        d = by_fam[fam][:]; rng.shuffle(d)
        dtrain += d[:train_per]
        dtest += d[train_per:train_per + test_per]
        test_fam += [fam] * len(d[train_per:train_per + test_per])
    rng.shuffle(legit)
    ltr = legit[:len(dtrain)]; lte = legit[len(dtrain):len(dtrain) + len(dtest)]

    train_dom = dtrain + ltr
    train_y = np.array([1] * len(dtrain) + [0] * len(ltr), dtype=np.float64)
    train_lab = [registrable_label(x) for x in train_dom]
    test_dom = dtest + lte
    test_y = np.array([1] * len(dtest) + [0] * len(lte), dtype=np.float64)

    print(f"train {len(train_dom)} ({len(dtrain)} dga / {len(ltr)} legit) · "
          f"test {len(test_dom)} ({len(dtest)} dga / {len(lte)} legit)")
    print("training char-n-gram logistic model...")
    model = DGAModel(hidden=256).fit(train_lab, train_y, epochs=18, lr=0.2, verbose=True)

    # scores on test
    scores = model.scores(test_dom)
    a = auc(scores, test_y)

    # precision-recall curve + average precision (threshold-independent quality)
    def pr_curve(sc, y, n=26):
        lo, hi = float(sc.min()), float(sc.max())
        pts = []
        for i in range(n):
            t = lo + (hi - lo) * i / (n - 1)
            pred = sc >= t
            tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
            fn = int((~pred & (y == 1)).sum())
            p = tp / (tp + fp) if tp + fp else 1.0
            r = tp / (tp + fn) if tp + fn else 0.0
            pts.append((round(t, 4), round(p, 4), round(r, 4)))
        ps = sorted(pts, key=lambda x: x[2]); ap = 0.0; pr = 0.0
        for _, p, r in ps:
            ap += p * (r - pr); pr = r
        return pts, round(ap, 4)
    pr_pts, avg_prec = pr_curve(scores, test_y)
    # calibrate threshold to ~1% FPR on legit test
    legit_scores = np.sort(scores[test_y == 0])
    thr = float(legit_scores[int(0.99 * len(legit_scores))]) if len(legit_scores) else 0.5
    model.threshold = thr

    m_default = prf(scores, test_y, 0.5)
    m_cal = prf(scores, test_y, thr)

    # per-family recall at calibrated threshold
    per_family = {}
    dga_scores = scores[:len(dtest)]
    for fam in families:
        mask = np.array([f == fam for f in test_fam])
        per_family[fam] = round(float((dga_scores[mask] >= thr).mean()), 3)

    # compare heuristic on the same test set
    heur = DGAClassifier()
    hpred = np.array([heur.score(x).is_dga for x in test_dom])
    h_tp = int((hpred & (test_y == 1)).sum()); h_fp = int((hpred & (test_y == 0)).sum())
    h_recall = h_tp / max(1, int((test_y == 1).sum()))
    h_fpr = h_fp / max(1, int((test_y == 0).sum()))

    model.save(MODEL)
    os.makedirs(OUT, exist_ok=True)
    result = {
        "dataset": "chrmor/DGA_domains_dataset (25 real families) + Alexa legit",
        "families": len(families), "train_size": len(train_dom), "test_size": len(test_dom),
        "auc": round(a, 4), "average_precision": avg_prec,
        "pr_curve": [{"threshold": t, "precision": p, "recall": r} for t, p, r in pr_pts],
        "at_threshold_0.5": {k: round(v, 4) for k, v in m_default.items()},
        "calibrated_threshold": round(thr, 4),
        "at_calibrated_1pct_fpr": {k: round(v, 4) for k, v in m_cal.items()},
        "per_family_recall": per_family,
        "heuristic_baseline": {"recall": round(h_recall, 4), "fpr": round(h_fpr, 4)},
    }
    with open(os.path.join(OUT, "dga_model_metrics.json"), "w") as f:
        json.dump(result, f, indent=2)

    print("\n" + "=" * 66)
    print("  TRAINED DGA MODEL — real data (held-out test)")
    print("=" * 66)
    print(f"  AUC                {a:.4f}   avg-precision {avg_prec:.4f}")
    print(f"  @0.5    acc {m_default['accuracy']:.3f}  prec {m_default['precision']:.3f}  "
          f"rec {m_default['recall']:.3f}  F1 {m_default['f1']:.3f}  FPR {m_default['fpr']:.3f}")
    print(f"  @cal    acc {m_cal['accuracy']:.3f}  prec {m_cal['precision']:.3f}  "
          f"rec {m_cal['recall']:.3f}  F1 {m_cal['f1']:.3f}  FPR {m_cal['fpr']:.3f}  (thr {thr:.3f})")
    print(f"  heuristic baseline: recall {h_recall:.3f}  FPR {h_fpr:.3f}")
    print("\n  per-family recall @calibrated (worst 8):")
    for fam, r in sorted(per_family.items(), key=lambda kv: kv[1])[:8]:
        print(f"    {fam:14} {r*100:5.1f}%")
    print("  best 6:")
    for fam, r in sorted(per_family.items(), key=lambda kv: -kv[1])[:6]:
        print(f"    {fam:14} {r*100:5.1f}%")
    print(f"\n  saved model -> halfsight/dga_model.npz  ·  metrics -> eval/results/dga_model_metrics.json")
    print("=" * 66)
    return result


if __name__ == "__main__":
    main()
