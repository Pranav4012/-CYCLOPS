#!/usr/bin/env python3
"""CI regression gate: fail the build if the headline eval numbers drop.

Run AFTER `python3 -m eval.run_eval <trials>` (which writes results/metrics.json).
Floors are set below the measured values with margin so normal variance passes but
a real regression fails.
"""
import json
import os
import sys

F1_FLOOR = 0.90        # measured 0.967 at 30 trials
FPR_CEIL = 0.05        # measured 0.0
AUC_FLOOR = 0.93       # trained DGA model, measured 0.970

path = os.path.join(os.path.dirname(__file__), "results", "metrics.json")
m = json.load(open(path))
d = m["detection"]
f1 = d["macro"]["f1"]
fpr = d["false_alarm_rate"]
auc = m.get("dga_realdata", {}).get("auc", 1.0)

print(f"  macro F1        = {f1:.3f}   (floor {F1_FLOOR})")
print(f"  false-alarm rate= {fpr:.3f}   (ceil  {FPR_CEIL})")
print(f"  DGA model AUC   = {auc:.3f}   (floor {AUC_FLOOR})")

fails = []
if f1 < F1_FLOOR:
    fails.append(f"macro F1 {f1:.3f} < {F1_FLOOR}")
if fpr > FPR_CEIL:
    fails.append(f"false-alarm {fpr:.3f} > {FPR_CEIL}")
if auc < AUC_FLOOR:
    fails.append(f"DGA AUC {auc:.3f} < {AUC_FLOOR}")

if fails:
    print("EVAL GATE: FAIL — " + "; ".join(fails), file=sys.stderr)
    sys.exit(1)
print("EVAL GATE: PASS")
