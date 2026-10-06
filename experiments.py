"""Robustness + ablation experiments for the project report.

    python experiments.py            # 5 seeds, writes reports/experiments.md

* Robustness: regenerate the whole company with different random seeds (different
  users, habits, attack victims) and re-measure. Shows results are not a one-off.
* Ablation: switch detection layers off to show what each contributes, in
  particular how well the *behavioural* layers do WITHOUT any hand-written rules.
"""
from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from ueba.config import CONFIG, REPORTS_DIR
from ueba.generator import generate_dataset
from ueba.pipeline import run
from ueba.risk import daily_risk

VARIANTS = {
    "Full system (baseline + peer + ML + rules)": dict(),
    "Without threat rules (behaviour only)": dict(rule=0),
    "Without ML ensemble": dict(ml=0),
    "Personal baseline only": dict(peer=0, ml=0, rule=0),
    "ML ensemble only": dict(stat=0, peer=0, rule=0),
    "Threat rules only": dict(stat=0, peer=0, ml=0),
}


def ablate(test: pd.DataFrame, off: dict, cfg) -> dict:
    t = test.copy()
    for k, v in off.items():
        t[k] = v
    # scale weights so a single remaining layer can still reach the alert band
    c = copy.deepcopy(cfg)
    active = [k for k in ("stat", "peer", "ml") if k not in off]
    if "rule" in off and active:
        total = sum(getattr(cfg, f"w_{k}") for k in active)
        for k in active:
            setattr(c, f"w_{k}", min(1.0, getattr(cfg, f"w_{k}") / total * 0.9))
    risk = daily_risk(t, c)
    y = t["label"].astype(int)
    pred = risk >= cfg.alert_threshold
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum()); fn = int((~pred & (y == 1)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0; r = tp / (tp + fn) if tp + fn else 0.0
    return dict(roc_auc=roc_auc_score(y, risk), pr_auc=average_precision_score(y, risk), precision=p,
                recall=r, f1=2 * p * r / (p + r) if p + r else 0.0)


def main(seeds=(42, 7, 123, 2024, 99)):
    rows, abl = [], []
    for seed in seeds:
        cfg = copy.deepcopy(CONFIG)
        cfg.seed = seed
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "raw"
            generate_dataset(raw, cfg)
            res = run(raw, Path(tmp) / "ueba.db", cfg, evaluate_results=True)
        m = res["metrics"]
        rows.append(dict(seed=seed, incidents=f"{m['incidents_detected']}/{m['incidents_total']}",
                         precision=m["precision"], recall=m["recall"], f1=m["f1"],
                         fpr=m["false_positive_rate"], alerts_per_day=m["alerts_per_day"],
                         roc_auc=m["detectors"]["Fused risk score"]["roc_auc"],
                         pr_auc=m["detectors"]["Fused risk score"]["pr_auc"]))
        test = res["scores"][~res["scores"]["is_train"]]
        for name, off in VARIANTS.items():
            abl.append(dict(seed=seed, variant=name, **ablate(test, off, cfg)))
        print(rows[-1], flush=True)

    R = pd.DataFrame(rows)
    A = pd.DataFrame(abl).groupby("variant", sort=False)[["roc_auc", "pr_auc", "precision", "recall", "f1"]]
    A = A.agg(["mean", "std"])
    REPORTS_DIR.mkdir(exist_ok=True)
    R.to_csv(REPORTS_DIR / "robustness_seeds.csv", index=False)
    pd.DataFrame(abl).to_csv(REPORTS_DIR / "ablation_raw.csv", index=False)

    md = ["# Experiments", "", "## Robustness across random seeds", "",
          "Each seed generates a different company (people, habits, victims, timing).", "",
          "| Seed | Incidents | Precision | Recall | F1 | FPR | Alerts/day | ROC-AUC | PR-AUC |",
          "|---|---|---|---|---|---|---|---|---|"]
    md += [f"| {r.seed} | {r.incidents} | {r.precision:.3f} | {r.recall:.3f} | {r.f1:.3f} | {r.fpr:.4f} | "
           f"{r.alerts_per_day} | {r.roc_auc:.3f} | {r.pr_auc:.3f} |" for r in R.itertuples()]
    md += [f"| **mean** | | **{R.precision.mean():.3f}** | **{R.recall.mean():.3f}** | **{R.f1.mean():.3f}** | "
           f"{R.fpr.mean():.4f} | {R.alerts_per_day.mean():.2f} | {R.roc_auc.mean():.3f} | {R.pr_auc.mean():.3f} |",
           "", "## Ablation (mean ± std over seeds, daily-risk alerts only)", "",
           "| Variant | ROC-AUC | PR-AUC | Precision | Recall | F1 |", "|---|---|---|---|---|---|"]
    for name in VARIANTS:
        a = A.loc[name]
        md.append(f"| {name} | " + " | ".join(f"{a[(k, 'mean')]:.3f} ± {a[(k, 'std')]:.3f}"
                                               for k in ("roc_auc", "pr_auc", "precision", "recall", "f1")) + " |")
    (REPORTS_DIR / "experiments.md").write_text("\n".join(md) + "\n")
    print("\n".join(md))


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    main(tuple([42, 7, 123, 2024, 99, 5, 11, 77][:n]))
