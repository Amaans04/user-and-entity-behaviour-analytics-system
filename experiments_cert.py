"""CERT r4.2 benchmark experiment - reproduces the numbers in reports/cert_r4.2.md.

    python run_pipeline.py --cert data/cert/r4.2     # once: converts the dataset (data/cert_converted/r4.2)
    python experiments_cert.py                       # ~16 min: both variants + held-out evaluation

Protocol
--------
* Unsupervised: no CERT labels are used for training; the learning period is Jan-May 2010,
  before the first malicious activity.
* Two variants are analysed from scratch:
    - **out-of-the-box**: the system exactly as designed on the synthetic organisation
      (rule R16 switched off);
    - **with R16**: plus one generic insider-threat indicator added after the out-of-the-box
      run had been analysed - removable-media use by an account with no removable-media
      history (MITRE T1052.001).
* To keep that addition honest, users are split at random (seed 2024) into a development
  half and a held-out test half, each with half of the insiders; R16 was chosen on the
  development half only and the test half is what the report quotes.
* Metrics are on user-days of the detection window: day-level precision / recall / FPR,
  ROC-AUC and PR-AUC of the fused risk and of each layer, insiders alerted on at least one
  of their malicious days, and a fixed analyst budget (top-k riskiest users per day).
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from ueba.config import CONFIG, DATA_DIR, REPORTS_DIR

SRC = DATA_DIR / "cert_converted" / "r4.2"
OUT = DATA_DIR / "cert_eval"
LAYERS = ["stat", "peer", "ml", "ml_iforest", "ml_lof", "ml_autoencoder", "rule", "daily_risk"]
SPLIT_SEED = 2024


def analyse(variant: str, disabled: tuple) -> dict:
    from ueba.pipeline import run
    info = json.loads((SRC / "conversion_info.json").read_text())
    cfg = copy.deepcopy(CONFIG)
    cfg.disabled_rules = disabled
    OUT.mkdir(parents=True, exist_ok=True)
    db = OUT / f"{variant}.db"
    db.unlink(missing_ok=True)
    return run(SRC, db, cfg, train_start=info["train_start"], train_end=info["train_end"], reports_dir=None)


def split_users(scores: pd.DataFrame) -> set:
    """Development half: half of the insiders + half of the other users (fixed seed)."""
    users = scores.loc[scores["entity_type"] == "user"]
    insiders = sorted(users.loc[users["label"] == 1, "entity"].unique())
    normals = sorted(set(users["entity"]) - set(insiders))
    rng = np.random.default_rng(SPLIT_SEED)
    return set(rng.choice(insiders, len(insiders) // 2, replace=False)) | \
        set(rng.choice(normals, len(normals) // 2, replace=False))


def evaluate(res: dict, dev: set) -> dict:
    s, a = res["scores"], res["alerts"]
    gt = res["frames"]["ground_truth"]
    t = s[(~s["is_train"].astype(bool)) & (s["entity_type"] == "user")].copy()
    t["split"] = np.where(t["entity"].isin(dev), "dev", "test")
    alerted = set(zip(a["entity"], a["date"]))
    t["alert"] = [(e, d) in alerted for e, d in zip(t["entity"], t["date"])]
    n_days = t["date"].nunique()
    scen = gt.assign(entity=gt["entity"].str.lower()).groupby("entity")["scenario"].first()
    out = {}
    for split in ("test", "dev", "all"):
        D = t if split == "all" else t[t["split"] == split]
        y, p = D["label"].astype(int), D["alert"]
        tp, fp, fn = int((p & (y == 1)).sum()), int((p & (y == 0)).sum()), int((~p & (y == 1)).sum())
        mal = D[D["label"] == 1]
        insiders = sorted(mal["entity"].unique())
        caught = sorted(mal.loc[mal["alert"], "entity"].unique())
        by_sc = {sc: [int(sum(scen.get(e) == sc for e in caught)), int(sum(scen.get(e) == sc for e in insiders))]
                 for sc in sorted(set(scen.get(e) for e in insiders))}
        budget = {}
        for k in (1, 3, 5):
            r = D.assign(rank=D.groupby("date")["daily_risk"].rank(ascending=False, method="first"))
            top = r[r["rank"] <= k]
            budget[k] = dict(reviews=len(top), malicious_days=int(top["label"].sum()),
                             insiders=int(top.loc[top["label"] == 1, "entity"].nunique()))
        out[split] = dict(
            user_days=len(D), malicious_days=int(y.sum()), insiders=len(insiders), insiders_caught=len(caught),
            by_scenario=by_sc, alerts=int(p.sum()), alerts_per_day=round(p.sum() / n_days, 2), tp=tp, fp=fp,
            precision=round(tp / max(1, tp + fp), 3), recall=round(tp / max(1, tp + fn), 3),
            fpr=round(fp / max(1, int((y == 0).sum())), 5),
            roc_auc=round(roc_auc_score(y, D["daily_risk"]), 3), pr_auc=round(average_precision_score(y, D["daily_risk"]), 4),
            layers={c: round(roc_auc_score(y, D[c]), 3) for c in LAYERS}, budget=budget)
    return out


def markdown(results: dict) -> str:
    L = ["# CERT r4.2 benchmark", "",
         "1,000 users, 70 insiders in three scenarios (r4.2-1: first-time USB user leaks data; r4.2-2: job-hunter "
         "steals data before leaving; r4.2-3: disgruntled admin plants a keylogger). Learning period Jan-May 2010 "
         "(attack-free); detection window Jun 2010 - May 2011; user-days. See `experiments_cert.py` for the protocol.", ""]
    for split, title in (("test", "Held-out test half (quoted)"), ("dev", "Development half"), ("all", "All users")):
        L += [f"## {title}", "", "| Measure | Out-of-the-box | With R16 |", "|---|---|---|"]
        a, b = results["out-of-the-box"][split], results["with R16"][split]
        rows = [("Insiders alerted on a malicious day", f"{a['insiders_caught']}/{a['insiders']}", f"{b['insiders_caught']}/{b['insiders']}")]
        for sc in a["by_scenario"]:
            rows.append((f"  {sc}", "{}/{}".format(*a["by_scenario"][sc]), "{}/{}".format(*b["by_scenario"][sc])))
        for k, lab, fmt in (("alerts_per_day", "Alerts per day", "{}"), ("precision", "Day-level precision", "{:.3f}"),
                            ("recall", "Day-level recall", "{:.3f}"), ("fpr", "False-positive rate", "{:.4%}"),
                            ("roc_auc", "Fused ROC-AUC", "{:.3f}"), ("pr_auc", "Fused PR-AUC", "{:.4f}")):
            rows.append((lab, fmt.format(a[k]), fmt.format(b[k])))
        for k in (1, 3, 5):
            rows.append((f"Insiders in the top-{k} users per day", f"{a['budget'][k]['insiders']}/{a['insiders']}",
                         f"{b['budget'][k]['insiders']}/{b['insiders']}"))
        L += [f"| {r[0]} | {r[1]} | {r[2]} |" for r in rows] + [""]
    L += ["## Ranking quality of each layer (ROC-AUC, all users)", "", "| Layer | Out-of-the-box | With R16 |", "|---|---|---|"]
    for c in LAYERS:
        L.append(f"| {c} | {results['out-of-the-box']['all']['layers'][c]} | {results['with R16']['all']['layers'][c]} |")
    return "\n".join(L) + "\n"


def main():
    results, dev = {}, None
    for variant, disabled in (("out-of-the-box", ("R16",)), ("with R16", ())):
        print(f"=== {variant}")
        res = analyse(variant.replace(" ", "_"), disabled)
        dev = dev or split_users(res["scores"])
        results[variant] = evaluate(res, dev)
        t = results[variant]["test"]
        print(f"held-out test: insiders {t['insiders_caught']}/{t['insiders']}, precision {t['precision']}, "
              f"alerts/day {t['alerts_per_day']}, ROC-AUC {t['roc_auc']}")
    REPORTS_DIR.mkdir(exist_ok=True)
    (REPORTS_DIR / "cert_r4.2.json").write_text(json.dumps(results, indent=1))
    (REPORTS_DIR / "cert_r4.2.md").write_text(markdown(results))
    print(f"Wrote {REPORTS_DIR / 'cert_r4.2.md'}")


if __name__ == "__main__":
    main()
