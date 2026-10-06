"""Negative result: a 7-day trend layer for gradual insiders (CERT r4.2 scenario 2).

    python experiments_cert.py      # first (creates data/cert_eval/with_R16.db)
    python experiments_trend.py     # ~2 min -> reports/cert_trend_layer.md

Idea: insiders who only gradually do *more* of something (job-site visits, USB copies) never
stand out on a single day, but might over a week. For each user and feature, the rolling
7-day total is compared with the same user's 7-day totals in the learning period (robust
z-score, same spread formula as the daily baselines); the three largest excesses over z = 2
give a trend score in [0, 1], added to the risk fusion with weight w.

Decided on the development half only (same split as experiments_cert.py); the test half is
shown for completeness. Outcome: ranking (ROC-AUC) improves, but no weight gives better
detection at a usable alert rate, and the top-k analyst budget gets *worse* - so the layer
was not adopted.
"""
from __future__ import annotations

import copy
import sqlite3

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from experiments_cert import OUT, split_users
from ueba.config import CONFIG, REPORTS_DIR
from ueba.risk import entity_risk, generate_alerts

FEATS = ["removable_media", "job_site_visits", "off_hours_logins", "off_hours_access", "new_domains",
         "access_events", "connections", "distinct_domains"]
WEIGHTS = (0.0, 0.25, 0.35, 0.5)
LEARN = (pd.Timestamp("2010-01-16"), pd.Timestamp("2010-06-01"))


def trend_scores(f: pd.DataFrame) -> pd.DataFrame:
    f = f.assign(date=pd.to_datetime(f["date"])).sort_values(["entity", "date"])
    roll = f.set_index("date").groupby("entity")[FEATS].rolling("7D").sum().reset_index()
    tr = roll[(roll["date"] >= LEARN[0] + pd.Timedelta(days=7)) & (roll["date"] < LEARN[1])]
    med = tr.groupby("entity")[FEATS].median()
    mad = tr.groupby("entity")[FEATS].apply(lambda g: (g - g.median()).abs().median() * 1.4826)
    q95 = tr.groupby("entity")[FEATS].quantile(0.95)
    floor = np.maximum(np.maximum(0.25 * tr[FEATS].std(ddof=0), 0.05 * tr[FEATS].mean().abs()), 1.0)
    scale = np.maximum(np.maximum(mad, (q95 - med) / 1.645), 0).clip(lower=floor, axis=1)
    z = (roll[FEATS].to_numpy() - med.reindex(roll["entity"]).to_numpy()) / scale.reindex(roll["entity"]).to_numpy()
    excess = np.clip(np.clip(np.nan_to_num(z), -10, 10) - 2.0, 0, None)
    top = -np.sort(-excess, axis=1)[:, :3]
    roll["trend"] = 1 - np.exp(-(top[:, 0] + 0.5 * top[:, 1] + 0.25 * top[:, 2]) / 4)
    roll["date"] = roll["date"].dt.strftime("%Y-%m-%d")
    return roll[["entity", "date", "trend"]]


def main():
    con = sqlite3.connect(OUT / "with_R16.db")
    s = pd.read_sql("SELECT entity, entity_type, date, department, is_admin, stat, peer, ml, rule, daily_risk, label, "
                    "scenario, is_train, rule_hits, reasons FROM scores WHERE entity_type='user'", con)
    dev = split_users(s)
    s = s.merge(trend_scores(pd.read_sql("SELECT * FROM features_user", con)), on=["entity", "date"], how="left")
    s["trend"] = s["trend"].fillna(0)
    s["split"] = np.where(s["entity"].isin(dev), "dev", "test")
    cfg = copy.deepcopy(CONFIG)
    crit = s["department"].map(cfg.criticality).fillna(1.0)
    crit = np.where(s["is_admin"].astype(bool), np.maximum(crit, 1.3), crit)
    base = 1 - (1 - cfg.w_stat * s.stat) * (1 - cfg.w_peer * s.peer) * (1 - cfg.w_ml * s.ml) * (1 - s.rule)
    rows = []
    for w in WEIGHTS:
        F = s.copy()
        F["daily_risk"] = np.round(100 * np.clip((1 - (1 - base) * (1 - w * F["trend"])) * crit, 0, 1), 1)
        F["entity_risk"] = entity_risk(F, cfg)
        test = F[F["is_train"] == 0]
        al = generate_alerts(test, cfg)
        alerted = set(zip(al["entity"], al["date"]))
        for split in ("dev", "test"):
            T = test[test["split"] == split]
            a = np.array([(e, d) in alerted for e, d in zip(T["entity"], T["date"])])
            mal = T[T["label"] == 1]
            sc = mal.groupby("entity")["scenario"].first()
            caught = set(T.loc[(T["label"] == 1) & a, "entity"])
            r = T.assign(rank=T.groupby("date")["daily_risk"].rank(ascending=False, method="first"))
            top5 = r[(r["rank"] <= 5) & (r["label"] == 1)]["entity"].nunique()
            rows.append(dict(weight=w, split=split, roc_auc=round(roc_auc_score(T["label"], T["daily_risk"]), 3),
                             alerts_per_day=round(a.sum() / T["date"].nunique(), 2),
                             precision=round(((T["label"] == 1) & a).sum() / max(1, a.sum()), 3),
                             insiders=f"{len(caught)}/{mal['entity'].nunique()}",
                             scenario2=f"{sum(sc.get(e) == 'r4.2-2' for e in caught)}/{(sc == 'r4.2-2').sum()}",
                             top5_budget=f"{top5}/{mal['entity'].nunique()}"))
    df = pd.DataFrame(rows)
    md = ["# Trend layer (7-day windows) on CERT r4.2 - not adopted", "",
          "Weight 0 = the system as used (with R16). Decided on the development half.", "",
          "| " + " | ".join(df.columns) + " |", "|" + "---|" * len(df.columns),
          *["| " + " | ".join(str(v) for v in r) + " |" for r in df.itertuples(index=False)], "",
          "Ranking (ROC-AUC) improves by about 0.1, but a weight small enough to keep alerts near one a day catches no "
          "additional insider, a weight that catches half of the scenario-2 insiders multiplies alerts by about 11 "
          "at 3-4 % precision, and every weight lowers the number of insiders an analyst finds in the five riskiest "
          "users per day. Gradual insiders need sequence-aware models rather than longer windows.", ""]
    (REPORTS_DIR / "cert_trend_layer.md").write_text("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
