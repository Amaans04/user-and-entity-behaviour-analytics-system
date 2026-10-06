"""Evaluation against the planted ground truth.

Reports, on the detection window only (never the baseline window):

* alert-level confusion matrix, precision, recall, F1, false-positive rate
* ROC-AUC and PR-AUC of every detector's score (shows what each layer adds)
* incident-level detection: was each attack caught, how fast, by what
* threshold sweep (precision/recall trade-off)
* figures for the project report (reports/figures/*.png)
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import (average_precision_score, confusion_matrix, precision_recall_curve,  # noqa: E402
                             roc_auc_score, roc_curve)

from .config import CONFIG, Config  # noqa: E402

DETECTORS = {"daily_risk": "Fused risk score", "stat": "Personal baseline (z-score)",
             "peer": "Peer-group baseline", "ml": "ML ensemble", "ml_iforest": "Isolation Forest",
             "ml_lof": "Local Outlier Factor", "ml_autoencoder": "Autoencoder", "rule": "Threat rules"}
COLORS = ["#2a6fdb", "#e0a100", "#1b998b", "#d1495b", "#8e5ad6", "#6c757d", "#f28f3b", "#3d405b"]


def _safe(fn, y, s):
    try:
        return float(fn(y, s)) if len(np.unique(y)) > 1 else float("nan")
    except ValueError:
        return float("nan")


def evaluate(scores: pd.DataFrame, alerts: pd.DataFrame, truth: pd.DataFrame, cfg: Config = CONFIG,
             out_dir: Path | None = None) -> dict:
    test = scores[~scores["is_train"]].copy()
    alerted = set(zip(alerts["entity"], alerts["date"]))
    test["pred"] = [int((e, d) in alerted) for e, d in zip(test["entity"], test["date"])]
    y, p = test["label"].astype(int).to_numpy(), test["pred"].to_numpy()
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    report = {
        "detection_window": [test["date"].min(), test["date"].max()],
        "entity_days_scored": int(len(test)), "attack_entity_days": int(y.sum()),
        "alerts": int(len(alerts)),
        "confusion": {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)},
        "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
        "alerts_per_day": round(len(alerts) / max(1, test["date"].nunique()), 2),
    }
    report["detectors"] = {
        name: {"roc_auc": round(_safe(roc_auc_score, y, test[col]), 3),
               "pr_auc": round(_safe(average_precision_score, y, test[col]), 3)}
        for col, name in DETECTORS.items()}
    for et in ("user", "device"):
        t = test[test["entity_type"] == et]
        report[f"{et}_roc_auc"] = round(_safe(roc_auc_score, t["label"], t["daily_risk"]), 3)

    # ---- incident level ----
    inc_rows = []
    for inc_id, g in truth.groupby("incident_id"):
        keys = set(zip(g["entity"], g["date"].astype(str)))
        hit = alerts[[k in keys for k in zip(alerts["entity"], alerts["date"])]]
        first_day = sorted(g["date"].astype(str))[0]
        row = dict(incident=inc_id, scenario=g["scenario"].iloc[0], mitre=g["mitre"].iloc[0],
                   entities=", ".join(sorted(g["entity"].unique())), days=int(g["date"].nunique()),
                   detected=bool(len(hit)))
        if len(hit):
            d0 = sorted(hit["date"])[0]
            row.update(first_alert=d0, delay_days=(pd.Timestamp(d0) - pd.Timestamp(first_day)).days,
                       max_risk=float(hit["risk_score"].max()),
                       top_severity=hit.sort_values("risk_score").iloc[-1]["severity"],
                       caught_by=", ".join(sorted({x for d in hit["detectors"] for x in json.loads(d)})))
        else:
            sc = test[[k in keys for k in zip(test["entity"], test["date"])]]
            row.update(first_alert="", delay_days=None,
                       max_risk=float(sc["daily_risk"].max()) if len(sc) else 0.0,
                       top_severity="none", caught_by="")
        inc_rows.append(row)
    incidents = pd.DataFrame(inc_rows)
    report["incidents_total"] = int(len(incidents))
    report["incidents_detected"] = int(incidents["detected"].sum())
    report["incident_detection_rate"] = round(incidents["detected"].mean(), 3)
    report["incidents"] = incidents.to_dict(orient="records")

    # ---- false positives explained ----
    fps = test[(test["pred"] == 1) & (test["label"] == 0)]
    fp_alerts = alerts.merge(fps[["entity", "date"]], on=["entity", "date"])
    report["false_positives"] = fp_alerts[["alert_id", "date", "entity", "title", "risk_score"]].to_dict("records")

    # ---- threshold sweep ----
    sweep = []
    for th in range(20, 85, 5):
        pr = (test["daily_risk"] >= th).astype(int)
        tp_ = int(((pr == 1) & (y == 1)).sum()); fp_ = int(((pr == 1) & (y == 0)).sum())
        fn_ = int(((pr == 0) & (y == 1)).sum())
        p_ = tp_ / (tp_ + fp_) if tp_ + fp_ else 0; r_ = tp_ / (tp_ + fn_) if tp_ + fn_ else 0
        sweep.append(dict(threshold=th, precision=round(p_, 3), recall=round(r_, 3),
                          f1=round(2 * p_ * r_ / (p_ + r_), 3) if p_ + r_ else 0, alerts=int(pr.sum())))
    report["threshold_sweep"] = sweep

    if out_dir is not None:
        out_dir = Path(out_dir)
        (out_dir / "figures").mkdir(parents=True, exist_ok=True)
        (out_dir / "evaluation.json").write_text(json.dumps(report, indent=2, default=str))
        incidents.to_csv(out_dir / "incident_detection.csv", index=False)
        pd.DataFrame(sweep).to_csv(out_dir / "threshold_sweep.csv", index=False)
        _figures(test, y, incidents, report, out_dir / "figures", cfg)
        (out_dir / "evaluation.md").write_text(to_markdown(report))
    return report


def _figures(test, y, incidents, report, fig_dir: Path, cfg: Config):
    plt.rcParams.update({"figure.dpi": 130, "font.size": 9, "axes.spines.top": False,
                         "axes.spines.right": False})
    # ROC
    fig, ax = plt.subplots(figsize=(5.2, 4.4))
    for (col, name), c in zip(DETECTORS.items(), COLORS):
        if len(np.unique(y)) > 1:
            fpr, tpr, _ = roc_curve(y, test[col])
            ax.plot(fpr, tpr, color=c, lw=2.2 if col == "daily_risk" else 1.2,
                    label=f"{name} (AUC {report['detectors'][name]['roc_auc']:.2f})")
    ax.plot([0, 1], [0, 1], ls="--", c="#bbb", lw=1)
    ax.set(xlabel="False positive rate", ylabel="True positive rate", title="ROC curves by detector")
    ax.legend(fontsize=7, frameon=False, loc="lower right")
    fig.tight_layout(); fig.savefig(fig_dir / "roc_curves.png"); plt.close(fig)
    # PR
    fig, ax = plt.subplots(figsize=(5.2, 4.4))
    for (col, name), c in zip(DETECTORS.items(), COLORS):
        pr, rc, _ = precision_recall_curve(y, test[col])
        ax.plot(rc, pr, color=c, lw=2.2 if col == "daily_risk" else 1.2,
                label=f"{name} (AP {report['detectors'][name]['pr_auc']:.2f})")
    ax.set(xlabel="Recall", ylabel="Precision", title="Precision-recall curves")
    ax.legend(fontsize=7, frameon=False, loc="lower left")
    fig.tight_layout(); fig.savefig(fig_dir / "pr_curves.png"); plt.close(fig)
    # Risk distribution
    fig, ax = plt.subplots(figsize=(6, 3.6))
    bins = np.linspace(0, 100, 41)
    ax.hist(test.loc[y == 0, "daily_risk"], bins=bins, color="#2a6fdb", alpha=.7, label="normal entity-days",
            log=True)
    ax.hist(test.loc[y == 1, "daily_risk"], bins=bins, color="#d1495b", alpha=.85, label="attack entity-days",
            log=True)
    ax.axvline(cfg.alert_threshold, c="k", ls="--", lw=1)
    ax.text(cfg.alert_threshold + 1, ax.get_ylim()[1] * .5, "alert threshold", fontsize=7)
    ax.set(xlabel="Daily risk score", ylabel="Entity-days (log)", title="Risk score separation")
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout(); fig.savefig(fig_dir / "risk_distribution.png"); plt.close(fig)
    # Confusion matrix
    c = report["confusion"]
    m = np.array([[c["tn"], c["fp"]], [c["fn"], c["tp"]]])
    fig, ax = plt.subplots(figsize=(3.6, 3.2))
    ax.imshow(m, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{m[i, j]:,}", ha="center", va="center",
                    color="white" if m[i, j] > m.max() / 2 else "black", fontsize=11)
    ax.set_xticks([0, 1], ["No alert", "Alert"]); ax.set_yticks([0, 1], ["Normal", "Attack"])
    ax.set_title("Confusion matrix (entity-days)")
    fig.tight_layout(); fig.savefig(fig_dir / "confusion_matrix.png"); plt.close(fig)
    # Detector AUC bars
    fig, ax = plt.subplots(figsize=(6, 3.4))
    names = list(report["detectors"]); vals = [report["detectors"][n]["roc_auc"] for n in names]
    ax.barh(names[::-1], vals[::-1], color=["#2a6fdb" if n != "Fused risk score" else "#d1495b" for n in names[::-1]])
    for i, v in enumerate(vals[::-1]):
        ax.text(v + .005, i, f"{v:.3f}", va="center", fontsize=7)
    ax.set(xlim=(0.4, 1.05), xlabel="ROC-AUC", title="Detection power of each layer")
    fig.tight_layout(); fig.savefig(fig_dir / "detector_auc.png"); plt.close(fig)
    # Incident risk bars
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    inc = incidents.sort_values("incident")
    ax.bar(inc["incident"] + "\n" + inc["scenario"].str.replace("_", "\n"), inc["max_risk"],
           color=np.where(inc["detected"], "#1b998b", "#d1495b"))
    ax.axhline(cfg.alert_threshold, c="k", ls="--", lw=1)
    ax.set(ylabel="Peak risk score", title="Peak risk per planted incident", ylim=(0, 105))
    ax.tick_params(axis="x", labelsize=5.5)
    fig.tight_layout(); fig.savefig(fig_dir / "incident_risk.png"); plt.close(fig)


def to_markdown(r: dict) -> str:
    c = r["confusion"]
    lines = [
        "# UEBA evaluation report", "",
        f"Detection window: **{r['detection_window'][0]} to {r['detection_window'][1]}**  ",
        f"Entity-days scored: **{r['entity_days_scored']:,}** (attack entity-days: {r['attack_entity_days']})", "",
        "## Alert quality", "",
        "| Metric | Value |", "|---|---|",
        f"| Precision | {r['precision']:.3f} |", f"| Recall | {r['recall']:.3f} |", f"| F1 | {r['f1']:.3f} |",
        f"| False-positive rate | {r['false_positive_rate']:.4f} |",
        f"| Alerts per day | {r['alerts_per_day']} |",
        f"| Incidents detected | {r['incidents_detected']} / {r['incidents_total']} |", "",
        f"Confusion matrix: TP={c['tp']}, FP={c['fp']}, FN={c['fn']}, TN={c['tn']}", "",
        "## Detector comparison", "", "| Detector | ROC-AUC | PR-AUC |", "|---|---|---|"]
    lines += [f"| {k} | {v['roc_auc']:.3f} | {v['pr_auc']:.3f} |" for k, v in r["detectors"].items()]
    lines += ["", "## Incident-level results", "",
              "| Incident | Scenario | Detected | First alert | Delay (days) | Peak risk | Caught by |",
              "|---|---|---|---|---|---|---|"]
    for i in r["incidents"]:
        lines.append(f"| {i['incident']} | {i['scenario']} | {'yes' if i['detected'] else 'no'} | "
                     f"{i.get('first_alert', '')} | {i.get('delay_days', '')} | {i['max_risk']:.0f} | "
                     f"{i.get('caught_by', '')} |")
    lines += ["", "## False positives", ""]
    lines += [f"- {f['date']} {f['entity']}: {f['title']} (risk {f['risk_score']:.0f})"
              for f in r["false_positives"]] or ["- none"]
    lines += ["", "## Threshold sweep", "", "| Threshold | Precision | Recall | F1 | Alerts |", "|---|---|---|---|---|"]
    lines += [f"| {s['threshold']} | {s['precision']} | {s['recall']} | {s['f1']} | {s['alerts']} |"
              for s in r["threshold_sweep"]]
    return "\n".join(lines) + "\n"
