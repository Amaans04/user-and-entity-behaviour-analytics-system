"""Model performance - accuracy against labelled incidents, with a what-if threshold."""
from __future__ import annotations

import json

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.ui import *  # noqa: F401,F403 - palette, chart helpers, ctx, queries
from dashboard.ui import ctx
from ueba import auth, feedback, notify, sources as SRC, workspace as WS  # noqa: F401
from ueba.config import CONFIG  # noqa: F401
from ueba.detectors import LABELS  # noqa: F401


def page_performance():
    has_truth, monitoring, test_scores = ctx.has_truth, ctx.monitoring, ctx.test_scores
    st.title("Model performance")
    if not monitoring:
        learning_banner()
        return
    if not has_truth or test_scores["label"].nunique() < 2:
        st.info("No labelled incidents for this dataset, so accuracy can't be measured. To measure it, upload a "
                "**Labels** file (entity, date of known incidents) in **Data sources** and re-analyse.")
        return
    from sklearn.metrics import roc_auc_score, roc_curve, precision_recall_curve, average_precision_score
    rep = json.loads(Q("SELECT value FROM metrics")["value"][0]) if table_exists("metrics") else {}
    T = test_scores.copy()
    y = T["label"].astype(int)
    st.caption("Measured only on the detection window, against the attacks planted by the log generator.")
    th = st.slider("Alert threshold (what-if)", 10, 90, int(CONFIG.alert_threshold), 5)
    pred = (T["daily_risk"] >= th).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0; rec = tp / (tp + fn) if tp + fn else 0
    c = st.columns(5)
    c[0].metric("Precision", f"{prec:.2f}")
    c[1].metric("Recall", f"{rec:.2f}")
    c[2].metric("F1", f"{(2 * prec * rec / (prec + rec)) if prec + rec else 0:.2f}")
    c[3].metric("False-positive rate", f"{fp / (fp + tn):.3%}" if fp + tn else "–")
    c[4].metric("Incidents caught (at default)", f"{rep.get('incidents_detected', '–')}/{rep.get('incidents_total', '–')}")
    st.caption(f"Confusion at threshold {th}: TP {tp} · FP {fp} · FN {fn} · TN {tn:,} "
               "(daily-risk threshold only; the pipeline also raises 'sustained risk' alerts)")

    dets = {"daily_risk": ("Fused risk", INK), "stat": ("Personal baseline", BLUE), "peer": ("Peer group", AQUA),
            "ml_iforest": ("Isolation Forest", "#eda100"), "ml_lof": ("LOF", "#e87ba4"),
            "ml_autoencoder": ("Autoencoder", VIOLET), "rule": ("Threat rules", ORANGE)}
    l, r = st.columns(2)
    roc, prc = go.Figure(), go.Figure()
    for col, (name, color) in dets.items():
        fpr, tpr, _ = roc_curve(y, T[col]); pr, rc, _ = precision_recall_curve(y, T[col])
        w = 3 if col == "daily_risk" else 1.6
        roc.add_scatter(x=fpr, y=tpr, mode="lines", name=f"{name} ({roc_auc_score(y, T[col]):.3f})",
                        line=dict(color=color, width=w))
        prc.add_scatter(x=rc, y=pr, mode="lines", name=f"{name} ({average_precision_score(y, T[col]):.3f})",
                        line=dict(color=color, width=w, shape="hv"))
    roc.add_scatter(x=[0, 1], y=[0, 1], showlegend=False, line=dict(color=AXIS, dash="dash", width=1))
    roc.update_layout(title="ROC curve (AUC)", xaxis_title="False-positive rate", yaxis_title="True-positive rate")
    prc.update_layout(title="Precision–recall (average precision)", xaxis_title="Recall", yaxis_title="Precision")
    inside = dict(orientation="v", y=0.03, yanchor="bottom", bgcolor="rgba(252,252,251,0.9)",
                  bordercolor="rgba(11,11,11,0.1)", borderwidth=1, font=dict(size=11))
    with l:
        show(style(roc, 440).update_layout(legend=dict(inside, x=0.97, xanchor="right")))
    with r:
        show(style(prc, 440).update_layout(legend=dict(inside, x=0.03, xanchor="left")))

    fig = go.Figure()
    bins = dict(start=0, end=100, size=2.5)
    fig.add_histogram(x=T.loc[y == 0, "daily_risk"], name="Normal entity-days", xbins=bins, marker_color=BLUE)
    fig.add_histogram(x=T.loc[y == 1, "daily_risk"], name="Attack entity-days", xbins=bins, marker_color="#d03b3b")
    fig.add_vline(x=th, line=dict(color=INK, dash="dash", width=1))
    fig.update_layout(title="How well risk separates attacks from normal days", barmode="overlay",
                      yaxis_type="log", xaxis_title="Daily risk", yaxis_title="Entity-days (log)")
    fig.update_traces(opacity=0.8)
    show(style(fig, 320))

    if rep.get("incidents"):
        st.markdown("**Incident-level detection (default threshold)**")
        inc = pd.DataFrame(rep["incidents"])
        inc["detected"] = inc["detected"].map({True: "✅ yes", False: "❌ no"})
        st.dataframe(inc[["incident", "scenario", "mitre", "entities", "days", "detected", "first_alert",
                          "delay_days", "max_risk", "caught_by"]], hide_index=True)
