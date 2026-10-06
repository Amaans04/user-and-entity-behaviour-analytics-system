"""Alerts - triage queue, alert detail and analyst verdicts."""
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


def detector_bar(row) -> go.Figure:
    names = ["Personal baseline", "Peer group", "ML ensemble", "Threat rules"]
    vals = [row["stat"], row["peer"], row["ml"], row["rule"]]
    fig = go.Figure(go.Bar(x=vals, y=names, orientation="h", marker_color=[BLUE, AQUA, VIOLET, ORANGE],
                           text=[f"{v:.2f}" for v in vals], textposition="outside",
                           hovertemplate="%{y}: %{x:.2f}<extra></extra>"))
    fig.update_layout(title="What triggered it (detector scores, 0-1)", xaxis_range=[0, 1.15])
    return style(fig, 230, legend=False).update_yaxes(autorange="reversed")


def page_alerts():
    DB, alerts, has_truth = ctx.DB, ctx.alerts, ctx.has_truth
    st.title("Alerts")
    learning_banner()
    if alerts.empty:
        st.info("No alerts in the detection window.")
        return
    f1, f2, f3, f4 = st.columns([2, 2, 2, 3])
    sev = f1.multiselect("Severity", SEV_ORDER, default=["critical", "high", "medium"])
    et = f2.multiselect("Entity type", ["user", "device"], default=["user", "device"])
    kinds = f3.multiselect("Alert type", sorted(alerts.alert_type.unique()), default=sorted(alerts.alert_type.unique()))
    search = f4.text_input("Search entity / title", "")
    fb = feedback.load(DB)
    verdict = {(e, d): v for e, d, v in zip(fb["entity"], fb["date"], fb["verdict"])}
    STATUS = {None: "🟡 open", "benign": "⚪ closed – benign", "threat": "🔴 confirmed threat"}
    alerts["status"] = [STATUS[verdict.get((e, d))] for e, d in zip(alerts["entity"], alerts["date"])]
    A = alerts[alerts.severity.isin(sev) & alerts.entity_type.isin(et) & alerts.alert_type.isin(kinds)]
    if search:
        s = search.lower()
        A = A[A.entity.str.lower().str.contains(s) | A.title.str.lower().str.contains(s)]
    A = A.sort_values(["date", "risk_score"], ascending=[False, False])
    view = A[["alert_id", "date", "severity", "entity", "entity_type", "department", "title", "risk_score",
              "status"]].copy()
    view["severity"] = view["severity"].map(lambda s: f"{SEV_ICON[s]} {s}")
    st.caption(f"{len(A)} alerts · click a row to open it")
    ev = st.dataframe(view, hide_index=True, height=320, on_select="rerun", selection_mode="single-row",
                      column_config={"risk_score": st.column_config.ProgressColumn(
                          "Risk", min_value=0, max_value=100, format="%.0f")})
    sel = ev.selection.rows if ev and hasattr(ev, "selection") else []
    row = A.iloc[sel[0]] if sel else (A.iloc[0] if len(A) else None)
    if row is None:
        return
    st.divider()
    l, r = st.columns([3, 2])
    with l:
        st.markdown(f"### {row['title']}  \n{sev_badge(row['severity'])} &nbsp; **{row['entity']}** "
                    f"({row['entity_type']}, {row['department']}) · {row['date']} · `{row['alert_id']}`",
                    unsafe_allow_html=True)
        st.markdown(f"**Risk score {row['risk_score']:.0f}/100** · daily risk {row['daily_risk']:.0f} · "
                    f"accumulated entity risk {row['entity_risk']:.0f} · type `{row['alert_type']}`")
        st.markdown("**Why this was flagged**")
        for reason in json.loads(row["reasons"]) or ["Combination of weak deviations across several features"]:
            st.markdown(f"- {reason}")
        mitre = json.loads(row["mitre"])
        if mitre:
            st.markdown("**MITRE ATT&CK:** " + " · ".join(f"`{m}`" for m in mitre))
        if has_truth:
            truth = Q("SELECT * FROM ground_truth WHERE entity=? AND date=?", (row["entity"], row["date"]))
            if len(truth):
                st.success(f"Ground truth: planted attack **{truth.iloc[0]['incident_id']} – "
                           f"{truth.iloc[0]['scenario']}**: {truth.iloc[0]['description']}")
            else:
                st.warning("Ground truth: no attack planted here – this is a **false positive** "
                           "(useful for tuning discussion).")
    with r:
        show(detector_bar(row))
        if st.button(f"Investigate {row['entity']} →"):
            st.session_state["entity"] = row["entity"]
            st.session_state["entity_date"] = row["date"]
            st.session_state["page_current"] = "Investigate entity"
            st.rerun()

        st.markdown("**Analyst verdict**")
        current = verdict.get((row["entity"], row["date"]))
        st.caption(f"Status: {STATUS[current]}")
        if not can("triage"):
            st.caption("Viewers can't record verdicts.")
        else:
            note = st.text_input("Note (optional)", key=f"note_{row['alert_id']}",
                                 placeholder="e.g. user confirmed new project access")
            who = ctx.user["username"]
            b1, b2, b3 = st.columns(3)
            if b1.button("✅ Benign", help="Mark as benign (false positive)", key=f"ben_{row['alert_id']}"):
                feedback.record(DB, row["entity"], row["date"], "benign", note, analyst=who, alert_id=row["alert_id"])
                audit("alert.benign", f"{row['alert_id']} {row['entity']} {row['date']} {note}")
                ctx.ws.changed_from(row["date"])
                st.rerun()
            if b2.button("🚨 Threat", help="Confirm as a real threat", key=f"thr_{row['alert_id']}"):
                feedback.record(DB, row["entity"], row["date"], "threat", note, analyst=who, alert_id=row["alert_id"])
                audit("alert.threat", f"{row['alert_id']} {row['entity']} {row['date']} {note}")
                ctx.ws.changed_from(row["date"])
                st.rerun()
            if current and b3.button("↩ Reopen", key=f"clr_{row['alert_id']}"):
                feedback.clear(DB, row["entity"], row["date"])
                audit("alert.reopen", f"{row['alert_id']} {row['entity']} {row['date']}")
                ctx.ws.changed_from(row["date"])
                st.rerun()
        st.caption("Benign days are learned into this entity's baseline at the next analysis (the collector "
                   "service re-scores the following days automatically), so the same legitimate behaviour is "
                   "not flagged again. Confirmed threats are never learned.")
