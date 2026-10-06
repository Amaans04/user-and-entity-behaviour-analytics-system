"""Overview - the SOC summary for the current workspace."""
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


def page_overview():
    alerts, monitoring, scores, test_scores = ctx.alerts, ctx.monitoring, ctx.scores, ctx.test_scores
    st.title("Security overview")
    learning_banner()
    if monitoring:
        st.caption(f"Detection window {test_scores['date'].min()} to {test_scores['date'].max()} · "
                   "each user and device is compared with its own baseline and its department peers")
    n_events = sum(int(Q(f"SELECT COUNT(*) n FROM {t}")["n"][0]) for t in ("auth", "access", "network", "resource"))
    c = st.columns(5)
    c[0].metric("Events analysed", f"{n_events:,}")
    c[1].metric("Users monitored", f"{scores.loc[scores.entity_type == 'user', 'entity'].nunique()}")
    c[2].metric("Devices monitored", f"{scores.loc[scores.entity_type == 'device', 'entity'].nunique()}")
    c[3].metric("Alerts raised", f"{len(alerts)}")
    c[4].metric("Critical / high", f"{(alerts.severity == 'critical').sum()} / {(alerts.severity == 'high').sum()}")
    if not monitoring:
        return

    left, right = st.columns([3, 2])
    with left:
        days = pd.date_range(test_scores["date"].min(), test_scores["date"].max()).strftime("%Y-%m-%d")
        fig = go.Figure()
        for sev in SEV_ORDER[::-1]:
            cnt = alerts[alerts.severity == sev].groupby("date").size().reindex(days, fill_value=0)
            fig.add_bar(x=days, y=cnt.values, name=f"{SEV_ICON[sev]} {sev}", marker_color=SEV_COLOR[sev],
                        marker_line=dict(color="white", width=1.5),
                        hovertemplate="%{x}<br>%{y} " + sev + " alerts<extra></extra>")
        fig.update_layout(barmode="stack", title="Alerts per day by severity")
        show(style(fig, 330))
    with right:
        latest = (scores.sort_values("date").groupby("entity").tail(1)
                  .set_index("entity")["entity_risk"])
        peak = test_scores.groupby(["entity", "entity_type", "department"])["daily_risk"].max().reset_index()
        peak["current_risk"] = peak["entity"].map(latest)
        peak["alerts"] = peak["entity"].map(alerts.groupby("entity").size()).fillna(0).astype(int)
        top = peak.sort_values(["daily_risk", "alerts"], ascending=False).head(12).drop(columns="current_risk")
        st.markdown("**Riskiest entities (peak daily risk)**")
        st.dataframe(
            top.rename(columns={"entity": "Entity", "entity_type": "Type", "department": "Dept",
                                "daily_risk": "Peak risk", "alerts": "Alerts"}),
            hide_index=True, height=330,
            column_config={"Peak risk": st.column_config.ProgressColumn(min_value=0, max_value=100, format="%.0f",
                                                                        width="small")})

    a, b = st.columns(2)
    with a:
        mt = pd.Series([m for x in alerts["mitre"] for m in json.loads(x)]).value_counts().sort_values()
        fig = go.Figure(go.Bar(x=mt.values, y=mt.index, orientation="h", marker_color=BLUE,
                               hovertemplate="%{y}: %{x} alerts<extra></extra>"))
        fig.update_layout(title="Alerts by MITRE ATT&CK technique")
        show(style(fig, 360, legend=False))
    with b:
        dept = (test_scores[test_scores.entity_type == "user"].groupby("department")
                .agg(mean=("daily_risk", "mean"), p95=("daily_risk", lambda s: s.quantile(.95)))
                .sort_values("p95"))
        fig = go.Figure()
        fig.add_bar(y=dept.index, x=dept["mean"], orientation="h", name="Average daily risk", marker_color=BLUE)
        fig.add_bar(y=dept.index, x=dept["p95"], orientation="h", name="95th percentile", marker_color=ORANGE)
        fig.update_layout(title="User risk by department", barmode="group")
        show(style(fig, 360))
