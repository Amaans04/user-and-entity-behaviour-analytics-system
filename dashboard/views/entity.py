"""Investigate entity - one user's or device's baseline, risk timeline and day drill-down."""
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


def page_entity():
    alerts, has_truth, meta, scores = ctx.alerts, ctx.has_truth, ctx.meta, ctx.scores
    st.title("Investigate entity")
    ents = scores[["entity", "entity_type"]].drop_duplicates().sort_values(["entity_type", "entity"])
    default = st.session_state.get("entity")
    if default is None and len(alerts):
        default = alerts.sort_values("risk_score").iloc[-1]["entity"]
    opts = ents["entity"].tolist()
    ent = st.selectbox("User or device", opts, index=opts.index(default) if default in opts else 0)
    etype = ents.set_index("entity").loc[ent, "entity_type"]
    S = scores[scores.entity == ent].sort_values("date")
    EA = alerts[alerts.entity == ent]

    prof = Q("SELECT * FROM profiles WHERE entity=?", (ent,))
    c = st.columns(4)
    c[0].metric("Department", S["department"].iloc[0])
    peak = S.loc[S.is_train == 0, "daily_risk"].max()
    c[1].metric("Peak daily risk", "–" if pd.isna(peak) else f"{peak:.0f}")
    c[2].metric("Current risk", f"{S['entity_risk'].iloc[-1]:.0f}")
    c[3].metric("Alerts", len(EA))
    if len(prof):
        p = prof.iloc[0]
        st.markdown(
            f'<div class="card"><b>Learned baseline</b> &nbsp;<span class="muted">(from {meta.get("train_start")} '
            f'to {meta.get("train_end")})</span><br>'
            f'Usual working hours: <b>{p.typical_hours}</b> · Countries: <b>{", ".join(json.loads(p.known_countries))}</b> '
            f'· Cities: {", ".join(json.loads(p.known_cities))}<br>'
            f'Hosts: {", ".join(json.loads(p.known_hosts)[:8])}<br>'
            f'Avg upload/day: <b>{p.avg_daily_upload_mb:.1f} MB</b> · Avg file accesses/day: '
            f'<b>{p.avg_daily_file_access:.0f}</b> · Top domains: {", ".join(json.loads(p.top_domains)[:6])}</div>',
            unsafe_allow_html=True)

    # risk timeline
    fig = go.Figure()
    fig.add_vrect(x0=S["date"].min(), x1=meta.get("train_end"), fillcolor="#f0efec", line_width=0, layer="below",
                  annotation_text="baseline", annotation_position="top left",
                  annotation_font=dict(size=10, color=MUTED))
    fig.add_scatter(x=S["date"], y=S["daily_risk"], name="Daily risk", mode="lines",
                    line=dict(color=BLUE, width=2), hovertemplate="%{x}<br>daily risk %{y:.0f}<extra></extra>")
    fig.add_scatter(x=S["date"], y=S["entity_risk"], name="Accumulated risk", mode="lines",
                    line=dict(color=ORANGE, width=2, dash="dot"),
                    hovertemplate="%{x}<br>accumulated %{y:.0f}<extra></extra>")
    if len(EA):
        fig.add_scatter(x=EA["date"], y=EA["risk_score"], mode="markers", name="Alert",
                        marker=dict(size=11, color=[SEV_COLOR[s] for s in EA.severity], symbol="diamond",
                                    line=dict(color="white", width=2)),
                        text=EA["title"], hovertemplate="%{x}<br>%{text}<br>risk %{y:.0f}<extra></extra>")
    if has_truth:
        lab = S[S.label == 1]
        if len(lab):
            fig.add_scatter(x=lab["date"], y=[103] * len(lab), mode="markers", name="Planted attack (truth)",
                            marker=dict(symbol="triangle-down", size=10, color=INK),
                            hovertemplate="%{x}: planted attack<extra></extra>")
    fig.add_hline(y=float(meta.get("alert_threshold", CONFIG.alert_threshold)), line=dict(color=MUTED, dash="dash", width=1))
    fig.update_layout(title="Risk over time", yaxis_range=[0, 108])
    show(style(fig, 340))

    # day drill-down
    test_days = S[S.is_train == 0]["date"].tolist()
    pre = st.session_state.get("entity_date")
    if pre not in test_days:
        pre = S.loc[S.is_train == 0].sort_values("daily_risk").iloc[-1]["date"] if len(test_days) else S["date"].iloc[-1]
    day = st.select_slider("Drill into day", options=S["date"].tolist(), value=pre)
    row = S[S.date == day].iloc[0]
    l, r = st.columns(2)
    with l:
        feats = Q(f"SELECT * FROM features_{etype} WHERE entity=?", (ent,))
        base = feats[(feats.date >= meta["train_start"]) & (feats.date < meta["train_end"])]
        today = feats[feats.date == day]
        topf = json.loads(row["top_features"])
        names = list(topf.keys())[::-1]
        fig = go.Figure(go.Bar(
            x=[topf[n] for n in names], y=[LABELS.get(n, n) for n in names], orientation="h",
            marker_color=[ORANGE if topf[n] >= CONFIG.z_alert else BLUE for n in names],
            customdata=[[float(today[n].iloc[0]) if len(today) else 0, float(base[n].median()) if len(base) else 0]
                        for n in names],
            hovertemplate="%{y}<br>today %{customdata[0]:,.1f} · usual %{customdata[1]:,.1f}<br>z = %{x:.1f}<extra></extra>"))
        fig.add_vline(x=CONFIG.z_alert, line=dict(color=MUTED, dash="dash", width=1))
        fig.update_layout(title=f"Biggest deviations on {day} (robust z-score)")
        show(style(fig, 300, legend=False))
        st.markdown(f"Daily risk **{row['daily_risk']:.0f}** · personal {row['stat']:.2f} · peer {row['peer']:.2f} "
                    f"· ML {row['ml']:.2f} (IF {row['ml_iforest']:.2f}, LOF {row['ml_lof']:.2f}, "
                    f"AE {row['ml_autoencoder']:.2f}) · rules {row['rule']:.2f}")
        for h in json.loads(row["rule_hits"]):
            st.markdown(f"- 🚩 **{h['name']}** – {h['message']} `{h['mitre']}`")
    with r:
        if etype == "user":
            au = Q("SELECT timestamp, date, result FROM auth WHERE user=?", (ent,))
            au["hour"] = pd.to_datetime(au["timestamp"]).dt.hour
            b = au[(au.date >= meta["train_start"]) & (au.date < meta["train_end"]) & (au.result == "success")]
            t = au[au.date == day]
            bh = b.groupby("hour").size().reindex(range(24), fill_value=0) / max(1, b.date.nunique())
            th = t.groupby("hour").size().reindex(range(24), fill_value=0)
            fig = go.Figure()
            fig.add_bar(x=list(range(24)), y=bh.values, name="Baseline (avg logins/day)", marker_color=BLUE)
            fig.add_bar(x=list(range(24)), y=th.values, name=f"{day} (logins incl. failures)", marker_color=ORANGE)
            fig.update_layout(title="Login hours: baseline vs selected day", barmode="group",
                              xaxis=dict(dtick=2, title="hour of day"))
            show(style(fig, 300))
        else:
            rs = Q("SELECT timestamp, cpu_pct, mem_pct FROM resource WHERE device=? AND date=?", (ent, day))
            fig = go.Figure()
            fig.add_scatter(x=rs["timestamp"], y=rs["cpu_pct"], name="CPU %", line=dict(color=BLUE, width=2))
            fig.add_scatter(x=rs["timestamp"], y=rs["mem_pct"], name="Memory %", line=dict(color=AQUA, width=2))
            fig.update_layout(title=f"Resource usage on {day}", yaxis_range=[0, 100])
            show(style(fig, 300))
    col = "user" if etype == "user" else "device"
    ev = Q(f"SELECT timestamp, source, action, target, outcome, detail, device, user FROM events "
           f"WHERE {col}=? AND date=? AND source != 'resource' ORDER BY timestamp", (ent, day))
    st.markdown(f"**Event timeline – {day}** ({len(ev):,} events)")
    st.dataframe(ev, hide_index=True, height=300)
