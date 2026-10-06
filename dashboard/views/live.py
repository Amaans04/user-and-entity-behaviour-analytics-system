"""Live host monitor - one-off capture of this machine's telemetry."""
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


def page_live():
    st.title("Live host monitor")
    st.caption("A one-off look at the computer running this dashboard (psutil), in the same log schema "
               "(saved to data/live/). For continuous monitoring of machines, run the endpoint agent - "
               "see Data sources → Automatic collection.")
    n = st.slider("Samples", 3, 30, 8)
    if st.button("Capture now", type="primary"):
        try:
            from ueba.collector import capture
            with st.spinner("Sampling…"):
                res, net = capture(n, interval=1.0)
            st.session_state["live"] = (res, net)
        except Exception as e:  # noqa: BLE001
            st.error(f"Capture failed: {e}")
    if "live" in st.session_state:
        res, net = st.session_state["live"]
        c = st.columns(4)
        c[0].metric("Avg CPU", f"{res.cpu_pct.mean():.0f}%")
        c[1].metric("Memory", f"{res.mem_pct.iloc[-1]:.0f}%")
        c[2].metric("Processes", f"{res.process_count.iloc[-1]}")
        c[3].metric("Open connections", f"{len(net.drop_duplicates(['dst_ip', 'dst_port'])) if len(net) else 0}")
        fig = go.Figure()
        fig.add_scatter(x=res.timestamp, y=res.cpu_pct, name="CPU %", line=dict(color=BLUE, width=2))
        fig.add_scatter(x=res.timestamp, y=res.mem_pct, name="Memory %", line=dict(color=AQUA, width=2))
        fig.update_layout(title="This machine", yaxis_range=[0, 100])
        show(style(fig, 300))
        if len(net):
            agg = (net.groupby(["domain", "dst_ip", "dst_port"]).size().rename("samples").reset_index()
                   .sort_values("samples", ascending=False))
            agg["mining_port"] = agg.dst_port.isin([3333, 4444, 5555, 7777, 14444])
            st.markdown("**Established connections (process → remote)**")
            st.dataframe(agg, hide_index=True)
