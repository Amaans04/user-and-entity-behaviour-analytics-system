"""Log explorer - browse and export the raw log streams."""
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


def page_logs():
    scores = ctx.scores
    st.title("Log explorer")
    stream = st.radio("Stream", ["auth", "access", "network", "resource", "events"], horizontal=True)
    c1, c2, c3 = st.columns(3)
    key = "device" if stream == "resource" else "user"
    ent = c1.text_input(f"Filter {key} (exact, optional)", "")
    dates = scores["date"].sort_values().unique()
    day = c2.selectbox("Date", ["(all)"] + list(dates[::-1]))
    limit = c3.number_input("Max rows", 100, 20000, 1000, step=500)
    where, params = [], []
    if ent:
        where.append(f"{key}=?"); params.append(ent.lower() if key == "user" else ent)
    if day != "(all)":
        where.append("date=?"); params.append(day)
    sql = f"SELECT * FROM {stream}" + (" WHERE " + " AND ".join(where) if where else "") + \
          f" ORDER BY timestamp LIMIT {int(limit)}"
    df = Q(sql, tuple(params))
    st.caption(f"{len(df):,} rows")
    st.dataframe(df, hide_index=True, height=520)
    st.download_button("Download CSV", df.to_csv(index=False), f"{stream}.csv", "text/csv")
