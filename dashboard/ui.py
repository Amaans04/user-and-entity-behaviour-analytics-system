"""Shared dashboard plumbing: palette and chart styling, the per-run context, cached
queries against the current workspace, permissions, audit and small UI helpers.

``ctx`` is filled by ``app.py`` at the start of every run (current user, workspace,
loaded scores/alerts ...) and read by the views.
"""
from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from ueba import auth

# ---------------------------------------------------------------- palette
BLUE, ORANGE, AQUA, VIOLET = "#2a78d6", "#eb6834", "#1baf7a", "#4a3aa7"
SEV_COLOR = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#898781"}
SEV_ICON = {"critical": "⛔", "high": "🔺", "medium": "⚠️", "low": "ℹ️"}
SEV_ORDER = ["critical", "high", "medium", "low"]
INK, INK2, MUTED, GRID, AXIS = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
STATE_UI = {"empty": ("⚪", "No data yet"), "needs_analysis": ("🟠", "New data - not analysed yet"),
            "learning": ("🟡", "Learning normal behaviour"), "monitoring": ("🟢", "Monitoring")}

CSS = """
<style>
.block-container {padding-top: 1.6rem; max-width: 1400px;}
div[data-testid="stMetricValue"] {font-size: 1.7rem;}
.sev {display:inline-block; padding:2px 8px; border-radius:10px; font-size:0.78rem; font-weight:600;
      color:#fff;}
.card {border:1px solid rgba(11,11,11,.10); border-radius:10px; padding:14px 16px; margin-bottom:10px;}
.muted {color:#6b6a66; font-size:0.85rem;}
</style>"""

class _SessionContext:
    """Per-browser-session context. Streamlit serves every session from the same process, so a
    plain module-level object would let two signed-in users overwrite each other's user and
    workspace mid-run; this proxies attribute access to the session's own ``st.session_state``."""

    @staticmethod
    def _ns() -> SimpleNamespace:
        if "_ctx" not in st.session_state:
            st.session_state["_ctx"] = SimpleNamespace(
                user=None, ws=None, DB=None, status={}, meta={}, scores=pd.DataFrame(), alerts=pd.DataFrame(),
                test_scores=pd.DataFrame(), has_truth=False, monitoring=False)
        return st.session_state["_ctx"]

    def __getattr__(self, name):
        return getattr(self._ns(), name)

    def __setattr__(self, name, value):
        setattr(self._ns(), name, value)


ctx = _SessionContext()


def apply_css():
    st.markdown(CSS, unsafe_allow_html=True)


def style(fig: go.Figure, height: int = 320, legend: bool = True) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=10, r=10, t=36, b=10), plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)", font=dict(family="system-ui, -apple-system, Segoe UI, sans-serif",
                                                 size=12, color=INK2),
        showlegend=legend, legend=dict(orientation="h", y=1.08, x=0, font=dict(size=11)),
        hoverlabel=dict(bgcolor="white", font_size=12), bargap=0.25, title_font=dict(size=14, color=INK))
    fig.update_xaxes(showgrid=False, linecolor=AXIS, tickfont=dict(color=MUTED))
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor=AXIS, tickfont=dict(color=MUTED))
    return fig


def show(fig):
    st.plotly_chart(fig, width="stretch", config={"displaylogo": False})


def sev_badge(sev: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLOR.get(sev, MUTED)}">{SEV_ICON.get(sev, "")} {sev.upper()}</span>'


# ---------------------------------------------------------------- data
def db_mtime() -> float:
    return ctx.DB.stat().st_mtime if ctx.DB is not None and ctx.DB.exists() else 0.0


@st.cache_data(show_spinner=False)
def _q(db: str, sql: str, mtime: float, params: tuple = ()) -> pd.DataFrame:
    with sqlite3.connect(db) as con:
        return pd.read_sql(sql, con, params=params)


def Q(sql: str, params: tuple = ()) -> pd.DataFrame:
    """Cached query against the current workspace; re-reads automatically when the database changes."""
    return _q(str(ctx.DB), sql, db_mtime(), params)


def table_exists(name: str) -> bool:
    return ctx.DB.exists() and not Q("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)).empty


# ---------------------------------------------------------------- permissions, audit, messages
def can(action: str) -> bool:
    return auth.can(ctx.user, action)


def audit(action: str, detail: str = ""):
    auth.audit(ctx.user["username"] if ctx.user else "?", action,
               workspace=ctx.ws.slug if ctx.ws is not None else "", detail=detail)


def flash(kind: str, msg: str):
    """Show ``msg`` at the top of the next run (survives st.rerun)."""
    st.session_state["flash"] = (kind, msg)


def show_flash():
    if "flash" in st.session_state:
        kind, msg = st.session_state.pop("flash")
        getattr(st, kind)(msg)


def pick_workspace(slug: str):
    st.session_state["ws_current"] = slug
    st.query_params["ws"] = slug


def goto(page: str):
    st.session_state["page_current"] = page


# ---------------------------------------------------------------- analysis
def analyse(regenerate: bool = False, seed: int | None = None, full: bool = False):
    """Run an analysis of the current workspace from the UI (incremental unless ``full``)."""
    ws = ctx.ws
    label = ("Generating demo logs and analysing" if regenerate else
             f"Re-training and analysing {ws.name}" if full else f"Analysing new data in {ws.name}")
    try:
        with st.spinner(f"{label}…"):
            if regenerate:
                res = ws.regenerate_demo(seed)
            elif full:
                res = ws.analyse()
            else:
                res = ws.update()
        how = {"update": "incremental update", "full": "full re-training"}.get(res.get("mode"), "analysis")
        flash("success", f"Analysis complete ({how}) - {len(res['alerts'])} alerts.")
        audit("analysis.regenerate" if regenerate else "analysis.full" if full else "analysis.update",
              f"mode={res.get('mode')} alerts={len(res['alerts'])}")
        from ueba import notify
        if not ws.is_demo:
            notify.notify_workspace(ws, res["alerts"])
    except (ValueError, FileNotFoundError) as e:
        flash("error", f"Analysis failed: {e}")
    st.cache_data.clear()
    st.rerun()


def learning_progress(stat: dict) -> tuple[int, int]:
    return min(stat["coverage"]["days"], stat["learning_days"]), stat["learning_days"]


def learning_banner():
    """Shown on result pages while the workspace hasn't covered its learning period yet."""
    if ctx.monitoring:
        return
    days = ctx.status["coverage"]["days"]
    st.info(f"🟡 **Learning normal behaviour - {min(days, ctx.status['learning_days'])} of "
            f"{ctx.status['learning_days']} days collected.** Profiles and models are built from these days; "
            f"alerts start once data after {ctx.meta.get('train_end')} arrives. Add newer logs in "
            "**Data sources**, or shorten the learning period there.")
