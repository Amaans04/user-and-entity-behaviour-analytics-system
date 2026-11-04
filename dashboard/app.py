"""UEBA Security Operations console (Streamlit).

Run:  streamlit run dashboard/app.py
      (with the collector service alongside:  python -m ueba.service --api)

This file is the shell: sign-in, workspace selection, status, navigation and live
refresh. Each page lives in ``dashboard/views/``; shared helpers in ``dashboard/ui.py``.
"""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from dashboard import ui  # noqa: E402
from dashboard.ui import Q, STATE_UI, ctx, learning_progress, table_exists  # noqa: E402
from dashboard.views import (activity, admin, alerts, entity, live, login, logs, overview, performance,  # noqa: E402
                             sources)
from ueba import auth, service, workspace as WS  # noqa: E402

st.set_page_config(page_title="UEBA Console", layout="wide")
ui.apply_css()

ctx.user = login.gate()          # stops here with the sign-in screen when nobody is logged in


# ---------------------------------------------------------------- workspace
def _create_workspace():
    try:
        new = WS.create(st.session_state.get("new_ws_name", ""), int(st.session_state.get("new_ws_days", 30)))
    except ValueError as e:
        ui.flash("error", str(e))
        return
    auth.audit(ctx.user["username"], "workspace.create", workspace=new.slug, detail=new.name)
    ui.pick_workspace(new.slug)
    ui.goto("Data sources")
    st.session_state["new_ws_name"] = ""
    ui.flash("success", f"Workspace **{new.name}** created - add logs below, or turn on automatic collection.")


all_ws = {w.slug: w for w in WS.list_all()}
if st.session_state.get("ws_current") not in all_ws:     # first load: take it from the URL (?ws=...)
    st.session_state["ws_current"] = st.query_params.get("ws") if st.query_params.get("ws") in all_ws else WS.DEMO
st.sidebar.title("UEBA Console")
st.sidebar.caption("AI-based User & Entity Behaviour Analytics")
slugs = list(all_ws)
picked = st.sidebar.selectbox("Workspace", slugs, index=slugs.index(st.session_state["ws_current"]),
                              format_func=lambda k: all_ws[k].name)
if picked != st.session_state["ws_current"]:
    ui.pick_workspace(picked)
    st.rerun()
if st.query_params.get("ws") != picked:
    st.query_params["ws"] = picked
ctx.ws = WS.get(picked)
ctx.DB = ctx.ws.db_path
if ui.can("manage"):
    with st.sidebar.expander("New workspace"):
        st.text_input("Name", key="new_ws_name", placeholder="e.g. Lab network - Oct 2026")
        st.number_input("Learning period (days)", WS.MIN_LEARNING_DAYS, 180, 30, key="new_ws_days",
                        help="Days of history used to learn normal behaviour before alerts start.")
        st.button("Create workspace", on_click=_create_workspace, type="primary")

# ---------------------------------------------------------------- status
ctx.status = ctx.ws.status()
icon, text = STATE_UI[ctx.status["state"]]
st.sidebar.markdown(f"**Status:** {text}")
if ctx.status["state"] == "learning":
    done, need = learning_progress(ctx.status)
    st.sidebar.progress(done / need, text=f"Baseline {done}/{need} days")
hb = service.read_heartbeat()
service_on = bool(hb and hb["alive"])
if not ctx.ws.is_demo:
    auto = ctx.ws.setting("auto_ingest")
    st.sidebar.caption(("Collector service: running" if service_on else "Collector service: not running")
                       + (" · auto-collect on" if auto and service_on else ""))
if ctx.status["state"] == "needs_analysis" and ui.can("manage") and not (service_on and ctx.ws.setting("auto_ingest")
                                                                        and not ctx.ws.is_demo):
    if st.sidebar.button("Analyse now", type="primary"):
        ui.analyse()

# ---------------------------------------------------------------- navigation
has_results = table_exists("scores")
PAGES = (["Overview", "Alerts", "Investigate entity", "User activity", "Model performance"] if has_results else []) + \
        ["Data sources", "Live host monitor"] + (["Log explorer"] if has_results else []) + \
        (["Administration"] if ui.can("manage") else [])
if st.session_state.get("page_current") not in PAGES:
    st.session_state["page_current"] = PAGES[0]
page = st.sidebar.radio("View", PAGES, index=PAGES.index(st.session_state["page_current"]))
if page != st.session_state["page_current"]:
    ui.goto(page)
    st.rerun()


@st.fragment(run_every="5s")
def live_watch():
    """Re-run the whole page when the workspace's data changes (new logs, a finished analysis)."""
    if not st.session_state.get("live_on", True):
        return
    sig = (ui.db_mtime(), ctx.ws.reload().meta.get("last_analysis"), ctx.ws.status()["state"])
    key = f"live_sig_{ctx.ws.slug}"
    if st.session_state.get(key) not in (None, sig):
        st.session_state[key] = sig
        st.cache_data.clear()
        st.rerun(scope="app")
    st.session_state[key] = sig


_ai = ui.ai_status()
st.sidebar.caption(f"AI assistant: {_ai['model']} (local)" if _ai["ready"] else "AI assistant: offline")
with st.sidebar:
    st.toggle("Live refresh", key="live_on", value=True,
              help="Refresh automatically when new data is analysed (checks every 5 s)")
    live_watch()

# ---------------------------------------------------------------- context for the views
if has_results:
    ctx.meta = dict(Q("SELECT key, value FROM meta").values)
    m = ctx.meta
    with st.sidebar.expander("Dataset details"):
        st.markdown(f"**Baseline:** {m.get('train_start')} → {m.get('train_end')}  \n"
                    f"**Data until:** {m.get('last_day')}  \n"
                    f"**Log streams:** {m.get('streams', 'auth,access,network,resource').replace(',', ', ')}  \n"
                    f"**Alert threshold:** {float(m.get('alert_threshold', 45)):.0f}/100")
    ctx.scores = Q("SELECT * FROM scores")
    ctx.alerts = Q("SELECT * FROM alerts")
    ctx.has_truth = table_exists("ground_truth") and ctx.scores["label"].notna().any()
    ctx.test_scores = ctx.scores[ctx.scores["is_train"] == 0]
    ctx.monitoring = len(ctx.test_scores) > 0

st.sidebar.divider()
c1, c2 = st.sidebar.columns([3, 2])
c1.markdown(f"**{ctx.user['username']}**  \n<span class='muted'>{ctx.user['role']}</span>",
            unsafe_allow_html=True)
if c2.button("Sign out"):
    login.logout()
with st.sidebar.popover("Change password"):
    with st.form("own_pw", clear_on_submit=True):
        old = st.text_input("Current password", type="password")
        new1 = st.text_input("New password", type="password")
        new2 = st.text_input("Repeat new password", type="password")
        if st.form_submit_button("Change"):
            try:
                if new1 != new2:
                    raise ValueError("The new passwords don't match")
                auth.change_password(ctx.user["username"], old, new1)
                st.success("Password changed.")
            except ValueError as e:
                st.error(str(e))

ui.show_flash()
{"Overview": overview.page_overview, "Alerts": alerts.page_alerts, "Investigate entity": entity.page_entity, "User activity": activity.page_activity,
 "Model performance": performance.page_performance, "Data sources": sources.page_sources,
 "Live host monitor": live.page_live, "Log explorer": logs.page_logs, "Administration": admin.page_admin}[page]()
