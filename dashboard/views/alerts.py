"""Alerts - the analyst's work queue.

* **Cases** (default): alerts on the same entity within a week are one case, with a status,
  an assignee and a notes timeline; closing a case records a verdict for every day it covers.
* **All alerts**: every alert with filters, CSV export and per-alert verdicts.
* **Suppressions**: known-benign patterns switched off for an entity until an expiry date.
"""
from __future__ import annotations

import json
from datetime import date, timedelta

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.ui import *  # noqa: F401,F403 - palette, chart helpers, ctx, queries
from dashboard.ui import ctx
from ueba import auth, cases, feedback

STATUS_ICON = {"open": "open", "investigating": "investigating", "closed - benign": "closed - benign",
               "closed - threat": "closed - threat", "confirmed threat": "confirmed threat",
               "suppressed": "suppressed"}


def detector_bar(row) -> go.Figure:
    names = ["Personal baseline", "Peer group", "ML ensemble", "Threat rules"]
    vals = [row["stat"], row["peer"], row["ml"], row["rule"]]
    fig = go.Figure(go.Bar(x=vals, y=names, orientation="h", marker_color=[BLUE, AQUA, VIOLET, ORANGE],
                           text=[f"{v:.2f}" for v in vals], textposition="outside",
                           hovertemplate="%{y}: %{x:.2f}<extra></extra>"))
    fig.update_layout(title="What triggered it (detector scores, 0-1)", xaxis_range=[0, 1.15])
    return style(fig, 230, legend=False).update_yaxes(autorange="reversed")


def _after_change(dates):
    """Analyst decisions change what baselines learn and what the queue shows."""
    cases.restatus(ctx.DB)
    if len(dates):
        ctx.ws.changed_from(min(dates))
    st.rerun()


def alert_detail(row, key: str):
    """Reasons, ATT&CK techniques, layer scores and ground truth for one alert."""
    l, r = st.columns([3, 2])
    with l:
        st.markdown(f"#### {row['title']}  \n{sev_badge(row['severity'])} &nbsp; **{row['entity']}** "
                    f"({row['entity_type']}, {row['department']}) · {row['date']} · `{row['alert_id']}`",
                    unsafe_allow_html=True)
        st.markdown(f"**Risk {row['risk_score']:.0f}/100** · daily risk {row['daily_risk']:.0f} · "
                    f"accumulated entity risk {row['entity_risk']:.0f} · type `{row['alert_type']}` · "
                    f"{STATUS_ICON.get(row['status'], row['status'])}")
        st.markdown("**Why this was flagged**")
        for reason in json.loads(row["reasons"]) or ["Combination of weak deviations across several features"]:
            st.markdown(f"- {reason}")
        mitre = json.loads(row["mitre"])
        if mitre:
            st.markdown("**MITRE ATT&CK:** " + " · ".join(f"`{m}`" for m in mitre))
        if ctx.has_truth:
            truth = Q("SELECT * FROM ground_truth WHERE entity=? AND date=?", (row["entity"], row["date"]))
            if len(truth):
                st.success(f"Ground truth: labelled attack **{truth.iloc[0]['incident_id']} – "
                           f"{truth.iloc[0]['scenario']}**: {truth.iloc[0]['description']}")
            else:
                st.warning("Ground truth: no attack labelled here – a **false positive**.")
    with r:
        show(detector_bar(row), key=f"det_{key}")
        if st.button(f"Investigate {row['entity']} →", key=f"inv_{key}"):
            st.session_state["entity"] = row["entity"]
            st.session_state["entity_date"] = row["date"]
            st.session_state["page_current"] = "Investigate entity"
            st.rerun()


def suppress_form(row, key: str):
    with st.popover("Suppress this pattern"):
        st.caption(f"Stop alerting on **{row['title']}** for **{row['entity']}**. Alerts are still computed "
                   "and kept (marked suppressed) and the decision is audited.")
        scope = st.radio("For", [row["entity"], "everyone (*)"], horizontal=True, key=f"sscope_{key}")
        days = st.select_slider("For how long", [7, 30, 90, 180, 365], value=30, key=f"sdays_{key}",
                                format_func=lambda d: f"{d} days")
        reason = st.text_input("Reason (required)", key=f"sreason_{key}",
                               placeholder="e.g. night-shift backup admin, confirmed with manager")
        if st.button("Suppress", key=f"sgo_{key}", type="primary"):
            until = (pd.Timestamp(ctx.meta.get("last_day", date.today())) + timedelta(days=days)).date()
            ent = "*" if scope.startswith("everyone") else row["entity"]
            try:
                cases.suppress(ctx.DB, ent, row["title"], str(until), reason, ctx.user["username"])
            except ValueError as e:
                st.error(str(e))
                return
            audit("alert.suppress", f"{ent} / {row['title']} until {until}: {reason}")
            flash("success", f"Suppressed '{row['title']}' for {ent} until {until}.")
            _after_change([])


# ---------------------------------------------------------------- cases
def cases_tab(alerts):
    DB = ctx.DB
    allc = cases.build_cases(alerts, DB)
    if allc.empty:
        st.info("No cases - every alert is closed or suppressed.")
        return
    users = [""] + auth.list_users()["username"].tolist()
    me = ctx.user["username"]
    f1, f2, f3, f4 = st.columns([2.2, 1.8, 1.6, 2.4])
    stat = f1.multiselect("Status", list(cases.CASE_STATUSES), default=["open", "investigating"], key="c_status")
    sev = f2.multiselect("Severity", SEV_ORDER, default=["critical", "high", "medium"], key="c_sev")
    who = f3.selectbox("Assignee", ["anyone", "me", "unassigned"], key="c_who")
    search = f4.text_input("Search entity / title", key="c_search")
    C = allc[allc["status"].isin(stat) & allc["severity"].isin(sev)]
    if who == "me":
        C = C[C["assignee"] == me]
    elif who == "unassigned":
        C = C[C["assignee"] == ""]
    if search:
        s = search.lower()
        C = C[C["entity"].str.lower().str.contains(s) | C["titles"].str.lower().str.contains(s)]
    open_n = allc["status"].isin(["open", "investigating"]).sum()
    st.caption(f"{len(C)} of {len(allc)} cases shown · {open_n} need attention · {len(alerts)} alerts in total · "
               "click a row to open it")
    view = C[["case_id", "severity", "entity", "department", "first", "last", "alerts", "max_risk", "titles",
              "status", "assignee"]].copy()
    view["severity"] = view["severity"].map(str.capitalize)
    view["status"] = view["status"].map(lambda s: STATUS_ICON.get(s, s))
    ev = st.dataframe(view, hide_index=True, height=300, on_select="rerun", selection_mode="single-row", key="c_tbl",
                      column_config={"max_risk": st.column_config.ProgressColumn("Peak risk", min_value=0,
                                                                                  max_value=100, format="%.0f"),
                                     "case_id": None})
    sel = ev.selection.rows if ev and hasattr(ev, "selection") else []
    if not len(C):
        return
    case = C.iloc[sel[0]] if sel else C.iloc[0]
    A = alerts.assign(case_id=cases.assign_cases(alerts))
    CA = A[A["case_id"] == case["case_id"]].sort_values("date", ascending=False)

    st.divider()
    st.markdown(f"### Case {case['entity']} · {case['first']} → {case['last']}  \n"
                f"{sev_badge(case['severity'])} &nbsp; {STATUS_ICON[case['status']]} · {case['alerts']} alert(s) · "
                f"peak risk {case['max_risk']:.0f} · assignee **{case['assignee'] or '—'}**",
                unsafe_allow_html=True)
    left, right = st.columns([3, 2])
    with left:
        tl = CA[["date", "title", "severity", "risk_score", "status"]].copy()
        tl["severity"] = tl["severity"].map(str.capitalize)
        tl["status"] = tl["status"].map(lambda s: STATUS_ICON.get(s, s))
        st.markdown("**Alerts in this case**")
        ev2 = st.dataframe(tl, hide_index=True, height=min(250, 40 + 35 * len(tl)), on_select="rerun",
                           selection_mode="single-row", key=f"ca_{case['case_id']}",
                           column_config={"risk_score": st.column_config.ProgressColumn(
                               "Risk", min_value=0, max_value=100, format="%.0f")})
        s2 = ev2.selection.rows if ev2 and hasattr(ev2, "selection") else []
        row = CA.iloc[s2[0]] if s2 else CA.iloc[0]
    with right:
        st.markdown("**Case actions**")
        if not can("triage"):
            st.caption("Viewers can't change cases.")
        else:
            closed = case["status"].startswith("closed")
            c1, c2 = st.columns(2)
            assignee = c1.selectbox("Assignee", users, index=users.index(case["assignee"]) if case["assignee"] in users
                                    else 0, key=f"asg_{case['case_id']}", format_func=lambda u: u or "— unassigned")
            status = c2.selectbox("Status", ["open", "investigating"], key=f"st_{case['case_id']}",
                                  index=1 if case["status"] == "investigating" else 0, disabled=closed)
            if st.button("Save", key=f"save_{case['case_id']}"):
                cases.set_state(DB, case["case_id"], status=None if closed else status, assignee=assignee, by=me)
                audit("case.update", f"{case['case_id']} status={status} assignee={assignee or '-'}")
                st.rerun()
            note = st.text_area("Note", key=f"note_{case['case_id']}", height=70,
                                placeholder="What you checked, who you spoke to, what you decided")
            if st.button("Add note", key=f"addn_{case['case_id']}") and note.strip():
                cases.add_note(DB, case["case_id"], me, note)
                audit("case.note", case["case_id"])
                st.rerun()
            b2, b3 = st.columns(2)
            if not closed:
                if b2.button("Close as benign", key=f"cb_{case['case_id']}", help="Close as benign - learned into the baseline"):
                    days = cases.close(DB, case["case_id"], alerts, "benign", me, note)
                    audit("case.close_benign", f"{case['case_id']} ({len(days)} days) {note}")
                    _after_change(days)
                if b3.button("Close as threat", key=f"ct_{case['case_id']}", help="Close as a confirmed threat - never learned"):
                    days = cases.close(DB, case["case_id"], alerts, "threat", me, note)
                    audit("case.close_threat", f"{case['case_id']} ({len(days)} days) {note}")
                    _after_change(days)
            elif b2.button("Reopen", key=f"ro_{case['case_id']}"):
                days = cases.reopen(DB, case["case_id"], alerts, me)
                audit("case.reopen", case["case_id"])
                _after_change(days)
            suppress_form(row, f"c_{row['alert_id']}")
        nts = cases.notes(DB, case["case_id"])
        st.markdown(f"**Timeline** ({len(nts)})")
        for _, n in nts.iloc[::-1].head(8).iterrows():
            st.caption(f"{n['ts'][:16].replace('T', ' ')} · **{n['username']}** - {n['note']}")
    st.divider()
    alert_detail(row, f"case_{row['alert_id']}")


# ---------------------------------------------------------------- all alerts
def alerts_tab(alerts):
    DB = ctx.DB
    f1, f2, f3, f4 = st.columns([2, 2.2, 1.6, 2.4])
    sev = f1.multiselect("Severity", SEV_ORDER, default=["critical", "high", "medium"], key="a_sev")
    stat = f2.multiselect("Status", list(STATUS_ICON), default=["open", "confirmed threat"], key="a_status",
                          format_func=lambda s: STATUS_ICON[s])
    et = f3.multiselect("Entity", ["user", "device"], default=["user", "device"], key="a_et")
    search = f4.text_input("Search entity / title", key="a_search")
    A = alerts[alerts.severity.isin(sev) & alerts.entity_type.isin(et) & alerts.status.isin(stat)]
    if search:
        s = search.lower()
        A = A[A.entity.str.lower().str.contains(s) | A.title.str.lower().str.contains(s)]
    A = A.sort_values(["date", "risk_score"], ascending=[False, False])
    c1, c2 = st.columns([4, 1])
    c1.caption(f"{len(A)} of {len(alerts)} alerts · click a row to open it")
    export = A.drop(columns=[c for c in ("stat", "peer", "ml", "rule") if c in A]).copy()
    for c in ("reasons", "mitre", "detectors"):
        export[c] = export[c].map(lambda x: "; ".join(json.loads(x)) if isinstance(x, str) else x)
    c2.download_button("Export CSV", export.to_csv(index=False), f"alerts_{ctx.ws.slug}.csv", "text/csv")
    view = A[["alert_id", "date", "severity", "entity", "entity_type", "department", "title", "risk_score",
              "status"]].copy()
    view["severity"] = view["severity"].map(str.capitalize)
    view["status"] = view["status"].map(lambda s: STATUS_ICON.get(s, s))
    ev = st.dataframe(view, hide_index=True, height=320, on_select="rerun", selection_mode="single-row", key="a_tbl",
                      column_config={"risk_score": st.column_config.ProgressColumn(
                          "Risk", min_value=0, max_value=100, format="%.0f")})
    sel = ev.selection.rows if ev and hasattr(ev, "selection") else []
    if not len(A):
        return
    row = A.iloc[sel[0]] if sel else A.iloc[0]
    st.divider()
    alert_detail(row, f"all_{row['alert_id']}")
    if not can("triage"):
        return
    st.markdown("**Verdict for this day**")
    note = st.text_input("Note (optional)", key=f"note_{row['alert_id']}",
                         placeholder="e.g. user confirmed new project access")
    who = ctx.user["username"]
    b1, b2, b3, b4 = st.columns([1, 1, 1, 3])
    if b1.button("Benign", help="Mark as benign (false positive)", key=f"ben_{row['alert_id']}"):
        feedback.record(DB, row["entity"], row["date"], "benign", note, analyst=who, alert_id=row["alert_id"])
        audit("alert.benign", f"{row['alert_id']} {row['entity']} {row['date']} {note}")
        _after_change([row["date"]])
    if b2.button("Threat", help="Confirm as a real threat", key=f"thr_{row['alert_id']}"):
        feedback.record(DB, row["entity"], row["date"], "threat", note, analyst=who, alert_id=row["alert_id"])
        audit("alert.threat", f"{row['alert_id']} {row['entity']} {row['date']} {note}")
        _after_change([row["date"]])
    if row["status"] in ("closed - benign", "confirmed threat") and b3.button("Reopen", key=f"clr_{row['alert_id']}"):
        feedback.clear(DB, row["entity"], row["date"])
        audit("alert.reopen", f"{row['alert_id']} {row['entity']} {row['date']}")
        _after_change([row["date"]])
    with b4:
        suppress_form(row, f"a_{row['alert_id']}")
    st.caption("Benign days are learned into this entity's baseline at the next analysis (the collector service "
               "re-scores the following days automatically). Confirmed threats are never learned.")


# ---------------------------------------------------------------- suppressions
def suppressions_tab():
    sup = cases.list_suppressions(ctx.DB)
    if sup.empty:
        st.info("No suppressions. Use **Suppress this pattern** on an alert to stop a known-benign pattern "
                "from alerting.")
        return
    alerts = ctx.alerts
    sup["hidden alerts"] = [int(((alerts["entity"] == r.entity) | (r.entity == "*")).mul(alerts["title"] == r.title)
                                .mul(alerts["status"] == "suppressed").sum()) for r in sup.itertuples()]
    sup["active"] = sup["active"].map({1: "active", 0: "lifted"})
    st.dataframe(sup[["sup_id", "entity", "title", "until", "reason", "created_by", "created_at", "active",
                      "hidden alerts"]], hide_index=True)
    live = sup[sup["active"] == "active"]
    if len(live) and can("triage"):
        c1, c2 = st.columns([4, 1])
        sid = c1.selectbox("Lift a suppression", live["sup_id"],
                           format_func=lambda i: f"#{i} - {live.set_index('sup_id').loc[i, 'entity']} / "
                                                 f"{live.set_index('sup_id').loc[i, 'title']}")
        if c2.button("Lift"):
            cases.lift(ctx.DB, sid)
            audit("alert.unsuppress", f"#{sid}")
            flash("info", f"Suppression #{sid} lifted.")
            _after_change([])


def page_alerts():
    alerts = ctx.alerts
    st.title("Alerts")
    learning_banner()
    if alerts.empty:
        st.info("No alerts in the detection window.")
        return
    alerts = alerts.copy()
    alerts["status"] = alerts["status"].fillna("open")
    n_sup = len(cases.list_suppressions(ctx.DB, active_only=True))
    t1, t2, t3 = st.tabs(["Cases", "All alerts", f"Suppressions ({n_sup})"])
    with t1:
        cases_tab(alerts)
    with t2:
        alerts_tab(alerts)
    with t3:
        suppressions_tab()
