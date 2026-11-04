"""Administration - users and roles, API tokens, audit trail and service health (admins only)."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from dashboard.ui import ai_status, ctx, flash
from ueba import auth, llm, service
from ueba import workspace as WS


def page_admin():
    st.title("Administration")
    if not auth.can(ctx.user, "manage"):
        st.warning("Administrators only.")
        return
    me = ctx.user["username"]
    t_users, t_tokens, t_audit, t_service, t_ai = st.tabs(["Users", "API tokens", "Audit log", "Service",
                                                            "AI assistant"])
    with t_ai:
        _ai_settings(me)

    with t_users:
        st.caption("**viewer** - read only · **analyst** - + triage alerts · **admin** - + data sources, "
                   "analysis, settings, users, tokens")
        users = auth.list_users()
        st.dataframe(users, hide_index=True)
        c1, c2 = st.columns(2)
        with c1, st.form("add_user", clear_on_submit=True):
            st.markdown("**Add user**")
            u = st.text_input("Username")
            p = st.text_input("Initial password", type="password")
            r = st.selectbox("Role", auth.ROLES, index=1)
            if st.form_submit_button("Add user"):
                try:
                    auth.create_user(u, p, r, by=me)
                    flash("success", f"User {u} created")
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))
        with c2:
            st.markdown("**Change user**")
            who = st.selectbox("User", users["username"].tolist(), key="adm_who")
            if who:
                r = st.selectbox("Role", auth.ROLES, index=auth.ROLES.index(
                    users.set_index("username").loc[who, "role"]), key="adm_role")
                newpw = st.text_input("New password (leave empty to keep)", type="password", key="adm_pw")
                b1, b2 = st.columns(2)
                if b1.button("Save changes"):
                    try:
                        auth.set_role(who, r, by=me)
                        if newpw:
                            auth.set_password(who, newpw, by=me)
                        flash("success", f"{who} updated")
                        st.rerun()
                    except ValueError as e:
                        st.error(str(e))
                if who != me and b2.button("Delete user", type="secondary"):
                    try:
                        auth.delete_user(who, by=me)
                        flash("info", f"{who} deleted")
                        st.rerun()
                    except ValueError as e:
                        st.error(str(e))

    with t_tokens:
        st.caption("Tokens let agents and log shippers push data to the ingest API "
                   "(`Authorization: Bearer <token>`). Each is limited to one workspace or `*` (all).")
        if st.session_state.get("new_token"):
            name, secret = st.session_state["new_token"]
            st.success(f"Token **{name}** created - copy it now, it is not shown again:")
            st.code(secret, language=None)
            if st.button("I've copied it"):
                st.session_state.pop("new_token")
                st.rerun()
        with st.form("new_token_form", clear_on_submit=True):
            c1, c2, c3 = st.columns([2, 2, 1])
            name = c1.text_input("Name", placeholder="e.g. laptop-agent, proxy-shipper")
            scopes = ["*"] + [w.slug for w in WS.list_all() if not w.is_demo]
            scope = c2.selectbox("Workspace", scopes,
                                 index=scopes.index(ctx.ws.slug) if ctx.ws.slug in scopes else 0)
            if c3.form_submit_button("Create token", type="primary"):
                secret = auth.create_token(name, scope, by=me)
                st.session_state["new_token"] = (name or "token", secret)
                st.rerun()
        toks = auth.list_tokens()
        if len(toks):
            st.dataframe(toks.assign(revoked=toks["revoked"].astype(bool)), hide_index=True)
            live = toks[toks["revoked"] == 0]
            if len(live):
                c1, c2 = st.columns([3, 1])
                tid = c1.selectbox("Revoke token", live["token_id"],
                                   format_func=lambda t: f"{t} - {live.set_index('token_id').loc[t, 'name']}")
                if c2.button("Revoke"):
                    auth.revoke_token(tid, by=me)
                    flash("info", f"Token {tid} revoked")
                    st.rerun()

    with t_audit:
        log = auth.audit_log(2000)
        c1, c2 = st.columns(2)
        users = c1.multiselect("User", sorted(log["username"].unique()))
        actions = c2.multiselect("Action", sorted(log["action"].unique()))
        if users:
            log = log[log["username"].isin(users)]
        if actions:
            log = log[log["action"].isin(actions)]
        st.dataframe(log, hide_index=True, height=420)
        st.download_button("Download CSV", log.to_csv(index=False), "ueba_audit.csv", "text/csv")

    with t_service:
        hb = service.read_heartbeat()
        if not hb:
            st.warning("The collector service has never run on this machine.")
        elif hb["alive"]:
            st.success(f"Collector service running (pid {hb['pid']}, last pass {hb['age_seconds']} s ago, "
                       f"every {hb['interval']:g} s)" + (f" · ingest API at `{hb['api']}`" if hb.get("api") else ""))
        else:
            st.error(f"Collector service stopped - last seen {hb['last_tick']}")
        st.code("python -m ueba.service --api        # inbox watcher + scoring + notifications + ingest API",
                language="bash")
        if hb and hb.get("last"):
            st.markdown("**Last activity per workspace**")
            st.dataframe(pd.DataFrame([dict(workspace=k, **v) for k, v in hb["last"].items()]), hide_index=True)


def _ai_settings(me: str):
    """Pick the local language model (Ollama) that writes case summaries and command explanations."""
    st.caption("A language model running locally through Ollama writes plain-English case summaries and "
               "explains logged commands. It never raises, scores or closes alerts - detection stays with the "
               "baselines, the ML ensemble and the threat rules - and no log data leaves this machine.")
    cur = llm.settings()
    stat = ai_status()
    models = llm.installed_models()
    st.markdown(f"**Status:** {'ready - ' + stat['model'] if stat['ready'] else 'offline - ' + stat['reason']}  \n"
                f"**Ollama address:** `{cur['url']}`")
    if not models:
        st.info("Ollama isn't reachable. Start it with `ollama serve`, then install a model, e.g. "
                "`ollama pull qwen2.5:7b`.")
    with st.form("ai_settings"):
        on = st.toggle("Use the AI assistant", value=cur["enabled"])
        options = models or [cur["model"]]
        model = st.selectbox("Model", options, index=options.index(cur["model"]) if cur["model"] in options else 0,
                             help="7-8B models are a good balance on a laptop; larger ones explain better but slower.")
        if st.form_submit_button("Save", type="primary"):
            llm.save_settings(on, model)
            ai_status.clear()
            auth.audit(me, "ai.settings", detail=f"enabled={on} model={model}")
            flash("success", f"AI assistant {'on' if on else 'off'} - model {model}.")
            st.rerun()
