"""Sign-in gate. First run: create the administrator account. Afterwards: log in."""
from __future__ import annotations

from datetime import datetime, timedelta

import streamlit as st

from ueba import auth

SESSION_HOURS = 8


def _center():
    _, mid, _ = st.columns([1, 1.3, 1])
    return mid


def gate() -> dict:
    """Return the signed-in user, or render the login / setup screen and stop the run."""
    user = st.session_state.get("user")
    if user and datetime.fromisoformat(user["since"]) > datetime.now() - timedelta(hours=SESSION_HOURS):
        return user
    st.session_state.pop("user", None)

    with _center():
        st.markdown("## UEBA Console")
        st.caption("AI-based User & Entity Behaviour Analytics")
        if not auth.has_users():
            st.markdown("#### Create the administrator account")
            st.caption("First start: this account manages data sources, users and API tokens. "
                       f"Passwords need at least {auth.MIN_PASSWORD} characters and are stored as salted "
                       "PBKDF2 hashes.")
            with st.form("setup"):
                u = st.text_input("Username", value="admin")
                p1 = st.text_input("Password", type="password")
                p2 = st.text_input("Confirm password", type="password")
                if st.form_submit_button("Create account and sign in", type="primary"):
                    if p1 != p2:
                        st.error("Passwords don't match")
                    else:
                        try:
                            auth.create_user(u, p1, "admin", by="setup")
                            _login(auth.authenticate(u, p1))
                        except ValueError as e:
                            st.error(str(e))
        else:
            with st.form("login"):
                u = st.text_input("Username")
                p = st.text_input("Password", type="password")
                if st.form_submit_button("Sign in", type="primary"):
                    try:
                        _login(auth.authenticate(u, p))
                    except ValueError as e:
                        st.error(str(e))
            st.caption("Forgot the password? An admin can reset it under Administration → Users.")
    st.stop()


def _login(user: dict):
    st.session_state["user"] = dict(user, since=datetime.now().isoformat(timespec="seconds"))
    st.rerun()


def logout():
    u = st.session_state.pop("user", None)
    if u:
        auth.audit(u["username"], "logout")
    st.rerun()
