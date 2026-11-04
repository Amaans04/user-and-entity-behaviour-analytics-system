"""User activity - what one person actually did on a day: pages, downloads, blocked attempts, files, logins,
USB sticks, admin rights, shared folders, printing and PowerShell.

The behaviour models say *how unusual* a day was; this page shows *what happened*, with every action that
is out of character for that person flagged (a site they never used, a blocked request, a hacking or
anonymizer site, an executable download, a sensitive file opened for the first time, a large upload).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.ui import BLUE, ORANGE, Q, ai_panel, ctx, show, style, table_exists
from ueba import web
from ueba.features import ACCOUNT_CMDS, ACTIVITY_ACTIONS, LOG_TAMPER, PS_SUSPICIOUS, share_root

LARGE_UPLOAD_MB = 50
LARGE_PRINT_PAGES = 50
SENSITIVE = ["confidential", "restricted"]
USB_ACTIONS = ["usb_connect", "copy_to_usb"]
ADMIN_ACTIONS = ["priv_escalation", "admin_logon", "runas"]


def _usual(feats: pd.DataFrame, col: str) -> float:
    return float(feats[col].median()) if col in feats and len(feats) else 0.0


def _metric(c, label: str, today: float, usual: float, fmt: str = "{:,.0f}"):
    hot = usual >= 0 and today >= max(3 * (usual + 1), usual + 3)
    c.metric(label, fmt.format(today), f"usual {fmt.format(usual)}", delta_color="inverse" if hot else "off",
             help="Today's value and this person's median day during the learning period")


def _net_select(cols: list[str], table: str = "network") -> str:
    """Only the columns this workspace's database has (analyses before web or print detail lack some)."""
    have = set(Q(f"PRAGMA table_info({table})")["name"])
    return ", ".join(c for c in cols if c in have)


def _text(df: pd.DataFrame) -> pd.DataFrame:
    """SQLite hands back mixed object columns (None, numbers); make every text column plain strings."""
    df = df.copy()
    for c in df.columns:
        if not pd.api.types.is_numeric_dtype(df[c]):
            df[c] = df[c].fillna("").astype(str).replace({"None": "", "nan": ""})
    return df


def _flags(df: pd.DataFrame, cond_labels: list[tuple[pd.Series, object]]) -> pd.Series:
    out = pd.Series([""] * len(df), index=df.index, dtype=object)
    for cond, label in cond_labels:
        lab = label.astype(str) if isinstance(label, pd.Series) else pd.Series([label] * len(df), index=df.index)
        hit = cond.fillna(False).astype(bool)
        out = out.where(~hit, (out + ", " + lab).str.lstrip(", "))
    return out


def page_activity():
    scores, alerts, meta = ctx.scores, ctx.alerts, ctx.meta
    st.title("User activity")
    st.caption("What a person actually did - pages visited, downloads, blocked attempts, files, logins, USB sticks, "
               "admin rights, shared folders, printing and PowerShell - with everything out of character for them "
               "flagged. Only metadata is shown, never page or file content.")
    users = sorted(scores.loc[scores.entity_type == "user", "entity"].unique())
    if not users:
        st.info("No user activity in this workspace yet.")
        return
    default = st.session_state.get("entity")
    if default not in users:
        ua = alerts[alerts.entity_type == "user"] if len(alerts) else alerts
        default = ua.sort_values("risk_score").iloc[-1]["entity"] if len(ua) else users[0]
    c1, c2 = st.columns([2, 3])
    user = c1.selectbox("Person", users, index=users.index(default))
    S = scores[scores.entity == user].sort_values("date")
    alert_days = set(alerts.loc[alerts.entity == user, "date"]) if len(alerts) else set()
    days = S["date"].tolist()
    pre = st.session_state.get("entity_date")
    if pre not in days:
        test = S[S.is_train == 0]
        pre = test.sort_values("daily_risk").iloc[-1]["date"] if len(test) else days[-1]
    risk = dict(zip(S["date"], S["daily_risk"]))
    day = c2.selectbox("Day", days[::-1], index=days[::-1].index(pre),
                       format_func=lambda d: f"{d} - risk {risk.get(d, 0):.0f}" + ("  (alert)" if d in alert_days else ""))
    st.session_state["entity"], st.session_state["entity_date"] = user, day

    feats = Q("SELECT * FROM features_user WHERE entity=?", (user,))
    base = feats[(feats.date >= meta.get("train_start", "")) & (feats.date < meta.get("train_end", ""))]
    today = feats[feats.date == day]
    tv = (lambda col: float(today[col].iloc[0]) if len(today) and col in today else 0.0)

    # ---------------------------------------------------------------- the day's data
    net = Q("SELECT * FROM network WHERE user=? AND date=? ORDER BY timestamp", (user, day))
    net = _text(web.enrich(net)) if len(net) else net
    prev = Q(f"SELECT DISTINCT {_net_select(['url', 'domain'])} FROM network WHERE user=? AND date<?", (user, day))
    prev = web.add_sites(prev.assign(url=prev["url"].fillna("") if "url" in prev else "")) if len(prev) else prev
    seen_sites = set(prev["site"]) if len(prev) else set()
    seen_hosts = set(prev["host"]) if len(prev) else set()
    acc_cols = _net_select(["timestamp", "device", "resource", "action", "sensitivity", "status", "pages", "printer"],
                           "access")
    acc = _text(Q(f"SELECT {acc_cols} FROM access WHERE user=? AND date=? ORDER BY timestamp", (user, day)))
    for c, empty in (("pages", 0), ("printer", "")):
        if c not in acc:
            acc[c] = empty
    acc["pages"] = pd.to_numeric(acc["pages"], errors="coerce").fillna(0).astype(int)
    past = Q("SELECT DISTINCT resource, action FROM access WHERE user=? AND date<?", (user, day))
    seen_files = set(past["resource"])
    seen_shares = set(share_root(past["resource"]).dropna())
    used_before = set(past["action"])                    # kinds of action this person has a history of
    au = Q("SELECT timestamp, auth_type, src_device, dest_host, src_ip, city, country, result FROM auth "
           "WHERE user=? AND date=? ORDER BY timestamp", (user, day)) if table_exists("auth") else pd.DataFrame()
    au = _text(au)

    # ---------------------------------------------------------------- headline numbers
    st.markdown(f"**{user} on {day}** - daily risk **{risk.get(day, 0):.0f}**"
                + (" · raised an alert" if day in alert_days else ""))
    m = st.columns(4)
    _metric(m[0], "Minutes online", tv("browsing_minutes"), _usual(base, "browsing_minutes"))
    _metric(m[1], "Websites", float(net["site"].nunique()) if len(net) else 0.0, _usual(base, "distinct_domains"))
    _metric(m[2], "Pages visited", tv("pages_visited"), _usual(base, "pages_visited"))
    _metric(m[3], "Downloads", tv("downloads"), _usual(base, "downloads"))
    m = st.columns(4)
    _metric(m[0], "Blocked attempts", tv("web_blocked"), _usual(base, "web_blocked"))
    _metric(m[1], "Files opened", tv("access_events"), _usual(base, "access_events"))
    _metric(m[2], "Sensitive files", tv("sensitive_access"), _usual(base, "sensitive_access"))
    _metric(m[3], "MB uploaded", tv("bytes_out_mb"), _usual(base, "bytes_out_mb"), "{:,.1f}")
    m = st.columns(5)
    _metric(m[0], "USB events", tv("removable_media"), _usual(base, "removable_media"))
    _metric(m[1], "Admin actions", tv("priv_esc") + tv("admin_logons") + tv("runas_events"),
            _usual(base, "priv_esc") + _usual(base, "admin_logons") + _usual(base, "runas_events"))
    _metric(m[2], "Shared folders", tv("shares_used"), _usual(base, "shares_used"))
    _metric(m[3], "Pages printed", tv("pages_printed"), _usual(base, "pages_printed"))
    _metric(m[4], "PowerShell commands", tv("ps_commands"), _usual(base, "ps_commands"))

    # ---------------------------------------------------------------- flagged tables
    if len(net):
        net["time"] = pd.to_datetime(net["timestamp"]).dt.strftime("%H:%M:%S")
        net["page"] = net["url"].where(net["url"] != "", net["domain"])
        net["MB down"] = (net["bytes_in"].astype(float) / 1e6).round(2)
        net["MB up"] = (net["bytes_out"].astype(float) / 1e6).round(2)
        net["flag"] = _net_flags(net, seen_sites, seen_hosts)
    if len(acc):
        acc["time"] = pd.to_datetime(acc["timestamp"]).dt.strftime("%H:%M:%S")
        act = acc["action"]
        is_file = ~act.isin(list(ACTIVITY_ACTIONS) + ["usb_connect"])
        new = ~acc["resource"].isin(seen_files) & ~acc.duplicated("resource")
        acc["share"] = share_root(acc["resource"]).where(is_file).fillna("")
        new_share = (acc["share"] != "") & ~acc["share"].isin(seen_shares) & ~acc.duplicated("share")
        sensitive = acc["sensitivity"].isin(SENSITIVE)
        acc["flag"] = _flags(acc, [
            (new & is_file & sensitive, "first time, " + acc["sensitivity"]),
            (new & is_file & ~sensitive, "first time"),
            (new & (act == "usb_connect"), "new USB device"),
            (act.isin(["priv_escalation", "copy_to_usb", "usb_connect", "admin_logon", "runas"]),
             act.replace({"priv_escalation": "privilege use", "copy_to_usb": "USB copy", "usb_connect": "USB device",
                          "admin_logon": "admin logon", "runas": "run as another account"})),
            (act.isin(ADMIN_ACTIONS) & ~act.isin(used_before), "never done before"),
            (new_share, "new shared folder"),
            (acc["share"].str.endswith("$"), "admin share"),
            ((act == "print") & sensitive, acc["sensitivity"] + " document printed"),
            ((act == "print") & (acc["pages"] >= LARGE_PRINT_PAGES), "large print job"),
            ((act == "powershell") & acc["resource"].str.contains(PS_SUSPICIOUS, case=False, regex=True),
             "suspicious PowerShell")])
    if len(au):
        au["time"] = pd.to_datetime(au["timestamp"]).dt.strftime("%H:%M:%S")

    tabs = st.tabs(["Story", "Websites", "Web browsing", "Downloads", "Blocked attempts", "Files", "Logins", "USB",
                    "Admin rights", "Shared folders", "Printing", "PowerShell"])
    with tabs[0]:
        _story(net, acc, au)
    with tabs[1]:
        _websites(user, day, net, seen_sites, seen_hosts, meta)
    tabs = tabs[1:]
    with tabs[1]:
        if not len(net):
            st.info("No web or network activity recorded for this day.")
        else:
            l, r = st.columns([3, 2])
            with l:
                only = st.toggle("Only flagged", key="web_only_flagged")
                v = net[net["flag"] != ""] if only else net
                st.dataframe(v[["time", "site", "host", "page", "category", "web_action", "MB down", "MB up", "flag"]]
                             .rename(columns={"host": "subdomain", "web_action": "result"}),
                             hide_index=True, height=420)
            with r:
                _category_chart(user, day, net, meta)
    with tabs[2]:
        dl = net[(net["file"] != "") & (net["web_action"] == "allowed")] if len(net) else net
        if not len(dl):
            st.info("No file downloads recorded for this day.")
        else:
            st.dataframe(dl[["time", "file", "domain", "category", "MB down", "flag"]]
                         .rename(columns={"domain": "from site"}), hide_index=True)
    with tabs[3]:
        bl = net[net["web_action"] == "blocked"] if len(net) else net
        if not len(bl):
            st.info("Nothing was blocked for this person on this day.")
        else:
            st.markdown(f"**{len(bl)} blocked request(s) to {bl['domain'].nunique()} site(s)** - usually "
                        f"{_usual(base, 'web_blocked'):.0f} a day.")
            st.dataframe(bl[["time", "domain", "page", "category"]].rename(columns={"domain": "site"}),
                         hide_index=True)
    with tabs[4]:
        files = acc[~acc["action"].isin(list(ACTIVITY_ACTIONS) + ["usb_connect"])] if len(acc) else acc
        if not len(files):
            st.info("No file or system access recorded for this day.")
        else:
            st.dataframe(files[["time", "resource", "action", "sensitivity", "status", "device", "flag"]]
                         .rename(columns={"resource": "file / command"}), hide_index=True, height=420)
    with tabs[5]:
        if not len(au):
            st.info("No logins recorded for this day.")
        else:
            st.dataframe(au[["time", "auth_type", "src_device", "dest_host", "src_ip", "city", "country", "result"]]
                         .rename(columns={"auth_type": "type", "src_device": "from device", "dest_host": "into"}),
                         hide_index=True)
    with tabs[6]:
        _usb(acc, base)
    with tabs[7]:
        _admin(acc, base)
    with tabs[8]:
        _shares(acc, base)
    with tabs[9]:
        _printing(acc, base)
    with tabs[10]:
        _powershell(acc, base)


def _explain_commands(rows: pd.DataFrame, kind: str, key: str):
    """Pick one logged command (flagged ones first) and have the local AI model explain it."""
    from ueba import llm
    if not len(rows):
        return
    r = rows.assign(_f=rows["flag"] != "").sort_values(["_f", "time"], ascending=[False, True])
    r = r.drop_duplicates("resource").head(40)
    st.markdown("**Explain a command with AI**")
    labels = {i: f"{'[flagged] ' if f else ''}{t}  {c[:90]}" for i, t, c, f in
              zip(r.index, r["time"], r["resource"], r["_f"])}
    pick = st.selectbox("Command", list(labels), format_func=labels.get, key=f"cmd_pick_{key}",
                        label_visibility="collapsed")
    row = r.loc[pick]
    ai_panel(llm.command_prompt(row["resource"], kind, host=row.get("device", ""), user=row.get("user", "")),
             "command", f"cmd_{key}_{pick}", button="Explain this command")


def _rows(acc: pd.DataFrame, actions: list[str]) -> pd.DataFrame:
    return acc[acc["action"].isin(actions)] if len(acc) else acc


def _usb(acc: pd.DataFrame, base: pd.DataFrame):
    """USB sticks plugged in and the files copied to them."""
    u = _rows(acc, USB_ACTIONS)
    if not len(u):
        st.info("No USB storage was used on this day.")
        return
    plugged, copied = u[u["action"] == "usb_connect"], u[u["action"] == "copy_to_usb"]
    st.markdown(f"**{plugged['resource'].nunique()} USB device(s) connected, {len(copied)} file(s) copied to USB** - "
                f"usually {_usual(base, 'removable_media'):.0f} USB event(s) a day.")
    u = u.assign(what=u["action"].map({"usb_connect": "Connected", "copy_to_usb": "Copied to USB"}))
    st.dataframe(u[["time", "what", "resource", "sensitivity", "device", "flag"]]
                 .rename(columns={"resource": "USB device / file", "device": "on computer"}), hide_index=True)
    st.caption("Windows logs a new device (Security 6416, DriverFrameworks 2003) under the computer, not the person; "
               "it is shown for whoever was logged on to that computer.")


def _admin(acc: pd.DataFrame, base: pd.DataFrame):
    """Everything done with elevated rights: admin logons, run-as, sudo, account changes, log clearing."""
    if not len(acc):
        st.info("No privileged activity recorded for this day.")
        return
    acct = acc["resource"].str.contains(ACCOUNT_CMDS, regex=True)
    tamper = acc["resource"].str.contains(LOG_TAMPER, regex=True)
    a = acc[acc["action"].isin(ADMIN_ACTIONS) | acct | tamper]
    if not len(a):
        st.info("No privileged activity recorded for this day.")
        return
    kind = a["action"].map({"priv_escalation": "Elevated (sudo / run as admin)", "admin_logon": "Logon with admin "
                            "privileges", "runas": "Ran as another account"}).fillna("Command")
    kind = kind.where(~acct.loc[a.index], "Account or group change").where(~tamper.loc[a.index], "Cleared a log")
    usual = _usual(base, "priv_esc") + _usual(base, "admin_logons") + _usual(base, "runas_events")
    st.markdown(f"**{len(a)} privileged action(s) on {a['device'].nunique()} computer(s)** - usually {usual:.0f} a day.")
    st.dataframe(a.assign(kind=kind)[["time", "kind", "resource", "device", "flag"]]
                 .rename(columns={"resource": "detail", "device": "on computer"}), hide_index=True, height=380,
                 column_config={"detail": st.column_config.TextColumn(width="medium"),
                                "flag": st.column_config.TextColumn(width="large")})
    cmds = a[a["action"].isin(["priv_escalation", "runas"]) | acct.loc[a.index] | tamper.loc[a.index]]
    _explain_commands(cmds, "privileged shell (sudo / run as)", "admin")


def _shares(acc: pd.DataFrame, base: pd.DataFrame):
    """One row per shared folder: how much was read, changed and deleted there."""
    s = acc[acc["share"] != ""] if len(acc) else acc
    if not len(s):
        st.info("No shared folders were used on this day.")
        return
    g = s.groupby("share")
    tab = pd.DataFrame({
        "files": g["resource"].nunique(), "read": g["action"].apply(lambda x: int((x == "read").sum())),
        "changed": g["action"].apply(lambda x: int((x == "write").sum())),
        "deleted": g["action"].apply(lambda x: int((x == "delete").sum())),
        "sensitive": g["sensitivity"].apply(lambda x: int(x.isin(SENSITIVE).sum())),
        "first": g["time"].min(), "last": g["time"].max(),
        "flag": g["flag"].apply(lambda x: ", ".join(sorted({f for v in x for f in v.split(", ")
                                                            if f in ("new shared folder", "admin share")})))})
    tab = tab.reset_index().rename(columns={"share": "shared folder"}).sort_values("files", ascending=False)
    st.markdown(f"**{len(tab)} shared folder(s), {s['resource'].nunique()} file(s)** - usually "
                f"{_usual(base, 'shares_used'):.0f} folder(s) a day.")
    st.dataframe(tab.style.apply(lambda r: ["background-color: rgba(235,104,52,.12)" if r["flag"] else ""] * len(r),
                                 axis=1), hide_index=True)
    st.caption("Admin shares (C$, ADMIN$) are the hidden shares administrators - and attackers moving between "
               "machines - use to reach a whole disk.")


def _printing(acc: pd.DataFrame, base: pd.DataFrame):
    p = _rows(acc, ["print"])
    if not len(p):
        st.info("Nothing was printed on this day.")
        return
    st.markdown(f"**{len(p)} print job(s), {int(p['pages'].sum())} page(s)** - usually "
                f"{_usual(base, 'pages_printed'):.0f} page(s) a day.")
    st.dataframe(p[["time", "resource", "pages", "printer", "sensitivity", "device", "flag"]]
                 .rename(columns={"resource": "document", "device": "sent from"}), hide_index=True)


def _powershell(acc: pd.DataFrame, base: pd.DataFrame):
    p = _rows(acc, ["powershell"])
    if not len(p):
        st.info("No PowerShell commands recorded for this day.")
        return
    bad = int((p["flag"].str.contains("suspicious PowerShell")).sum())
    st.markdown(f"**{len(p)} PowerShell command(s), {bad} suspicious** - usually "
                f"{_usual(base, 'ps_commands'):.0f} command(s) a day.")
    only = st.toggle("Only suspicious", value=False, key="ps_only_flagged")
    v = p[p["flag"] != ""] if only else p
    st.dataframe(v[["time", "resource", "device", "flag"]].rename(columns={"resource": "command", "device": "on computer"})
                 .style.apply(lambda r: ["background-color: rgba(235,104,52,.12)" if r["flag"] else ""] * len(r), axis=1),
                 hide_index=True, height=380, column_config={"command": st.column_config.TextColumn(width="large")})
    st.caption("Suspicious means encoded or hidden commands, download-and-run, credential dumping, fake password prompts, switching the "
               "antivirus off or deleting backups.")
    _explain_commands(p, "PowerShell", "ps")


def _net_flags(net: pd.DataFrame, seen_sites: set, seen_hosts: set) -> pd.Series:
    risky = web.is_risky(net["category"])
    new_site = ~net["site"].isin(seen_sites)
    return _flags(net, [
        (net["web_action"] == "blocked", "blocked"),
        (new_site & ~net.duplicated("site"), "new site"),
        (~new_site & (net["url"] != "") & ~net["host"].isin(seen_hosts) & ~net.duplicated("host"), "new subdomain"),
        (risky, net["category"] + " site"),
        (web.is_executable(net["file"]) & (net["web_action"] == "allowed"), "executable"),
        (net["MB up"] >= LARGE_UPLOAD_MB, "large upload")])


def _story(net: pd.DataFrame, acc: pd.DataFrame, au: pd.DataFrame):
    """One readable timeline. Routine repeats are folded so the unusual steps stand out."""
    parts = []
    if len(au):
        parts.append(pd.DataFrame({"time": au["time"], "what": np.where(au["result"] == "success", "Logged in",
                                                                         "Failed login"),
                                   "detail": au["auth_type"] + " into " + au["dest_host"] + " from "
                                   + au["src_ip"].astype(str) + np.where(au["city"].astype(str) != "",
                                                                          " (" + au["city"].astype(str) + ")", ""),
                                   "flag": np.where(au["result"] == "success", "", "failed")}))
    if len(net):
        what = np.select([net["web_action"] == "blocked", net["file"] != "", net["MB up"] >= LARGE_UPLOAD_MB],
                         ["Blocked", "Downloaded", "Uploaded"], "Visited")
        detail = np.where(net["file"] != "", net["file"] + " from " + net["domain"], net["page"])
        detail = np.where(what == "Uploaded", net["MB up"].round(0).astype(int).astype(str) + " MB to " + net["domain"],
                          detail)
        parts.append(pd.DataFrame({"time": net["time"], "what": what, "detail": detail, "flag": net["flag"]}))
    if len(acc):
        verb = acc["action"].map({"read": "Opened", "write": "Edited", "delete": "Deleted", "execute": "Ran",
                                  "priv_escalation": "Elevated", "copy_to_usb": "Copied to USB",
                                  "usb_connect": "Connected USB", "print": "Printed", "powershell": "PowerShell",
                                  "admin_logon": "Admin logon", "runas": "Ran as"}).fillna(acc["action"])
        detail = acc["resource"].where(acc["action"] != "print", acc["resource"] + " (" + acc["pages"].astype(str)
                                       + " pages on " + acc["printer"] + ")")
        detail = detail.where(acc["action"] != "admin_logon", "on " + acc["device"])
        parts.append(pd.DataFrame({"time": acc["time"], "what": verb, "detail": detail, "flag": acc["flag"]}))
    if not parts:
        st.info("No activity recorded for this day.")
        return
    ev = pd.concat(parts, ignore_index=True).sort_values("time", kind="stable").reset_index(drop=True)
    only = st.toggle("Only flagged steps", value=len(ev) > 60, key="story_only_flagged")
    if only:
        ev = ev[ev["flag"] != ""]
    # fold runs of the same routine action (e.g. 30 visits to office365.com) into one line
    key = ev["what"] + "|" + ev["detail"].str.extract(r"^(?:https?://)?([^/ ]+)", expand=False).fillna(ev["detail"])
    grp = (key != key.shift()).cumsum()
    rows = []
    for _, g in ev.groupby(grp, sort=False):
        first = g.iloc[0]
        n = len(g)
        detail = first["detail"] if n == 1 else f"{first['detail']}  (+{n - 1} more like this until {g['time'].iloc[-1]})"
        flags = ", ".join(sorted({f for x in g["flag"] for f in x.split(", ") if f}))
        rows.append(dict(time=first["time"], what=first["what"], detail=detail, flag=flags))
    out = pd.DataFrame(rows)
    st.caption(f"{len(out)} steps" + (" (flagged only)" if only else "") + ". Flags mark what is out of character "
               "for this person: a site or file never used before, a blocked request, a risky site, an executable "
               "download, a sensitive file, a large upload, a new USB stick or shared folder, admin rights, a large "
               "or sensitive print job, suspicious PowerShell.")
    st.dataframe(out.style.apply(lambda r: ["background-color: rgba(235,104,52,.12)" if r["flag"] else ""] * len(r),
                                 axis=1), hide_index=True, height=480, width="stretch")


def _websites(user: str, day: str, net: pd.DataFrame, seen_sites: set, seen_hosts: set, meta: dict):
    """One row per website: its subdomains, estimated time spent, requests, data and anything unusual."""
    if not len(net):
        st.info("No web activity recorded for this day.")
        return
    n = net.assign(timestamp=pd.to_datetime(net["timestamp"]))
    t = web.time_on_sites(n).set_index("site")
    sig = web.site_signals(n).set_index("site")
    rows = []
    for site, g in n.groupby("site"):
        hosts = sorted(set(g["host"]))
        subs = ", ".join(h + (" (new)" if site in seen_sites and h not in seen_hosts and (g["url"] != "").any() else "")
                         for h in hosts)
        flags = []
        if site not in seen_sites:
            flags.append("new site")
        elif any(h not in seen_hosts for h in hosts) and (g["url"] != "").any():
            flags.append("new subdomain")
        if (g["web_action"] == "blocked").any():
            flags.append(f"{int((g['web_action'] == 'blocked').sum())} blocked")
        cat = g["category"].iloc[0]
        if web.is_risky(pd.Series([cat])).iloc[0]:
            flags.append(cat + " site")
        if site in sig.index and sig.at[site, "random_hosts"] >= 30:
            flags.append(f"{int(sig.at[site, 'random_hosts'])} random subdomains")
        if site in sig.index and sig.at[site, "clockwork"] and site not in seen_sites:
            flags.append("clockwork requests")
        if g["MB up"].sum() >= LARGE_UPLOAD_MB:
            flags.append("large upload")
        rows.append(dict(website=site, subdomains=subs if len(subs) < 160 else f"{len(hosts)} subdomains, e.g. "
                         + ", ".join(hosts[:3]), minutes=float(t["minutes"].get(site, 0.0)) if len(t) else 0.0,
                         visits=int(t["visits"].get(site, 0)) if len(t) else 0, requests=len(g),
                         pages=g.loc[g["url"] != "", "url"].nunique(), category=cat,
                         **{"MB down": round(g["MB down"].sum(), 1), "MB up": round(g["MB up"].sum(), 1)},
                         flag=", ".join(flags)))
    tab = pd.DataFrame(rows).sort_values(["minutes", "requests"], ascending=False)
    tab = tab[["website", "minutes", "visits", "flag", "subdomains", "MB down", "MB up", "requests", "pages", "category"]]
    st.caption("Time is estimated from the proxy log the way web-analytics tools do it: requests to a site less than 5 "
               "minutes apart form one visit, from the first to the last request plus a minute of reading.")
    st.dataframe(tab.style.format({"minutes": "{:.0f}", "MB down": "{:,.1f}", "MB up": "{:,.1f}"})
                 .apply(lambda x: ["background-color: rgba(235,104,52,.12)" if x["flag"] else ""] * len(x), axis=1),
                 hide_index=True, height=min(440, 38 + 35 * len(tab)), width="stretch",
                 column_config={"flag": st.column_config.TextColumn(width="large"),
                                "subdomains": st.column_config.TextColumn(width="large")})
    hist = Q(f"SELECT {_net_select(['timestamp', 'url', 'domain', 'web_action', 'user'])} FROM network "
             "WHERE user=? AND date>=? AND date<?", (user, meta.get("train_start", ""), meta.get("train_end", "")))
    usual = pd.Series(dtype=float)
    if len(hist):
        hist = web.enrich(hist.assign(timestamp=pd.to_datetime(hist["timestamp"])))
        th = web.time_on_sites(hist)
        if len(th):
            usual = th.groupby("site")["minutes"].sum() / max(1, th["date"].nunique())
    top = tab.head(10)
    fig = go.Figure()
    fig.add_bar(x=top["website"], y=[usual.get(s_, 0) for s_ in top["website"]], name="usual minutes / day",
                marker_color=BLUE)
    fig.add_bar(x=top["website"], y=top["minutes"], name=f"minutes on {day}", marker_color=ORANGE)
    fig.update_layout(title="Minutes per website: this day vs usual", barmode="group", yaxis_title="minutes")
    show(style(fig, 320), key="activity_sites")


def _category_chart(user: str, day: str, net: pd.DataFrame, meta: dict):
    hist = Q("SELECT category, domain, date FROM network WHERE user=? AND date>=? AND date<?",
             (user, meta.get("train_start", ""), meta.get("train_end", "")))
    if "category" not in hist or not len(hist):
        hist = web.enrich(hist.assign(url="")) if len(hist) else pd.DataFrame(columns=["category", "date"])
    n_days = max(1, hist["date"].nunique()) if len(hist) else 1
    usual = hist.assign(category=hist["category"].replace("", "other")).groupby("category").size() / n_days
    now = net.assign(category=net["category"].replace("", "other")).groupby("category").size()
    cats = now.sort_values(ascending=False).index[:10][::-1]
    fig = go.Figure()
    fig.add_bar(y=list(cats), x=[usual.get(c, 0) for c in cats], orientation="h", name="usual / day",
                marker_color=BLUE)
    fig.add_bar(y=list(cats), x=[now.get(c, 0) for c in cats], orientation="h", name=day, marker_color=ORANGE)
    fig.update_layout(title="Kinds of site: today vs usual", barmode="group", xaxis_title="requests")
    show(style(fig, 420), key="activity_categories")
    st.caption("Categories come from the web gateway when it provides them, otherwise from a built-in list of "
               "well-known sites.")
