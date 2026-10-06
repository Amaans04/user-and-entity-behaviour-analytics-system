"""Data sources - uploads, automatic collection, notifications and workspace settings."""
from __future__ import annotations

import json

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from dashboard.ui import *  # noqa: F401,F403 - palette, chart helpers, ctx, queries
from dashboard.ui import ctx
from ueba import auth, feedback, notify, service, sources as SRC, workspace as WS  # noqa: F401
from ueba.config import CONFIG  # noqa: F401
from ueba.detectors import LABELS  # noqa: F401


NOT_MAPPED = "— not in file —"


@st.cache_data(show_spinner=False, max_entries=20)
def parse_upload(name: str, file_id: str, _data: bytes) -> list[tuple[str, pd.DataFrame]]:
    return SRC.read_bytes(name, _data)


@st.cache_data(show_spinner=False, max_entries=40)
def convert_cached(stream: str, file_key: str, mapping_json: str, _df: pd.DataFrame) -> SRC.Conversion:
    return SRC.convert(stream, _df, json.loads(mapping_json))


@st.cache_data(show_spinner=False)
def example_zip(full: bool) -> bytes:
    """Example files in the expected format - samples (or the whole demo dataset) from the demo workspace."""
    import io
    import zipfile
    buf = io.BytesIO()
    demo_raw = WS.demo().raw_dir
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for stream in SRC.SCHEMA:
            p = demo_raw / f"{stream}.csv"
            if p.exists():
                df = pd.read_csv(p) if full else pd.read_csv(p, nrows=25)
            else:
                df = pd.DataFrame(columns=list(SRC.SCHEMA[stream]))
            z.writestr(f"{stream}.csv", df.to_csv(index=False))
    return buf.getvalue()


def status_card():
    ws = ctx.ws
    stt = ws.status()
    cov = stt["coverage"]
    icon, text = STATE_UI[stt["state"]]
    with st.container(border=True):
        a, b, c, d = st.columns([2, 1, 1, 1])
        a.markdown(f"#### {text}")
        if stt["state"] == "empty":
            a.caption("Upload at least one log stream below to get started.")
        elif stt["state"] == "needs_analysis":
            a.caption("Logs were added or settings changed since the last analysis.")
        elif stt["state"] == "learning":
            done, need = learning_progress(stt)
            a.progress(done / need, text=f"{done} of {need} learning days collected - alerts start after that")
        else:
            a.caption(f"Baseline learned from the first {stt['learning_days']} days; "
                      f"{cov['days'] - stt['learning_days']} days scored for threats.")
        b.metric("Days of logs", cov["days"])
        c.metric("First day", cov["first"] or "–")
        d.metric("Last day", cov["last"] or "–")
        if ws.meta.get("last_error"):
            st.warning(f"Last automatic analysis was skipped: {ws.meta['last_error']}")
        if stt["inbox"]:
            st.caption(f"{stt['inbox']} file(s) waiting in the inbox for the collector service.")
        if stt["state"] != "empty" and can("manage") and (not ws.is_demo or stt["state"] == "needs_analysis"):
            b1, b2, _ = st.columns([1.2, 1.4, 3])
            if b1.button("Analyse now" if stt["state"] == "needs_analysis" else "Analyse",
                         type="primary" if stt["state"] == "needs_analysis" else "secondary",
                         help="Incremental: re-uses the trained models and scores only new / changed days"):
                analyse()
            if not ws.is_demo and stt["analysed"] and b2.button(
                    "⟲ Re-train models", help="Re-learn baselines and ML models from the learning period, "
                                              "then re-score all history"):
                analyse(full=True)
        if 0 < cov["days"] <= stt["learning_days"]:
            st.caption(f"Tip: you have {cov['days']} days of logs. Detection starts on day {stt['learning_days'] + 1}. "
                       f"To start now, set the learning period below {cov['days']} days "
                       "(a shorter baseline knows less about normal behaviour, so expect more false positives).")


def streams_table():
    ws = ctx.ws
    info = ws.streams()
    st.markdown("**Log streams**")
    hdr = st.columns([3, 1.2, 2.2, 2.2, 1, 1])
    for col, h in zip(hdr, ["Stream", "Rows", "From", "To", "Days", ""]):
        col.caption(h)
    for stream, label in SRC.STREAM_LABELS.items():
        i = info.get(stream)
        row = st.columns([3, 1.2, 2.2, 2.2, 1, 1])
        row[0].markdown(label if i else f"<span class='muted'>{label}</span>", unsafe_allow_html=True)
        row[1].write(f"{i['rows']:,}" if i else "–")
        row[2].write(str(i.get("first", "–"))[:16] if i else "–")
        row[3].write(str(i.get("last", "–"))[:16] if i else "–")
        row[4].write(str(i.get("days", "–")) if i else "–")
        if i and not ws.is_demo and can("manage") and row[5].button("Clear", key=f"clr_{stream}",
                                                                     help=f"Remove all {label} data"):
            ws.clear_stream(stream)
            audit("data.clear", stream)
            flash("info", f"{label} data removed - re-analyse to update results.")
            st.rerun()
    missing = [SRC.STREAM_LABELS[s].split(" (")[0] for s in SRC.LOG_STREAMS if s not in info]
    if info and missing:
        st.caption("Not uploaded: " + ", ".join(missing) + ". The system still works - features from missing "
                   "streams stay at zero, so those behaviours simply aren't monitored.")


def mapping_editor(stream: str, cols: list[str], default: dict, key: str) -> dict:
    fields = SRC.SCHEMA[stream]
    opts = [NOT_MAPPED] + cols
    out = {}
    grid = st.columns(3)
    for j, (fld, (req, _, _)) in enumerate(fields.items()):
        d = default.get(fld)
        out[fld] = grid[j % 3].selectbox(
            f"{fld}{' *' if req else ''}", opts, index=opts.index(d) if d in opts else 0, key=f"{key}_{fld}",
            help="Required" if req else "Optional - a sensible default is used when not in the file")
        if out[fld] == NOT_MAPPED:
            out[fld] = None
    return out


def upload_section():
    ws = ctx.ws
    st.markdown("### Add logs")
    st.caption("CSV, JSON / JSON-lines or a ZIP of them - exports from a SIEM, Windows Event Viewer, a proxy, "
               "Zeek, a VPN, `last`/`auth.log` converted to CSV, … New uploads are **appended** to what is "
               "already here (duplicates are dropped), so you can add a day or a week at a time.")
    nonce = st.session_state.get("upload_nonce", 0)
    files = st.file_uploader("Log files", type=["csv", "jsonl", "ndjson", "json", "log", "txt", "zip"],
                             accept_multiple_files=True, key=f"uploader_{ws.slug}_{nonce}",
                             label_visibility="collapsed")
    if not files:
        return
    ready = []
    streams = list(SRC.SCHEMA) + ["skip"]
    for f in files:
        try:
            parsed = parse_upload(f.name, f.file_id, f.getvalue())
        except Exception as e:  # noqa: BLE001
            st.error(f"**{f.name}**: could not read the file ({e}).")
            continue
        if not parsed:
            st.warning(f"**{f.name}**: no readable CSV/JSON files inside.")
        for k, (fname, raw) in enumerate(parsed):
            cols = [str(c) for c in raw.columns]
            raw.columns = cols
            sig = SRC.mapping_signature(cols)
            saved = ws.saved_mapping(sig)
            key = f"{f.file_id}_{k}"
            with st.expander(f"**{fname}** · {len(raw):,} rows · {len(cols)} columns", expanded=True):
                guess = saved["stream"] if saved else SRC.guess_stream(cols, fname)
                stream = st.selectbox("This file contains", streams, index=streams.index(guess), key=f"st_{key}",
                                      format_func=lambda s: "Skip this file" if s == "skip" else SRC.STREAM_LABELS[s])
                if stream == "skip":
                    continue
                if saved and saved["stream"] == stream:
                    default = saved["mapping"]
                    st.caption("Same columns as an earlier upload - reusing that mapping.")
                else:
                    default = SRC.guess_mapping(stream, cols)
                    st.caption("Columns matched automatically - check them, `*` = required.")
                mapping = mapping_editor(stream, cols, default, key=f"map_{key}_{stream}")
                conv = convert_cached(stream, key, json.dumps(mapping, sort_keys=True), raw)
                for e in conv.errors:
                    st.error(e)
                for w in conv.warnings:
                    st.warning(w)
                if conv.ok:
                    sm = conv.summary()
                    m = st.columns(4)
                    m[0].metric("Rows usable", f"{sm['rows_kept']:,}")
                    m[1].metric("Days", sm.get("days", "–"))
                    m[2].metric("Users", sm.get("users", "–"))
                    m[3].metric("Devices", sm.get("devices", "–"))
                    if "first" in sm:
                        st.caption(f"{sm['first'][:16]} → {sm['last'][:16]}")
                    t1, t2 = st.tabs(["After mapping", "Original file"])
                    t1.dataframe(conv.df.head(8), hide_index=True)
                    t2.dataframe(raw.head(8), hide_index=True)
                    ready.append((fname, stream, conv, mapping, sig))
    if ready:
        if st.button(f"Import {len(ready)} file{'s' if len(ready) > 1 else ''} into {ws.name}", type="primary"):
            msgs = []
            with st.spinner("Importing…"):
                for fname, stream, conv, mapping, sig in ready:
                    r = ws.add(stream, conv.df, fname, mapping, sig)
                    audit("data.upload", f"{fname} -> {stream}: +{r['added']} rows")
                    msgs.append(f"{fname} → {SRC.STREAM_LABELS[stream].split(' (')[0]}: "
                                f"{r['added']:,} new rows ({r['total']:,} total)")
            st.session_state["upload_nonce"] = nonce + 1
            flash("success", "Imported. " + " · ".join(msgs) +
                  " — press **Analyse now** (or let the collector service pick it up).")
            st.rerun()


def collection_section():
    ws = ctx.ws
    hb = service.read_heartbeat()
    alive = bool(hb and hb["alive"])
    with st.expander("Automatic collection" + (" (on)" if alive and ws.setting("auto_ingest") else " (off)"),
                     expanded=not ws.meta.get("streams")):
        if alive:
            st.success(f"Collector service running - checks every {hb['interval']:g} s"
                       + (f", ingest API at `{hb['api']}`" if hb.get("api") else " (ingest API off)"))
        else:
            st.warning("Collector service not running. Start it next to the dashboard:")
            st.code("python -m ueba.service --api", language="bash")
        auto = st.toggle("Collect & analyse automatically", value=bool(ws.setting("auto_ingest")),
                         help="The service imports files from the inbox and API, scores them incrementally "
                              "and sends notifications.")
        if auto != bool(ws.setting("auto_ingest")):
            ws.update_settings(auto_ingest=auto)
            audit("settings.auto_ingest", str(auto))
            st.rerun()
        t1, t2, t3, t4 = st.tabs(["Drop folder", "Ingest API", "Endpoint agent", "Replay demo"])
        with t1:
            st.markdown("Any CSV / JSON / ZIP file copied into this folder is imported on the next pass "
                        "(an export job, `rsync`, a SIEM forwarder …). Name a file `auth__anything.csv` to force "
                        "its stream; otherwise the saved column mapping or auto-detection is used. Rejected files "
                        "move to `failed/` with an `.error.txt` explaining why.")
            st.code(str(ws.inbox), language=None)
        api = (hb or {}).get("api") or "http://127.0.0.1:8600/api/v1"
        with t2:
            st.markdown("Push batches over HTTP (JSON array, JSON-lines or CSV). Create a token under "
                        "**Administration → API tokens**.")
            st.code(f"curl -X POST {api}/workspaces/{ws.slug}/ingest/auth \\\n"
                    f"     -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: text/csv' \\\n"
                    f"     --data-binary @auth_export.csv", language="bash")
        with t3:
            st.markdown("Streams a machine's CPU, memory, disk, processes and network connections every 15 s "
                        "(keeps data and retries while the server is unreachable).")
            st.code(f"python -m ueba.agent --url {api.rsplit('/api/v1', 1)[0]} --workspace {ws.slug} "
                    "--token <TOKEN>", language="bash")
        with t4:
            st.markdown("Feed the synthetic company into this workspace as if it were happening now: 30 days "
                        "of history at once, then one day every 20 s - alerts appear live as the attacks happen.")
            st.code(f"python -m ueba.replay --workspace {ws.slug} --labels", language="bash")


def notifications_section():
    ws = ctx.ws
    with st.expander("Notifications"):
        st.caption("Sent by the collector service (and after manual analyses) for new or escalated alerts. "
                   "Slack, Microsoft Teams, Discord and most chat tools accept the webhook format.")
        with st.form("notify_form"):
            hook = st.text_input("Webhook URL", ws.setting("notify_webhook") or "",
                                 placeholder="https://hooks.slack.com/services/…")
            mail = st.text_input("E-mail to", ws.setting("notify_email") or "", placeholder="soc@example.com",
                                 help="Needs UEBA_SMTP_HOST (+ _PORT, _USER, _PASSWORD, _FROM) in the environment "
                                      "of the service and dashboard." + ("" if notify.smtp_configured()
                                                                         else " Not configured yet."))
            sev = st.select_slider("Minimum severity", ["medium", "high", "critical"],
                                   value=ws.setting("notify_min_severity") or "high")
            c1, c2 = st.columns(2)
            save = c1.form_submit_button("Save", type="primary")
            test = c2.form_submit_button("Save & send test")
        if save or test:
            ws.update_settings(notify_webhook=hook.strip(), notify_email=mail.strip(), notify_min_severity=sev)
            audit("settings.notifications", f"webhook={'set' if hook else 'none'} email={mail or 'none'} min={sev}")
            if test:
                res = notify.send_test(ws.reload())
                bad = [r for r in res if r["status"] != "sent"]
                if not res:
                    flash("warning", "Nothing to test - add a webhook URL or an e-mail address.")
                elif bad:
                    flash("error", "Test failed: " + "; ".join(f"{r['channel']}: {r['error']}" for r in bad))
                else:
                    flash("success", "Test notification sent.")
            else:
                flash("success", "Notification settings saved.")
            st.rerun()
        hist = notify.history(ws.db_path)
        if len(hist):
            st.markdown(f"**Sent so far** ({(hist['status'] == 'sent').sum()} ok, "
                        f"{(hist['status'] != 'sent').sum()} failed)")
            st.dataframe(hist.head(200), hide_index=True, height=220)


def page_sources():
    ws = ctx.ws
    st.title("Data sources")
    status_card()
    streams_table()
    st.divider()

    if ws.is_demo:
        st.info("**Demo workspace** - a simulated 48-person company with 11 planted attacks, generated by the "
                "log generator. It is read-only: create a workspace in the sidebar (**New workspace**) to "
                "analyse your own logs.")
        c1, c2 = st.columns([1, 3])
        seed = c1.number_input("Random seed", 0, 99999, CONFIG.seed,
                               help="Each seed simulates a different company: other people, habits and victims.")
        if c2.button("Regenerate demo company & analyse", disabled=not can("manage")):
            analyse(regenerate=True, seed=int(seed))
    elif not can("manage"):
        st.info("Only administrators can add data or change this workspace's settings.")
    else:
        upload_section()
        st.divider()
        collection_section()
        notifications_section()
        with st.expander("Settings"):
            days = st.number_input("Learning period (days)", WS.MIN_LEARNING_DAYS, 180, ws.learning_days,
                                   help="The first N days of logs teach the system what normal looks like; "
                                        "only later days are scored for threats. 30 is typical; shorter "
                                        "baselines raise more false positives.")
            if days != ws.learning_days and st.button("Save learning period"):
                ws.set_learning_days(days)
                audit("settings.learning_days", str(days))
                flash("info", f"Learning period set to {days} days - re-analyse to apply.")
                st.rerun()
            th = st.slider("Alert threshold (daily risk 0-100)", 10, 95, int(ws.alert_threshold), 5,
                           help="Lower = more alerts and fewer misses; higher = fewer, surer alerts. Every "
                                "organisation needs its own value - try values on the Model performance page "
                                "first if you have labelled incidents. Changing it needs no re-training.")
            if th != int(ws.alert_threshold) and st.button("Save alert threshold"):
                ws.set_alert_threshold(th)
                audit("settings.alert_threshold", str(th))
                flash("info", f"Alert threshold set to {th} - alerts are regenerated at the next analysis.")
                st.rerun()
        if ws.meta.get("uploads"):
            with st.expander(f"Upload history ({len(ws.meta['uploads'])})"):
                st.dataframe(pd.DataFrame(ws.meta["uploads"][::-1]), hide_index=True)
        with st.expander("Delete workspace"):
            st.caption("Removes this workspace's logs, profiles, alerts, analyst verdicts and models. Cannot be undone.")
            sure = st.checkbox(f"Yes, delete **{ws.name}**")
            if st.button("Delete workspace", disabled=not sure):
                WS.delete(ws.slug)
                audit("workspace.delete", ws.name)
                pick_workspace(WS.DEMO)
                flash("info", f"Workspace {ws.name} deleted.")
                st.rerun()

    with st.expander("Expected formats and example files"):
        st.markdown("Column names don't have to match - you map them on upload. What each stream needs "
                    "(**bold** = required):")
        for stream, label in SRC.STREAM_LABELS.items():
            flds = ", ".join(f"**{f}**" if r else f for f, (r, _, _) in SRC.SCHEMA[stream].items())
            st.markdown(f"- *{label}* - {flds}")
        st.caption("Values are normalised for you: `Success`/`Failed`/`4624`/`4625`, `CORP\\\\alice`, epoch or ISO "
                   "timestamps, CPU as 0-1 or 0-100, full URLs → host names. Without a user directory everyone "
                   "is in one peer group; without an asset inventory every device seen counts as registered.")
        c1, c2 = st.columns(2)
        c1.download_button("Download example files (25 rows each)", example_zip(False), "ueba_examples.zip",
                           "application/zip")
        if (WS.demo().raw_dir / "auth.csv").exists():
            c2.download_button("Download the full demo dataset (to test uploading)", example_zip(True),
                               "ueba_demo_logs.zip", "application/zip")
