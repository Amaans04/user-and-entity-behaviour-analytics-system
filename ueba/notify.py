"""Alert notifications: webhook (Slack / Teams / Discord / any JSON endpoint) and e-mail.

Rules
-----
* Only alerts at or above the workspace's minimum severity are sent.
* Each alert (entity, date, alert type) is sent once; it is sent again only if its
  severity escalates later (e.g. more evidence arrives during the same day).
* Back-fills stay quiet: alerts more than ``MAX_AGE_DAYS`` (7) days older than the newest data
  are never sent, so importing three months of history doesn't fire 50 messages.
* Every attempt is recorded in the workspace database (``notifications`` table),
  including failures, so the dashboard can show what was sent and what went wrong.

E-mail uses SMTP settings from environment variables::

    UEBA_SMTP_HOST, UEBA_SMTP_PORT (587), UEBA_SMTP_USER, UEBA_SMTP_PASSWORD, UEBA_SMTP_FROM
"""
from __future__ import annotations

import json
import os
import smtplib
import sqlite3
import urllib.request
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

import pandas as pd

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MAX_AGE_DAYS = 7
TIMEOUT = 8


def _ensure(con: sqlite3.Connection):
    con.execute("""CREATE TABLE IF NOT EXISTS notifications (
        entity TEXT, date TEXT, alert_type TEXT, severity TEXT, alert_id TEXT, title TEXT,
        channel TEXT, status TEXT, error TEXT, sent_at TEXT)""")


def history(db_path: Path) -> pd.DataFrame:
    if not Path(db_path).exists():
        return pd.DataFrame()
    with sqlite3.connect(db_path) as con:
        _ensure(con)
        return pd.read_sql("SELECT * FROM notifications ORDER BY sent_at DESC", con)


def due(db_path: Path, alerts: pd.DataFrame, min_severity: str = "high", newest_day: str | None = None
        ) -> pd.DataFrame:
    """Alerts that should be (re-)sent now."""
    if alerts is None or alerts.empty:
        return pd.DataFrame()
    a = alerts[alerts["severity"].map(SEV_RANK).fillna(0) >= SEV_RANK.get(min_severity, 2)].copy()
    a = a[a["status"].fillna("open") == "open"] if "status" in a else a
    if newest_day:
        cutoff = (pd.Timestamp(newest_day) - timedelta(days=MAX_AGE_DAYS)).date().isoformat()
        a = a[a["date"].astype(str) >= cutoff]
    if a.empty:
        return a
    sent = history(db_path)
    if len(sent):
        ok = sent[sent["status"] == "sent"]
        best = ok.assign(rank=ok["severity"].map(SEV_RANK)).groupby(["entity", "date", "alert_type"])["rank"].max()
        prev = [best.get((e, str(d), t), -1) for e, d, t in zip(a["entity"], a["date"], a["alert_type"])]
        a = a[a["severity"].map(SEV_RANK).to_numpy() > pd.Series(prev, index=a.index).to_numpy()]
    return a


def _text(ws_name: str, a: pd.Series) -> str:
    reasons = json.loads(a["reasons"]) if isinstance(a.get("reasons"), str) else []
    mitre = json.loads(a["mitre"]) if isinstance(a.get("mitre"), str) else []
    lines = [f"[UEBA - {ws_name}] {a['severity'].upper()}: {a['title']}",
             f"{a['entity_type']} {a['entity']} ({a.get('department', '')}) on {a['date']} - risk {a['risk_score']:.0f}/100"]
    lines += [f"- {r}" for r in reasons[:4]]
    if mitre:
        lines.append("MITRE ATT&CK: " + ", ".join(mitre))
    return "\n".join(lines)


def _post_webhook(url: str, text: str, payload: dict):
    body = json.dumps({"text": text, "content": text[:1900], **payload}).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "ueba-console"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        if r.status >= 300:
            raise RuntimeError(f"HTTP {r.status}")


def smtp_configured() -> bool:
    return bool(os.environ.get("UEBA_SMTP_HOST"))


def _send_email(to: str, subject: str, text: str):
    host = os.environ.get("UEBA_SMTP_HOST")
    if not host:
        raise RuntimeError("UEBA_SMTP_HOST is not set")
    msg = EmailMessage()
    msg["Subject"], msg["To"] = subject, to
    msg["From"] = os.environ.get("UEBA_SMTP_FROM", os.environ.get("UEBA_SMTP_USER", "ueba@localhost"))
    msg.set_content(text)
    with smtplib.SMTP(host, int(os.environ.get("UEBA_SMTP_PORT", 587)), timeout=TIMEOUT) as s:
        if os.environ.get("UEBA_SMTP_STARTTLS", "1") != "0":
            s.starttls()
        if os.environ.get("UEBA_SMTP_USER"):
            s.login(os.environ["UEBA_SMTP_USER"], os.environ.get("UEBA_SMTP_PASSWORD", ""))
        s.send_message(msg)


def _channels(webhook: str, email: str) -> list[tuple[str, str]]:
    out = []
    if webhook:
        out.append(("webhook", webhook))
    if email:
        out.append(("email", email))
    return out


def send(db_path: Path, ws_name: str, alerts: pd.DataFrame, webhook: str = "", email: str = "") -> list[dict]:
    """Send every row of ``alerts`` on every configured channel and record the outcome."""
    results = []
    chans = _channels(webhook, email)
    if not chans or alerts.empty:
        return results
    with sqlite3.connect(db_path) as con:
        _ensure(con)
        for _, a in alerts.iterrows():
            text = _text(ws_name, a)
            payload = {"alert": {k: (v.item() if hasattr(v, "item") else v) for k, v in a.items()
                                 if k in ("alert_id", "date", "entity", "entity_type", "department", "title",
                                          "severity", "risk_score", "alert_type")}, "workspace": ws_name}
            for chan, target in chans:
                status, err = "sent", ""
                try:
                    if chan == "webhook":
                        _post_webhook(target, text, payload)
                    else:
                        _send_email(target, text.splitlines()[0], text)
                except Exception as e:  # noqa: BLE001 - record and carry on
                    status, err = "failed", f"{type(e).__name__}: {e}"[:300]
                con.execute("INSERT INTO notifications VALUES (?,?,?,?,?,?,?,?,?,?)",
                            (a["entity"], str(a["date"]), a["alert_type"], a["severity"], a["alert_id"],
                             a["title"], chan, status, err, datetime.now().isoformat(timespec="seconds")))
                results.append(dict(alert_id=a["alert_id"], channel=chan, status=status, error=err))
    return results


def notify_workspace(ws, alerts: pd.DataFrame) -> list[dict]:
    """Send whatever is due for a workspace, using its notification settings."""
    webhook, email = ws.setting("notify_webhook") or "", ws.setting("notify_email") or ""
    if not (webhook or email) or alerts is None or alerts.empty:
        return []
    newest = ws.coverage()["last"]
    todo = due(ws.db_path, alerts, ws.setting("notify_min_severity") or "high", newest)
    return send(ws.db_path, ws.name, todo, webhook, email)


def send_test(ws) -> list[dict]:
    test = pd.DataFrame([dict(alert_id="TEST", date=datetime.now().date().isoformat(), entity="test.user",
                              entity_type="user", department="-", alert_type="test", title="Test notification",
                              severity="high", risk_score=0.0,
                              reasons=json.dumps(["This is a test message from the UEBA console"]),
                              mitre=json.dumps([]), status="open")])
    ws.db_path.parent.mkdir(parents=True, exist_ok=True)
    return send(ws.db_path, ws.name, test, ws.setting("notify_webhook") or "", ws.setting("notify_email") or "")
