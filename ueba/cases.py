"""Cases and suppressions - turning a stream of daily alerts into analyst work items.

Cases
-----
A real SOC does not triage the same person 30 times; it opens one *case*. Alerts on the
same entity belong to the same case while they are no more than ``CASE_GAP_DAYS`` apart.
A case id is ``<entity>@<first alert date>``, so it is stable while the case grows.

Analyst state (status, assignee) and the notes timeline live in the workspace database
(``case_state`` / ``case_notes``) and survive every re-analysis. Closing a case records a
verdict for every day it covers (``feedback``), so a benign case is learned into the
entity's baseline and a confirmed threat is never learned.

Suppressions
------------
A known-benign pattern (a backup admin who always works at night) can be suppressed for one
entity (or ``*`` = everyone) and one alert title, until an expiry date. Suppressed alerts
are still computed and kept - marked ``status = suppressed`` - so nothing is lost and the
decision stays auditable, but they are hidden from the queue and never notified.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd

CASE_GAP_DAYS = 7
CASE_STATUSES = ("open", "investigating", "closed - benign", "closed - threat")
SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _con(db_path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(db_path, timeout=10)
    con.execute("""CREATE TABLE IF NOT EXISTS case_state (
        case_id TEXT PRIMARY KEY, status TEXT, assignee TEXT, updated_by TEXT, updated_at TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS case_notes (
        case_id TEXT, ts TEXT, username TEXT, note TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS suppressions (
        sup_id INTEGER PRIMARY KEY AUTOINCREMENT, entity TEXT, title TEXT, until TEXT, reason TEXT,
        created_by TEXT, created_at TEXT, active INTEGER DEFAULT 1)""")
    return con


def _read(db_path: Path, sql: str, params=()) -> pd.DataFrame:
    if not Path(db_path).exists():
        return pd.DataFrame()
    con = _con(db_path)
    try:
        return pd.read_sql(sql, con, params=params)
    finally:
        con.close()


def _write(db_path: Path, sql: str, params=()):
    con = _con(db_path)
    try:
        con.execute(sql, params)
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------- cases
def assign_cases(alerts: pd.DataFrame) -> pd.Series:
    """Case id for every alert (same entity, gaps of at most CASE_GAP_DAYS)."""
    if alerts.empty:
        return pd.Series(dtype=str)
    a = alerts.assign(_d=pd.to_datetime(alerts["date"])).sort_values(["entity", "_d"])
    ids = {}
    for ent, g in a.groupby("entity"):
        start, prev = None, None
        for idx, d in zip(g.index, g["_d"]):
            if prev is None or (d - prev).days > CASE_GAP_DAYS:
                start = d
            ids[idx] = f"{ent}@{start.date()}"
            prev = d
    return pd.Series(ids).reindex(alerts.index)


def build_cases(alerts: pd.DataFrame, db_path: Path) -> pd.DataFrame:
    """One row per case with its alerts summarised and the analyst state attached."""
    cols = ["case_id", "entity", "entity_type", "department", "first", "last", "alerts", "severity", "max_risk",
            "titles", "status", "assignee", "updated_at"]
    a = alerts[alerts["status"] != "suppressed"] if "status" in alerts else alerts
    if a.empty:
        return pd.DataFrame(columns=cols)
    a = a.assign(case_id=assign_cases(a), _rank=a["severity"].map(SEV_RANK))
    g = a.groupby("case_id")
    c = pd.DataFrame({
        "entity": g["entity"].first(), "entity_type": g["entity_type"].first(), "department": g["department"].first(),
        "first": g["date"].min(), "last": g["date"].max(), "alerts": g.size(),
        "severity": g["_rank"].max().map({v: k for k, v in SEV_RANK.items()}), "max_risk": g["risk_score"].max(),
        "titles": g["title"].agg(lambda s: ", ".join(s.value_counts().index[:3]))}).reset_index()
    st = _read(db_path, "SELECT * FROM case_state")
    if len(st):
        c = c.merge(st[["case_id", "status", "assignee", "updated_at"]], on="case_id", how="left")
    else:
        c["status"], c["assignee"], c["updated_at"] = None, None, None
    # a case whose days were all given verdicts in the alert queue counts as closed
    verdicts = a.groupby("case_id")["status"].agg(lambda s: set(s))
    def derived(row):
        if isinstance(row["status"], str) and row["status"]:
            return row["status"]
        v = verdicts.get(row["case_id"], {"open"})
        if v == {"closed - benign"}:
            return "closed - benign"
        if "confirmed threat" in v and "open" not in v:
            return "closed - threat"
        return "open"
    c["status"] = c.apply(derived, axis=1)
    c["assignee"] = c["assignee"].fillna("")
    return c[cols].sort_values(["last", "max_risk"], ascending=[False, False]).reset_index(drop=True)


def set_state(db_path: Path, case_id: str, status: str | None = None, assignee: str | None = None,
              by: str = ""):
    if status is not None and status not in CASE_STATUSES:
        raise ValueError(f"status must be one of {CASE_STATUSES}")
    cur = _read(db_path, "SELECT * FROM case_state WHERE case_id=?", (case_id,))
    old = cur.iloc[0].to_dict() if len(cur) else dict(status="open", assignee="")
    _write(db_path, "INSERT OR REPLACE INTO case_state VALUES (?,?,?,?,?)",
           (case_id, status if status is not None else old["status"],
            assignee if assignee is not None else old["assignee"], by, _now()))


def add_note(db_path: Path, case_id: str, username: str, note: str):
    note = note.strip()
    if note:
        _write(db_path, "INSERT INTO case_notes VALUES (?,?,?,?)", (case_id, _now(), username, note[:2000]))


def notes(db_path: Path, case_id: str) -> pd.DataFrame:
    return _read(db_path, "SELECT ts, username, note FROM case_notes WHERE case_id=? ORDER BY ts", (case_id,))


def close(db_path: Path, case_id: str, alerts: pd.DataFrame, verdict: str, by: str, note: str = "") -> list[str]:
    """Close a case and record the verdict for every day it covers. Returns those days."""
    from . import feedback
    a = alerts.assign(case_id=assign_cases(alerts))
    days = a[a["case_id"] == case_id]
    for _, r in days.iterrows():
        feedback.record(db_path, r["entity"], r["date"], verdict, note, analyst=by, alert_id=r["alert_id"])
    set_state(db_path, case_id, status="closed - benign" if verdict == "benign" else "closed - threat", by=by)
    add_note(db_path, case_id, by, f"Closed as {verdict}" + (f": {note}" if note else ""))
    return sorted(days["date"].astype(str).unique())


def reopen(db_path: Path, case_id: str, alerts: pd.DataFrame, by: str) -> list[str]:
    from . import feedback
    a = alerts.assign(case_id=assign_cases(alerts))
    days = a[a["case_id"] == case_id]
    for _, r in days.iterrows():
        feedback.clear(db_path, r["entity"], r["date"])
    set_state(db_path, case_id, status="open", by=by)
    add_note(db_path, case_id, by, "Reopened")
    return sorted(days["date"].astype(str).unique())


# ---------------------------------------------------------------- suppressions
def suppress(db_path: Path, entity: str, title: str, until: str, reason: str, by: str) -> None:
    if not reason.strip():
        raise ValueError("Give a reason - suppressions are reviewed later")
    _write(db_path, "INSERT INTO suppressions (entity, title, until, reason, created_by, created_at) "
                    "VALUES (?,?,?,?,?,?)", (entity, title, str(until), reason.strip()[:500], by, _now()))


def list_suppressions(db_path: Path, active_only: bool = False) -> pd.DataFrame:
    df = _read(db_path, "SELECT * FROM suppressions ORDER BY created_at DESC")
    if active_only and len(df):
        df = df[df["active"] == 1]
    return df


def lift(db_path: Path, sup_id: int) -> None:
    _write(db_path, "UPDATE suppressions SET active=0 WHERE sup_id=?", (int(sup_id),))


def apply_suppressions(alerts: pd.DataFrame, db_path: Path) -> pd.DataFrame:
    """Mark alerts covered by an active suppression (same entity or '*', same title, date <= until)."""
    sup = list_suppressions(db_path, active_only=True)
    if alerts.empty or sup.empty:
        return alerts
    alerts = alerts.copy()
    hit = pd.Series(False, index=alerts.index)
    for _, s in sup.iterrows():
        hit |= ((alerts["entity"] == s["entity"]) | (s["entity"] == "*")) & (alerts["title"] == s["title"]) \
            & (alerts["date"].astype(str) <= str(s["until"]))
    alerts.loc[hit & (alerts["status"] == "open"), "status"] = "suppressed"
    return alerts


def restatus(db_path: Path) -> None:
    """Recompute every alert's status from verdicts and suppressions, in place - so analyst
    actions show immediately instead of at the next analysis."""
    from . import feedback
    if not Path(db_path).exists():
        return
    con = _con(db_path)
    try:
        if not con.execute("SELECT name FROM sqlite_master WHERE name='alerts'").fetchone():
            return
        alerts = pd.read_sql("SELECT * FROM alerts", con)
    finally:
        con.close()
    if alerts.empty:
        return
    fb = feedback.load(db_path)
    v = {(e, d): x for e, d, x in zip(fb["entity"], fb["date"], fb["verdict"])}
    alerts["status"] = [{"benign": "closed - benign", "threat": "confirmed threat"}.get(v.get((e, str(d))), "open")
                        for e, d in zip(alerts["entity"], alerts["date"])]
    alerts = apply_suppressions(alerts, db_path)
    con = _con(db_path)
    try:
        con.executemany("UPDATE alerts SET status=? WHERE alert_id=?", list(zip(alerts["status"], alerts["alert_id"])))
        con.commit()
    finally:
        con.close()
