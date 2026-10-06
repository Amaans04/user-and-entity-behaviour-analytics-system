"""Analyst feedback loop.

An analyst reviewing an alert in the dashboard can mark it:

* **benign**  - a false positive. The entity-day is released from quarantine and
  learned into that entity's adaptive baseline at the next analysis run, so the
  same legitimate behaviour is not flagged again.
* **threat**  - a confirmed attack. The entity-day stays quarantined for good, so
  it can never become part of "normal".

Feedback is kept in its own SQLite table (``feedback``), keyed by entity and date,
so it survives every re-run of the pipeline.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd

VERDICTS = ("benign", "threat")
COLUMNS = ["entity", "date", "verdict", "note", "analyst", "alert_id", "created_at"]


def _ensure(con: sqlite3.Connection):
    con.execute("""CREATE TABLE IF NOT EXISTS feedback (
        entity TEXT, date TEXT, verdict TEXT, note TEXT, analyst TEXT, alert_id TEXT, created_at TEXT,
        PRIMARY KEY (entity, date))""")


def record(db_path: Path, entity: str, date: str, verdict: str, note: str = "", analyst: str = "analyst",
           alert_id: str = "") -> None:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    with sqlite3.connect(db_path) as con:
        _ensure(con)
        con.execute("INSERT OR REPLACE INTO feedback VALUES (?,?,?,?,?,?,?)",
                    (entity, str(date), verdict, note, analyst, alert_id,
                     datetime.now().isoformat(timespec="seconds")))


def clear(db_path: Path, entity: str, date: str) -> None:
    with sqlite3.connect(db_path) as con:
        _ensure(con)
        con.execute("DELETE FROM feedback WHERE entity=? AND date=?", (entity, str(date)))


def load(db_path: Path) -> pd.DataFrame:
    if not Path(db_path).exists():
        return pd.DataFrame(columns=COLUMNS)
    with sqlite3.connect(db_path) as con:
        _ensure(con)
        return pd.read_sql("SELECT * FROM feedback", con)


def as_sets(fb: pd.DataFrame) -> tuple[set, set]:
    """(benign keys, confirmed-threat keys) as sets of (entity, date)."""
    benign = set(zip(fb.loc[fb["verdict"] == "benign", "entity"], fb.loc[fb["verdict"] == "benign", "date"]))
    threat = set(zip(fb.loc[fb["verdict"] == "threat", "entity"], fb.loc[fb["verdict"] == "threat", "date"]))
    return benign, threat
