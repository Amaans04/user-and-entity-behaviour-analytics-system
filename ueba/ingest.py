"""Log ingestion & normalisation.

* Reads the four raw log streams (CSV or JSON-lines) from a folder.
* Validates / cleans them (types, lower-case identities, missing columns).
* Produces a single *unified event* table with a common schema, which is what
  an analyst sees in the investigation timeline.
* Persists everything to SQLite (``data/ueba.db``).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import numpy as np
import pandas as pd

from . import web

REQUIRED = {
    "auth": ["timestamp", "user", "src_device", "src_ip", "dest_host", "auth_type", "result",
             "city", "country", "lat", "lon"],
    "access": ["timestamp", "user", "device", "resource", "action", "sensitivity", "status", "pages", "printer"],
    "network": ["timestamp", "user", "device", "src_ip", "dst_ip", "dst_port", "protocol",
                "bytes_out", "bytes_in", "domain"],
    "resource": ["timestamp", "device", "user", "cpu_pct", "mem_pct", "disk_io_mb", "process_count"],
}
OPTIONAL = ["users", "devices", "ground_truth"]


def _read(path: Path) -> pd.DataFrame:
    if path.suffix in (".jsonl", ".json"):
        return pd.read_json(path, lines=path.suffix == ".jsonl")
    return pd.read_csv(path)


def _find(folder: Path, name: str) -> Path | None:
    for ext in (".csv", ".jsonl", ".json"):
        p = folder / f"{name}{ext}"
        if p.exists():
            return p
    return None


def normalise(name: str, df: pd.DataFrame) -> pd.DataFrame:
    """Coerce types and fill optional columns so downstream code can rely on them."""
    df = df.copy()
    for col in REQUIRED[name]:
        if col not in df.columns:
            df[col] = None
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    for col in ("user", "device", "src_device", "dest_host"):
        if col in df.columns:
            df[col] = df[col].fillna("unknown").astype(str).str.strip()
    if "user" in df.columns:
        df["user"] = df["user"].str.lower()
    if name == "auth":
        df["result"] = df["result"].astype(str).str.lower()
        df["lat"] = pd.to_numeric(df["lat"], errors="coerce")
        df["lon"] = pd.to_numeric(df["lon"], errors="coerce")
    if name == "access":
        df["pages"] = pd.to_numeric(df["pages"], errors="coerce").fillna(0).astype("int64")
        df["printer"] = df["printer"].fillna("").astype(str)
    if name == "network":
        for c in ("bytes_out", "bytes_in", "dst_port"):
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype("int64")
        df = web.enrich(df)                  # page, site category, allowed/blocked, downloaded file
    if name == "resource":
        for c in ("cpu_pct", "mem_pct", "disk_io_mb", "process_count"):
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0)
    df["date"] = df["timestamp"].dt.date.astype(str)
    return df.sort_values("timestamp").reset_index(drop=True)


def resolve_device_users(frames: dict) -> None:
    """USB and PowerShell script-block events are logged by the computer, not the person; the parsers
    leave them as ``?computer`` when the file itself does not say who was on it. Settle them here from
    the asset inventory (the device's owner), then from who normally logs into that computer.
    Whatever is still unknown is dropped: it cannot be tied to anyone's behaviour."""
    acc = frames["access"]
    unknown = acc["user"].str.startswith("?")
    if not unknown.any():
        return
    owners: dict = {}
    a = frames["auth"]
    ok = a[(a["result"] == "success") & ~a["user"].str.startswith("?")]
    for col in ("src_device", "dest_host"):                  # the usual user of each computer
        top = ok.groupby(ok[col].str.lower())["user"].agg(lambda s: s.value_counts().index[0])
        owners = {**top.to_dict(), **owners}
    if "devices" in frames and "owner" in frames["devices"]:
        d = frames["devices"]
        named = d[d["owner"].fillna("").astype(str).str.strip().str.lower().isin(["", "system", "nan"]) == False]  # noqa: E712
        owners.update(dict(zip(named["device"].astype(str).str.lower(), named["owner"].astype(str).str.lower())))
    who = acc.loc[unknown, "user"].str[1:].str.lower().map(owners)
    acc.loc[unknown, "user"] = who
    frames["access"] = acc[acc["user"].notna()].reset_index(drop=True)


def available_streams(folder: Path) -> list[str]:
    return [name for name in REQUIRED if _find(Path(folder), name) is not None]


def load_logs(folder: Path) -> dict:
    """Load whatever log streams exist. Missing streams become empty tables, so a
    deployment with (say) only authentication logs still works - the features of
    the missing streams simply stay at zero."""
    folder = Path(folder)
    frames = {}
    for name in REQUIRED:
        p = _find(folder, name)
        raw = _read(p) if p is not None else pd.DataFrame(columns=REQUIRED[name])
        frames[name] = normalise(name, raw)
    if all(frames[n].empty for n in REQUIRED):
        raise FileNotFoundError(f"No log streams (auth/access/network/resource) found in {folder}")
    for name in OPTIONAL:
        p = _find(folder, name)
        if p is not None:
            frames[name] = _read(p)
    resolve_device_users(frames)
    if "users" not in frames:  # derive a minimal user directory
        users = sorted(set(frames["auth"]["user"]) | set(frames["access"]["user"]))
        frames["users"] = pd.DataFrame({"user": users, "full_name": users, "department": "unknown",
                                        "is_admin": False, "device": "", "home_city": "", "remote": False})
    if "devices" not in frames:
        # no asset inventory: every device seen in the logs counts as registered, so the
        # "login from unregistered device" signal is effectively off
        devs = (set(frames["resource"]["device"]) | set(frames["network"]["device"])
                | set(frames["access"]["device"]) | set(frames["auth"]["src_device"])) - {"unknown", "", "nan"}
        frames["devices"] = pd.DataFrame({"device": sorted(devs), "device_type": "laptop", "owner": "",
                                          "department": "unknown"})
    frames["users"]["department"] = frames["users"]["department"].fillna("unknown").astype(str)
    frames["devices"]["department"] = frames["devices"]["department"].fillna("unknown").astype(str)
    frames["users"]["is_admin"] = frames["users"]["is_admin"].astype(str).str.lower().isin(["true", "1"])
    return frames


def unified_events(frames: dict) -> pd.DataFrame:
    """Map every stream onto one schema: timestamp, source, user, device, action, target, outcome, detail."""
    a = frames["auth"]
    auth = pd.DataFrame({
        "timestamp": a["timestamp"], "source": "auth", "user": a["user"], "device": a["src_device"],
        "action": "login:" + a["auth_type"].astype(str), "target": a["dest_host"], "outcome": a["result"],
        "detail": a["city"].astype(str) + ", " + a["country"].astype(str) + " from " + a["src_ip"].astype(str)})
    x = frames["access"]
    acc = pd.DataFrame({
        "timestamp": x["timestamp"], "source": "access", "user": x["user"], "device": x["device"],
        "action": x["action"], "target": x["resource"], "outcome": x["status"],
        "detail": "sensitivity=" + x["sensitivity"].astype(str)})
    n = web.enrich(frames["network"])
    url, cat, fil = (n[c].astype(str) for c in ("url", "category", "file"))
    kind = pd.Series(np.select([n["web_action"] == "blocked", fil != "", url != ""],
                               ["web:blocked", "web:download", "web:visit"], ""), index=n.index, dtype=object)
    kind = kind.where(kind != "", "connect:" + n["dst_port"].astype(str))
    detail = (("category=" + cat + " ").where(cat != "", "") + ("file=" + fil + " ").where(fil != "", "")
              + "out=" + (n["bytes_out"] / 1e6).round(2).astype(str) + "MB in="
              + (n["bytes_in"] / 1e6).round(2).astype(str) + "MB")
    net = pd.DataFrame({
        "timestamp": n["timestamp"], "source": "network", "user": n["user"], "device": n["device"],
        "action": kind, "target": url.where(url != "", n["domain"].astype(str)), "outcome": n["web_action"],
        "detail": detail})
    r = frames["resource"]
    res = pd.DataFrame({
        "timestamp": r["timestamp"], "source": "resource", "user": r["user"], "device": r["device"],
        "action": "sample", "target": r["device"], "outcome": "ok",
        "detail": "cpu=" + r["cpu_pct"].astype(str) + "% mem=" + r["mem_pct"].astype(str) + "%"})
    ev = pd.concat([auth, acc, net, res], ignore_index=True).sort_values("timestamp")
    ev["date"] = ev["timestamp"].dt.date.astype(str)
    return ev.reset_index(drop=True)


def save_tables(db_path: Path, tables: dict, replace: bool = True):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as con:
        for name, df in tables.items():
            out = df.copy()
            for c in out.columns:
                if out[c].dtype == object and len(out) and isinstance(out[c].iloc[0], (list, dict)):
                    out[c] = out[c].apply(json.dumps)
                elif pd.api.types.is_datetime64_any_dtype(out[c]):
                    out[c] = out[c].dt.strftime("%Y-%m-%d %H:%M:%S")
            out.to_sql(name, con, if_exists="replace" if replace else "append", index=False)
        cur = con.cursor()
        for t, cols in [("auth", "user, date"), ("access", "user, date"), ("network", "user, date"),
                        ("resource", "device, date"), ("events", "user, date"),
                        ("scores", "entity, date"), ("alerts", "entity")]:
            if t in tables:
                cur.execute(f"CREATE INDEX IF NOT EXISTS idx_{t} ON {t} ({cols})")


def load_table(db_path: Path, name: str, where: str = "", params: tuple = ()) -> pd.DataFrame:
    with sqlite3.connect(db_path) as con:
        return pd.read_sql(f"SELECT * FROM {name} {where}", con, params=params)
