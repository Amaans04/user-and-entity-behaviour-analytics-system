"""Behavioural profiles (baselines) for users and devices.

For each entity we learn, from the attack-free baseline window:

* a **personal baseline** per feature - robust centre (median) and spread
  (the larger of MAD and the spread implied by the entity's own 95th percentile)
* a **peer-group baseline** per feature - same, over the entity's department
* a **descriptive profile** for analysts: usual login hours, usual hosts,
  countries, top resources, top domains, typical data volume.

Deviations are expressed as robust z-scores:  z = (x - median) / scale
where ``scale`` has sensible floors so features that are *always zero* in the
baseline (e.g. impossible travel) do not explode to infinity.
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd

from .config import CONFIG, Config

MAD_K = 1.4826  # makes MAD comparable to a standard deviation


def _scales(train: pd.DataFrame, cols: list, global_floor: pd.Series) -> pd.DataFrame:
    med = train[cols].median()
    mad = (train[cols] - med).abs().median() * MAD_K
    # spread implied by the entity's own 95th percentile: respects occasional legitimate peaks
    tail = (train[cols].quantile(0.95) - med) / 1.645
    scale = np.maximum(np.maximum(mad, tail), global_floor[cols])
    return pd.DataFrame({"median": med, "scale": scale})


def global_floor(train: pd.DataFrame, cols: list) -> pd.Series:
    g = train[cols]
    # at least 25% of the population spread, 5% of the population mean, and 1 unit
    return np.maximum(np.maximum(0.25 * g.std(ddof=0).fillna(0), 0.05 * g.mean().abs()), 1.0)


class BaselineModel:
    """Learns personal and peer baselines and turns feature rows into z-scores."""

    def __init__(self, cols: list, cfg: Config = CONFIG):
        self.cols = cols
        self.cfg = cfg
        self.personal: dict[str, pd.DataFrame] = {}
        self.peer: dict[str, pd.DataFrame] = {}
        self.floor: pd.Series | None = None
        self.population: pd.DataFrame | None = None

    def fit(self, train: pd.DataFrame) -> "BaselineModel":
        self.floor = global_floor(train, self.cols)
        self.population = _scales(train, self.cols, self.floor)
        for ent, g in train.groupby("entity"):
            if len(g) >= 5:
                self.personal[ent] = _scales(g, self.cols, self.floor)
        for dept, g in train.groupby("department"):
            if g["entity"].nunique() >= 2:
                self.peer[dept] = _scales(g, self.cols, self.floor)
        return self

    def _z(self, df: pd.DataFrame, table: dict, key: str) -> pd.DataFrame:
        med = np.vstack([table.get(k, self.population)["median"].to_numpy() for k in df[key]])
        sc = np.vstack([table.get(k, self.population)["scale"].to_numpy() for k in df[key]])
        z = (df[self.cols].to_numpy(dtype=float) - med) / sc
        z = np.clip(z, -self.cfg.z_clip, self.cfg.z_clip)
        return pd.DataFrame(z, columns=self.cols, index=df.index)

    def personal_z(self, df):
        return self._z(df, self.personal, "entity")

    def peer_z(self, df):
        return self._z(df, self.peer, "department")

    def baseline_of(self, entity: str) -> pd.DataFrame:
        return self.personal.get(entity, self.population)


# --------------------------------------------------------------------------
# Descriptive profiles (shown in the dashboard)
# --------------------------------------------------------------------------
def descriptive_profiles(frames: dict, train_end: str) -> pd.DataFrame:
    auth = frames["auth"][(frames["auth"]["date"] < train_end) & (frames["auth"]["result"] == "success")]
    acc = frames["access"][frames["access"]["date"] < train_end]
    net = frames["network"][frames["network"]["date"] < train_end]
    rows = []
    users = frames["users"].set_index("user")
    for user, g in auth.groupby("user"):
        hours = np.bincount(g["timestamp"].dt.hour, minlength=24)
        a = acc[acc["user"] == user]
        n = net[net["user"] == user]
        days = max(1, g["date"].nunique())
        rows.append(dict(
            entity=user, entity_type="user",
            department=users["department"].get(user, "unknown") if user in users.index else "unknown",
            hour_histogram=json.dumps(hours.tolist()),
            typical_hours=_hour_range(hours),
            known_hosts=json.dumps(sorted(g["dest_host"].unique().tolist())),
            known_countries=json.dumps(sorted(g["country"].dropna().unique().tolist())),
            known_cities=json.dumps(sorted(g["city"].dropna().unique().tolist())),
            top_resources=json.dumps(a["resource"].value_counts().head(8).index.tolist()),
            top_domains=json.dumps(n["domain"].value_counts().head(8).index.tolist()),
            avg_daily_upload_mb=round(n["bytes_out"].sum() / 1e6 / days, 2),
            avg_daily_file_access=round(len(a) / days, 1),
            active_days=int(days),
        ))
    return pd.DataFrame(rows, columns=PROFILE_COLUMNS)


PROFILE_COLUMNS = ["entity", "entity_type", "department", "hour_histogram", "typical_hours", "known_hosts",
                   "known_countries", "known_cities", "top_resources", "top_domains", "avg_daily_upload_mb",
                   "avg_daily_file_access", "active_days"]


def _hour_range(hist: np.ndarray) -> str:
    if hist.sum() == 0:
        return "n/a"
    cdf = np.cumsum(hist) / hist.sum()
    lo = int(np.searchsorted(cdf, 0.05))
    hi = int(np.searchsorted(cdf, 0.95))
    return f"{lo:02d}:00-{hi + 1:02d}:00"
