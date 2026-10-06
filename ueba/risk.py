"""Risk scoring and alert generation.

Daily risk (0-100) for an entity-day:

    A = 1 - (1 - w_stat*stat) (1 - w_peer*peer) (1 - w_ml*ml) (1 - rules)
    daily_risk = 100 * min(1, A * criticality)

It behaves like a probabilistic OR: any single strong signal raises risk,
several weak signals together raise it further, and nothing exceeds 100.
``criticality`` boosts accounts/assets whose compromise hurts more (admins,
finance, servers).

Entity risk (0-100) accumulates daily risk above a noise floor and decays with
a half-life, so slow multi-day behaviour (e.g. an insider exfiltrating a bit
more each day) builds up even when no single day looks alarming.
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd

from .config import CONFIG, Config

NOISE_FLOOR = 15.0
SUSTAINED_THRESHOLD = 60.0


def severity(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def daily_risk(df: pd.DataFrame, cfg: Config = CONFIG) -> np.ndarray:
    a = 1 - ((1 - cfg.w_stat * df["stat"]) * (1 - cfg.w_peer * df["peer"]) *
             (1 - cfg.w_ml * df["ml"]) * (1 - df["rule"]))
    crit = df["department"].map(cfg.criticality).fillna(1.0)
    crit = np.where(df["is_admin"].astype(bool), np.maximum(crit, cfg.criticality.get("IT-Admin", 1.3)), crit)
    return np.round(100 * np.clip(a * crit, 0, 1), 1)


def entity_risk(df: pd.DataFrame, cfg: Config = CONFIG) -> np.ndarray:
    """Decayed accumulation of daily risk above the noise floor (per entity, chronological)."""
    out = np.zeros(len(df))
    decay_per_day = 0.5 ** (1 / cfg.risk_half_life_days)
    order = df.sort_values(["entity", "date"]).index
    prev_ent, prev_date, r = None, None, 0.0
    dates = pd.to_datetime(df["date"])
    for idx in order:
        ent, d = df.at[idx, "entity"], dates.at[idx]
        if ent != prev_ent:
            r = 0.0
        else:
            r *= decay_per_day ** max(1, (d - prev_date).days)
        r = min(100.0, r + max(0.0, df.at[idx, "daily_risk"] - NOISE_FLOOR))
        out[df.index.get_loc(idx)] = r
        prev_ent, prev_date = ent, d
    return np.round(out, 1)


def generate_alerts(scores: pd.DataFrame, cfg: Config = CONFIG) -> pd.DataFrame:
    rows = []
    last_alert: dict[str, pd.Timestamp] = {}
    for _, s in scores.sort_values(["date", "daily_risk"], ascending=[True, False]).iterrows():
        hits = json.loads(s["rule_hits"])
        reasons = json.loads(s["reasons"])
        kind = None
        if s["daily_risk"] >= cfg.alert_threshold:
            kind, score = "anomalous_day", s["daily_risk"]
        elif s["entity_risk"] >= SUSTAINED_THRESHOLD:
            # only for slow build-ups: skip if this entity was alerted in the last 3 days
            last = last_alert.get(s["entity"])
            if last is None or (pd.Timestamp(s["date"]) - last).days > 3:
                kind, score = "sustained_risk", s["entity_risk"]
        if kind is None:
            continue
        last_alert[s["entity"]] = pd.Timestamp(s["date"])
        title = (max(hits, key=lambda h: h["severity"])["name"] if hits
                 else "Sustained elevated risk" if kind == "sustained_risk" else "Behavioural anomaly")
        detectors = [n for n, v in (("personal baseline", s["stat"]), ("peer group", s["peer"]),
                                    ("ML ensemble", s["ml"]), ("threat rules", s["rule"])) if v >= 0.3]
        rows.append(dict(
            alert_id=f"AL-{len(rows) + 1:04d}", date=s["date"], entity=s["entity"],
            entity_type=s["entity_type"], department=s["department"], alert_type=kind,
            title=title, severity=severity(score), risk_score=float(score),
            daily_risk=float(s["daily_risk"]), entity_risk=float(s["entity_risk"]),
            reasons=json.dumps([h["message"] for h in hits] + reasons),
            mitre=json.dumps(sorted({h["mitre"] for h in hits})),
            detectors=json.dumps(detectors),
            stat=float(s["stat"]), peer=float(s["peer"]), ml=float(s["ml"]), rule=float(s["rule"]),
            status="open"))
    return pd.DataFrame(rows, columns=[
        "alert_id", "date", "entity", "entity_type", "department", "alert_type", "title", "severity",
        "risk_score", "daily_risk", "entity_risk", "reasons", "mitre", "detectors", "stat", "peer", "ml",
        "rule", "status"])
