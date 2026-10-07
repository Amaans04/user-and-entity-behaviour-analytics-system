"""End-to-end UEBA pipeline.

    raw logs -> normalise -> features -> baselines -> detectors -> risk -> alerts -> SQLite

Run with ``python run_pipeline.py`` (see README for options).
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from . import detectors as det
from . import cases, feedback
from .config import CONFIG, DATA_DIR, DB_PATH, REPORTS_DIR, Config
from . import web
from .features import DEVICE_FEATURES, USER_FEATURES, WEB_FEATURES, build_features
from .ingest import load_logs, load_table, save_tables, unified_events
from .profiles import BaselineModel, descriptive_profiles
from .risk import daily_risk, entity_risk, generate_alerts


MIN_BASELINE_ROWS = 30   # entity-days needed to fit baselines + the ML ensemble


QUIET = False   # the collector service turns the step-by-step log off


def log(msg: str):
    if not QUIET:
        print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def _robust(hist: np.ndarray, floor: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Median and robust scale of an entity's history (same formula as profiles._scales)."""
    med = np.median(hist, axis=0)
    mad = np.median(np.abs(hist - med), axis=0) * 1.4826
    tail = (np.quantile(hist, 0.95, axis=0) - med) / 1.645
    return med, np.maximum(np.maximum(mad, tail), floor)


def score_entities(feats: pd.DataFrame, cols: list, etype: str, train_start: str, train_end: str,
                   cfg: Config, benign: set | None = None, threat: set | None = None,
                   models: tuple | None = None, prev: pd.DataFrame | None = None,
                   rescore_from: str | None = None) -> tuple[pd.DataFrame, BaselineModel, det.MLEnsemble]:
    """Score every entity-day.

    Baseline window: z-scores against the static baseline learned from that window.
    Detection window: *adaptive* baseline - each day is compared with the entity's
    last ``cfg.history_days`` accepted days. Profiles keep learning legitimate change,
    while high-risk days and days matching a threat signature are quarantined, so an
    attacker cannot train the model to accept the attack.

    Analyst feedback overrides quarantine: days marked *benign* are always learned,
    days confirmed as *threat* are never learned.

    Incremental mode (``models`` + ``prev`` + ``rescore_from``): the saved baseline and
    ML models are reused, detection days before ``rescore_from`` keep their previous
    scores (and accept/quarantine decisions), and only later days are scored. Because
    features are causal, this gives exactly the same result as a full re-run.
    """
    F = feats[feats["date"] >= train_start].reset_index(drop=True)
    train_mask = (F["date"] < train_end).to_numpy()
    base = models[0] if models else BaselineModel(cols, cfg).fit(F[train_mask])
    X = F[cols].to_numpy(dtype=float)
    floor = base.floor[cols].to_numpy()
    pop_med = base.population["median"].to_numpy()
    pop_sc = base.population["scale"].to_numpy()

    med = np.tile(pop_med, (len(F), 1))
    scale = np.tile(pop_sc, (len(F), 1))
    for i in np.flatnonzero(train_mask):
        b = base.personal.get(F.at[i, "entity"])
        if b is not None:
            med[i], scale[i] = b["median"].to_numpy(), b["scale"].to_numpy()

    zpeer = base.peer_z(F)
    peer = det.deviation_score(zpeer, cfg.z_alert)
    F["baseline_restricted"] = [float(base.baseline_of(e)["median"].get("restricted_access", 0))
                                if "restricted_access" in cols else 0.0 for e in F["entity"]]
    # removable-media use during the learning period (insider indicator R16: first-time USB users)
    F["baseline_removable"] = (F["entity"].map(F.loc[train_mask].groupby("entity")["removable_media"].sum())
                               .fillna(0).to_numpy() if "removable_media" in cols else 1.0)
    # privilege use during the learning period: routine for that account (no admin list needed)
    F["baseline_priv"] = (F["entity"].map(F.loc[train_mask].groupby("entity")["priv_esc"].sum())
                          .fillna(0).to_numpy() if "priv_esc" in cols else 0.0)
    # web filter history: a person who is blocked a few times every day is not news; a burst is
    if "web_blocked" in F:
        F["baseline_blocked"] = F["entity"].map(F.loc[train_mask].groupby("entity")["web_blocked"].mean()) \
            .fillna(0).round(1).to_numpy()
        F["baseline_risky"] = F["entity"].map(F.loc[train_mask].groupby("entity")["risky_site_visits"].sum()) \
            .fillna(0).to_numpy()
    rule, hits = det.apply_rules(F, etype, cfg.disabled_rules)

    def zfor(idx):
        return np.clip((X[idx] - med[idx]) / scale[idx], -cfg.z_clip, cfg.z_clip)

    Z = np.zeros_like(X)
    Z[train_mask] = zfor(train_mask)
    ml = models[1] if models else det.MLEnsemble(cfg).fit(Z[train_mask])

    S = F[["entity_type", "entity", "date", "department", "is_admin"]].copy()
    S["peer"], S["rule"] = np.round(peer, 4), np.round(rule, 4)
    for c in ("stat", "ml", "ml_iforest", "ml_lof", "ml_autoencoder", "daily_risk"):
        S[c] = 0.0

    def score_rows(idx):
        Z[idx] = zfor(idx)
        zdf = pd.DataFrame(Z[idx], columns=cols)
        S.loc[idx, "stat"] = np.round(det.deviation_score(zdf, cfg.z_alert), 4)
        m = ml.score(Z[idx])
        for c in ("ml", "ml_iforest", "ml_lof", "ml_autoencoder"):
            S.loc[idx, c] = np.round(m[c].to_numpy(), 4)
        S.loc[idx, "daily_risk"] = daily_risk(S.loc[idx], cfg)

    def accept(idx):
        # quarantine high-risk days and anything matching a threat signature; medium,
        # purely behavioural deviations are absorbed so the profile adapts to new habits
        accepted[idx] = ((S.loc[idx, "daily_risk"].to_numpy() < cfg.quarantine_risk)
                         & (S.loc[idx, "rule"].to_numpy() < 0.2))
        for i in idx:
            key = (F.at[i, "entity"], F.at[i, "date"])
            if benign and key in benign:
                accepted[i] = True
            elif threat and key in threat:
                accepted[i] = False

    score_rows(np.flatnonzero(train_mask))
    accepted = train_mask.copy()
    rows_by_entity = {e: np.array(ix) for e, ix in F.groupby("entity").indices.items()}
    dates = F["date"].to_numpy()
    days = sorted(F.loc[~train_mask, "date"].unique())
    kept = np.zeros(len(F), dtype=bool)          # rows whose previous scores are reused
    if models and prev is not None and rescore_from:
        P = prev.drop_duplicates(["entity", "date"]).set_index(["entity", "date"])
        keys = pd.MultiIndex.from_arrays([F["entity"], F["date"]])
        known = keys.isin(P.index)
        gap = (~train_mask) & (dates < rescore_from) & ~known      # back-filled days -> rescore from there
        if gap.any():
            rescore_from = min(rescore_from, dates[gap].min())
        kept = (~train_mask) & (dates < rescore_from)
        idx = np.flatnonzero(kept)
        old = P.loc[keys[idx]]
        for c in ("stat", "ml", "ml_iforest", "ml_lof", "ml_autoencoder", "daily_risk"):
            S.loc[idx, c] = old[c].to_numpy(dtype=float)
        accept(idx)
        days = [d for d in days if d >= rescore_from]
    for day in days:
        idx = np.flatnonzero((dates == day))
        for i in idx:
            ix = rows_by_entity[F.at[i, "entity"]]
            hist = ix[(dates[ix] < day) & accepted[ix]][-cfg.history_days:]
            if len(hist) >= 5:
                med[i], scale[i] = _robust(X[hist], floor)
        score_rows(idx)
        accept(idx)

    S["entity_risk"] = entity_risk(S, cfg)
    S["is_train"] = train_mask
    zp = pd.DataFrame(Z, columns=cols)

    reasons = [[] for _ in range(len(S))]
    idx = np.flatnonzero((S["daily_risk"].to_numpy() >= 20) & ~kept)
    if len(idx):
        med_df = pd.DataFrame(med, columns=cols)
        sub = det.explain(F.iloc[idx], zp.iloc[idx], zpeer.iloc[idx], cols, cfg.z_alert, med_df.iloc[idx])
        for j, i in enumerate(idx):
            reasons[i] = sub[j]
    S["reasons"] = [json.dumps(r) for r in reasons]
    S["rule_hits"] = [json.dumps(h) for h in hits]
    S["top_features"] = [json.dumps(zp.iloc[i].nlargest(5).round(2).to_dict()) for i in range(len(S))]
    if kept.any():
        idx = np.flatnonzero(kept)
        old = P.loc[keys[idx]]
        S.loc[idx, "reasons"] = old["reasons"].to_numpy()
        S.loc[idx, "top_features"] = old["top_features"].to_numpy()
    return S, base, ml


def _fingerprint(cfg: Config) -> str:
    """Everything that changes how models are trained or days are scored. The alert threshold
    is left out: it only decides which scores become alerts, and alerts are regenerated on
    every run, so changing it needs no re-training."""
    d = asdict(cfg)
    d.pop("alert_threshold", None)
    return json.dumps(d, sort_keys=True, default=str)


def load_models(db_path: Path) -> dict | None:
    p = Path(db_path).with_name("models.joblib")
    try:
        return joblib.load(p) if p.exists() else None
    except Exception:  # noqa: BLE001 - corrupt / incompatible pickle -> retrain
        return None


def _reuse_problem(saved: dict | None, cfg: Config, train_start: str, train_end: str,
                   feature_sets: dict) -> str | None:
    """Why the saved models can NOT be reused for an incremental update (None = they can)."""
    if not saved or "fingerprint" not in saved:
        return "no saved models"
    if saved["fingerprint"] != _fingerprint(cfg):
        return "settings changed"
    if (saved["train_start"], saved["train_end"]) != (train_start, train_end):
        return "learning window changed"
    if not saved.get("complete"):
        return "models were trained before the learning period was complete"
    if saved.get("features") != feature_sets:
        return "feature set changed"
    return None


def run(raw_dir: Path = DATA_DIR / "raw", db_path: Path = DB_PATH, cfg: Config = CONFIG,
        evaluate_results: bool = True, train_start: str | None = None, train_end: str | None = None,
        reports_dir: Path | None = REPORTS_DIR, mode: str = "full", rescore_from: str | None = None) -> dict:
    """Run the analysis.

    ``mode="full"``   - (re)train baselines + ML models on the learning window and score every day.
    ``mode="update"`` - reuse the saved models and only score days from ``rescore_from`` (default:
                        the last day already scored, which may have been partial) onwards. Falls
                        back to a full run whenever the saved models can't be reused.
    """
    t0 = time.time()
    log(f"Loading logs from {raw_dir}")
    frames = load_logs(raw_dir)
    for k in ("auth", "access", "network", "resource"):
        log(f"  {k:9s} {len(frames[k]):>9,} events")

    present = [k for k in ("auth", "access", "network", "resource") if len(frames[k])]
    first_day = min(frames[k]["timestamp"].min() for k in present).normalize()
    last_day = max(frames[k]["timestamp"].max() for k in present).normalize()
    train_start = train_start or (first_day + timedelta(days=cfg.warmup_days)).date().isoformat()
    train_end = train_end or (first_day + timedelta(days=cfg.train_days)).date().isoformat()
    log(f"Baseline window: {train_start} .. {train_end} (exclusive); detection from {train_end}")

    log("Building behavioural features")
    feats = build_features(frames, cfg)
    # web pages / categories / blocks are profiled only when the logs carry them (proxy or gateway)
    web_detail = web.has_web_detail(frames["network"])
    feature_sets = {"user": USER_FEATURES + (WEB_FEATURES if web_detail else []), "device": DEVICE_FEATURES}
    if web_detail:
        log("  web gateway detail found: profiling pages, categories, blocked requests and downloads")

    fb = feedback.load(db_path)
    benign, threat = feedback.as_sets(fb)
    if len(fb):
        log(f"Analyst feedback: {len(benign)} benign, {len(threat)} confirmed threats")

    saved, prev = None, None
    if mode == "update":
        saved = load_models(db_path)
        problem = _reuse_problem(saved, cfg, train_start, train_end, feature_sets)
        if problem is None:
            prev = load_table(db_path, "scores") if Path(db_path).exists() else None
            if prev is None or prev.empty:
                problem = "no previous scores"
        if problem:
            log(f"Full re-training ({problem})")
            mode, saved, prev = "full", None, None
        else:
            last_scored = str(prev["date"].max())
            rescore_from = max(min(rescore_from or last_scored, last_scored), train_end)
            log(f"Incremental update: reusing trained models, scoring days from {rescore_from}")

    parts, models = [], {}
    for etype, cols in feature_sets.items():
        F = feats[etype]
        n_train = int(((F["date"] >= train_start) & (F["date"] < train_end)).sum()) if len(F) else 0
        if n_train < MIN_BASELINE_ROWS:
            log(f"Skipping {etype}s: only {n_train} baseline {etype}-days (need {MIN_BASELINE_ROWS})")
            continue
        if mode == "update" and etype not in saved:
            continue                    # was not trainable when the models were built
        log(f"Profiling {etype}s & scoring (statistical + ML + rules)")
        s, base, ml = score_entities(
            F, cols, etype, train_start, train_end, cfg, benign, threat,
            models=saved.get(etype) if saved else None,
            prev=prev[prev["entity_type"] == etype] if prev is not None else None, rescore_from=rescore_from)
        parts.append(s)
        models[etype] = (base, ml)
    if not parts:
        raise ValueError(f"Not enough baseline data to learn from: need at least {MIN_BASELINE_ROWS} "
                         f"entity-days before {train_end} (e.g. 5 users x 6 days). Upload more history "
                         "or shorten the learning period.")
    scores = pd.concat(parts, ignore_index=True)

    truth = frames.get("ground_truth")
    if truth is not None and len(truth):
        keys = set(zip(truth["entity"], truth["date"].astype(str)))
        scores["label"] = [int((e, d) in keys) for e, d in zip(scores["entity"], scores["date"])]
        inc = truth.groupby(["entity", "date"])["scenario"].first()
        scores["scenario"] = [inc.get((e, d), "") for e, d in zip(scores["entity"], scores["date"])]
    else:
        scores["label"], scores["scenario"] = np.nan, ""

    log("Generating alerts")
    alerts = generate_alerts(scores[~scores["is_train"]], cfg)
    status = {(e, d): v for e, d, v in zip(fb["entity"], fb["date"], fb["verdict"])}
    alerts["status"] = [{"benign": "closed - benign", "threat": "confirmed threat"}.get(
        status.get((e, d)), "open") for e, d in zip(alerts["entity"], alerts["date"])]
    alerts = cases.apply_suppressions(alerts, db_path)
    log(f"  {len(alerts)} alerts ({(alerts['severity'] == 'critical').sum()} critical, "
        f"{(alerts['severity'] == 'high').sum()} high)")

    profiles = descriptive_profiles(frames, train_end)
    meta = pd.DataFrame([dict(key=k, value=str(v)) for k, v in {
        "generated_at": datetime.now().isoformat(timespec="seconds"), "train_start": train_start,
        "train_end": train_end, "first_day": str(first_day.date()),
        "last_day": str(last_day.date()), "streams": ",".join(present),
        "learning_days": cfg.train_days, "monitoring": str(last_day >= pd.Timestamp(train_end)),
        "mode": mode, "models_trained_at": (saved or {}).get("trained_at", datetime.now().isoformat(timespec="seconds")),
        "alert_threshold": cfg.alert_threshold, "raw_dir": str(raw_dir)}.items()])

    tables = {k: frames[k] for k in ("auth", "access", "network", "resource", "users", "devices")}
    if truth is not None:
        tables["ground_truth"] = truth
    tables.update({
        "events": unified_events(frames), "features_user": feats["user"], "features_device": feats["device"],
        "scores": scores, "alerts": alerts, "profiles": profiles, "meta": meta})
    log(f"Saving to {db_path}")
    save_tables(db_path, tables)
    if mode == "full":
        joblib.dump({**models, "cfg": cfg, "fingerprint": _fingerprint(cfg), "train_start": train_start,
                     "train_end": train_end, "complete": bool(last_day >= pd.Timestamp(train_end)),
                     "features": feature_sets,
                     "trained_at": datetime.now().isoformat(timespec="seconds")},
                    Path(db_path).with_name("models.joblib"))

    result = {"scores": scores, "alerts": alerts, "frames": frames, "features": feats, "mode": mode}
    detect = scores[~scores["is_train"].astype(bool)]
    measurable = len(detect) and detect["label"].nunique() == 2      # needs attack AND normal days
    if evaluate_results and truth is not None and len(truth) and measurable:
        from .evaluate import evaluate
        log("Evaluating against ground truth")
        # figures are only redrawn on full runs - incremental updates must stay fast
        metrics = evaluate(scores, alerts, truth, cfg, reports_dir if mode == "full" else None)
        save_tables(db_path, {"metrics": pd.DataFrame([dict(key="report", value=json.dumps(metrics))])},
                    replace=True)
        result["metrics"] = metrics
    else:
        with sqlite3.connect(db_path) as con:            # never show accuracy from an older run
            con.execute("DROP TABLE IF EXISTS metrics")
    log(f"Done in {time.time() - t0:.1f}s")
    return result
