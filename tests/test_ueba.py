"""Unit + integration tests.  Run:  python -m pytest -q"""
import copy
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from ueba.config import CONFIG  # noqa: E402
from ueba.detectors import apply_rules, deviation_score  # noqa: E402
from ueba.features import haversine_km, hour_rarity, impossible_travel_events  # noqa: E402
from ueba.risk import daily_risk, severity  # noqa: E402


# ---------------------------------------------------------------- units
def test_haversine_bengaluru_amsterdam():
    km = haversine_km(12.97, 77.59, 52.37, 4.90)
    assert 7600 < km < 7800   # great-circle distance is ~7,700 km


def test_impossible_travel_detected():
    auth = pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-08-01 10:00", "2026-08-01 11:10", "2026-08-01 12:00"]),
        "user": ["a", "a", "a"], "result": ["success"] * 3, "city": ["Bengaluru", "Amsterdam", "Amsterdam"],
        "lat": [12.97, 52.37, 52.37], "lon": [77.59, 4.90, 4.90]})
    auth["date"] = auth["timestamp"].dt.date.astype(str)
    hits = impossible_travel_events(auth, 900)
    assert len(hits) == 1 and hits.iloc[0]["city"] == "Amsterdam"


def test_hour_rarity_flags_unusual_hour():
    ts = [f"2026-07-{d:02d} 10:00" for d in range(1, 21)] + ["2026-07-21 03:00"]
    df = pd.DataFrame({"timestamp": pd.to_datetime(ts), "user": "a"})
    df["date"] = df["timestamp"].dt.date.astype(str)
    p = hour_rarity(df, "user")
    assert p.iloc[-1] < 0.05 and p.iloc[-2] > 0.5


def test_deviation_score_monotonic():
    z = pd.DataFrame([[0, 0], [4, 0], [10, 0], [10, 10]])
    s = deviation_score(z, 3.0)
    assert s[0] == 0 and s[0] < s[1] < s[2] < s[3] <= 1


def test_rules_brute_force_and_privilege():
    cols = {c: 0.0 for c in ["max_fail_10min", "fail_then_success", "impossible_travel", "new_countries",
                             "priv_esc", "account_changes", "log_tamper", "new_domain_upload_mb",
                             "cloud_upload_mb", "mining_conns", "new_dest_hosts", "off_hours_access",
                             "sensitive_access", "unregistered_device_logins", "job_site_visits",
                             "new_sensitive_resources", "restricted_access", "baseline_restricted"]}
    df = pd.DataFrame([dict(cols, is_admin=False, department="Sales"),
                       dict(cols, max_fail_10min=40, fail_then_success=1, is_admin=False, department="Sales"),
                       dict(cols, priv_esc=3, is_admin=False, department="Sales"),
                       dict(cols, priv_esc=3, is_admin=True, department="IT-Admin")])
    score, hits = apply_rules(df, "user")
    assert score[0] == 0
    assert {h["rule_id"] for h in hits[1]} == {"R01"}
    assert {h["rule_id"] for h in hits[2]} == {"R05"}
    assert hits[3] == []   # admins may escalate privileges


def test_risk_fusion_bounds_and_corroboration():
    top = 1 - np.exp(-12.25 / 4)   # highest possible deviation_score (three features at z=10)
    df = pd.DataFrame({"stat": [0, top, top, 0, top], "peer": [0, top, top, 0, top], "ml": [0, 0, 1, 0, 1],
                       "rule": [0, 0, 0, 0.8, 0.8], "department": ["Sales", "IT-Admin", "Sales", "Sales", "IT-Admin"],
                       "is_admin": [False, True, False, False, True]})
    r = daily_risk(df, CONFIG)
    assert r[0] == 0 and r.max() <= 100
    assert r[1] < CONFIG.alert_threshold          # one behavioural layer alone never alerts
    assert r[2] >= CONFIG.alert_threshold         # corroborated by ML -> alert
    assert r[3] >= CONFIG.alert_threshold         # strong threat signature -> alert
    assert severity(85) == "critical" and severity(10) == "low"


# ---------------------------------------------------------------- integration
@pytest.fixture(scope="module")
def small_run(tmp_path_factory):
    from ueba.generator import generate_dataset
    from ueba.pipeline import run
    tmp = tmp_path_factory.mktemp("ueba")
    cfg = copy.deepcopy(CONFIG)
    generate_dataset(tmp / "raw", cfg, n_users_scale=0.5)
    return run(tmp / "raw", tmp / "ueba.db", cfg, evaluate_results=True, reports_dir=tmp / "reports"), tmp


def test_pipeline_outputs(small_run):
    res, tmp = small_run
    assert (tmp / "ueba.db").exists()
    s = res["scores"]
    assert s["daily_risk"].between(0, 100).all()
    assert {"user", "device"} <= set(s["entity_type"])
    for r in res["alerts"]["reasons"]:
        assert isinstance(json.loads(r), list)


def test_pipeline_detects_planted_attacks(small_run):
    m = small_run[0]["metrics"]
    assert m["incidents_detected"] >= m["incidents_total"] - 1
    assert m["detectors"]["Fused risk score"]["roc_auc"] > 0.95
    assert m["false_positive_rate"] < 0.02


def test_baseline_window_has_no_attacks(small_run):
    s = small_run[0]["scores"]
    assert s.loc[s["is_train"], "label"].sum() == 0


def test_cert_adapter(tmp_path):
    from cert_sample import write_cert_sample
    from ueba.cert_loader import convert_cert
    from ueba.pipeline import run
    root = write_cert_sample(tmp_path)
    info = convert_cert(root, tmp_path / "conv", max_users=12)
    assert info["insiders"] == 1 and info["attack_user_days"] > 0
    res = run(tmp_path / "conv", tmp_path / "c.db", copy.deepcopy(CONFIG),
              train_start=info["train_start"], train_end=info["train_end"], reports_dir=None)
    assert res["metrics"]["incidents_detected"] == 1


def test_feedback_roundtrip_and_status(small_run):
    from ueba import feedback
    from ueba.pipeline import run
    res, tmp = small_run
    db = tmp / "ueba.db"
    a = res["alerts"].iloc[0]
    feedback.record(db, a["entity"], a["date"], "benign", "test note")
    fb = feedback.load(db)
    assert len(fb) == 1 and fb.iloc[0]["verdict"] == "benign"
    with pytest.raises(ValueError):
        feedback.record(db, a["entity"], a["date"], "maybe")
    res2 = run(tmp / "raw", db, copy.deepcopy(CONFIG), evaluate_results=False)   # feedback survives re-runs
    al = res2["alerts"]
    assert al.loc[(al.entity == a["entity"]) & (al.date == a["date"]), "status"].iloc[0] == "closed - benign"
    feedback.clear(db, a["entity"], a["date"])
    assert feedback.load(db).empty


# ---------------------------------------------------------------- bring-your-own-logs
def test_sources_map_foreign_columns_and_values():
    from ueba import sources
    raw = pd.DataFrame({"TimeCreated": ["2026-07-01T08:00:00Z", "2026-07-01T08:01:00Z", "bad"],
                        "TargetUserName": ["CORP\\Alice", "CORP\\Alice", "bob"],
                        "Status": ["Success", "Logon Failure", "4625"], "IpAddress": ["1.2.3.4"] * 3})
    stream = sources.guess_stream(list(raw.columns), "Security-4624.csv")
    assert stream == "auth"
    m = sources.guess_mapping(stream, list(raw.columns))
    assert m["timestamp"] == "TimeCreated" and m["user"] == "TargetUserName" and m["src_ip"] == "IpAddress"
    conv = sources.convert(stream, raw, m)
    assert conv.ok and list(conv.df["user"]) == ["alice", "alice"]      # bad timestamp row dropped
    assert list(conv.df["result"]) == ["success", "failure"]
    assert conv.warnings                                                # the dropped row is reported
    missing = sources.convert("auth", raw, {**m, "user": None})
    assert not missing.ok and "user" in missing.errors[0]


def test_pipeline_runs_with_partial_streams(small_run, tmp_path):
    import shutil
    from ueba.pipeline import run
    _, tmp = small_run
    (tmp_path / "raw").mkdir()
    shutil.copy(tmp / "raw" / "auth.csv", tmp_path / "raw" / "auth.csv")   # authentication logs only
    res = run(tmp_path / "raw", tmp_path / "p.db", copy.deepcopy(CONFIG), reports_dir=None)
    assert len(res["scores"]) and res["scores"]["daily_risk"].between(0, 100).all()


def test_workspace_upload_learning_then_monitoring(small_run, tmp_path, monkeypatch):
    from ueba import sources, workspace
    _, tmp = small_run
    monkeypatch.setattr(workspace, "WS_ROOT", tmp_path / "ws")
    ws = workspace.create("Lab logs", learning_days=30)
    auth = pd.read_csv(tmp / "raw" / "auth.csv")
    t = pd.to_datetime(auth["timestamp"])
    first20 = auth[t < t.min().normalize() + pd.Timedelta(days=20)]
    for part in (first20, auth):                       # second upload overlaps the first: no duplicates
        m = sources.guess_mapping("auth", list(part.columns))
        ws.add("auth", sources.convert("auth", part, m).df, "auth.csv", m, "sig")
        if part is first20:
            assert ws.status()["state"] == "needs_analysis"
            ws.set_learning_days(30)
            ws.analyse()
            assert ws.status()["state"] == "learning"
    assert ws.streams()["auth"]["rows"] == len(auth)
    ws.analyse()
    assert ws.status()["state"] == "monitoring"
    assert workspace.get(ws.slug).meta["mappings"]["sig"]["stream"] == "auth"
    workspace.delete(ws.slug)
    assert [w.slug for w in workspace.list_all()] == ["demo"]


def test_cert_labels_only_this_release(tmp_path):
    """Answer files of other CERT releases (which re-use user ids) must not label anyone."""
    from cert_sample import write_cert_sample
    from ueba.cert_loader import convert_cert
    root = write_cert_sample(tmp_path)
    users = pd.read_csv(root / "logon.csv")["user"].unique()
    insider = pd.read_csv(root / "answers" / "insiders.csv")["user"][0]
    bystander = next(u for u in users if u != insider)
    for rel, who in (("r4.1-1", bystander), ("r4.2-1", insider)):
        (root / "answers" / rel).mkdir()
        (root / "answers" / rel / f"{rel}-{who}.csv").write_text(
            f"logon,{{X1}},03/01/2010 02:00:00,{who},PC-1,Logon\n")
    convert_cert(root, tmp_path / "conv", max_users=12)
    gt = pd.read_csv(tmp_path / "conv" / "ground_truth.csv")
    assert set(gt["entity"]) == {insider.lower()} and set(gt["date"]) == {"2010-03-01"}
