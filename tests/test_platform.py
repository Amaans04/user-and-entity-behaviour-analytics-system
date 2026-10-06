"""Tests for the platform layer: incremental engine, inbox, ingest API, security,
notifications and the collector service."""
import copy
import json
import shutil
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pandas as pd
import pytest

from ueba.config import CONFIG


def _cut(raw, dst, before: str):
    """Copy a log folder keeping only events before ``before``."""
    dst.mkdir(parents=True, exist_ok=True)
    for f in raw.glob("*.csv"):
        df = pd.read_csv(f)
        if "timestamp" in df:
            df = df[df["timestamp"] < before]
        df.to_csv(dst / f.name, index=False)
    return dst


# ---------------------------------------------------------------- incremental engine
@pytest.mark.parametrize("cut", ["2026-08-12 00:00:00", "2026-08-20 14:30:00"])   # day boundary / mid-day
def test_incremental_update_equals_full_run(small_raw, tmp_path, cut):
    from ueba.pipeline import run
    cfg = copy.deepcopy(CONFIG)
    full = run(small_raw, tmp_path / "full.db", cfg, reports_dir=None)
    run(_cut(small_raw, tmp_path / "part", cut), tmp_path / "inc.db", cfg, reports_dir=None)
    inc = run(small_raw, tmp_path / "inc.db", cfg, reports_dir=None, mode="update")
    assert inc["mode"] == "update"
    cols = ["entity", "date", "stat", "peer", "ml", "rule", "daily_risk", "entity_risk", "reasons"]
    a = full["scores"][cols].sort_values(["entity", "date"]).reset_index(drop=True)
    b = inc["scores"][cols].sort_values(["entity", "date"]).reset_index(drop=True)
    pd.testing.assert_frame_equal(a, b)
    pd.testing.assert_frame_equal(full["alerts"], inc["alerts"])


def test_update_retrains_when_it_must(small_raw, tmp_path):
    from ueba.pipeline import run
    cfg = copy.deepcopy(CONFIG)
    learning_only = _cut(small_raw, tmp_path / "learn", "2026-07-20")
    assert run(learning_only, tmp_path / "a.db", cfg, reports_dir=None)["mode"] == "full"
    # models trained before the learning period was complete must not be reused
    assert run(small_raw, tmp_path / "a.db", cfg, reports_dir=None, mode="update")["mode"] == "full"
    assert run(small_raw, tmp_path / "a.db", cfg, reports_dir=None, mode="update")["mode"] == "update"
    cfg.z_alert = 3.5                                  # settings changed -> retrain
    assert run(small_raw, tmp_path / "a.db", cfg, reports_dir=None, mode="update")["mode"] == "full"


# ---------------------------------------------------------------- inbox
def test_inbox_imports_good_files_and_explains_bad_ones(small_raw, isolated):
    from ueba import workspace
    ws = workspace.create("Inbox test")
    shutil.copy(small_raw / "auth.csv", ws.inbox / "auth__export.csv")
    (ws.inbox / "garbage.csv").write_text("colour,shape\nred,round\n")
    (ws.inbox / "half-written.csv.part").write_text("x")
    import os
    import time
    for p in ws.inbox.iterdir():
        os.utime(p, (time.time() - 10, time.time() - 10))     # settled
    res = {r["file"]: r for r in ws.process_inbox()}
    assert res["auth__export.csv"]["ok"] and not res["garbage.csv"]["ok"]
    assert "half-written.csv.part" not in res                       # in-progress files are left alone
    assert (ws.inbox / "processed" / "auth__export.csv").exists()
    assert "Map the required" in (ws.inbox / "failed" / "garbage.csv.error.txt").read_text()
    ws.reload()
    assert ws.meta["dirty"] and ws.meta["pending_from"] == "2026-07-01"


# ---------------------------------------------------------------- security
def test_passwords_roles_lockout_and_tokens(isolated):
    from ueba import auth
    auth.create_user("boss", "long-password", "admin")
    auth.create_user("ana", "analyst-pass", "analyst")
    assert auth.authenticate("BOSS", "long-password")["role"] == "admin"
    with pytest.raises(ValueError, match="Wrong"):
        auth.authenticate("boss", "nope")
    with pytest.raises(ValueError):
        auth.create_user("x", "short")
    for _ in range(auth.MAX_FAILS):
        with pytest.raises(ValueError):
            auth.authenticate("ana", "bad-password")
    with pytest.raises(ValueError, match="locked"):
        auth.authenticate("ana", "analyst-pass")              # correct password, still locked
    assert auth.can({"role": "analyst"}, "triage") and not auth.can({"role": "analyst"}, "manage")
    assert not auth.can({"role": "viewer"}, "triage") and not auth.can(None, "view")
    with pytest.raises(ValueError, match="last admin"):
        auth.set_role("boss", "viewer", by="boss")
    secret = auth.create_token("agent", "lab", by="boss")
    assert auth.verify_token(secret, "lab") and auth.verify_token(secret, "other") is None
    assert auth.verify_token("ueba_guess", "lab") is None
    tid = auth.list_tokens().iloc[0]["token_id"]
    auth.revoke_token(tid, by="boss")
    assert auth.verify_token(secret, "lab") is None
    stored = str(auth.list_tokens().to_dict()) + str(auth.list_users().to_dict())
    assert secret not in stored and "long-password" not in stored
    assert {"login", "login.failed", "token.create", "token.revoke"} <= set(auth.audit_log()["action"])


def test_ingest_api(isolated):
    from ueba import auth, workspace
    from ueba.api import make_server
    ws = workspace.create("Lab")
    good = auth.create_token("t", ws.slug, by="test")
    other = auth.create_token("t2", "elsewhere", by="test")
    srv = make_server("127.0.0.1", 0, console_db=isolated / "console.db")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/api/v1"

    def call(path, token="", data=None):
        req = urllib.request.Request(base + path, data=data, method="POST" if data else "GET",
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "text/csv"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())
    try:
        assert call("/health")[0] == 200
        assert call(f"/workspaces/{ws.slug}/status")[0] == 401
        assert call(f"/workspaces/{ws.slug}/status", other)[0] == 401
        assert call(f"/workspaces/{ws.slug}/status", good)[1]["state"] == "empty"
        assert call(f"/workspaces/{ws.slug}/ingest/bogus", good, b"a\n1\n")[0] == 400
        assert call("/workspaces/demo/status", good)[0] == 403
        code, body = call(f"/workspaces/{ws.slug}/ingest/auth", good,
                          b"timestamp,user,result\n2026-07-01 09:00:00,alice,success\n")
        assert code == 202 and body["rows"] == 1
        assert (ws.inbox / body["queued"]).read_text().startswith("timestamp")
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- notifications
class _Hook(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        _Hook.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def webhook():
    _Hook.received = []
    srv = HTTPServer(("127.0.0.1", 0), _Hook)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/hook", _Hook.received
    srv.shutdown()


def _alert(**kw):
    a = dict(alert_id="AL-1", date="2026-08-20", entity="eve", entity_type="user", department="Finance",
             alert_type="anomalous_day", title="Impossible travel", severity="high", risk_score=70.0,
             reasons=json.dumps(["far apart"]), mitre=json.dumps(["T1078"]), status="open")
    a.update(kw)
    return pd.DataFrame([a])


def test_notifications_dedupe_escalate_and_skip_backfill(tmp_path, webhook):
    from ueba import notify
    url, got = webhook
    db = tmp_path / "n.db"
    todo = notify.due(db, _alert(), "high", "2026-08-20")
    assert notify.send(db, "Lab", todo, url)[0]["status"] == "sent" and len(got) == 1
    assert "Impossible travel" in got[0]["text"] and got[0]["alert"]["entity"] == "eve"
    assert notify.due(db, _alert(), "high", "2026-08-20").empty                      # already sent
    assert len(notify.due(db, _alert(severity="critical"), "high", "2026-08-20")) == 1  # escalated
    assert notify.due(db, _alert(severity="medium", entity="bob"), "high", "2026-08-20").empty
    assert notify.due(db, _alert(entity="old", date="2026-07-01"), "high", "2026-08-20").empty   # back-fill
    assert notify.due(db, _alert(entity="closed", status="closed - benign"), "high", "2026-08-20").empty
    res = notify.send(db, "Lab", _alert(entity="x"), "http://127.0.0.1:1/unreachable")
    assert res[0]["status"] == "failed" and "failed" in set(notify.history(db)["status"])


# ---------------------------------------------------------------- collector service
def test_service_tick_learns_then_detects_and_notifies(small_raw, isolated, webhook):
    import os
    import time
    from ueba import service, workspace
    url, got = webhook
    ws = workspace.create("Live", learning_days=30)
    ws.update_settings(notify_webhook=url, notify_min_severity="high")
    for f in small_raw.glob("*.csv"):
        df = pd.read_csv(f)
        if "timestamp" in df:
            df = df[df["timestamp"] < "2026-07-31"]          # the learning period only
        df.to_csv(ws.inbox / f"{f.stem}__history.csv", index=False)
    for p in ws.inbox.iterdir():
        os.utime(p, (time.time() - 10, time.time() - 10))
    r = service.tick()[ws.slug]
    assert r["imported"] == len(list(small_raw.glob("*.csv"))) and r["alerts"] == 0
    assert workspace.get(ws.slug).status()["state"] == "learning" and not got

    for f in small_raw.glob("*.csv"):                         # the rest arrives later
        df = pd.read_csv(f)
        if "timestamp" in df:
            df[df["timestamp"] >= "2026-07-31"].to_csv(ws.inbox / f"{f.stem}__live.csv", index=False)
    for p in ws.inbox.glob("*__live.csv"):
        os.utime(p, (time.time() - 10, time.time() - 10))
    r = service.tick()[ws.slug]
    assert workspace.get(ws.slug).status()["state"] == "monitoring"
    assert r["alerts"] > 0 and r["notified"] > 0 and len(got) == r["notified"]
    service.write_heartbeat(dict(pid=1, interval=10, last_tick=pd.Timestamp.now().isoformat(), last={}))
    assert service.read_heartbeat()["alive"]
