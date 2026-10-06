"""Collector service - the part of the system that runs continuously.

    python -m ueba.service                 # watch every workspace's inbox, score, notify
    python -m ueba.service --api           # ... and serve the ingest API on 127.0.0.1:8600
    python -m ueba.service --once          # one pass, then exit (cron-friendly)

Every ``--interval`` seconds, for each workspace with automatic collection on:

1. import settled files from ``inbox/`` (uploaded by the API, an agent, rsync, a SIEM export job ...)
2. if anything changed, run an *incremental* analysis (saved models, only new days scored;
   a full re-train only when needed)
3. send notifications for new / escalated alerts

A heartbeat is written to ``data/service.json`` so the dashboard can show whether the
service is alive and what it last did.
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
from datetime import datetime

from . import notify, pipeline
from . import workspace as W
from .config import DATA_DIR

HEARTBEAT = DATA_DIR / "service.json"


def _log(msg: str):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def process_workspace(ws: W.Workspace) -> dict:
    out = dict(imported=0, failed=0)
    for r in ws.process_inbox():
        if r["ok"]:
            out["imported"] += 1
            _log(f"{ws.name}: imported {r['file']} -> " +
                 ", ".join(f"{i['stream']} +{i['added']}" for i in r["imported"]))
        else:
            out["failed"] += 1
            _log(f"{ws.name}: REJECTED {r['file']} - {r['error']}")
    ws.reload()
    if not ws.meta.get("dirty"):
        return out
    t = time.time()
    try:
        res = ws.update()
    except (ValueError, FileNotFoundError) as e:
        # e.g. not enough history yet - don't retry until new data arrives
        with ws.mutate() as meta:
            meta["dirty"], meta["last_error"] = False, str(e)
        out["error"] = str(e)
        _log(f"{ws.name}: analysis skipped - {e}")
        return out
    with ws.mutate() as meta:
        meta.pop("last_error", None)
    sent = notify.notify_workspace(ws, res["alerts"])
    out.update(mode=res.get("mode"), alerts=len(res["alerts"]), seconds=round(time.time() - t, 1),
               notified=sum(1 for s in sent if s["status"] == "sent"),
               notify_failed=sum(1 for s in sent if s["status"] != "sent"))
    _log(f"{ws.name}: {out['mode']} analysis in {out['seconds']}s - {out['alerts']} alerts"
         + (f", {out['notified']} notification(s) sent" if sent else ""))
    return out


def tick() -> dict:
    results = {}
    for ws in W.list_all():
        if ws.is_demo or not ws.setting("auto_ingest"):
            continue
        try:
            results[ws.slug] = process_workspace(ws)
        except Exception as e:  # noqa: BLE001 - one broken workspace must not stop the service
            results[ws.slug] = dict(error=f"{type(e).__name__}: {e}")
            _log(f"{ws.name}: ERROR {type(e).__name__}: {e}")
    return results


def write_heartbeat(state: dict):
    HEARTBEAT.parent.mkdir(parents=True, exist_ok=True)
    tmp = HEARTBEAT.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, default=str))
    tmp.replace(HEARTBEAT)


def read_heartbeat() -> dict | None:
    """Heartbeat plus ``alive`` (seen within 3 intervals)."""
    try:
        hb = json.loads(HEARTBEAT.read_text())
    except (OSError, ValueError):
        return None
    age = (datetime.now() - datetime.fromisoformat(hb["last_tick"])).total_seconds()
    hb["alive"] = age < 3 * hb.get("interval", 10) + 30
    hb["age_seconds"] = round(age)
    return hb


def main(argv=None):
    ap = argparse.ArgumentParser(description="UEBA collector service")
    ap.add_argument("--interval", type=float, default=10, help="seconds between passes (default 10)")
    ap.add_argument("--api", action="store_true", help="also serve the ingest API")
    ap.add_argument("--host", default="127.0.0.1", help="API bind address (default 127.0.0.1 = this machine only)")
    ap.add_argument("--port", type=int, default=8600)
    ap.add_argument("--once", action="store_true", help="run a single pass and exit")
    ap.add_argument("--verbose", action="store_true", help="show the pipeline's step-by-step log")
    args = ap.parse_args(argv)
    pipeline.QUIET = not args.verbose

    api_url = None
    if args.api:
        from .api import make_server
        srv = make_server(args.host, args.port)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        api_url = f"http://{args.host}:{args.port}/api/v1"
        _log(f"Ingest API listening on {api_url}")
    state = dict(pid=os.getpid(), started=datetime.now().isoformat(timespec="seconds"),
                 interval=args.interval, api=api_url, last=dict())
    _log(f"Collector service started - checking every {args.interval:g}s (Ctrl+C to stop)")
    try:
        while True:
            res = tick()
            state["last_tick"] = datetime.now().isoformat(timespec="seconds")
            for slug, r in res.items():
                if r.get("imported") or r.get("mode") or r.get("error"):
                    state["last"][slug] = dict(r, at=state["last_tick"])
            write_heartbeat(state)
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        _log("Stopped")


if __name__ == "__main__":
    main()
