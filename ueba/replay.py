"""Replay a log dataset as a live feed - watch the system catch attacks as they happen.

    python -m ueba.replay --workspace "Live demo"                       # local: writes to the inbox
    python -m ueba.replay --workspace live-demo --url http://127.0.0.1:8600 --token ueba_...   # via the API

1. The learning period (first ``--learning-days`` days) is sent in one batch, together
   with the user directory and asset inventory - like connecting a SIEM with 30 days
   of history.
2. Every following day is then streamed in ``--chunks`` slices (default 4 x 6 h),
   one day every ``--seconds-per-day`` seconds.

With the collector service running (``python -m ueba.service``) each slice is imported,
scored incrementally and - when an attack starts - alerted on and notified within one
service interval, while the dashboard refreshes live.

``--labels`` also streams each day's ground-truth incidents so the Model performance
page fills in as the replay progresses (an answer key - real deployments have none).
"""
from __future__ import annotations

import argparse
import io
import time
from pathlib import Path

import pandas as pd

from . import workspace as W
from .config import DATA_DIR
from .sources import LOG_STREAMS


def _sink(args):
    """Return a function(stream, df) that delivers a batch, via the API or straight into the inbox."""
    if args.url:
        from .agent import post

        def send(stream, df):
            if len(df):
                post(args.url, args.workspace, args.token, stream, df.to_dict("records"), timeout=120)
        return send, args.workspace

    try:
        ws = W.find(args.workspace)
    except KeyError:
        ws = W.create(args.workspace, learning_days=args.learning_days)
        print(f"Created workspace '{ws.name}' (id {ws.slug})")
    if ws.is_demo:
        raise SystemExit("Pick another workspace - the demo workspace is read-only")

    def send(stream, df):
        if len(df):
            ws.inbox.mkdir(parents=True, exist_ok=True)
            name = f"{stream}__replay-{time.time_ns()}.csv"
            buf = io.StringIO()
            df.to_csv(buf, index=False)
            (ws.inbox / (name + ".part")).write_text(buf.getvalue())
            (ws.inbox / (name + ".part")).replace(ws.inbox / name)
    return send, ws.slug


def main(argv=None):
    ap = argparse.ArgumentParser(description="Replay logs as a live feed")
    ap.add_argument("--workspace", required=True, help="workspace name or id (created if local and missing)")
    ap.add_argument("--source", type=Path, default=DATA_DIR / "raw", help="folder with auth/access/network/resource csv")
    ap.add_argument("--url", help="ingest API base URL - omit to write straight into the local inbox")
    ap.add_argument("--token", help="API token (with --url)")
    ap.add_argument("--learning-days", type=int, default=30)
    ap.add_argument("--seconds-per-day", type=float, default=20)
    ap.add_argument("--chunks", type=int, default=4, help="slices per day (default 4 = every 6 h)")
    ap.add_argument("--labels", action="store_true", help="also stream ground-truth labels day by day")
    ap.add_argument("--start-day", type=int, default=0, help="skip the bulk phase and resume at this live day")
    args = ap.parse_args(argv)
    if args.url and not args.token:
        ap.error("--token is required with --url")

    send, slug = _sink(args)
    logs = {s: pd.read_csv(args.source / f"{s}.csv") for s in LOG_STREAMS if (args.source / f"{s}.csv").exists()}
    for df in logs.values():
        df["_ts"] = pd.to_datetime(df["timestamp"])
    truth = pd.read_csv(args.source / "ground_truth.csv") if (args.source / "ground_truth.csv").exists() else None
    first = min(df["_ts"].min() for df in logs.values()).normalize()
    last = max(df["_ts"].max() for df in logs.values()).normalize()
    learn_end = first + pd.Timedelta(days=args.learning_days)

    if args.start_day == 0:
        for extra in ("users", "devices"):
            p = args.source / f"{extra}.csv"
            if p.exists():
                send(extra, pd.read_csv(p))
        total = 0
        for s, df in logs.items():
            part = df[df["_ts"] < learn_end].drop(columns="_ts")
            send(s, part)
            total += len(part)
        print(f"Sent the learning period: {first.date()} .. {(learn_end - pd.Timedelta(days=1)).date()} "
              f"({total:,} events). Live replay starts now.", flush=True)

    days = pd.date_range(learn_end + pd.Timedelta(days=args.start_day), last, freq="D")
    step = pd.Timedelta(hours=24 / args.chunks)
    try:
        for n, day in enumerate(days, start=args.start_day + 1):
            sent = 0
            for c in range(args.chunks):
                lo, hi = day + c * step, day + (c + 1) * step
                for s, df in logs.items():
                    part = df[(df["_ts"] >= lo) & (df["_ts"] < hi)].drop(columns="_ts")
                    send(s, part)
                    sent += len(part)
                time.sleep(args.seconds_per_day / args.chunks)
            if args.labels and truth is not None:
                send("ground_truth", truth[truth["date"] == str(day.date())])
            planted = "" if truth is None else ", ".join(truth.loc[truth["date"] == str(day.date()), "incident_id"].unique())
            print(f"Live day {n:>2} ({day.date()}): {sent:,} events" + (f"   <- attack in the data: {planted}" if planted else ""),
                  flush=True)
    except KeyboardInterrupt:
        print(f"Stopped. Resume with --start-day {n - 1}")
        return
    print(f"Replay finished - workspace '{slug}'.")


if __name__ == "__main__":
    main()
