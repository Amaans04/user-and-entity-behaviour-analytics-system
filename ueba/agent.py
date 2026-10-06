"""Endpoint agent - streams this machine's telemetry to the ingest API.

    python -m ueba.agent --url http://SERVER:8600 --workspace lab --token ueba_...

Every ``--every`` seconds it samples CPU, memory, disk I/O, process count and the
established network connections (psutil, via ``collector.sample``); every ``--flush``
seconds it sends the batch as the ``resource`` and ``network`` streams.

Store-and-forward: if the server is unreachable the batch is kept (up to
``MAX_BUFFER`` rows per stream) and retried on the next flush, so a network outage
loses no data.

Limitation (by design of the OS APIs): per-connection byte counts are not available
without packet capture, so ``bytes_out`` is 0 on connection rows - upload volumes
should come from proxy / firewall logs. The agent contributes host behaviour
(resource usage, new destinations and ports, mining-pool connections).
"""
from __future__ import annotations

import argparse
import json
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime

import pandas as pd

from .collector import sample

MAX_BUFFER = 50_000


def post(url: str, workspace: str, token: str, stream: str, rows: list[dict], timeout: float = 15) -> dict:
    body = pd.DataFrame(rows).to_csv(index=False).encode()
    req = urllib.request.Request(f"{url.rstrip('/')}/api/v1/workspaces/{workspace}/ingest/{stream}", data=body,
                                 method="POST", headers={"Content-Type": "text/csv",
                                                         "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def main(argv=None):
    ap = argparse.ArgumentParser(description="UEBA endpoint agent")
    ap.add_argument("--url", required=True, help="ingest API base, e.g. http://127.0.0.1:8600")
    ap.add_argument("--workspace", required=True, help="workspace id (shown in Data sources)")
    ap.add_argument("--token", required=True, help="API token (Administration -> API tokens)")
    ap.add_argument("--every", type=float, default=15, help="seconds between samples (default 15)")
    ap.add_argument("--flush", type=float, default=60, help="seconds between uploads (default 60)")
    ap.add_argument("--once", action="store_true", help="take one sample, send it and exit")
    args = ap.parse_args(argv)

    host = socket.gethostname()
    print(f"UEBA agent on {host} -> {args.url} (workspace '{args.workspace}'); Ctrl+C to stop", flush=True)
    buf: dict[str, list] = {"resource": [], "network": []}
    seen: set = set()
    pdisk = pnet = None
    last_flush = time.time()
    try:
        while True:
            res, conns, pdisk, pnet = sample(pdisk, pnet)
            buf["resource"].append({k: v for k, v in res.items() if not k.startswith("net_")})
            for c in conns:   # one row per new destination per flush window, not per sample
                key = (c["dst_ip"], c["dst_port"], c["domain"])
                if key not in seen:
                    seen.add(key)
                    buf["network"].append(c)
            if args.once or time.time() - last_flush >= args.flush:
                for stream in ("resource", "network"):
                    if not buf[stream]:
                        continue
                    try:
                        r = post(args.url, args.workspace, args.token, stream, buf[stream])
                        print(f"[{datetime.now():%H:%M:%S}] sent {len(buf[stream])} {stream} rows -> {r['queued']}",
                              flush=True)
                        buf[stream] = []
                    except urllib.error.HTTPError as e:
                        msg = e.read().decode(errors="replace")[:200]
                        print(f"[{datetime.now():%H:%M:%S}] server refused {stream}: HTTP {e.code} {msg}", flush=True)
                        if e.code in (400, 401, 403, 404):
                            raise SystemExit(1)
                    except (urllib.error.URLError, OSError) as e:
                        buf[stream] = buf[stream][-MAX_BUFFER:]
                        print(f"[{datetime.now():%H:%M:%S}] server unreachable ({e}); keeping "
                              f"{len(buf[stream])} {stream} rows for retry", flush=True)
                seen.clear()
                last_flush = time.time()
                if args.once:
                    break
            time.sleep(max(0.0, args.every - 0.5))       # sample() itself takes ~0.5 s
    except KeyboardInterrupt:
        print("Agent stopped", flush=True)


if __name__ == "__main__":
    main()
