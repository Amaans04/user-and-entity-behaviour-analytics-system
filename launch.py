"""Start the whole system with one command: collector service (+ ingest API) and the dashboard.

    python launch.py                     # dashboard on http://localhost:8501, API on 127.0.0.1:8600
    python launch.py --port 8502 --api-port 8601
    python launch.py --no-api            # inbox watcher only, no HTTP ingest

Ctrl+C stops both. Both listen on this machine only; to expose them on a network put
them behind a reverse proxy with TLS (see README, "Deployment").
"""
from __future__ import annotations

import argparse
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser(description="Start the UEBA collector service and dashboard")
    ap.add_argument("--port", type=int, default=8501, help="dashboard port")
    ap.add_argument("--api-port", type=int, default=8600, help="ingest API port")
    ap.add_argument("--no-api", action="store_true", help="don't serve the ingest API")
    ap.add_argument("--interval", type=float, default=10, help="service pass interval in seconds")
    args = ap.parse_args()

    svc_cmd = [sys.executable, "-m", "ueba.service", "--interval", str(args.interval)]
    if not args.no_api:
        svc_cmd += ["--api", "--port", str(args.api_port)]
    ui_cmd = [sys.executable, "-m", "streamlit", "run", str(ROOT / "dashboard" / "app.py"),
              "--server.port", str(args.port), "--server.headless", "true"]
    procs = [subprocess.Popen(svc_cmd, cwd=ROOT), subprocess.Popen(ui_cmd, cwd=ROOT)]
    print(f"\n  UEBA console:  http://localhost:{args.port}"
          + ("" if args.no_api else f"\n  Ingest API:    http://127.0.0.1:{args.api_port}/api/v1")
          + "\n  Ctrl+C to stop\n", flush=True)
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(1)
        print("A component exited - stopping the other one.", flush=True)
    except KeyboardInterrupt:
        pass
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
    for p in procs:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


if __name__ == "__main__":
    main()
