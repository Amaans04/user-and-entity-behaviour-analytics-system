"""Live log collector for the local machine (optional).

Captures real resource-usage and network-connection data from the computer the
dashboard runs on, and writes it in the same schema as the other log streams
(``data/live/resource.csv`` and ``data/live/network.csv``). It demonstrates the
"capture" stage of the UEBA on genuine host telemetry.

Requires ``psutil`` (in requirements.txt). Reading other processes' connections
may need admin rights on macOS; without them only the current user's
connections are listed.
"""
from __future__ import annotations

import getpass
import socket
import time
from datetime import datetime
from pathlib import Path

import pandas as pd

from .config import DATA_DIR

LIVE_DIR = DATA_DIR / "live"


def _psutil():
    try:
        import psutil  # noqa: F401
        return psutil
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("psutil is not installed - run: pip install psutil") from e


def sample(prev_disk=None, prev_net=None):
    ps = _psutil()
    host, user = socket.gethostname(), getpass.getuser().lower()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    disk = ps.disk_io_counters()
    net = ps.net_io_counters()
    disk_mb = ((disk.read_bytes + disk.write_bytes) - prev_disk) / 1e6 if prev_disk and disk else 0.0
    res = dict(timestamp=now, device=host, user=user, cpu_pct=ps.cpu_percent(interval=0.5),
               mem_pct=ps.virtual_memory().percent, disk_io_mb=round(max(disk_mb, 0), 3),
               process_count=len(ps.pids()))
    conns = []
    try:
        for c in ps.net_connections(kind="inet"):
            if c.raddr and c.status == "ESTABLISHED":
                name = ""
                try:
                    name = ps.Process(c.pid).name() if c.pid else ""
                except Exception:
                    pass
                conns.append(dict(timestamp=now, user=user, device=host, src_ip=c.laddr.ip,
                                  dst_ip=c.raddr.ip, dst_port=c.raddr.port, protocol="tcp",
                                  bytes_out=0, bytes_in=0, domain=name or c.raddr.ip))
    except Exception:  # permission denied on some OSes
        pass
    totals = dict(sent=net.bytes_sent, recv=net.bytes_recv)
    if prev_net:
        res["net_sent_mb"] = round((net.bytes_sent - prev_net["sent"]) / 1e6, 3)
        res["net_recv_mb"] = round((net.bytes_recv - prev_net["recv"]) / 1e6, 3)
    return res, conns, (disk.read_bytes + disk.write_bytes) if disk else None, totals


def capture(n: int = 10, interval: float = 1.0, out_dir: Path = LIVE_DIR) -> tuple[pd.DataFrame, pd.DataFrame]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, conns = [], []
    pdisk = pnet = None
    for i in range(n):
        r, c, pdisk, pnet = sample(pdisk, pnet)
        rows.append(r)
        conns += c
        if i < n - 1:
            time.sleep(interval)
    res, net = pd.DataFrame(rows), pd.DataFrame(conns)
    for df, name in ((res, "resource.csv"), (net, "network.csv")):
        if len(df):
            p = out_dir / name
            df.to_csv(p, mode="a", header=not p.exists(), index=False)
    return res, net


if __name__ == "__main__":
    r, n = capture(5)
    print(r.to_string())
    print(n.head(20).to_string())
