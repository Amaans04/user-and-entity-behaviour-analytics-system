"""Writes a tiny dataset in the exact CMU CERT r4.2 file format.

Used only to test ``ueba.cert_loader`` without the multi-GB real dataset.
The planted insider follows CERT scenario 1 (after-hours logins, USB use,
uploads to a leak site).
"""
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

FMT = "%m/%d/%Y %H:%M:%S"


def write_cert_sample(root: Path, n_users: int = 20, n_days: int = 120, seed: int = 3) -> Path:
    root = Path(root) / "r4.2"
    (root / "LDAP").mkdir(parents=True, exist_ok=True)
    (root / "answers").mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    start = datetime(2010, 1, 4)
    users = [f"ABC{i:04d}" for i in range(n_users)]
    pcs = {u: f"PC-{1000 + i}" for i, u in enumerate(users)}
    insider = users[3]
    logon, device, file_, http, email = [], [], [], [], []
    k = 0
    sites = ["google.com", "msn.com", "yahoo.com", "cnn.com", "bbc.co.uk", "wikipedia.org", "espn.com"]
    for d in range(n_days):
        day = start + timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for u in users:
            t = day + timedelta(hours=float(rng.normal(8.5, 0.5)))
            e = t + timedelta(hours=float(rng.normal(8.5, 0.5)))
            k += 1; logon.append((f"{{L{k}}}", t.strftime(FMT), u, pcs[u], "Logon"))
            k += 1; logon.append((f"{{L{k}}}", e.strftime(FMT), u, pcs[u], "Logoff"))
            for _ in range(rng.poisson(15)):
                ts = t + (e - t) * float(rng.random())
                k += 1; http.append((f"{{H{k}}}", ts.strftime(FMT), u, pcs[u],
                                     f"http://{sites[rng.integers(len(sites))]}/page{rng.integers(99)}"))
            for _ in range(rng.poisson(3)):
                ts = t + (e - t) * float(rng.random())
                k += 1; email.append((f"{{E{k}}}", ts.strftime(FMT), u, pcs[u], "a@dtaa.com", "", "",
                                      f"{u}@dtaa.com", int(rng.integers(20_000, 60_000)), 0))
        if d >= 100 and d <= 105:  # insider: after hours, USB, leak site
            t = day + timedelta(hours=23, minutes=10)
            k += 1; logon.append((f"{{L{k}}}", t.strftime(FMT), insider, pcs[insider], "Logon"))
            k += 1; device.append((f"{{D{k}}}", (t + timedelta(minutes=2)).strftime(FMT), insider,
                                   pcs[insider], "Connect"))
            for j in range(8):
                k += 1; file_.append((f"{{F{k}}}", (t + timedelta(minutes=3 + j)).strftime(FMT), insider,
                                      pcs[insider], f"R:\\secret\\doc{j}.docx"))
            k += 1; http.append((f"{{H{k}}}", (t + timedelta(minutes=20)).strftime(FMT), insider,
                                 pcs[insider], "http://wikileaks.org/upload"))
    cols = ["id", "date", "user", "pc"]
    pd.DataFrame(logon, columns=cols + ["activity"]).to_csv(root / "logon.csv", index=False)
    pd.DataFrame(device, columns=cols + ["activity"]).to_csv(root / "device.csv", index=False)
    pd.DataFrame(file_, columns=cols + ["filename"]).to_csv(root / "file.csv", index=False)
    pd.DataFrame(http, columns=cols + ["url"]).to_csv(root / "http.csv", index=False)
    pd.DataFrame(email, columns=cols + ["to", "cc", "bcc", "from", "size", "attachments"]).to_csv(
        root / "email.csv", index=False)
    pd.DataFrame({"employee_name": users, "user_id": users, "email": [f"{u}@dtaa.com" for u in users],
                  "role": ["ITAdmin" if i == 0 else "Salesman" for i in range(n_users)],
                  "business_unit": 1, "functional_unit": ["Sales" if i % 2 else "Research" for i in range(n_users)],
                  "department": "Dept", "team": "T", "supervisor": "Boss"}).to_csv(root / "LDAP" / "2010-05.csv",
                                                                                   index=False)
    s = (start + timedelta(days=100)).strftime(FMT)
    e = (start + timedelta(days=105, hours=23)).strftime(FMT)
    pd.DataFrame([dict(dataset="4.2", scenario=1, details="r4.2-1-ABC0003.csv", user=insider, start=s, end=e)]
                 ).to_csv(root / "answers" / "insiders.csv", index=False)
    return root
