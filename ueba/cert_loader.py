"""Adapter for the CMU CERT Insider Threat Test Dataset (r4.2 / r5.2 / r6.2).

Download (free, ~10-15 GB unzipped) from Carnegie Mellon's KiltHub:
    https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247

Expected folder layout (r4.2 shown)::

    r4.2/
      logon.csv   device.csv   file.csv   http.csv   email.csv
      LDAP/2010-01.csv ...
      answers/insiders.csv            (from the separate answers.tar.bz2)
      answers/r4.2-1/*.csv ...        (optional: per-insider malicious events)

The CERT streams are mapped onto this project's four log streams:

    logon.csv  -> auth      (Logon = successful interactive login on a PC)
    device.csv -> access    (USB connect  = "usb_connect", confidential)
    file.csv   -> access    (file copied to removable media = "copy_to_usb")
    http.csv   -> network   (domain from URL, port 80/443)
    email.csv  -> network   (recipient domain, bytes = email size, port 25)
    (no resource stream in CERT - the resource features stay at zero)

``http.csv`` is very large, so files are streamed in chunks and filtered to a
subset of users (all insiders + a random sample of normal users).
"""
from __future__ import annotations

import json
import zlib
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd

CHUNK = 500_000
DATE_FMT = "%m/%d/%Y %H:%M:%S"


def _read_filtered(path: Path, users: set | None, usecols: list) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=usecols)
    out = []
    for chunk in pd.read_csv(path, usecols=lambda c: c in usecols, chunksize=CHUNK, dtype=str):
        chunk["user"] = chunk["user"].str.lower()
        if users is not None:
            chunk = chunk[chunk["user"].isin(users)]
        out.append(chunk)
    df = pd.concat(out, ignore_index=True) if out else pd.DataFrame(columns=usecols)
    df["timestamp"] = pd.to_datetime(df["date"], format=DATE_FMT, errors="coerce")
    return df.dropna(subset=["timestamp"])


def _ip(pc: str) -> str:
    h = zlib.crc32(str(pc).encode())
    return f"10.{(h >> 16) & 255}.{(h >> 8) & 255}.{h & 255}"


def load_insiders(root: Path, dataset: str) -> pd.DataFrame:
    ans = root / "answers" / "insiders.csv"
    if not ans.exists():
        return pd.DataFrame(columns=["dataset", "scenario", "user", "start", "end"])
    ins = pd.read_csv(ans, dtype=str)
    ins.columns = [c.strip().lower() for c in ins.columns]
    if dataset:
        ins = ins[ins["dataset"].astype(str).str.strip() == dataset.replace("r", "")]
    ins["user"] = ins["user"].str.lower()
    ins["start"] = pd.to_datetime(ins["start"], errors="coerce")
    ins["end"] = pd.to_datetime(ins["end"], errors="coerce")
    return ins


def _malicious_days(root: Path, ins: pd.DataFrame) -> pd.DataFrame:
    """Dates with malicious events, from answers/<dataset>-<scenario>/*.csv when present."""
    rows = []
    for f in (root / "answers").glob("r*-*/*.csv"):
        for line in f.read_text(errors="ignore").splitlines():
            parts = [p.strip().strip('"') for p in line.split(",")]
            if len(parts) < 4:
                continue
            ts = pd.to_datetime(parts[2], format=DATE_FMT, errors="coerce")
            if pd.notna(ts):
                rows.append((parts[3].lower(), ts.date().isoformat(), f.parent.name))
    if rows:
        return pd.DataFrame(rows, columns=["user", "date", "scenario"]).drop_duplicates()
    return pd.DataFrame(columns=["user", "date", "scenario"])


def convert_cert(root: Path, out_dir: Path, max_users: int = 150, seed: int = 7,
                 dataset: str | None = None) -> dict:
    root, out_dir = Path(root), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dataset = dataset or root.name  # e.g. "r4.2"
    ins = load_insiders(root, dataset)

    # ---- choose users: every insider + random normal users ----
    logon_users = pd.read_csv(root / "logon.csv", usecols=["user"], dtype=str)["user"].str.lower().unique()
    insiders = set(ins["user"]) & set(logon_users)
    rng = np.random.default_rng(seed)
    others = sorted(set(logon_users) - insiders)
    n_other = max(0, min(len(others), max_users - len(insiders)))
    users = insiders | set(rng.choice(others, n_other, replace=False).tolist() if n_other else [])

    logon = _read_filtered(root / "logon.csv", users, ["date", "user", "pc", "activity"])
    device = _read_filtered(root / "device.csv", users, ["date", "user", "pc", "activity"])
    files = _read_filtered(root / "file.csv", users, ["date", "user", "pc", "filename"])
    http = _read_filtered(root / "http.csv", users, ["date", "user", "pc", "url"])
    email = _read_filtered(root / "email.csv", users, ["date", "user", "pc", "to", "size", "attachments"])

    # ---- auth ----
    lg = logon[logon["activity"].str.lower() == "logon"]
    auth = pd.DataFrame({
        "timestamp": lg["timestamp"], "user": lg["user"], "src_device": lg["pc"], "src_ip": lg["pc"].map(_ip),
        "dest_host": lg["pc"], "auth_type": "interactive", "result": "success", "city": "unknown",
        "country": "unknown", "lat": np.nan, "lon": np.nan})

    # ---- access ----
    dv = device[device["activity"].str.lower() == "connect"]
    acc = pd.concat([
        pd.DataFrame({"timestamp": dv["timestamp"], "user": dv["user"], "device": dv["pc"],
                      "resource": "removable_media", "action": "usb_connect", "sensitivity": "confidential",
                      "status": "success"}),
        pd.DataFrame({"timestamp": files["timestamp"], "user": files["user"], "device": files["pc"],
                      "resource": files["filename"], "action": "copy_to_usb", "sensitivity": "confidential",
                      "status": "success"}),
    ], ignore_index=True)

    # ---- network ----
    dom = http["url"].map(lambda u: urlparse(u if "//" in str(u) else f"http://{u}").netloc.lower())
    net_http = pd.DataFrame({
        "timestamp": http["timestamp"], "user": http["user"], "device": http["pc"],
        "src_ip": http["pc"].map(_ip), "dst_ip": dom.map(lambda d: _ip(d).replace("10.", "142.", 1)),
        "dst_port": 80, "protocol": "tcp", "bytes_out": 2_000, "bytes_in": 50_000, "domain": dom})
    to_dom = email["to"].fillna("").str.split(";").str[0].str.split("@").str[-1].str.lower()
    net_mail = pd.DataFrame({
        "timestamp": email["timestamp"], "user": email["user"], "device": email["pc"],
        "src_ip": email["pc"].map(_ip), "dst_ip": to_dom.map(lambda d: _ip(d).replace("10.", "142.", 1)),
        "dst_port": 25, "protocol": "smtp",
        "bytes_out": pd.to_numeric(email["size"], errors="coerce").fillna(0).astype(int),
        "bytes_in": 0, "domain": to_dom})
    network = pd.concat([net_http, net_mail], ignore_index=True)

    resource = pd.DataFrame(columns=["timestamp", "device", "user", "cpu_pct", "mem_pct", "disk_io_mb",
                                     "process_count"])

    # ---- directory ----
    ldap_files = sorted((root / "LDAP").glob("*.csv"))
    if ldap_files:
        ldap = pd.read_csv(ldap_files[-1], dtype=str)
        ldap.columns = [c.lower() for c in ldap.columns]
        ldap["user"] = ldap["user_id"].str.lower()
        ldap = ldap[ldap["user"].isin(users)]
        dept_col = "functional_unit" if "functional_unit" in ldap else "department"
        users_df = pd.DataFrame({
            "user": ldap["user"], "full_name": ldap.get("employee_name", ldap["user"]),
            "department": ldap[dept_col].fillna("unknown"),
            "is_admin": ldap.get("role", pd.Series("", index=ldap.index)).str.contains("ITAdmin", na=False),
            "device": "", "home_city": "", "remote": False})
    else:
        users_df = pd.DataFrame({"user": sorted(users), "full_name": sorted(users), "department": "unknown",
                                 "is_admin": False, "device": "", "home_city": "", "remote": False})
    main_pc = lg.groupby("user")["pc"].agg(lambda s: s.value_counts().index[0])
    users_df["device"] = users_df["user"].map(main_pc).fillna("")
    pcs = sorted(set(lg["pc"]))
    owner = lg.groupby("pc")["user"].agg(lambda s: s.value_counts().index[0])
    dept = users_df.set_index("user")["department"]
    devices_df = pd.DataFrame({"device": pcs, "device_type": "laptop",
                               "owner": [owner.get(p, "") for p in pcs],
                               "department": [dept.get(owner.get(p, ""), "unknown") for p in pcs]})

    # ---- ground truth ----
    mal = _malicious_days(root, ins)
    if mal.empty and len(ins):  # fall back to whole insider windows (active days only)
        act = auth.assign(date=auth["timestamp"].dt.date.astype(str))[["user", "date"]].drop_duplicates()
        rows = []
        for _, r in ins.iterrows():
            a = act[(act["user"] == r["user"]) & (act["date"] >= str(r["start"].date()))
                    & (act["date"] <= str(r["end"].date()))]
            rows += [(r["user"], d, f"scenario_{r['scenario']}") for d in a["date"]]
        mal = pd.DataFrame(rows, columns=["user", "date", "scenario"])
    gt = pd.DataFrame({
        "incident_id": "CERT-" + mal["user"].str.upper(), "scenario": mal["scenario"], "entity": mal["user"],
        "entity_type": "user", "date": mal["date"], "mitre": "Insider threat (CERT)",
        "description": "CERT ground-truth malicious activity"})

    for name, df in {"auth": auth, "access": acc, "network": network, "resource": resource,
                     "users": users_df, "devices": devices_df, "ground_truth": gt}.items():
        if "timestamp" in df.columns and len(df):
            df = df.sort_values("timestamp")
            df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        df.to_csv(out_dir / f"{name}.csv", index=False)

    first = auth["timestamp"].min().normalize()
    earliest = pd.to_datetime(gt["date"]).min() if len(gt) else first + pd.Timedelta(days=180)
    train_end = min(first + pd.Timedelta(days=150), earliest - pd.Timedelta(days=1))
    info = {"users": len(users), "insiders": len(insiders), "auth": len(auth), "access": len(acc),
            "network": len(network), "attack_user_days": len(gt),
            "train_start": (first + pd.Timedelta(days=14)).date().isoformat(),
            "train_end": train_end.date().isoformat()}
    (out_dir / "conversion_info.json").write_text(json.dumps(info, indent=2))
    return info
