"""Behavioural feature engineering.

Turns raw events into one feature vector per *entity-day*:

* user-day   (who did what today)
* device-day (what happened on / from this machine today)

"Novelty" features (new host, new domain, new country ...) and the
"off-hours" features are computed *causally*: they only compare today with
what that entity did on earlier days, exactly as a live UEBA would.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import CONFIG, Config

CLOUD_STORAGE = ("mega.nz", "dropbox.com", "wetransfer.com", "transfer.sh", "anonfiles.io",
                 "drive.google.com", "mediafire.com", "file.io", "pastebin.com")
JOB_SITES = ("linkedin.com/jobs", "indeed.com", "naukri.com", "monster.com", "glassdoor.com", "careerbuilder.com",
             "simplyhired.com", "ziprecruiter.com", "dice.com")
MINING_PORTS = (3333, 4444, 5555, 7777, 14444, 45700)
ACCOUNT_CMDS = r"New-ADUser|useradd|net user .*/add|net group .*/add|Add-ADGroupMember"
LOG_TAMPER = r"wevtutil cl|Clear-EventLog|rm -rf /var/log|auditctl -D"

USER_FEATURES = [
    # authentication
    "logins", "failed_logins", "max_fail_10min", "fail_then_success", "distinct_src_ips", "new_src_ips",
    "distinct_dest_hosts", "new_dest_hosts", "remote_admin_logins", "unregistered_device_logins",
    "off_hours_logins", "countries", "new_countries", "impossible_travel",
    # system / resource access
    "access_events", "sensitive_access", "restricted_access", "priv_esc", "deletes",
    "distinct_resources", "new_resources", "new_sensitive_resources", "off_hours_access",
    "account_changes", "log_tamper", "removable_media",
    # network
    "connections", "bytes_out_mb", "bytes_in_mb", "max_upload_mb", "distinct_domains", "new_domains",
    "new_domain_upload_mb", "cloud_upload_mb", "new_ports", "mining_conns", "job_site_visits",
    "internal_hosts",
    # resource usage (user's own laptop)
    "cpu_mean", "cpu_max", "cpu_high_hours", "mem_mean", "disk_io_mb", "active_hours",
]
DEVICE_FEATURES = [
    "logins_to_device", "failed_logins_to_device", "distinct_users_on_device", "new_users_on_device",
    "connections", "bytes_out_mb", "max_upload_mb", "new_domains", "new_domain_upload_mb",
    "cloud_upload_mb", "new_ports", "mining_conns",
    "cpu_mean", "cpu_max", "cpu_high_hours", "mem_mean", "disk_io_mb", "proc_max", "active_hours",
]


# --------------------------------------------------------------------------
# generic helpers
# --------------------------------------------------------------------------
def first_seen_flags(df: pd.DataFrame, key: str, item: str) -> pd.Series:
    """True for rows whose (key, item) pair appears for the first time on that row's date."""
    first = df.groupby([key, item])["date"].transform("min")
    return df["date"] == first


def count_new(df: pd.DataFrame, key: str, item: str, name: str) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=[key, "date", name])
    flags = first_seen_flags(df, key, item)
    new = df[flags].groupby([key, "date"])[item].nunique().rename(name)
    return new.reset_index()


def hour_rarity(df: pd.DataFrame, key: str, alpha: float = 0.5, min_history: int = 10) -> pd.Series:
    """Probability of each event's hour under the entity's *previous-days* hour histogram.

    Returns NaN where there is not enough history yet.
    """
    if df.empty:
        return pd.Series(dtype=float)
    hours = df["timestamp"].dt.hour
    daily = (pd.crosstab([df[key], df["date"]], hours)
             .reindex(columns=range(24), fill_value=0).sort_index())
    hist = daily.groupby(level=0).cumsum().groupby(level=0).shift(1).fillna(0)
    totals = hist.sum(axis=1)
    idx = pd.MultiIndex.from_arrays([df[key], df["date"]])
    h = hist.reindex(idx).to_numpy()
    tot = totals.reindex(idx).to_numpy()
    counts = h[np.arange(len(df)), hours.to_numpy()]
    p = (counts + alpha) / (tot + 24 * alpha)
    p[tot < min_history] = np.nan
    return pd.Series(p, index=df.index)


def haversine_km(lat1, lon1, lat2, lon2):
    lat1, lon1, lat2, lon2 = map(np.radians, (lat1, lon1, lat2, lon2))
    a = np.sin((lat2 - lat1) / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * np.arcsin(np.sqrt(a))


def impossible_travel_events(auth: pd.DataFrame, max_kmh: float) -> pd.DataFrame:
    """Consecutive successful logins whose implied speed exceeds ``max_kmh``."""
    ok = auth[(auth["result"] == "success") & auth["lat"].notna()].sort_values(["user", "timestamp"]).copy()
    ok["prev_lat"] = ok.groupby("user")["lat"].shift()
    ok["prev_lon"] = ok.groupby("user")["lon"].shift()
    ok["prev_ts"] = ok.groupby("user")["timestamp"].shift()
    ok["prev_city"] = ok.groupby("user")["city"].shift()
    ok = ok.dropna(subset=["prev_lat"])
    ok["km"] = haversine_km(ok["prev_lat"], ok["prev_lon"], ok["lat"], ok["lon"])
    hrs = (ok["timestamp"] - ok["prev_ts"]).dt.total_seconds() / 3600
    ok["kmh"] = ok["km"] / hrs.clip(lower=1 / 60)
    return ok[(ok["km"] > 500) & (ok["kmh"] > max_kmh)]


def _agg(df, key, spec):
    if df.empty:
        return pd.DataFrame(columns=[key, "date"] + list(spec))
    return df.groupby([key, "date"]).agg(**spec).reset_index()


# --------------------------------------------------------------------------
# user-day features
# --------------------------------------------------------------------------
def user_features(frames: dict, cfg: Config = CONFIG) -> pd.DataFrame:
    auth, acc, net, res = (frames[k] for k in ("auth", "access", "network", "resource"))
    users = frames["users"]
    registered = set(frames["devices"]["device"])
    admins = set(users.loc[users["is_admin"], "user"])

    # ---- authentication ----
    a = auth.copy()
    a["fail"] = (a["result"] != "success").astype(int)
    a["ok"] = 1 - a["fail"]
    a["remote_admin"] = (a["auth_type"].isin(["ssh", "rdp"]) & (a["ok"] == 1)).astype(int)
    a["unreg"] = ((~a["src_device"].isin(registered)) & (a["src_device"] != "unknown") & (a["ok"] == 1)).astype(int)
    p_hour = hour_rarity(a[a["ok"] == 1], "user")
    a["off_hours"] = 0
    a.loc[p_hour.index, "off_hours"] = (p_hour < cfg.off_hours_prob).astype(int)

    # failures within a sliding 10-minute window
    f = a[a["fail"] == 1].set_index("timestamp").sort_index()
    if len(f):
        win = f.groupby("user")["fail"].rolling("10min").sum().reset_index()
        win["date"] = win["timestamp"].dt.date.astype(str)
        maxfail = win.groupby(["user", "date"])["fail"].max().rename("max_fail_10min").reset_index()
    else:
        maxfail = pd.DataFrame(columns=["user", "date", "max_fail_10min"])

    # failure burst followed by a success within 30 min
    a_sorted = a.sort_values(["user", "timestamp"]).reset_index(drop=True)
    recent = (a_sorted.set_index("timestamp").groupby("user")["fail"]
              .rolling("30min").sum().reset_index(drop=True))
    a_sorted["prev_fails"] = recent.to_numpy()   # same (user, timestamp) order as a_sorted
    a_sorted["fts"] = ((a_sorted["ok"] == 1) & (a_sorted["prev_fails"] >= 5)).astype(int)

    au = _agg(a_sorted, "user", dict(
        logins=("ok", "sum"), failed_logins=("fail", "sum"), fail_then_success=("fts", "max"),
        distinct_src_ips=("src_ip", "nunique"), distinct_dest_hosts=("dest_host", "nunique"),
        remote_admin_logins=("remote_admin", "sum"), unregistered_device_logins=("unreg", "sum"),
        off_hours_logins=("off_hours", "sum"), countries=("country", "nunique")))
    okd = a[a["ok"] == 1]
    parts = [au, maxfail,
             count_new(okd, "user", "src_ip", "new_src_ips"),
             count_new(okd, "user", "dest_host", "new_dest_hosts"),
             count_new(okd, "user", "country", "new_countries")]
    it = impossible_travel_events(auth, cfg.max_travel_kmh)
    parts.append(it.groupby(["user", "date"]).size().rename("impossible_travel").reset_index())

    # ---- access ----
    x = acc.copy()
    x["sensitive"] = x["sensitivity"].isin(["confidential", "restricted"]).astype(int)
    x["restricted"] = (x["sensitivity"] == "restricted").astype(int)
    x["pe"] = (x["action"] == "priv_escalation").astype(int)
    x["del"] = (x["action"] == "delete").astype(int)
    x["acct"] = x["resource"].str.contains(ACCOUNT_CMDS, regex=True, na=False).astype(int)
    x["tamper"] = x["resource"].str.contains(LOG_TAMPER, regex=True, na=False).astype(int)
    x["usb"] = x["action"].isin(["usb_connect", "copy_to_usb"]).astype(int)
    p_hour = hour_rarity(x, "user", min_history=50)
    x["off_hours"] = (p_hour < cfg.off_hours_prob).astype(int)
    parts.append(_agg(x, "user", dict(
        access_events=("resource", "size"), sensitive_access=("sensitive", "sum"),
        restricted_access=("restricted", "sum"), priv_esc=("pe", "sum"), deletes=("del", "sum"),
        distinct_resources=("resource", "nunique"), off_hours_access=("off_hours", "sum"),
        account_changes=("acct", "sum"), log_tamper=("tamper", "sum"), removable_media=("usb", "sum"))))
    parts.append(count_new(x, "user", "resource", "new_resources"))
    parts.append(count_new(x[x["sensitive"] == 1], "user", "resource", "new_sensitive_resources"))

    # ---- network ----
    parts += _network_parts(net, "user")

    # ---- resource usage (the user's own laptop samples) ----
    r = res[res["user"] != "system"].copy()
    r["high"] = (r["cpu_pct"] > 85).astype(int)
    parts.append(_agg(r, "user", dict(cpu_mean=("cpu_pct", "mean"), cpu_max=("cpu_pct", "max"),
                                      cpu_high_hours=("high", "sum"), mem_mean=("mem_pct", "mean"),
                                      disk_io_mb=("disk_io_mb", "sum"), active_hours=("cpu_pct", "size"))))

    out = _merge(parts, "user", USER_FEATURES)
    out = out.merge(users[["user", "department", "is_admin"]], on="user", how="left")
    out["department"] = out["department"].fillna("unknown")
    out["is_admin"] = out["user"].isin(admins)
    out.insert(0, "entity_type", "user")
    return out.rename(columns={"user": "entity"})


def _network_parts(net: pd.DataFrame, key: str) -> list:
    n = net.copy()
    n["mb_out"] = n["bytes_out"] / 1e6
    n["mb_in"] = n["bytes_in"] / 1e6
    n["internal"] = n["dst_ip"].astype(str).str.startswith("10.")
    n["cloud"] = n["domain"].astype(str).str.lower().str.contains("|".join(CLOUD_STORAGE), regex=True)
    n["cloud_mb"] = np.where(n["cloud"], n["mb_out"], 0.0)
    n["mining"] = (n["dst_port"].isin(MINING_PORTS) |
                   n["domain"].astype(str).str.contains(r"pool\.|xmr|nicehash|stratum", regex=True)).astype(int)
    n["job"] = n["domain"].astype(str).str.contains("|".join(JOB_SITES), regex=True).astype(int)
    n["int_host"] = np.where(n["internal"], n["domain"], None)
    flags = first_seen_flags(n, key, "domain")
    n["new_dom_mb"] = np.where(flags & ~n["internal"], n["mb_out"], 0.0)  # external only
    parts = [_agg(n, key, dict(
        connections=("domain", "size"), bytes_out_mb=("mb_out", "sum"), bytes_in_mb=("mb_in", "sum"),
        max_upload_mb=("mb_out", "max"), distinct_domains=("domain", "nunique"),
        new_domain_upload_mb=("new_dom_mb", "sum"), cloud_upload_mb=("cloud_mb", "sum"),
        mining_conns=("mining", "sum"), job_site_visits=("job", "sum"),
        internal_hosts=("int_host", "nunique")))]
    parts.append(count_new(n, key, "domain", "new_domains"))
    parts.append(count_new(n, key, "dst_port", "new_ports"))
    return parts


def _merge(parts: list, key: str, cols: list) -> pd.DataFrame:
    base = None
    for p in parts:
        if p is None or len(p) == 0:
            continue
        p = p.copy()
        p["date"] = p["date"].astype(str)
        base = p if base is None else base.merge(p, on=[key, "date"], how="outer")
    if base is None:
        return pd.DataFrame(columns=[key, "date"] + cols)
    for c in cols:
        if c not in base.columns:
            base[c] = 0.0
    base[cols] = base[cols].apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(float)
    return base[[key, "date"] + cols].sort_values(["date", key]).reset_index(drop=True)


# --------------------------------------------------------------------------
# device-day features
# --------------------------------------------------------------------------
def device_features(frames: dict, cfg: Config = CONFIG) -> pd.DataFrame:
    auth, net, res = frames["auth"], frames["network"], frames["resource"]
    devices = frames["devices"]
    known = set(devices["device"])
    a = auth[auth["dest_host"].isin(known)].copy()
    a["fail"] = (a["result"] != "success").astype(int)
    a["ok"] = 1 - a["fail"]
    parts = [_agg(a.rename(columns={"dest_host": "device"}), "device", dict(
        logins_to_device=("ok", "sum"), failed_logins_to_device=("fail", "sum"),
        distinct_users_on_device=("user", "nunique")))]
    okd = a[a["ok"] == 1].rename(columns={"dest_host": "device"})
    parts.append(count_new(okd, "device", "user", "new_users_on_device"))
    parts += _network_parts(net[net["device"].isin(known)], "device")
    r = res.copy()
    r["high"] = (r["cpu_pct"] > 85).astype(int)
    parts.append(_agg(r, "device", dict(cpu_mean=("cpu_pct", "mean"), cpu_max=("cpu_pct", "max"),
                                        cpu_high_hours=("high", "sum"), mem_mean=("mem_pct", "mean"),
                                        disk_io_mb=("disk_io_mb", "sum"), proc_max=("process_count", "max"),
                                        active_hours=("cpu_pct", "size"))))
    out = _merge(parts, "device", DEVICE_FEATURES)
    out = out[out["device"].isin(known)]
    out = out.merge(devices[["device", "device_type", "department"]], on="device", how="left")
    out["department"] = np.where(out["device_type"] == "server", "server", out["department"])
    out["is_admin"] = False
    out.insert(0, "entity_type", "device")
    return out.rename(columns={"device": "entity"}).reset_index(drop=True)


def build_features(frames: dict, cfg: Config = CONFIG) -> dict:
    return {"user": user_features(frames, cfg), "device": device_features(frames, cfg)}
