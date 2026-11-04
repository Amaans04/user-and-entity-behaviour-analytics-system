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

from . import web
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
# web activity - only modelled when the logs carry page / category / allow-block detail (a proxy or
# web gateway); plain flow records leave these at zero and the models use USER_FEATURES alone
WEB_FEATURES = [
    "pages_visited", "web_blocked", "blocked_sites", "risky_site_visits", "new_categories",
    "downloads", "executable_downloads",
]
# web signals that are not modelled: read by the threat rules and shown on the User activity page
WEB_RULE_SIGNALS = ["block_bypass", "new_site_executables", "browsing_minutes", "new_subdomains",
                    "random_subdomains", "beaconing"]
# what people do with USB sticks, admin rights, shared folders, printers and PowerShell. Like the web
# signals above these are not modelled (the ML feature set stays the same whatever logs arrive): they
# feed the threat rules and the User activity page
ACTIVITY_SIGNALS = ["usb_devices", "new_usb_devices", "usb_copies", "admin_logons", "runas_events",
                    "shares_used", "new_shares", "admin_share_access", "print_jobs", "pages_printed",
                    "off_hours_prints", "ps_commands", "ps_suspicious"]
ACTIVITY_ACTIONS = ("print", "powershell", "admin_logon", "runas")     # not file / system accesses
SHARE_ROOT = r"^(\\\\[^\\]+\\[^\\]+|/shares/[^/]+)"                       # \\\\server\\share  or  /shares/name
# PowerShell that is rarely innocent: encoded or hidden commands, download-and-run, credential dumping,
# fake password prompts, switching the antivirus off, deleting backups
PS_SUSPICIOUS = (r"-e(?:nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|"
                 r"net\.webclient|\biex\b|invoke-expression|-w(?:indowstyle)?\s+hid|mimikatz|sekurlsa|lsass|"
                 r"promptforcredential|"
                 r"ntds\.dit|set-mppreference|add-mppreference|disablerealtimemonitoring|"
                 r"vssadmin\s+delete\s+shadows|certutil.*-urlcache")
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
    x = acc[~acc["action"].isin(ACTIVITY_ACTIONS)].copy()
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
    parts += _activity_parts(acc, cfg)

    # ---- network ----
    parts += _network_parts(net, "user")
    parts += _web_parts(net)

    # ---- resource usage (the user's own laptop samples) ----
    r = res[res["user"] != "system"].copy()
    r["high"] = (r["cpu_pct"] > 85).astype(int)
    parts.append(_agg(r, "user", dict(cpu_mean=("cpu_pct", "mean"), cpu_max=("cpu_pct", "max"),
                                      cpu_high_hours=("high", "sum"), mem_mean=("mem_pct", "mean"),
                                      disk_io_mb=("disk_io_mb", "sum"), active_hours=("cpu_pct", "size"))))

    out = _merge(parts, "user", USER_FEATURES + WEB_FEATURES + WEB_RULE_SIGNALS + ACTIVITY_SIGNALS)
    # rule-only signal (kept out of USER_FEATURES so the ML models and baselines are unchanged):
    # successful logins from a source that failed against several different accounts within the
    # hour - a password spray that worked (one attacker spread thin over many accounts is
    # invisible to per-account profiles)
    out = out.merge(spray_success(a), on=["user", "date"], how="left")
    out["spray_success"] = out["spray_success"].fillna(0.0)
    out = out.merge(users[["user", "department", "is_admin"]], on="user", how="left")
    out["department"] = out["department"].fillna("unknown")
    out["is_admin"] = out["user"].isin(admins)
    out.insert(0, "entity_type", "user")
    return out.rename(columns={"user": "entity"})


def share_root(resource: pd.Series) -> pd.Series:
    """The shared folder a path lives in (lower-case), NaN for anything that is not on a share."""
    return resource.astype(str).str.extract(SHARE_ROOT, expand=False).str.lower()


def _activity_parts(acc: pd.DataFrame, cfg: Config) -> list:
    """USB sticks, admin rights, shared folders, printing and PowerShell, per user-day.

    * ``usb_devices`` / ``new_usb_devices`` - different sticks plugged in, and ones never seen for this user
    * ``admin_logons`` / ``runas_events``   - logons carrying admin privileges, commands run as someone else
    * ``shares_used`` / ``new_shares``      - shared folders worked in; ``admin_share_access`` counts the hidden
                                              C$ / ADMIN$ shares that only administrators and attackers use
    * ``pages_printed`` / ``off_hours_prints`` - print volume, and jobs at hours this person is never active
    * ``ps_commands`` / ``ps_suspicious``   - PowerShell commands, and the ones matching ``PS_SUSPICIOUS``
    """
    if acc.empty:
        return []
    x = acc.copy()
    act, res = x["action"], x["resource"].astype(str)
    off = (hour_rarity(x, "user", min_history=50) < cfg.off_hours_prob).to_numpy()
    x["usb_dev"] = np.where(act == "usb_connect", res, None)
    x["usb_copy"] = (act == "copy_to_usb").astype(int)
    x["admin_logon"] = (act == "admin_logon").astype(int)
    x["runas"] = (act == "runas").astype(int)
    x["share"] = share_root(res).where(~act.isin(ACTIVITY_ACTIONS + ("usb_connect",)))
    x["admin_share"] = x["share"].str.endswith("$", na=False).astype(int)
    printed = (act == "print").to_numpy()
    x["print"] = printed.astype(int)
    x["pages_p"] = np.where(printed, pd.to_numeric(x.get("pages", 0), errors="coerce").fillna(0), 0)
    x["off_print"] = (printed & off).astype(int)
    ps = (act == "powershell").to_numpy()
    x["ps"] = ps.astype(int)
    x["ps_susp"] = (ps & res.str.contains(PS_SUSPICIOUS, case=False, regex=True).to_numpy()).astype(int)
    parts = [_agg(x, "user", dict(
        usb_devices=("usb_dev", "nunique"), usb_copies=("usb_copy", "sum"), admin_logons=("admin_logon", "sum"),
        runas_events=("runas", "sum"), shares_used=("share", "nunique"), admin_share_access=("admin_share", "sum"),
        print_jobs=("print", "sum"), pages_printed=("pages_p", "sum"), off_hours_prints=("off_print", "sum"),
        ps_commands=("ps", "sum"), ps_suspicious=("ps_susp", "sum")))]
    parts.append(count_new(x[x["usb_dev"].notna()], "user", "usb_dev", "new_usb_devices"))
    parts.append(count_new(x[x["share"].notna()], "user", "share", "new_shares"))
    return parts


SPRAY_MIN_ACCOUNTS = 5


def spray_success(a: pd.DataFrame) -> pd.DataFrame:
    """Per user-day: successful logins from a source IP that failed against at least
    ``SPRAY_MIN_ACCOUNTS`` different accounts in the same or the previous hour."""
    cols = ["user", "date", "spray_success"]
    if a.empty or "src_ip" not in a:
        return pd.DataFrame(columns=cols)
    x = a[a["src_ip"].astype(str).str.len() > 0].assign(hour=lambda d: d["timestamp"].dt.floor("h"))
    fails = x[x["fail"] == 1]
    if fails.empty:
        return pd.DataFrame(columns=cols)
    per = fails.groupby(["src_ip", "hour"])["user"].nunique()
    sources = set(per[per >= SPRAY_MIN_ACCOUNTS].index)
    if not sources:
        return pd.DataFrame(columns=cols)
    ok = x[x["ok"] == 1]
    hit = [(ip, h) in sources or (ip, h - pd.Timedelta(hours=1)) in sources for ip, h in zip(ok["src_ip"], ok["hour"])]
    ok = ok[hit]
    if ok.empty:
        return pd.DataFrame(columns=cols)
    return ok.groupby(["user", "date"]).size().rename("spray_success").reset_index()


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


BYPASS_WINDOW = pd.Timedelta(minutes=60)


def _web_parts(net: pd.DataFrame) -> list:
    """What the user did on the web: pages, blocked attempts, risky sites, downloads.

    * ``new_categories``      - kinds of site this user never visited before (causal, like new_domains)
    * ``block_bypass``        - an anonymizer / proxy / VPN site reached within an hour of being blocked:
                                the classic way round a web filter
    * ``new_site_executables`` - an executable or script downloaded from a site the user never used before
    """
    n = web.enrich(net)
    if n.empty:
        return []
    n = n.sort_values("timestamp")
    n["blocked"] = (n["web_action"] == "blocked").astype(int)
    n["risky"] = web.is_risky(n["category"]).astype(int)
    ok = n["blocked"] == 0
    n["page"] = np.where((n["url"] != "") & ok, n["url"], None)
    n["dl"] = ((n["file"] != "") & ok).astype(int)
    n["exe"] = (web.is_executable(n["file"]) & ok).astype(int)
    n["blocked_dom"] = np.where(n["blocked"] == 1, n["domain"], None)
    first_dom = first_seen_flags(n, "user", "domain")
    n["new_exe"] = (n["exe"].astype(bool) & first_dom).astype(int)
    # allowed anonymizer visit shortly after a blocked request (per user, time-ordered)
    last_block = n["timestamp"].where(n["blocked"] == 1).groupby(n["user"]).ffill()
    n["bypass"] = (ok & (n["category"] == "anonymizer") & last_block.notna()
                   & ((n["timestamp"] - last_block) <= BYPASS_WINDOW)).astype(int)
    parts = [_agg(n, "user", dict(
        pages_visited=("page", "nunique"), web_blocked=("blocked", "sum"), blocked_sites=("blocked_dom", "nunique"),
        risky_site_visits=("risky", "sum"), downloads=("dl", "sum"), executable_downloads=("exe", "sum"),
        block_bypass=("bypass", "sum"), new_site_executables=("new_exe", "sum")))]
    cat = n[n["category"] != ""]
    parts.append(count_new(cat, "user", "category", "new_categories"))
    seen = n[ok & (n["url"] != "")]                       # subdomains are only known from full URLs / hosts
    parts.append(count_new(seen, "user", "host", "new_subdomains"))
    parts.append(web.time_online(n))
    parts.append(web.tunnelling_and_beacons(n))
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
