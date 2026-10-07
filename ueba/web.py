"""Web activity: what a user browsed, downloaded and was blocked from.

Proxy / secure-web-gateway / firewall logs carry far more than byte counts: the full URL
(which page), the site's category (social, job search, hacking tools ...), whether the
request was allowed or blocked, and - from the URL - which file was downloaded. This
module normalises those fields so the behaviour engine can profile them per user:

* ``category``  - taken from the log when present (most gateways categorise), otherwise
                  looked up in a small built-in list of well-known sites;
* ``web_action`` - ``allowed`` / ``blocked`` (TCP_DENIED/403, deny, drop, reject ...);
* ``file``      - the downloaded file name when the URL path ends in a file.

Only metadata is used - which page, never its content.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

# categories that are a security concern on their own (not merely against policy)
RISKY_CATEGORIES = ("hacking", "anonymizer", "malware", "phishing", "crypto-mining")
RISKY_PAT = r"hack|anonymi|proxy avoid|proxy-avoid|\bvpn\b|\btor\b|malware|malicious|phish|botnet|exploit|crack|" \
            r"warez|keygen|command.and.control|\bc2\b|mining|miner"

SITE_CATEGORIES = {
    "file-sharing": ("mega.nz", "dropbox.com", "wetransfer.com", "transfer.sh", "anonfiles.io", "file.io",
                     "mediafire.com", "drive.google.com", "pastebin.com", "sendspace.com"),
    "job-search": ("linkedin.com/jobs", "indeed.com", "naukri.com", "monster.com", "glassdoor.com",
                   "careerbuilder.com", "simplyhired.com", "ziprecruiter.com", "dice.com"),
    "anonymizer": ("croxyproxy.com", "hide.me", "hidester.com", "proxysite.com", "kproxy.com",
                   "torproject.org", "protonvpn.com", "nordvpn.com", "windscribe.com", "whoer.net"),
    "hacking": ("exploit-db.com", "nmap.org", "gentilkiwi.com", "hashcat.net", "kali.org",
                "metasploit.com", "hacktricks.xyz", "0day.today"),
    "crypto-mining": ("supportxmr.com", "nicehash.com", "minexmr.com", "2miners.com", "f2pool.com"),
    "streaming": ("netflix.com", "hotstar.com", "primevideo.com", "youtube.com", "twitch.tv", "spotify.com"),
    "gambling": ("bet365.com", "dream11.com", "pokerstars.com", "1xbet.com"),
    "social": ("facebook.com", "instagram.com", "twitter.com", "x.com", "reddit.com", "linkedin.com"),
    "games": ("steampowered.com", "epicgames.com", "miniclip.com"),
    "collaboration": ("office365.com", "slack.com", "zoom.us", "atlassian.net", "salesforce.com",
                      "sharepoint.com", "teams.microsoft.com"),
    "development": ("github.com", "stackoverflow.com", "pypi.org", "docker.io", "ubuntu.com",
                    "python.org", "npmjs.com"),
    "search": ("google.com", "bing.com", "duckduckgo.com"),
    "finance": ("icicibank.com", "tally.in", "gst.gov.in"),
    "news": ("economictimes.com", "thehindu.com", "bbc.com"),
    "technology": ("microsoft.com",),
}
_LOOKUP = sorted(((s, c) for c, sites in SITE_CATEGORIES.items() for s in sites), key=lambda x: -len(x[0]))

BLOCK_PAT = r"block|den(?:y|ied)|drop|reject|forbid|prohibit|quarantin|filtered|tcp_denied|/403\b|^403$|^407$"
DOWNLOAD_EXT = ("exe", "msi", "dmg", "pkg", "apk", "iso", "zip", "rar", "7z", "tar", "gz", "jar", "ps1", "bat",
                "sh", "vbs", "scr", "pdf", "docx", "xlsx", "pptx", "csv", "doc", "xls", "torrent")
EXECUTABLE_EXT = ("exe", "msi", "dmg", "pkg", "apk", "iso", "jar", "ps1", "bat", "sh", "vbs", "scr")
_FILE_RE = re.compile(r"/([^/?#]+\.(" + "|".join(DOWNLOAD_EXT) + r"))(?:[?#]|$)", re.I)


def site_category(domain: str, url: str = "") -> str:
    """Built-in category for a well-known site ('' when unknown)."""
    probe = f"{domain} {url}".lower()
    for site, cat in _LOOKUP:
        if site in probe:
            return cat
    if re.search(r"(^|\.)pool\.|xmr|nicehash|stratum", domain.lower()):
        return "crypto-mining"
    return ""


def normalise_category(s: pd.Series) -> pd.Series:
    """Gateway category names vary ('Proxy Avoidance', 'Hacking/Cracking'...); keep them readable
    and fold the security-relevant ones onto our canonical names."""
    v = s.fillna("").astype(str).str.strip().str.lower()
    out = v.copy()
    for pat, name in [(r"anonymi|proxy|vpn|\btor\b", "anonymizer"), (r"hack|crack|exploit|warez|keygen", "hacking"),
                      (r"malware|malicious|botnet|command.and.control|\bc2\b", "malware"), (r"phish", "phishing"),
                      (r"mining|miner|crypto", "crypto-mining"), (r"job|career|employ", "job-search"),
                      (r"file.?shar|storage|upload|transfer", "file-sharing")]:
        out[v.str.contains(pat, regex=True) & (out == v)] = name
    return out.replace({"nan": "", "none": "", "-": "", "uncategorized": "", "unknown": ""})


def web_action(s: pd.Series) -> np.ndarray:
    v = s.fillna("").astype(str).str.strip().str.lower()
    return np.where(v.str.contains(BLOCK_PAT, regex=True), "blocked", "allowed")


def downloaded_file(url: pd.Series) -> pd.Series:
    return url.fillna("").astype(str).str.extract(_FILE_RE, expand=True)[0].fillna("")


def enrich(net: pd.DataFrame) -> pd.DataFrame:
    """Add url / category / web_action / file / host / site columns to a network frame (idempotent)."""
    n = net.copy()
    for c, d in (("url", ""), ("category", ""), ("web_action", "allowed"), ("file", "")):
        if c not in n.columns:
            n[c] = d
        n[c] = n[c].fillna(d).astype(str).replace({"nan": d})
    n["category"] = normalise_category(n["category"])
    missing = n["category"] == ""
    if missing.any():                          # look up each distinct site once (logs can be millions of rows)
        dom = n.loc[missing, "domain"].astype(str)
        cats = {d: site_category(d) for d in dom.unique()}
        n.loc[missing, "category"] = dom.map(cats)
        jobs = missing & n["domain"].astype(str).str.contains("linkedin.com", regex=False) \
            & n["url"].str.contains("/jobs", regex=False)
        n.loc[jobs, "category"] = "job-search"
    n["web_action"] = web_action(n["web_action"])
    nofile = n["file"] == ""
    if nofile.any():
        n.loc[nofile, "file"] = downloaded_file(n.loc[nofile, "url"])
    return add_sites(n)


def has_web_detail(net: pd.DataFrame) -> bool:
    """True when the logs carry page / category / allow-block detail (a proxy or gateway), not just
    flow records. Only then are the web-activity features added to the behaviour models."""
    if net is None or net.empty:
        return False
    url = net["url"].astype(str) if "url" in net else pd.Series("", index=net.index)
    pages = url.str.contains(r"://[^/]+/.", regex=True).mean() >= 0.2
    blocked = (net["web_action"] == "blocked").any() if "web_action" in net else False
    return bool(pages or blocked)


def is_risky(category: pd.Series) -> pd.Series:
    return category.isin(RISKY_CATEGORIES)


def is_executable(file: pd.Series) -> pd.Series:
    return file.str.lower().str.extract(r"\.([a-z0-9]+)$", expand=False).isin(EXECUTABLE_EXT)


# --------------------------------------------------------------------------
# sites and subdomains
# --------------------------------------------------------------------------
# two-part public suffixes common in the logs we see (a full public-suffix list is not needed for this)
MULTI_SUFFIXES = {"co.in", "gov.in", "ac.in", "org.in", "net.in", "edu.in", "nic.in", "res.in", "co.uk", "org.uk",
                  "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.br", "co.za", "com.sg", "com.my", "co.nz"}
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def host_of(url: str, domain: str) -> str:
    """Full host name of a request - the subdomain level (erp.ibm.com), from the URL when there is one."""
    u = str(url or "").strip().lower()
    if u:
        h = re.sub(r"^[a-z]+://", "", u).split("/")[0].split("?")[0].split("@")[-1].split(":")[0]
        if h:
            return h
    return str(domain or "").strip().lower()


def registered_domain(host: str) -> str:
    """The organisation's domain a host belongs to: erp.ibm.com -> ibm.com, mail.irctc.co.in -> irctc.co.in."""
    h = str(host or "").strip().lower().rstrip(".")
    if not h or _IP.match(h) or "." not in h:
        return h
    parts = h.split(".")
    n = 3 if ".".join(parts[-2:]) in MULTI_SUFFIXES and len(parts) >= 3 else 2
    return ".".join(parts[-n:])


def add_sites(n: pd.DataFrame) -> pd.DataFrame:
    """Add ``host`` (subdomain level) and ``site`` (registered domain) columns."""
    n = n.copy()
    url = n["url"] if "url" in n else pd.Series("", index=n.index)
    pairs = pd.Series(list(zip(url.fillna("").astype(str), n["domain"].fillna("").astype(str))), index=n.index)
    hosts = {p: host_of(*p) for p in pairs.unique()}
    n["host"] = pairs.map(hosts)
    sites = {h: registered_domain(h) for h in n["host"].unique()}
    n["site"] = n["host"].map(sites)
    return n


# --------------------------------------------------------------------------
# time spent
# --------------------------------------------------------------------------
IDLE = pd.Timedelta(minutes=5)       # a gap longer than this ends a visit
TAIL = pd.Timedelta(minutes=1)       # credit for reading the last page of a visit


def _visits(df: pd.DataFrame, keys: list) -> pd.DataFrame:
    d = df.sort_values(keys + ["timestamp"])
    gap = d.groupby(keys)["timestamp"].diff()
    d = d.assign(visit=(gap.isna() | (gap > IDLE)).cumsum())
    v = d.groupby(keys + ["visit"])["timestamp"].agg(["min", "max", "size"]).reset_index()
    v["minutes"] = ((v["max"] - v["min"]) + TAIL).dt.total_seconds() / 60
    return v


def time_on_sites(net: pd.DataFrame) -> pd.DataFrame:
    """Estimated minutes per (user, date, site). Proxies log requests, not time on page, so - like web analytics
    tools - requests to a site less than 5 minutes apart count as one visit, lasting from the first to the last
    request plus a minute for reading. Blocked requests are not time spent."""
    cols = ["user", "date", "site", "minutes", "visits", "requests"]
    if net is None or net.empty:
        return pd.DataFrame(columns=cols)
    n = net if "site" in net else add_sites(net)
    n = n[n["web_action"] != "blocked"] if "web_action" in n else n
    if n.empty:
        return pd.DataFrame(columns=cols)
    v = _visits(n.assign(date=n["timestamp"].dt.date.astype(str)), ["user", "date", "site"])
    out = v.groupby(["user", "date", "site"]).agg(minutes=("minutes", "sum"), visits=("visit", "size"),
                                                  requests=("size", "sum")).reset_index()
    out["minutes"] = out["minutes"].round(1)
    return out[cols]


def time_online(net: pd.DataFrame) -> pd.DataFrame:
    """Estimated minutes per (user, date) actively on the web, whatever the site (overlapping tabs counted once)."""
    if net is None or net.empty:
        return pd.DataFrame(columns=["user", "date", "browsing_minutes"])
    n = net[net["web_action"] != "blocked"] if "web_action" in net else net
    if n.empty:
        return pd.DataFrame(columns=["user", "date", "browsing_minutes"])
    v = _visits(n.assign(date=n["timestamp"].dt.date.astype(str)), ["user", "date"])
    return v.groupby(["user", "date"])["minutes"].sum().round(1).rename("browsing_minutes").reset_index()


# --------------------------------------------------------------------------
# tunnelling and beaconing
# --------------------------------------------------------------------------
QUIET_CATEGORIES = ("collaboration", "development", "search", "technology", "finance", "news", "social", "streaming")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    p = pd.Series(list(s)).value_counts(normalize=True).to_numpy()
    return float(-(p * np.log2(p)).sum())


def random_label(host: str, site: str) -> bool:
    """Does the subdomain part look machine-generated (encoded data, a DGA)? e.g. a8f3k2x9q1z7.cdn-sync.net"""
    sub = host[: -len(site)].rstrip(".") if site and host.endswith(site) else ""
    label = sub.split(".")[0] if sub else ""
    if len(label) < 12:
        return False
    digits = sum(c.isdigit() for c in label)
    return digits >= 2 and _entropy(label) >= 3.2


def site_signals(net: pd.DataFrame) -> pd.DataFrame:
    """Per (user, date, site): distinct random-looking subdomains and whether requests run like clockwork
    (vectorised - proxy logs can hold millions of rows)."""
    cols = ["user", "date", "site", "random_hosts", "clockwork"]
    if net is None or net.empty:
        return pd.DataFrame(columns=cols)
    n = net if "site" in net else add_sites(net)
    n = n.assign(date=n["timestamp"].dt.date.astype(str))[["user", "date", "site", "host", "timestamp"]]
    keys = ["user", "date", "site"]
    uh = n[["host", "site"]].drop_duplicates()
    rnd_hosts = {h for h, s_ in zip(uh["host"], uh["site"]) if random_label(h, s_)}
    out = n.groupby(keys).size().rename("requests").to_frame()
    out["random_hosts"] = n[n["host"].isin(rnd_hosts)].groupby(keys)["host"].nunique()
    big = out.index[out["requests"] >= 24]
    out["clockwork"] = False
    if len(big):
        b = n.set_index(keys).loc[big].reset_index().sort_values(keys + ["timestamp"])
        b["gap"] = b.groupby(keys)["timestamp"].diff().dt.total_seconds()
        g = b[b["gap"] > 0].groupby(keys)["gap"].agg(["size", "median", "mean", "std"])
        ok = (g["size"] >= 20) & (g["median"] >= 20) & (g["std"] / g["mean"] < 0.25)
        out.loc[ok[ok].index, "clockwork"] = True
    out = out.reset_index()
    out["random_hosts"] = out["random_hosts"].fillna(0).astype(int)
    return out[cols]


def tunnelling_and_beacons(net: pd.DataFrame) -> pd.DataFrame:
    """Per user-day:

    * ``random_subdomains`` - the most distinct random-looking subdomains of any one site: hiding data in DNS /
      host names (DNS tunnelling, DGA command-and-control) produces hundreds a day, normal browsing almost none;
    * ``beaconing``         - sites first contacted that day with at least 24 requests at clockwork intervals
      (gaps vary by less than 25%): software calling home, as malware does; people do not browse like that.
    """
    cols = ["user", "date", "random_subdomains", "beaconing"]
    sig = site_signals(net)
    if sig.empty:
        return pd.DataFrame(columns=cols)
    n = net if "site" in net else add_sites(net)
    n = n.assign(date=n["timestamp"].dt.date.astype(str))
    first = n.groupby(["user", "site"])["date"].min().rename("first").reset_index()
    cat = n.groupby("site")["category"].first() if "category" in n else pd.Series(dtype=str)
    sig = sig.merge(first, on=["user", "site"], how="left")
    sig["beacon"] = (sig["clockwork"] & (sig["date"] == sig["first"])
                     & ~sig["site"].map(cat).isin(QUIET_CATEGORIES)).astype(int)
    out = sig.groupby(["user", "date"]).agg(random_subdomains=("random_hosts", "max"),
                                            beaconing=("beacon", "sum")).reset_index()
    return out[cols]
