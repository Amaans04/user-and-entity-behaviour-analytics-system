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
    """Add url / category / web_action / file columns to a network frame (idempotent)."""
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
    return n


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
