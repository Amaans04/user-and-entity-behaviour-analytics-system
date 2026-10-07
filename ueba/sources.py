"""Bring-your-own-logs: read uploaded files, recognise the log type, map columns.

Real logs never arrive with our exact column names (a Windows export says
``TimeCreated`` / ``TargetUserName``, a proxy says ``cs_bytes`` ...). This module

1. reads CSV / JSON / JSON-lines files (and ZIP archives of them),
2. guesses which stream a file is (auth / access / network / resource /
   users / devices / labels) from its headers and file name,
3. guesses a column mapping from a synonym list (the analyst can override it),
4. converts the mapped data to the canonical schema in ``ingest.REQUIRED`` -
   filling optional fields with safe defaults and normalising common values
   (``"Failed"`` / ``4625`` -> ``failure``, ``CORP\\alice`` -> ``alice``,
   epoch timestamps, CPU as 0-1 vs 0-100 ...),
5. reports what was kept, dropped and why.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from . import web

# field -> (required?, default for optional fields, synonyms)
SCHEMA: dict[str, dict[str, tuple[bool, object, list[str]]]] = {
    "auth": {
        "timestamp": (True, None, ["time", "datetime", "eventtime", "timecreated", "ts", "@timestamp", "_time",
                                   "logtime", "date", "logontime"]),
        "user": (True, None, ["username", "account", "accountname", "targetusername", "userprincipalname", "upn",
                              "login", "email", "principal", "uid", "subjectusername", "actor"]),
        "result": (True, None, ["outcome", "status", "success", "eventresult", "logonresult", "authresult",
                                "eventid", "event_id"]),
        "src_ip": (False, "", ["sourceip", "ipaddress", "clientip", "srcaddr", "sourceaddress", "srcaddress",
                               "srcip", "sourceaddr", "clientaddress", "remoteip", "callerip", "ip", "src"]),
        "src_device": (False, "unknown", ["workstation", "workstationname", "sourcehost", "srchost", "client",
                                          "clientname", "sourcedevice", "pc"]),
        "dest_host": (False, "unknown", ["destination", "targethost", "desthost", "server", "computer",
                                         "computername", "host", "hostname", "target", "app", "application"]),
        "auth_type": (False, "interactive", ["logontype", "authtype", "method", "authmethod", "protocol",
                                             "authenticationpackage", "type"]),
        "city": (False, "", ["location", "geocity"]),
        "country": (False, "", ["countrycode", "geocountry", "countryname"]),
        "lat": (False, np.nan, ["latitude"]),
        "lon": (False, np.nan, ["longitude", "lng", "long"]),
    },
    "access": {
        "timestamp": (True, None, ["time", "datetime", "eventtime", "timecreated", "ts", "@timestamp", "_time",
                                   "logtime", "date"]),
        "user": (True, None, ["username", "account", "accountname", "subjectusername", "userprincipalname",
                              "email", "uid", "actor"]),
        "resource": (True, None, ["file", "filename", "filepath", "path", "object", "objectname", "target",
                                  "command", "commandline", "item", "document"]),
        "action": (True, None, ["operation", "activity", "accesstype", "accessmask", "eventtype", "verb",
                                "event", "accesses"]),
        "device": (False, "unknown", ["host", "hostname", "computer", "computername", "pc", "workstation",
                                      "machine"]),
        "sensitivity": (False, "internal", ["classification", "label", "sensitivitylabel", "datalabel"]),
        "status": (False, "success", ["result", "outcome"]),
    },
    "network": {
        "timestamp": (True, None, ["time", "datetime", "eventtime", "ts", "@timestamp", "_time", "logtime",
                                   "date", "starttime"]),
        "user": (True, None, ["username", "account", "csusername", "uid", "email", "actor", "login", "loginname",
                              "userid", "principal"]),
        "bytes_out": (True, None, ["bytessent", "sentbytes", "outbytes", "csbytes", "origbytes", "upload",
                                   "uploadbytes", "txbytes", "bytesout", "out", "requestsize", "reqsize",
                                   "requestbytes", "clientbytes"]),
        "domain": (True, None, ["url", "target", "destination", "website", "site", "uri", "csuri", "cshost",
                                "query", "destdomain", "sni", "servername", "destinationhost", "fqdn", "host",
                                "hostname"]),
        "device": (False, "unknown", ["sourcehost", "srchost", "computer", "computername", "pc", "workstation",
                                      "machine", "client", "host", "hostname"]),
        "src_ip": (False, "", ["sourceip", "srcaddr", "sourceaddress", "srcaddress", "srcip", "sourceaddr",
                               "clientip", "clientaddress", "cip", "origh", "src"]),
        "dst_ip": (False, "", ["destip", "destinationip", "dstaddr", "destinationaddress", "destaddress", "dstip",
                               "destaddr", "serverip", "sip", "resph", "dst"]),
        "dst_port": (False, 0, ["destport", "destinationport", "dstport", "port", "respp", "serverport"]),
        "protocol": (False, "tcp", ["proto", "transport"]),
        "bytes_in": (False, 0, ["bytesreceived", "receivedbytes", "inbytes", "scbytes", "respbytes",
                                "download", "downloadbytes", "rxbytes", "bytesin", "in", "responsesize",
                                "respsize", "responsebytes", "serverbytes"]),
        # proxy / web-gateway detail (optional): which page, what kind of site, allowed or blocked
        "url": (False, "", ["uri", "requesturl", "fullurl", "csuri", "urlpath", "request", "link", "page"]),
        "category": (False, "", ["urlcategory", "webcategory", "sitecategory", "categoryname",
                                 "contentcategory", "cat"]),
        "web_action": (False, "allowed", ["action", "disposition", "verdict", "policyaction", "decision",
                                          "filteraction", "proxyaction", "status", "result", "outcome",
                                          "httpstatus", "statuscode"]),
    },
    "resource": {
        "timestamp": (True, None, ["time", "datetime", "ts", "@timestamp", "_time", "logtime", "date"]),
        "device": (True, None, ["host", "hostname", "computer", "computername", "pc", "machine", "node"]),
        "cpu_pct": (True, None, ["cpu", "cpupercent", "cpuusage", "cpuutil", "cpuutilization", "processor",
                                 "processortime"]),
        "user": (False, "system", ["username", "account", "owner"]),
        "mem_pct": (False, 0.0, ["mem", "memory", "mempercent", "memoryusage", "memorypercent", "ram"]),
        "disk_io_mb": (False, 0.0, ["disk", "diskio", "diskmb", "io"]),
        "process_count": (False, 0, ["processes", "procs", "nproc", "processcount", "numprocesses"]),
    },
    "users": {
        "user": (True, None, ["username", "account", "accountname", "samaccountname", "userprincipalname",
                              "email", "uid", "login"]),
        "department": (False, "unknown", ["dept", "team", "group", "division", "ou", "businessunit"]),
        "is_admin": (False, False, ["admin", "privileged", "isprivileged", "role", "accounttype"]),
        "full_name": (False, "", ["name", "displayname", "fullname", "employeename"]),
        "device": (False, "", ["laptop", "assigneddevice", "computer", "pc", "primarydevice"]),
        "home_city": (False, "", ["city", "location", "office", "site"]),
        "remote": (False, False, ["isremote", "remoteworker", "wfh"]),
    },
    "devices": {
        "device": (True, None, ["host", "hostname", "computer", "computername", "pc", "asset", "assetname",
                                "machine"]),
        "device_type": (False, "laptop", ["type", "category", "role", "assettype", "class"]),
        "owner": (False, "", ["user", "username", "assignedto", "owneruser"]),
        "department": (False, "unknown", ["dept", "team", "businessunit", "ou"]),
    },
    "ground_truth": {
        "entity": (True, None, ["user", "username", "device", "host", "account"]),
        "date": (True, None, ["day", "timestamp", "time"]),
        "incident_id": (False, "", ["incident", "id", "case", "caseid"]),
        "scenario": (False, "labelled attack", ["type", "attack", "category", "label"]),
        "entity_type": (False, "user", ["type_of_entity", "kind"]),
        "mitre": (False, "", ["technique", "attck", "mitretechnique"]),
        "description": (False, "", ["details", "notes", "summary"]),
    },
}

STREAM_LABELS = {
    "auth": "Authentication (logins)", "access": "System / file access", "network": "Network / proxy",
    "resource": "Resource usage (CPU, memory)", "users": "User directory (departments, admins)",
    "devices": "Asset inventory (devices, servers)", "ground_truth": "Labels - known incidents (optional)",
}
LOG_STREAMS = ("auth", "access", "network", "resource")
FILENAME_HINTS = {
    "auth": ("auth", "logon", "login", "signin", "sign-in", "vpn", "4624", "4625", "sso"),
    "access": ("access", "file", "audit", "object", "command", "sudo", "share"),
    "network": ("net", "proxy", "firewall", "dns", "conn", "flow", "zeek", "http", "web"),
    "resource": ("resource", "cpu", "perf", "metric", "telemetry", "usage"),
    "users": ("user", "employee", "staff", "people", "directory", "hr"),
    "devices": ("device", "asset", "host", "inventory", "cmdb", "computer"),
    "ground_truth": ("truth", "label", "answer", "incident"),
}
SUPPORTED = (".csv", ".jsonl", ".json", ".ndjson", ".txt", ".log", ".evtx", ".zip")
TEXT_LOG_NAMES = ("auth.log", "secure", "syslog", "messages")


def _key(name: str) -> str:
    return re.sub(r"[^a-z0-9@]", "", str(name).lower())


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------
def _named(name: str, parsed: dict, kind: str) -> list[tuple[str, pd.DataFrame]]:
    """Frames from a format parser, named so that the stream guess picks them up."""
    if not parsed:
        raise ValueError(f"Recognised a {kind}, but it holds no logins, privilege use or other security events "
                         "this system analyses")
    return [(f"{name} - {stream}", df) for stream, df in parsed.items()]


def read_bytes(name: str, data: bytes) -> list[tuple[str, pd.DataFrame]]:
    """Parse one uploaded file into (name, dataframe) pairs. ZIPs yield one pair per member.

    Besides tables (CSV / JSON / JSON-lines) this understands Linux auth.log / syslog text,
    Windows Event Viewer CSV exports, PowerShell event exports, raw .evtx files and Squid proxy
    access.log files (see ``parsers.py``)."""
    from . import parsers
    low = name.lower()
    if low.endswith(".zip"):
        out = []
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for m in z.namelist():
                base = m.rsplit("/", 1)[-1]
                b = base.lower()
                if m.endswith("/") or base.startswith((".", "__")):
                    continue
                if not (b.endswith(SUPPORTED[:-1]) or any(t in b for t in TEXT_LOG_NAMES)):
                    continue
                out += read_bytes(base, z.read(m))
        return out
    if low.endswith(".evtx"):
        return _named(name, parsers.parse_evtx(data), "Windows event log")
    text_head = data[:2048].lstrip()
    if low.endswith((".jsonl", ".ndjson")) or (low.endswith((".json", ".log", ".txt")) and text_head[:1] == b"{"):
        try:
            return [(name, pd.read_json(io.BytesIO(data), lines=True))]
        except ValueError:
            pass
    if low.endswith(".json") and text_head[:1] == b"[":
        return [(name, pd.json_normalize(json.loads(data)))]
    head_text = data[:8192].decode("utf-8-sig", errors="replace")
    if not low.endswith((".csv", ".json")) and parsers.looks_like_squid(head_text):
        return _named(name, parsers.parse_squid(data.decode("utf-8", errors="replace")), "Squid proxy log")
    if not low.endswith((".csv", ".json")) and parsers.looks_like_syslog(head_text):
        return _named(name, parsers.parse_syslog(data.decode("utf-8", errors="replace")), "Linux auth / syslog file")
    if parsers.looks_like_eventviewer_csv(head_text):
        return _named(name, parsers.parse_eventviewer_csv(data), "Windows Event Viewer export")
    df = pd.read_csv(io.BytesIO(data), sep=None, engine="python", on_bad_lines="skip")
    if parsers.is_powershell_export(df):
        return _named(name, parsers.parse_powershell(df), "PowerShell event export")
    return [(name, df)]


# --------------------------------------------------------------------------
# guessing
# --------------------------------------------------------------------------
_URLISH = re.compile(r"(://|^[a-z0-9_-]+(\.[a-z0-9_-]+)*\.[a-z]{2,}(/|:|$))", re.I)
_IPLIKE = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:]+)$", re.I)


def _share(col: pd.Series, test) -> float:
    v = col.dropna().astype(str).str.strip()
    v = v[v != ""].head(300)
    return float(v.map(test).mean()) if len(v) else 0.0


def _numeric_share(col: pd.Series) -> float:
    v = col.dropna().head(300)
    return float(pd.to_numeric(v, errors="coerce").notna().mean()) if len(v) else 0.0


def _time_share(col: pd.Series) -> float:
    v = col.dropna().head(200)
    if not len(v):
        return 0.0
    if pd.api.types.is_numeric_dtype(v):
        return 1.0
    return float(pd.to_datetime(v.astype(str), errors="coerce", format="mixed").notna().mean())


# What a column's *values* must look like before a name match is trusted (the name "Host" can be a
# computer or a web site; the values tell which).
VALUE_CHECKS = {
    "timestamp": lambda c: _time_share(c) >= 0.6,
    "domain": lambda c: _share(c, lambda x: bool(_URLISH.search(x)) or bool(_IPLIKE.match(x))) >= 0.6,
    "src_ip": lambda c: _share(c, lambda x: bool(_IPLIKE.match(x))) >= 0.6,
    "dst_ip": lambda c: _share(c, lambda x: bool(_IPLIKE.match(x))) >= 0.6,
    "device": lambda c: _share(c, lambda x: "://" in x) < 0.2,
    "src_device": lambda c: _share(c, lambda x: "://" in x) < 0.2,
    "dest_host": lambda c: _share(c, lambda x: "://" in x) < 0.2,
    "bytes_out": lambda c: _numeric_share(c) >= 0.6,
    "bytes_in": lambda c: _numeric_share(c) >= 0.6,
    "dst_port": lambda c: _numeric_share(c) >= 0.6,
    "cpu_pct": lambda c: _numeric_share(c) >= 0.6,
    "mem_pct": lambda c: _numeric_share(c) >= 0.6,
    "lat": lambda c: _numeric_share(c) >= 0.6,
    "lon": lambda c: _numeric_share(c) >= 0.6,
}


def guess_mapping(stream: str, columns: list[str], sample: pd.DataFrame | None = None) -> dict[str, str | None]:
    """Field -> source column. Exact names win, then synonyms; each column is used once. With a
    ``sample`` of the data, a candidate is only accepted if its values look right for the field."""
    keyed = {_key(c): c for c in columns}

    def ok(fld, col):
        check = VALUE_CHECKS.get(fld)
        return sample is None or check is None or col not in sample or check(sample[col])
    used: set[str] = set()
    mapping: dict[str, str | None] = {}
    fields = SCHEMA[stream]
    for exact_pass in (True, False):
        for fld, (_, _, syn) in fields.items():
            if mapping.get(fld):
                continue
            cands = [_key(fld)] if exact_pass else [_key(s) for s in syn]
            hit = next((keyed[k] for k in cands if k in keyed and keyed[k] not in used and ok(fld, keyed[k])), None)
            mapping[fld] = hit
            if hit:
                used.add(hit)
    if stream == "network" and mapping.get("url") and not mapping.get("domain"):
        mapping["domain"] = mapping["url"]            # the site is taken from the full URL
    return mapping


def guess_stream(columns: list[str], filename: str = "", sample: pd.DataFrame | None = None) -> str:
    fname = filename.lower()
    best, best_score = "auth", -1.0
    for stream, fields in SCHEMA.items():
        m = guess_mapping(stream, columns, sample)
        req = [f for f, (r, _, _) in fields.items() if r]
        score = sum(1.0 for f in req if m[f]) / len(req) * 4
        score += sum(0.3 for f, (r, _, _) in fields.items() if not r and m[f])
        if any(h in fname for h in FILENAME_HINTS[stream]):
            score += 2.5
        if stream in ("users", "devices", "ground_truth") and not any(h in fname for h in FILENAME_HINTS[stream]):
            score -= 1.0   # tiny tables - only when the name says so or nothing else fits
        if score > best_score:
            best, best_score = stream, score
    return best


def mapping_signature(columns: list[str]) -> str:
    return "|".join(sorted(_key(c) for c in columns))


# --------------------------------------------------------------------------
# conversion
# --------------------------------------------------------------------------
FAIL_PAT = r"fail|unsuccess|den(?:y|ied)|invalid|reject|error|bad|locked|block|4625|4771|^false$|^0$|^no$"


def _timestamps(s: pd.Series) -> pd.Series:
    if pd.api.types.is_numeric_dtype(s):
        v = pd.to_numeric(s, errors="coerce")
        unit = "ms" if v.dropna().abs().median() > 1e11 else "s"
        return pd.to_datetime(v, unit=unit, errors="coerce")
    t = pd.to_datetime(s, errors="coerce", format="mixed")
    if t.dtype == object:   # mixed time-zones
        t = pd.to_datetime(s, errors="coerce", format="mixed", utc=True)
    if getattr(t.dt, "tz", None) is not None:
        t = t.dt.tz_localize(None)   # keep the wall-clock time the log recorded
    return t


def _identity(s: pd.Series) -> pd.Series:
    s = s.astype(str).str.strip()
    s = s.str.replace(r"^.*\\", "", regex=True)          # CORP\alice -> alice
    return s.str.lower().replace({"nan": "", "none": "", "-": ""})


def _result(s: pd.Series) -> pd.Series:
    """Anything that reads as a failure (text or Windows event id) -> failure, everything else -> success."""
    v = s.astype(str).str.strip().str.lower()
    return np.where(v.str.contains(FAIL_PAT, regex=True), "failure", "success")


def _action(s: pd.Series) -> pd.Series:
    v = s.astype(str).str.strip().str.lower()
    rules = [(r"priv|elevat|sudo|runas|4672|4673|setuid|admin", "priv_escalation"),
             (r"usb|removable|thumb", "usb_connect"),
             (r"delet|remov|unlink|erase|rm$|\bdel\b|4660", "delete"),
             (r"writ|modif|edit|save|put|upload|creat|chang|4663", "write"),
             (r"read|open|view|get|download|list|access|4656", "read"),
             (r"exec|run|launch|start|4688", "execute")]
    out = v.copy()
    done = pd.Series(False, index=v.index)
    for pat, name in rules:
        hit = v.str.contains(pat, regex=True) & ~done
        out[hit] = name
        done |= hit
    return out


def _sensitivity(s: pd.Series) -> pd.Series:
    v = s.astype(str).str.strip().str.lower()
    return np.where(v.str.contains("restrict|top.?secret|highly|pii|pci|phi"), "restricted",
                    np.where(v.str.contains("confid|secret|sensitive|private"), "confidential",
                             np.where(v.str.contains("public"), "public", "internal")))


def _truthy(s: pd.Series) -> pd.Series:
    v = s.astype(str).str.strip().str.lower()
    return v.isin(["true", "1", "yes", "y", "t"]) | v.str.contains("admin|privileged|domain admin")


@dataclass
class Conversion:
    stream: str
    df: pd.DataFrame
    rows_in: int
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and len(self.df) > 0

    def summary(self) -> dict:
        d = self.df
        out = dict(rows_in=self.rows_in, rows_kept=len(d))
        if "timestamp" in d and len(d):
            out.update(first=str(d["timestamp"].min()), last=str(d["timestamp"].max()),
                       days=int(d["timestamp"].dt.normalize().nunique()))
        for k in ("user", "device"):
            if k in d and len(d):
                out[f"{k}s"] = int(d[k].replace({"system": "", "unknown": ""}).replace("", np.nan).nunique())
        return out


def convert(stream: str, raw: pd.DataFrame, mapping: dict[str, str | None]) -> Conversion:
    """Apply a column mapping and normalise values into the canonical schema."""
    fields = SCHEMA[stream]
    conv = Conversion(stream, pd.DataFrame(), len(raw))
    missing = [f for f, (req, _, _) in fields.items() if req and not mapping.get(f)]
    if stream == "network" and "domain" in missing and (mapping.get("url") or mapping.get("dst_ip")):
        missing.remove("domain")          # fall back to the URL's site, or the destination IP
    if missing:
        conv.errors.append("Map the required field(s): " + ", ".join(missing))
        return conv
    df = pd.DataFrame(index=raw.index)
    for f, (_, default, _) in fields.items():
        src = mapping.get(f)
        df[f] = raw[src] if src else default
    if stream == "network" and not mapping.get("domain"):
        df["domain"] = df["url"] if mapping.get("url") else df["dst_ip"]

    if "timestamp" in df:
        df["timestamp"] = _timestamps(df["timestamp"])
    if stream == "ground_truth":
        df["date"] = _timestamps(df["date"]).dt.date.astype(str)
        is_user = df["entity_type"].astype(str).str.lower().eq("user")
        df["entity"] = np.where(is_user, _identity(df["entity"]), df["entity"].astype(str).str.strip())
        if not mapping.get("incident_id"):
            df["incident_id"] = [f"L-{i + 1:03d}" for i in range(len(df))]
    for f in ("user", "owner"):
        if f in df:
            df[f] = _identity(df[f])
    for f in ("device", "dest_host", "src_device"):
        if f in df:
            df[f] = df[f].astype(str).str.strip().replace({"nan": "unknown", "": "unknown", "None": "unknown"})
    if stream == "auth":
        df["result"] = _result(df["result"])
        df["auth_type"] = df["auth_type"].astype(str).str.strip().str.lower()
        for c in ("lat", "lon"):
            df[c] = pd.to_numeric(df[c], errors="coerce")
        df["country"] = df["country"].fillna("").astype(str)
        df["city"] = df["city"].fillna("").astype(str)
    if stream == "access":
        df["action"] = _action(df["action"])
        df["sensitivity"] = _sensitivity(df["sensitivity"])
        df["status"] = pd.Series(_result(df["status"]), index=df.index)
        df["resource"] = df["resource"].astype(str)
    if stream == "network":
        for c in ("bytes_out", "bytes_in", "dst_port"):
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).clip(lower=0).astype("int64")
        d = df["domain"].astype(str).str.strip().str.lower()
        is_url = d.str.contains("://", regex=False) | d.str.contains(r"^[^/\s]+\.[a-z]{2,}/", regex=True)
        if not mapping.get("url"):                           # keep the page when the site column holds URLs
            df["url"] = np.where(is_url, df["domain"].astype(str).str.strip(), "")
        df["domain"] = np.where(is_url, d.str.replace(r"^[a-z]+://", "", regex=True)   # full URL -> host name
                                .str.split("/").str[0].str.split(":").str[0], d)
        df = web.enrich(df.drop(columns=["file"], errors="ignore"))
    if stream == "resource":
        for c in ("cpu_pct", "mem_pct", "disk_io_mb", "process_count"):
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0)
        for c in ("cpu_pct", "mem_pct"):
            if len(df) and df[c].max() <= 1.0 and df[c].max() > 0:
                df[c] = df[c] * 100
                conv.warnings.append(f"{c} looked like a 0-1 fraction - converted to percent")
        df["user"] = df["user"].replace("", "system")
    if stream == "users":
        df["is_admin"] = _truthy(df["is_admin"])
        df["remote"] = _truthy(df["remote"])
        df["department"] = df["department"].fillna("unknown").astype(str).replace({"": "unknown", "nan": "unknown"})
    if stream == "devices":
        t = df["device_type"].astype(str).str.lower()
        df["device_type"] = np.where(t.str.contains("serv|dc|domain|db|srv"), "server",
                                     np.where(t.str.contains("desk|work"), "desktop", "laptop"))
        df["department"] = df["department"].fillna("unknown").astype(str)

    n0 = len(df)
    key_cols = [f for f, (req, _, _) in fields.items() if req and f in df and f != "result"]
    if "timestamp" in df:
        df = df[df["timestamp"].notna()]
    for c in key_cols:
        if c != "timestamp":
            df = df[df[c].astype(str).str.strip().ne("") & df[c].notna()]
    dropped = n0 - len(df)
    if dropped:
        pct = dropped / max(1, n0)
        msg = f"{dropped:,} of {n0:,} rows dropped ({pct:.0%}) - missing or unreadable timestamp / required value"
        (conv.errors if pct > 0.5 else conv.warnings).append(msg)
    if "timestamp" in df and len(df):
        df = df.sort_values("timestamp")
    conv.df = df.reset_index(drop=True)
    if conv.df.empty and not conv.errors:
        conv.errors.append("No usable rows after conversion")
    return conv
