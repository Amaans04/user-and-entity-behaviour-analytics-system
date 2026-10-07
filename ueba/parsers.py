"""Readers for log formats that are not plain tables, and splitting of mixed files.

Turned into the canonical streams (auth / access) so the rest of the pipeline - mapping,
features, detection - works unchanged:

* **Linux** ``auth.log`` / ``secure`` / syslog text: sshd logins (accepted / failed),
  ``sudo`` and ``su`` (privilege use), ``useradd`` (account creation). Syslog lines carry no
  year; it is inferred (current year, rolled back when dates would lie in the future, and
  forward across a December -> January wrap).
* **Windows Security events** from an Event Viewer CSV export ("Save All Events As" - the
  description is an extra, header-less column), a PowerShell ``Get-WinEvent | Export-Csv``
  export (``TimeCreated, Id, Message``) or a raw ``.evtx`` file:
    4624 / 4625 logon success / failure    -> auth
    4688 process creation                  -> access (execute)
    4663 object access                     -> access (read / write / delete)
    4720 account created, 4728/4732/4756   -> access (account change)
    1102 / 104 audit log cleared           -> access (log tampering)
  Machine accounts (``NAME$``), SYSTEM, ANONYMOUS LOGON and window-manager sessions are
  dropped - they are noise for behaviour analytics.
* **Mixed tables**: one file holding several kinds of events, told apart by a column such as
  ``event_type`` = Logon / File / HTTP. :func:`detect_mixed` finds that column and suggests a
  stream for each value; logoff / disconnect events are skipped (they are not logins).
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime

import numpy as np
import pandas as pd

# ---------------------------------------------------------------- mixed files
TYPE_COLUMN_NAMES = ("event_type", "eventtype", "type", "activity", "category", "event", "log_type", "logtype",
                     "source", "kind", "action_type", "eventname", "event_name", "record_type", "log_source",
                     "data_source", "stream")
STREAM_WORDS = {
    "auth": ("logon", "login", "log-in", "signin", "sign-in", "auth", "ssh", "vpn", "kerberos", "4624", "4625",
             "password", "mfa", "sso"),
    "access": ("file", "access", "device", "usb", "removable", "object", "process", "command", "sudo", "exec",
               "priv", "4663", "4688", "share", "document", "print"),
    "network": ("http", "web", "url", "dns", "net", "conn", "flow", "proxy", "email", "mail", "firewall",
                "traffic", "upload", "download", "browse"),
    "resource": ("cpu", "perf", "metric", "resource", "memory", "usage", "telemetry", "health"),
}
SKIP_WORDS = ("logoff", "logout", "log-off", "sign-out", "signout", "disconnect", "session end", "4634", "4647")


def guess_value_stream(value) -> str | None:
    v = str(value).strip().lower()
    if any(w in v for w in SKIP_WORDS):
        return None
    for stream, words in STREAM_WORDS.items():
        if any(w in v for w in words):
            return stream
    return None


def detect_mixed(df: pd.DataFrame) -> tuple[str, dict] | None:
    """(column, {value: suggested stream or None}) if ``df`` mixes at least two kinds of events."""
    from .sources import _key
    best = None
    for col in df.columns:
        s = df[col]
        if not (pd.api.types.is_object_dtype(s) or pd.api.types.is_string_dtype(s)
                or isinstance(s.dtype, pd.CategoricalDtype)):
            continue
        vals = s.dropna().astype(str).str.strip()
        n = vals.nunique()
        if n < 2 or n > 40:
            continue
        counts = vals.value_counts()
        streams = {v: guess_value_stream(v) for v in counts.index}
        kinds = {x for x in streams.values() if x}
        named = _key(col) in {_key(c) for c in TYPE_COLUMN_NAMES}
        # a type-like column name needs two kinds of events; any other column needs three, so an
        # auth log whose method column says "vpn / ssh / web" is not mistaken for a mixed file
        if len(kinds) < (2 if named else 3):
            continue
        score = len(kinds) + (2 if named else 0)
        if best is None or score > best[0]:
            best = (score, col, streams)
    return (best[1], best[2]) if best else None


def split_mixed(df: pd.DataFrame, col: str, assign: dict) -> list[tuple[str, str, pd.DataFrame]]:
    """[(value label, stream, rows)] - columns that are empty for a part are dropped."""
    out = []
    for stream in ("auth", "access", "network", "resource"):
        vals = [v for v, s in assign.items() if s == stream]
        if not vals:
            continue
        part = df[df[col].astype(str).str.strip().isin(vals)].dropna(axis=1, how="all")
        if len(part):
            out.append((", ".join(map(str, vals))[:60], stream, part.reset_index(drop=True)))
    return out


# ---------------------------------------------------------------- Linux syslog / auth.log
_SYSLOG = re.compile(r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
                     r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+(?P<host>\S+)\s+(?P<prog>[^:\[\s]+)(?:\[\d+\])?:\s*(?P<msg>.*)$")
_ACCEPTED = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
_FAILED = re.compile(r"Failed (\S+) for (?:invalid user )?(\S+) from (\S+)")
_SUDO = re.compile(r"^\s*(\S+)\s*:.*?USER=(\S+)\s*;\s*COMMAND=(.*)$")
_SU = re.compile(r"session opened for user (\S+?)(?:\(uid=\d+\))? by (\S+?)(?:\(uid=\d+\))?\s*$")
_USERADD = re.compile(r"new user: name=([^,\s]+)")


def looks_like_syslog(text: str) -> bool:
    lines = [ln for ln in text.splitlines()[:200] if ln.strip()]
    return bool(lines) and sum(bool(_SYSLOG.match(ln)) for ln in lines) / len(lines) >= 0.6


def _syslog_times(stamps: list[str], year: int | None) -> list[pd.Timestamp]:
    if stamps and re.match(r"\d{4}-", stamps[0]):
        t = pd.to_datetime(pd.Series(stamps), errors="coerce", utc=True, format="mixed")
        return list(t.dt.tz_localize(None))
    now = datetime.now()
    year = year or now.year
    out, prev_month = [], None
    for s in stamps:
        try:
            t = datetime.strptime(f"{year} {' '.join(s.split())}", "%Y %b %d %H:%M:%S")
        except ValueError:
            out.append(pd.NaT)
            continue
        if prev_month and t.month < prev_month - 6:          # December -> January wrap
            year += 1
            t = t.replace(year=year)
        prev_month = t.month
        out.append(pd.Timestamp(t))
    valid = [t for t in out if not pd.isna(t)]
    if valid and max(valid) > pd.Timestamp(now) + pd.Timedelta(days=1):   # dates in the future: last year
        out = [t - pd.DateOffset(years=1) if not pd.isna(t) else t for t in out]
    return out


def parse_syslog(text: str, year: int | None = None) -> dict[str, pd.DataFrame]:
    """auth.log / secure / syslog text -> {'auth': ..., 'access': ...} in the canonical schema."""
    rows_a, rows_x, stamps_a, stamps_x = [], [], [], []
    for line in text.splitlines():
        m = _SYSLOG.match(line)
        if not m:
            continue
        host, prog, msg = m["host"], m["prog"].lower(), m["msg"]
        if prog in ("sshd", "sshd-session"):
            if (a := _ACCEPTED.search(msg)):
                rows_a.append(dict(user=a[2], result="success", src_ip=a[3], src_device=a[3], dest_host=host,
                                   auth_type="ssh"))
                stamps_a.append(m["ts"])
            elif (f := _FAILED.search(msg)):
                rows_a.append(dict(user=f[2], result="failure", src_ip=f[3], src_device=f[3], dest_host=host,
                                   auth_type="ssh"))
                stamps_a.append(m["ts"])
        elif prog == "sudo" and (s := _SUDO.match(msg)) and "COMMAND=" in msg:
            rows_x.append(dict(user=s[1], device=host, resource=s[3].strip(),
                               action="priv_escalation" if s[2] == "root" else "execute",
                               sensitivity="restricted" if s[2] == "root" else "internal", status="success"))
            stamps_x.append(m["ts"])
        elif prog == "su" and (s := _SU.search(msg)):
            rows_x.append(dict(user=s[2], device=host, resource=f"su {s[1]}",
                               action="priv_escalation" if s[1] == "root" else "execute",
                               sensitivity="restricted", status="success"))
            stamps_x.append(m["ts"])
        elif prog == "useradd" and (u := _USERADD.search(msg)):
            rows_x.append(dict(user="root", device=host, resource=f"useradd {u[1]}", action="write",
                               sensitivity="restricted", status="success"))
            stamps_x.append(m["ts"])
    out = {}
    if rows_a:
        out["auth"] = pd.DataFrame(rows_a).assign(timestamp=_syslog_times(stamps_a, year))
    if rows_x:
        out["access"] = pd.DataFrame(rows_x).assign(timestamp=_syslog_times(stamps_x, year))
    return out


# ---------------------------------------------------------------- Windows Security events
NOISE_ACCOUNTS = re.compile(r"(\$$|^system$|^anonymous logon$|^local service$|^network service$|^dwm-\d+$|^umfd-\d+$|^-$)",
                            re.I)
LOGON_TYPES = {"2": "interactive", "3": "network", "7": "unlock", "8": "network", "9": "runas", "10": "rdp",
               "11": "cached"}
WIN_IDS = {4624, 4625, 4688, 4663, 4720, 4728, 4732, 4756, 1102, 104}


def _section(msg: str, header: str) -> str:
    """Text of one block of an event description, e.g. the 'New Logon:' block."""
    i = msg.find(header)
    if i < 0:
        return ""
    rest = msg[i + len(header):]
    nxt = re.search(r"\n\s*\n|\r\n\s*\r\n|\n[A-Z][A-Za-z ]+:\s*\n", rest)
    return rest[:nxt.start()] if nxt else rest


def _field(text: str, name: str) -> str:
    m = re.search(rf"{re.escape(name)}:\s*([^\r\n\t]*)", text)
    return m.group(1).strip() if m else ""


def _fields_from_message(eid: int, msg: str) -> dict:
    """Event-data fields recovered from the description text of an Event Viewer / PowerShell export."""
    msg = msg.replace("\r\n", "\n")
    f = {}
    if eid in (4624, 4625):
        sec = _section(msg, "New Logon:") or _section(msg, "Account For Which Logon Failed:")
        f["TargetUserName"] = _field(sec, "Account Name")
        f["LogonType"] = _field(msg, "Logon Type")
        f["WorkstationName"] = _field(msg, "Workstation Name")
        f["IpAddress"] = _field(msg, "Source Network Address")
    else:
        f["SubjectUserName"] = _field(_section(msg, "Subject:") or msg, "Account Name")
        f["NewProcessName"] = _field(msg, "New Process Name")
        f["ObjectName"] = _field(msg, "Object Name")
        f["AccessList"] = _field(msg, "Accesses")
        f["TargetUserName"] = _field(_section(msg, "New Account:") or _section(msg, "Member:"), "Account Name") \
            or _field(_section(msg, "Group:"), "Group Name")
    return f


def _event_rows(eid: int, ts, computer: str, f: dict) -> tuple[str, dict] | None:
    """One Windows event -> (stream, canonical row) or None."""
    if eid in (4624, 4625):
        user = f.get("TargetUserName", "")
        if not user or NOISE_ACCOUNTS.search(user):
            return None
        lt = str(f.get("LogonType", "")).strip()
        if lt in ("0", "4", "5"):                 # system, batch, service logons
            return None
        ip = f.get("IpAddress", "") or ""
        ip = "" if ip in ("-", "::1", "127.0.0.1") else ip
        ws = f.get("WorkstationName", "") or ""
        return "auth", dict(timestamp=ts, user=user, result="success" if eid == 4624 else "failure", src_ip=ip,
                            src_device=ws if ws and ws != "-" else (ip or computer), dest_host=computer,
                            auth_type=LOGON_TYPES.get(lt, "interactive"))
    user = f.get("SubjectUserName", "")
    if not user or NOISE_ACCOUNTS.search(user):
        return None
    base = dict(timestamp=ts, user=user, device=computer, status="success")
    if eid == 4688:
        return "access", dict(base, resource=f.get("NewProcessName", "") or "process", action="execute",
                              sensitivity="internal")
    if eid == 4663:
        acc = (f.get("AccessList", "") or "").lower()
        action = "delete" if "delete" in acc else "write" if ("write" in acc or "append" in acc) else "read"
        return "access", dict(base, resource=f.get("ObjectName", "") or "object", action=action,
                              sensitivity="confidential")
    if eid == 4720:
        return "access", dict(base, resource=f"New-ADUser {f.get('TargetUserName', '')}", action="write",
                              sensitivity="restricted")
    if eid in (4728, 4732, 4756):
        return "access", dict(base, resource=f"Add-ADGroupMember {f.get('TargetUserName', '')}", action="write",
                              sensitivity="restricted")
    if eid in (1102, 104):
        return "access", dict(base, resource="wevtutil cl Security", action="delete", sensitivity="restricted")
    return None


def _collect(events) -> dict[str, pd.DataFrame]:
    rows: dict[str, list] = {"auth": [], "access": []}
    for eid, ts, computer, f in events:
        r = _event_rows(eid, ts, computer, f)
        if r:
            rows[r[0]].append(r[1])
    return {k: pd.DataFrame(v) for k, v in rows.items() if v}


def looks_like_eventviewer_csv(head: str) -> bool:
    first = head.splitlines()[0] if head else ""
    return "Event ID" in first and "Date and Time" in first


def parse_eventviewer_csv(data: bytes) -> dict[str, pd.DataFrame]:
    """Event Viewer 'Save All Events As .csv': Level/Keywords, Date and Time, Source, Event ID, Task Category,
    then the description as an extra column without a header."""
    text = data.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    header = next(reader)
    idx = {h.strip(): i for i, h in enumerate(header)}
    t_i, id_i = idx["Date and Time"], idx["Event ID"]
    events = []
    for row in reader:
        if len(row) <= max(t_i, id_i):
            continue
        try:
            eid = int(row[id_i])
        except ValueError:
            continue
        if eid not in WIN_IDS:
            continue
        msg = ",".join(row[len(header):]) if len(row) > len(header) else ""
        ts = pd.to_datetime(row[t_i], errors="coerce")
        if pd.isna(ts):
            continue
        events.append((eid, ts, _field(msg, "Computer") or "windows-host", _fields_from_message(eid, msg)))
    return _collect(events)


def is_powershell_export(df: pd.DataFrame) -> bool:
    cols = {c.lower() for c in df.columns}
    return "message" in cols and ("id" in cols or "eventid" in cols) and ("timecreated" in cols or "timegenerated" in cols)


def parse_powershell(df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    c = {k.lower(): k for k in df.columns}
    idc, tc = c.get("id") or c.get("eventid"), c.get("timecreated") or c.get("timegenerated")
    host = c.get("machinename")
    events = []
    for _, r in df.iterrows():
        try:
            eid = int(r[idc])
        except (ValueError, TypeError):
            continue
        if eid not in WIN_IDS:
            continue
        ts = pd.to_datetime(r[tc], errors="coerce")
        if pd.isna(ts):
            continue
        events.append((eid, ts, str(r[host]) if host else "windows-host", _fields_from_message(eid, str(r[c["message"]]))))
    return _collect(events)


def parse_evtx(data: bytes) -> dict[str, pd.DataFrame]:
    """Raw .evtx (Windows event log file) - needs the python-evtx package."""
    try:
        from Evtx.Evtx import Evtx
    except ImportError as e:  # pragma: no cover
        raise ValueError("Reading .evtx files needs the python-evtx package: pip install python-evtx") from e
    import tempfile
    import xml.etree.ElementTree as ET
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    events = []
    with tempfile.NamedTemporaryFile(suffix=".evtx") as tmp:
        tmp.write(data)
        tmp.flush()
        with Evtx(tmp.name) as log:
            for rec in log.records():
                try:
                    root = ET.fromstring(rec.xml())
                    eid = int(root.find("e:System/e:EventID", ns).text)
                except Exception:  # noqa: BLE001 - skip unreadable records
                    continue
                if eid not in WIN_IDS:
                    continue
                ts = pd.to_datetime(root.find("e:System/e:TimeCreated", ns).get("SystemTime"), utc=True,
                                    errors="coerce")
                if pd.isna(ts):
                    continue
                comp = root.find("e:System/e:Computer", ns)
                fields = {d.get("Name"): (d.text or "") for d in root.findall("e:EventData/e:Data", ns) if d.get("Name")}
                events.append((eid, ts.tz_localize(None), comp.text if comp is not None else "windows-host", fields))
    return _collect(events)


# --------------------------------------------------------------------------
# Web proxy: Squid native access.log
# --------------------------------------------------------------------------
# time elapsed client code/status bytes method URL user hierarchy/peer type
_SQUID = re.compile(r"^(?P<ts>\d{9,11}(?:\.\d+)?)\s+\d+\s+(?P<client>\S+)\s+(?P<code>[A-Z_]+/\d{3})\s+(?P<bytes>\d+)\s+"
                    r"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+(?P<user>\S+)\s+(?P<peer>\S+)(?:\s+(?P<type>\S+))?")


def looks_like_squid(text: str) -> bool:
    lines = [ln for ln in text.splitlines()[:200] if ln.strip()]
    return bool(lines) and sum(bool(_SQUID.match(ln)) for ln in lines) / len(lines) >= 0.6


def parse_squid(text: str) -> dict[str, pd.DataFrame]:
    """Squid's native access.log -> the network stream with page, allowed/blocked and download size.

    ``TCP_DENIED`` (or a 403) means the proxy blocked the request. Authenticated proxies log the user
    name; without one the client address stands in for the user (re-map it if a user column exists)."""
    rows = []
    for ln in text.splitlines():
        m = _SQUID.match(ln)
        if not m:
            continue
        url, method = m["url"], m["method"]
        if method == "CONNECT":                      # HTTPS tunnel: only host:port is visible
            host, _, port = url.partition(":")
            page, port = f"https://{host}/", int(port or 443)
        else:
            page = url
            host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/")[0]
            host, _, p = host.partition(":")
            port = int(p) if p.isdigit() else (443 if url.lower().startswith("https") else 80)
        user = m["user"] if m["user"] not in ("-", "") else m["client"]
        peer_ip = m["peer"].split("/", 1)[1] if "/" in m["peer"] else ""
        rows.append(dict(timestamp=pd.to_datetime(float(m["ts"]), unit="s"), user=user.lower(),
                         device=m["client"], src_ip=m["client"], dst_ip=peer_ip if peer_ip != "-" else "",
                         dst_port=port, protocol="tcp", bytes_out=0, bytes_in=int(m["bytes"]),
                         domain=host.lower(), url=page, category="", web_action=m["code"]))
    return {"network": pd.DataFrame(rows)} if rows else {}
