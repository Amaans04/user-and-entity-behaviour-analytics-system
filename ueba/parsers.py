"""Readers for log formats that are not plain tables, and splitting of mixed files.

Turned into the canonical streams (auth / access) so the rest of the pipeline - mapping,
features, detection - works unchanged:

* **Linux** ``auth.log`` / ``secure`` / syslog text: sshd logins (accepted / failed),
  ``sudo`` and ``su`` (privilege use), ``useradd`` (account creation), kernel "USB Mass Storage
  device detected" lines (removable media). Syslog lines carry no
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
    4672 special privileges at logon       -> access (admin_logon)
    4648 logon with explicit credentials   -> access (runas)
    5140 / 5145 network share access       -> access (read / write / delete on \\\\server\\share\\file)
    6416 new external device (USB storage) -> access (usb_connect)
  and, from the other Windows logs exported the same way:
    307  PrintService: document printed    -> access (print, with pages and printer)
    2003 DriverFrameworks: USB storage     -> access (usb_connect)
    4103 / 4104 / 800 PowerShell commands  -> access (powershell); 4688 with a powershell.exe command line too
  USB and script-block events are logged by the machine, not the person. They are given to whoever
  was last seen on that computer in the same file; what is left is marked ``?computer`` and settled
  at load time from the asset inventory or the login history (see ``ingest.resolve_device_users``).
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
_KUSB = re.compile(r"usb (\S+?): (Product|Manufacturer|SerialNumber): (.*)$")
_KUSB_STORAGE = re.compile(r"usb-storage (\S+?):[\d.]+: USB Mass Storage device detected")


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
    plugged: dict = {}                                   # (host, usb port) -> what the kernel said about the device
    for line in text.splitlines():
        m = _SYSLOG.match(line)
        if not m:
            continue
        host, prog, msg = m["host"], m["prog"].lower(), m["msg"]
        if prog == "kernel":
            msg = re.sub(r"^\[\s*[\d.]+\]\s*", "", msg)
            if (k := _KUSB.search(msg)):
                plugged.setdefault((host, k[1]), {})[k[2]] = k[3].strip()
            elif (k := _KUSB_STORAGE.search(msg)):
                d = plugged.pop((host, k[1]), {})
                model = " ".join(x for x in (d.get("Manufacturer"), d.get("Product")) if x) or "device"
                rows_x.append(dict(user=UNKNOWN_USER + host, device=host, action="usb_connect",
                                   resource=f"USB storage: {model}" + (f" [{d['SerialNumber']}]" if d.get("SerialNumber") else ""),
                                   sensitivity="internal", status="success"))
                stamps_x.append(m["ts"])
            continue
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
        out["access"] = settle_unknown_users(pd.DataFrame(rows_x).assign(timestamp=_syslog_times(stamps_x, year)),
                                             out.get("auth"))
    return out


# ---------------------------------------------------------------- Windows Security events
NOISE_ACCOUNTS = re.compile(r"(\$$|^system$|^anonymous logon$|^local service$|^network service$|^dwm-\d+$|^umfd-\d+$|^-$)",
                            re.I)
LOGON_TYPES = {"2": "interactive", "3": "network", "7": "unlock", "8": "network", "9": "runas", "10": "rdp",
               "11": "cached"}
WIN_IDS = {4624, 4625, 4688, 4663, 4720, 4728, 4732, 4756, 1102, 104,
           4672, 4648, 5140, 5145, 6416, 307, 2003, 4103, 4104, 800}
TEXT_IDS = {307, 2003, 4103, 4104, 800}          # read from the description text, not from named fields
# Sysmon (Microsoft-Windows-Sysmon/Operational) reuses small event numbers that other logs also use, so its
# events are keyed as SYSMON + id: 1 process start, 3 network connection, 11 file created, 22 DNS query
SYSMON = 100000
SYSMON_IDS = {1, 3, 11, 22}
WIN_IDS |= {SYSMON + i for i in SYSMON_IDS}


def event_key(eid: int, channel_or_source: str) -> int:
    """The id used internally: Sysmon events are moved to SYSMON + id."""
    return SYSMON + eid if "sysmon" in (channel_or_source or "").lower() and eid in SYSMON_IDS else eid
NOISE_SHARES = {"IPC$", "SYSVOL", "NETLOGON", "PRINT$"}
UNKNOWN_USER = "?"                               # prefix of a user still to be worked out from the computer
_USB_ID = re.compile(r"(?:USBSTOR|UASPSTOR|WPDBUSENUM)[\\#][^\s\"<>]+", re.I)
_PRINTED = re.compile(r"Document \d+, (?P<doc>.*?) owned by (?P<user>\S+) on (?P<client>\S+) was printed on "
                      r"(?P<printer>.*?) through port .*?Pages printed: (?P<pages>\d+)", re.S)
_PS_HOSTS = re.compile(r"(?:^|[\\/])(?:powershell(?:_ise)?|pwsh)(?:\.exe)?$", re.I)


def _access_action(accesses: str) -> str:
    """Windows access list (words in an export, %%codes in a raw .evtx) -> read / write / delete."""
    a = (accesses or "").lower()
    if "delete" in a or "%%1537" in a:
        return "delete"
    return "write" if ("write" in a or "append" in a or "%%4417" in a or "%%4418" in a) else "read"


def usb_device(text: str, name: str = "") -> str:
    """'USB storage: SanDisk Ultra [serial]' from a device id such as USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra\\4C53..."""
    m = _USB_ID.search(text or "")
    if not m:
        return ""
    parts = re.split(r"[\\#]", m.group(0))
    ven = re.search(r"ven_([^&]+)", parts[1], re.I) if len(parts) > 1 else None
    prod = re.search(r"prod_([^&]+)", parts[1], re.I) if len(parts) > 1 else None
    model = " ".join(x.group(1).replace("_", " ").strip() for x in (ven, prod) if x) or name.strip() or "device"
    serial = parts[2].split("&")[0] if len(parts) > 2 else ""
    return f"USB storage: {model}" + (f" [{serial}]" if serial else "")


def _one_line(text: str, limit: int = 400) -> str:
    return re.sub(r"\s+", " ", text or "").strip()[:limit]


def powershell_command(eid: int, f: dict) -> tuple[str, str]:
    """(user, command) of a PowerShell event. Script blocks (4104) do not name the user."""
    text = f.get("_text", "")
    if eid == 4104:
        script = f.get("ScriptBlockText") or ""
        if not script:
            m = re.search(r"Creating Scriptblock text \(\d+ of \d+\):\s*(.*?)(?:\n\s*ScriptBlock ID:|\Z)", text, re.S)
            script = m.group(1) if m else ""
        return "", _one_line(script)
    if eid == 4103:
        ctx = (f.get("ContextInfo") or "") + "\n" + (f.get("Payload") or "") + "\n" + text
        user = re.search(r"\bUser\s*=\s*(\S+)", ctx)
        name = re.search(r"Command Name\s*=\s*(\S+)", ctx)
        args = " ".join(f"-{n} {v}" for n, v in re.findall(r'name="([^"]*)";\s*value="([^"]*)"', ctx))
        host = re.search(r"Host Application\s*=\s*([^\r\n]*)", ctx)
        cmd = f"{name.group(1) if name else ''} {args}".strip()
        if host and " " in host.group(1).strip():          # the launching command line carries -enc, -w hidden ...
            cmd = f"{cmd}  [started by: {host.group(1).strip()}]"
        return (user.group(1) if user else ""), _one_line(cmd)
    user = re.search(r"UserId=(\S+)", text)                # 800: classic "Windows PowerShell" log
    cmd = re.search(r"CommandLine=([^\r\n]*)", text) or re.search(r"for command line:\s*([^\r\n]*)", text)
    return (user.group(1) if user else ""), _one_line(cmd.group(1).rstrip(". ") if cmd else "")


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
    if eid > SYSMON:
        for line in msg.split("\n"):
            k, sep, v = line.partition(":")
            if sep and k.strip() and " " not in k.strip():
                f.setdefault(k.strip(), v.strip())
        return f
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
        f["CommandLine"] = _field(msg, "Process Command Line")
        if eid == 4672:
            f["PrivilegeList"] = _one_line(msg.split("Privileges:", 1)[1]) if "Privileges:" in msg else ""
        elif eid == 4648:
            f["TargetUserName"] = _field(_section(msg, "Account Whose Credentials Were Used:"), "Account Name")
            f["TargetServerName"] = _field(msg, "Target Server Name")
            f["ProcessName"] = _field(msg, "Process Name")
        elif eid in (5140, 5145):
            f["ShareName"] = _field(msg, "Share Name")
            f["RelativeTargetName"] = _field(msg, "Relative Target Name")
        elif eid == 6416:
            f["DeviceId"] = _field(msg, "Device ID")
            f["DeviceDescription"] = _field(msg, "Device Name")
        elif eid in TEXT_IDS:
            f["_text"] = msg
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
    if eid > SYSMON:
        return _sysmon_row(eid - SYSMON, ts, computer, f)
    user = f.get("SubjectUserName", "") or ""
    known = bool(user) and not NOISE_ACCOUNTS.search(user)
    base = dict(timestamp=ts, user=user if known else UNKNOWN_USER + computer, device=computer, status="success")
    # ---- events the machine logs on a person's behalf: keep them even without a user name ----
    if eid in (6416, 2003):
        dev = usb_device(f.get("DeviceId", "") or f.get("_text", ""), f.get("DeviceDescription", "") or "")
        return ("access", dict(base, resource=dev, action="usb_connect", sensitivity="internal")) if dev else None
    if eid == 307:
        m = _PRINTED.search(f.get("_text", ""))
        doc, owner = f.get("Param2") or (m["doc"] if m else ""), f.get("Param3") or (m["user"] if m else "")
        if not owner:
            return None
        client = (f.get("Param4") or (m["client"] if m else "")).lstrip("\\") or computer
        pages = pd.to_numeric(f.get("Param8") or (m["pages"] if m else 0), errors="coerce")
        return "access", dict(base, user=owner, device=client, resource=doc or "Print Document", action="print",
                              sensitivity="internal", pages=0 if pd.isna(pages) else int(pages),
                              printer=f.get("Param5") or (m["printer"] if m else ""))
    if eid in (4103, 4104, 800):
        who, cmd = powershell_command(eid, f)
        if not cmd or (who and NOISE_ACCOUNTS.search(who.rsplit("\\", 1)[-1])):
            return None
        return "access", dict(base, user=who or UNKNOWN_USER + computer, resource=cmd, action="powershell",
                              sensitivity="internal")
    if not known:
        return None
    if eid == 4688:
        cmd = (f.get("CommandLine", "") or "").strip()
        proc = f.get("NewProcessName", "") or "process"
        if cmd and _PS_HOSTS.search(proc):                   # command-line auditing is on: the command itself
            return "access", dict(base, resource=_one_line(cmd), action="powershell", sensitivity="internal")
        return "access", dict(base, resource=proc, action="execute", sensitivity="internal")
    if eid == 4663:
        return "access", dict(base, resource=f.get("ObjectName", "") or "object",
                              action=_access_action(f.get("AccessList", "")), sensitivity="confidential")
    if eid == 4672:
        return "access", dict(base, resource="Special privileges: " + (f.get("PrivilegeList", "") or "").strip(),
                              action="admin_logon", sensitivity="restricted")
    if eid == 4648:
        target = f.get("TargetUserName", "") or ""
        if not target or target.lower() == user.lower() or NOISE_ACCOUNTS.search(target):
            return None
        server = f.get("TargetServerName", "") or computer
        return "access", dict(base, resource=f"run as {target} on {'this computer' if server == 'localhost' else server}",
                              action="runas", sensitivity="restricted")
    if eid in (5140, 5145):
        share = (f.get("ShareName", "") or "").replace("\\\\*\\", "").strip("\\ ")
        if not share or share.upper() in NOISE_SHARES:
            return None
        rel = (f.get("RelativeTargetName", "") or "").strip("\\ ")
        return "access", dict(base, resource=f"\\\\{computer}\\{share}" + (f"\\{rel}" if rel else ""),
                              action=_access_action(f.get("AccessList", "")) if eid == 5145 else "read",
                              sensitivity="restricted" if share.endswith("$") else "internal")
    if eid == 4720:
        return "access", dict(base, resource=f"New-ADUser {f.get('TargetUserName', '')}", action="write",
                              sensitivity="restricted")
    if eid in (4728, 4732, 4756):
        return "access", dict(base, resource=f"Add-ADGroupMember {f.get('TargetUserName', '')}", action="write",
                              sensitivity="restricted")
    if eid in (1102, 104):
        return "access", dict(base, resource="wevtutil cl Security", action="delete", sensitivity="restricted")
    return None


def _sysmon_row(eid: int, ts, computer: str, f: dict) -> tuple[str, dict] | None:
    """Sysmon: process starts, network connections, files created and DNS queries, by the account that did it."""
    user = (f.get("User", "") or "").rsplit("\\", 1)[-1]
    if not user or NOISE_ACCOUNTS.search(user):
        return None
    base = dict(timestamp=ts, user=user, device=computer, status="success")
    if eid == 1:
        image, cmd = f.get("Image", "") or "process", (f.get("CommandLine", "") or "").strip()
        if cmd and _PS_HOSTS.search(image):
            return "access", dict(base, resource=_one_line(cmd), action="powershell", sensitivity="internal")
        return "access", dict(base, resource=image, action="execute", sensitivity="internal")
    if eid == 11:
        target = f.get("TargetFilename", "")
        return ("access", dict(base, resource=target, action="write", sensitivity="internal")) if target else None
    if eid == 3:
        dst = f.get("DestinationIp", "") or ""
        if not dst:
            return None
        port = pd.to_numeric(f.get("DestinationPort", 0), errors="coerce")
        return "network", dict(base, src_ip=f.get("SourceIp", "") or "", dst_ip=dst,
                               dst_port=0 if pd.isna(port) else int(port),
                               protocol=(f.get("Protocol", "") or "tcp").lower(), bytes_out=0, bytes_in=0,
                               domain=(f.get("DestinationHostname", "") or dst).lower())
    if eid == 22:
        q = (f.get("QueryName", "") or "").strip().lower()
        return ("network", dict(base, src_ip="", dst_ip="", dst_port=53, protocol="udp", bytes_out=0, bytes_in=0,
                                domain=q)) if q else None
    return None


def settle_unknown_users(acc: pd.DataFrame, auth: pd.DataFrame | None = None) -> pd.DataFrame:
    """Give machine-logged events (``?computer``) to the person last seen on that computer before them:
    a successful login into it, or an action of theirs on it. Events nobody can be tied to stay marked."""
    if acc.empty or "user" not in acc:
        return acc
    unknown = acc["user"].astype(str).str.startswith(UNKNOWN_USER)
    if not unknown.any():
        return acc

    def keyed(df):
        return df.assign(timestamp=pd.to_datetime(df["timestamp"], errors="coerce").astype("datetime64[ns]"),
                         device=df["device"].astype(str).str.lower()).dropna(subset=["timestamp"])
    seen = [acc.loc[~unknown, ["timestamp", "device", "user"]]]
    if auth is not None and len(auth):
        ok = auth[(auth["result"] == "success") & ~auth["auth_type"].isin(["network", "kerberos"])]
        seen.append(ok.rename(columns={"dest_host": "device"})[["timestamp", "device", "user"]])
    seen = keyed(pd.concat(seen, ignore_index=True))
    todo = keyed(acc.loc[unknown, ["timestamp", "device"]].assign(row=lambda d: d.index))
    if seen.empty or todo.empty:
        return acc
    hit = pd.merge_asof(todo.sort_values("timestamp"), seen.sort_values("timestamp"), on="timestamp", by="device")
    hit = hit.dropna(subset=["user"])
    acc = acc.copy()
    acc.loc[hit["row"].to_numpy(), "user"] = hit["user"].to_numpy()
    return acc


def _collect(events) -> dict[str, pd.DataFrame]:
    rows: dict[str, list] = {"auth": [], "access": [], "network": []}
    for eid, ts, computer, f in events:
        r = _event_rows(eid, ts, computer, f)
        if r:
            rows[r[0]].append(r[1])
    out = {k: pd.DataFrame(v) for k, v in rows.items() if v}
    if "network" in out:
        out["network"] = out["network"].drop(columns="status", errors="ignore")
    if "access" in out:
        out["access"] = settle_unknown_users(out["access"], out.get("auth"))
    return out


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
    t_i, id_i, src_i = idx["Date and Time"], idx["Event ID"], idx.get("Source")
    events = []
    for row in reader:
        if len(row) <= max(t_i, id_i):
            continue
        try:
            eid = int(row[id_i])
        except ValueError:
            continue
        eid = event_key(eid, row[src_i] if src_i is not None and src_i < len(row) else "")
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
    src = c.get("providername") or c.get("logname") or c.get("source")
    events = []
    for _, r in df.iterrows():
        try:
            eid = int(r[idc])
        except (ValueError, TypeError):
            continue
        eid = event_key(eid, str(r[src]) if src else "")
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
                    ch = root.find("e:System/e:Channel", ns)
                    eid = event_key(eid, ch.text if ch is not None else "")
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
                if eid in TEXT_IDS:
                    # PrintService / DriverFrameworks keep their values under UserData (Param1..8, InstanceId);
                    # the classic PowerShell log uses unnamed Data strings
                    for ud in root.findall("e:UserData", ns):
                        for el in ud.iter():
                            if el.text and el.text.strip():
                                fields.setdefault(el.tag.rsplit("}", 1)[-1], el.text.strip())
                    loose = [d.text or "" for d in root.findall("e:EventData/e:Data", ns) if not d.get("Name")]
                    fields["_text"] = "\n".join(loose + [v for k, v in fields.items() if k != "_text"])
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
