"""Synthetic enterprise log generator.

Produces four log streams for a fictional ~50-person company:

* auth.csv      - authentication events (interactive, VPN, SSH, RDP, Kerberos)
* access.csv    - system / file / application access events
* network.csv   - web-proxy / network log (page URL, site category, allowed or blocked, bytes)
* resource.csv  - hourly CPU / memory / disk / process samples per device

plus ``ground_truth.csv`` describing every planted attack so detection quality
can be measured objectively.

The first ``train_days`` are attack-free (baseline). Attacks and a few *benign*
anomalies (late-night deadline work, business travel, a large backup, a new
project) are injected into the remaining days, so the evaluation also shows
realistic false positives.
"""
from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

from . import web
from .config import CONFIG, DATA_DIR, Config

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------
CITIES = {  # name: (lat, lon, country)
    "Bengaluru": (12.97, 77.59, "IN"), "Mumbai": (19.08, 72.88, "IN"),
    "Hyderabad": (17.39, 78.49, "IN"), "Pune": (18.52, 73.86, "IN"),
    "Chennai": (13.08, 80.27, "IN"), "Delhi": (28.61, 77.21, "IN"),
    "Singapore": (1.35, 103.82, "SG"), "Amsterdam": (52.37, 4.90, "NL"),
    "Moscow": (55.76, 37.62, "RU"), "Lagos": (6.52, 3.38, "NG"),
    "Frankfurt": (50.11, 8.68, "DE"), "Ashburn": (39.04, -77.49, "US"),
}

FIRST = ["Aarav", "Vivaan", "Aditya", "Arjun", "Sai", "Reyansh", "Krishna", "Ishaan",
         "Rohan", "Kabir", "Ananya", "Diya", "Saanvi", "Aadhya", "Kavya", "Priya",
         "Neha", "Pooja", "Meera", "Riya", "Farhan", "Zoya", "Imran", "Sana",
         "Rahul", "Vikram", "Nikhil", "Sneha", "Divya", "Tanvi", "Karthik", "Manoj",
         "Suresh", "Lakshmi", "Deepak", "Anjali", "Varun", "Shreya", "Harsh", "Nisha",
         "Gaurav", "Swati", "Ayaan", "Fatima", "Joseph", "Maria", "Tenzin", "Harpreet"]
LAST = ["Sharma", "Reddy", "Iyer", "Nair", "Khan", "Gupta", "Rao", "Patel", "Menon",
        "Singh", "Das", "Joshi", "Kulkarni", "Shetty", "Pillai", "Verma"]

DEPARTMENTS = {
    "Engineering": dict(
        n=14, servers=["git-srv01", "build-srv01", "dev-db01", "jira-srv01"],
        domains=["github.com", "stackoverflow.com", "pypi.org", "docker.io", "slack.com",
                 "office365.com", "google.com", "atlassian.net"],
        ports=[443, 22, 80], files=("engineering", 40, 0.15, 0.02)),
    "Finance": dict(
        n=8, servers=["erp-srv01", "fin-db01", "sharepoint01"],
        domains=["office365.com", "google.com", "tally.in", "icicibank.com", "slack.com",
                 "gst.gov.in"],
        ports=[443, 80], files=("finance", 30, 0.45, 0.10)),
    "HR": dict(
        n=6, servers=["hrms-srv01", "sharepoint01"],
        domains=["office365.com", "google.com", "linkedin.com", "naukri.com", "slack.com"],
        ports=[443, 80], files=("hr", 25, 0.45, 0.12)),
    "Sales": dict(
        n=10, servers=["crm-srv01", "sharepoint01"],
        domains=["salesforce.com", "office365.com", "google.com", "linkedin.com",
                 "zoom.us", "slack.com"],
        ports=[443, 80], files=("sales", 30, 0.20, 0.02)),
    "IT-Admin": dict(
        n=5, servers=["dc01", "git-srv01", "erp-srv01", "hrms-srv01", "crm-srv01",
                      "fin-db01", "backup-srv01", "fs01"],
        domains=["microsoft.com", "office365.com", "google.com", "github.com",
                 "ubuntu.com", "slack.com"],
        ports=[443, 22, 3389, 445, 80], files=("it", 30, 0.30, 0.20)),
    "Management": dict(
        n=5, servers=["sharepoint01", "erp-srv01"],
        domains=["office365.com", "google.com", "linkedin.com", "zoom.us",
                 "economictimes.com"],
        ports=[443, 80], files=("management", 20, 0.50, 0.15)),
}
DEPT_CODE = {"Engineering": "ENG", "Finance": "FIN", "HR": "HR", "Sales": "SAL", "IT-Admin": "ITA",
             "Management": "MGT"}
ALL_SERVERS = sorted({s for d in DEPARTMENTS.values() for s in d["servers"]})
COMMON_FILES = [f"/shares/common/{n}" for n in
                ["handbook.pdf", "holiday_list.xlsx", "org_chart.pdf", "templates/ppt_master.pptx",
                 "policies/it_policy.pdf", "policies/leave_policy.pdf"]]

FILE_WORDS = ["report", "plan", "budget", "design", "notes", "review", "roadmap", "contract",
              "invoice", "forecast", "summary", "spec", "audit", "payroll", "credentials",
              "backup", "config", "customer_list", "pricing", "strategy"]
EXT = [".xlsx", ".docx", ".pdf", ".csv", ".pptx", ".py", ".json"]


# page paths per site, so the proxy log shows *which page* was visited, not only the site
PAGES = {
    "github.com": ["/{org}/{repo}", "/{org}/{repo}/pull/{n}", "/{org}/{repo}/issues/{n}", "/{org}/{repo}/blob/main/{word}.py"],
    "stackoverflow.com": ["/questions/{n}/{word}-{word2}-error"],
    "pypi.org": ["/project/{repo}/"], "docker.io": ["/r/library/{repo}"], "atlassian.net": ["/browse/PRJ-{n}"],
    "google.com": ["/search?q={word}+{word2}"], "office365.com": ["/mail/inbox", "/calendar/view/week",
                                                                 "/sites/{team}/Shared%20Documents/{word}"],
    "slack.com": ["/client/T0{n}/C0{n}"], "zoom.us": ["/j/{n}"], "salesforce.com": ["/lightning/r/Opportunity/{n}/view",
                                                                                   "/lightning/o/Account/list"],
    "linkedin.com": ["/feed/", "/in/{word}-{word2}", "/company/{org}"], "naukri.com": ["/{word}-jobs-in-bengaluru"],
    "icicibank.com": ["/corporate/login", "/corporate/payments/{n}"], "tally.in": ["/support/{word}"],
    "gst.gov.in": ["/returns/gstr-3b", "/services/{word}"], "microsoft.com": ["/en-us/security/{word}",
                                                                              "/en-us/download/details.aspx?id={n}"],
    "ubuntu.com": ["/security/notices/USN-{n}-1", "/server/docs/{word}"], "economictimes.com": ["/markets/{word}/{n}"],
}
# subdomains per site (erp.ibm.com-style hosts); picked from the page path, so no random numbers are used
HOSTS = {
    "office365.com": ["outlook.office365.com", "portal.office365.com", "login.office365.com"],
    "google.com": ["www.google.com", "mail.google.com", "docs.google.com", "meet.google.com"],
    "github.com": ["github.com", "gist.github.com", "api.github.com"],
    "slack.com": ["acme-corp.slack.com", "files.slack.com"],
    "salesforce.com": ["acme.my.salesforce.com", "acme.lightning.salesforce.com"],
    "linkedin.com": ["www.linkedin.com"], "atlassian.net": ["acme.atlassian.net"], "zoom.us": ["acme.zoom.us"],
    "icicibank.com": ["cib.icicibank.com", "www.icicibank.com"],
    "microsoft.com": ["learn.microsoft.com", "www.microsoft.com", "download.microsoft.com"],
    "ubuntu.com": ["ubuntu.com", "releases.ubuntu.com"], "gst.gov.in": ["services.gst.gov.in", "www.gst.gov.in"],
    "economictimes.com": ["economictimes.com", "m.economictimes.com"], "docker.io": ["hub.docker.io"],
    "pypi.org": ["pypi.org", "files.pythonhosted.pypi.org"],
}
PAGE_WORDS = ["pipeline", "invoice", "deploy", "budget", "login", "report", "pandas", "docker", "timeout",
              "payroll", "forecast", "kubernetes", "sales", "review", "export", "python", "api", "quarterly"]
DOWNLOADS = {"office365.com": [".pdf", ".xlsx", ".docx", ".pptx"], "salesforce.com": [".csv", ".pdf"],
             "gst.gov.in": [".pdf"], "icicibank.com": [".pdf", ".csv"], "github.com": [".zip", ".tar.gz"],
             "microsoft.com": [".msi", ".exe"], "ubuntu.com": [".iso"], "pypi.org": [".tar.gz"]}
POLICY_BLOCKED = ["netflix.com", "hotstar.com", "bet365.com", "steampowered.com", "dream11.com", "twitch.tv"]


def _ip_for(name: str, prefix: str = "103") -> str:
    h = zlib.crc32(name.encode())
    return f"{prefix}.{(h >> 16) & 255}.{(h >> 8) & 255}.{h & 255 or 1}"


@dataclass
class User:
    username: str
    full_name: str
    dept: str
    is_admin: bool
    device: str
    ip: str
    city: str
    remote: bool
    work_start: float
    work_len: float
    activity: float
    bytes_scale: float
    cpu_base: float
    servers: list
    files: list
    domains: list
    ports: list


PRINT_RATE = {"Finance": 1.2, "HR": 1.0, "Management": 0.9, "Sales": 0.5}      # print jobs a day, by department
ADMIN_PRIVILEGES = "Special privileges: SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege"
PS_ROUTINE = ["Get-Service -Name Spooler", "Get-ChildItem C:\\Deploy", "Get-EventLog -LogName System -Newest 50",
              "Restart-Service w3svc", "Test-NetConnection fs01 -Port 445", "Import-Module ActiveDirectory",
              "Get-ADUser -Filter * -SearchBase 'OU=Staff,DC=corp,DC=local'", "Get-Process | Sort-Object CPU -Descending",
              "dotnet build .\\api.sln", "Get-Content .\\deploy.log -Tail 100", "Get-Disk | Get-Partition",
              "Invoke-Command -ComputerName app-srv01 -ScriptBlock { Get-Service }"]


@dataclass
class Streams:
    auth: list = field(default_factory=list)
    access: list = field(default_factory=list)
    network: list = field(default_factory=list)
    resource: list = field(default_factory=list)
    truth: list = field(default_factory=list)


class LogGenerator:
    def __init__(self, cfg: Config = CONFIG, n_users_scale: float = 1.0):
        self.cfg = cfg
        self.rng = np.random.default_rng(cfg.seed)
        # web-page detail has its own random stream, so adding it leaves every other log line unchanged
        self.web_rng = np.random.default_rng(cfg.seed + 1009)
        # ... and so do printing, USB sticks, admin logons and PowerShell
        self.act_rng = np.random.default_rng(cfg.seed + 2003)
        self.start = datetime.fromisoformat(cfg.start_date)
        self.s = Streams()
        self.scale = n_users_scale
        self.file_catalog = self._build_file_catalog()
        self.users = self._build_users()
        self.by_name = {u.username: u for u in self.users}

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------
    def _build_file_catalog(self) -> dict:
        cat = {}
        for dept, spec in DEPARTMENTS.items():
            folder, n, p_conf, p_restr = spec["files"]
            items = []
            for i in range(n):
                w = FILE_WORDS[self.rng.integers(len(FILE_WORDS))]
                path = f"/shares/{folder}/{w}_{i:02d}{EXT[self.rng.integers(len(EXT))]}"
                r = self.rng.random()
                sens = "restricted" if r < p_restr else "confidential" if r < p_restr + p_conf \
                    else "internal"
                items.append((path, sens))
            cat[dept] = items
        # Crown jewels that normal users never touch
        cat["_restricted"] = [
            ("/shares/it/admin/domain_admins.kdbx", "restricted"),
            ("/shares/hr/payroll/salaries_2026.xlsx", "restricted"),
            ("/shares/finance/bank/net_banking_tokens.csv", "restricted"),
            ("/shares/management/board/acquisition_plan.docx", "restricted"),
            ("/etc/shadow@dc01", "restricted"),
            ("/shares/engineering/secrets/prod_api_keys.json", "restricted"),
        ]
        return cat

    def _build_users(self) -> list:
        users, used = [], set()
        idx = 0
        for dept, spec in DEPARTMENTS.items():
            for _ in range(max(1, round(spec["n"] * self.scale))):
                while True:
                    f = FIRST[self.rng.integers(len(FIRST))]
                    l = LAST[self.rng.integers(len(LAST))]
                    uname = f"{f}.{l}".lower()
                    if uname not in used:
                        used.add(uname)
                        break
                idx += 1
                remote = self.rng.random() < 0.2
                city = "Bengaluru" if not remote else \
                    ["Mumbai", "Hyderabad", "Pune", "Chennai"][self.rng.integers(4)]
                # IT admins include on-call staff with late shifts
                start = self.rng.normal(9.3, 0.8)
                if dept == "IT-Admin" and self.rng.random() < 0.5:
                    start = self.rng.normal(14.0, 1.0)
                dept_files = self.cfg_files(dept)
                k = min(len(dept_files), int(self.rng.integers(10, 18)))
                chosen = [dept_files[i] for i in self.rng.choice(len(dept_files), k, replace=False)]
                chosen += [(p, "public") for p in COMMON_FILES]
                n_srv = len(spec["servers"])
                servers = list(self.rng.choice(spec["servers"],
                                               max(1, min(n_srv, int(self.rng.integers(1, n_srv + 1)))),
                                               replace=False))
                users.append(User(
                    username=uname, full_name=f"{f} {l}", dept=dept,
                    is_admin=dept == "IT-Admin",
                    device=f"LT-{DEPT_CODE[dept]}-{idx:03d}",
                    ip=f"10.10.{list(DEPARTMENTS).index(dept) + 1}.{idx + 10}",
                    city=city, remote=remote,
                    work_start=float(np.clip(start, 6.5, 16)),
                    work_len=float(np.clip(self.rng.normal(8.5, 0.7), 6.5, 11)),
                    activity=float(self.rng.uniform(0.6, 1.5)),
                    bytes_scale=float(self.rng.lognormal(0, 0.5)),
                    cpu_base=float(self.rng.uniform(12, 35)),
                    servers=servers, files=chosen,
                    domains=list(spec["domains"]), ports=list(spec["ports"]),
                ))
        return users

    def cfg_files(self, dept):
        return self.file_catalog[dept]

    # ------------------------------------------------------------------
    # Event helpers
    # ------------------------------------------------------------------
    def day(self, d: int) -> datetime:
        return self.start + timedelta(days=d)

    def _geo(self, u: User, city: str | None = None):
        city = city or u.city
        lat, lon, cc = CITIES[city]
        return city, cc, lat, lon

    def auth(self, ts, u, dest, auth_type, result, city=None, src_ip=None, src_device=None):
        city, cc, lat, lon = self._geo(u, city)
        if src_ip is None:
            src_ip = _ip_for(u.username + "home", "49") if (u.remote or auth_type == "vpn") else u.ip
        self.s.auth.append((ts, u.username, src_device or u.device, src_ip, dest, auth_type,
                            result, city, cc, lat, lon))

    def access(self, ts, u, resource, sens, action, success="success", device=None, pages=0, printer=""):
        self.s.access.append((ts, u.username, device or u.device, resource, action, sens, success, pages, printer))

    def print_job(self, ts, u, path, sens, pages):
        self.access(ts, u, path.rsplit("/", 1)[-1], sens, "print", pages=int(pages),
                    printer=f"PRN-{DEPT_CODE[u.dept]}-01")

    def office_activity(self, u: User, base: datetime, start: float, end: float):
        """The rest of an ordinary day: a few print jobs, the odd USB stick, and for IT staff admin logons
        and PowerShell. Habits are fixed per person; uses its own random stream (see ``act_rng``)."""
        a = self.act_rng
        habit = zlib.crc32(u.username.encode())
        when = lambda: base + timedelta(hours=float(a.uniform(start, max(start + 0.1, end))))  # noqa: E731
        for _ in range(a.poisson(PRINT_RATE.get(u.dept, 0.2) * (0.5 + habit % 100 / 100))):
            path, sens = u.files[int(a.integers(len(u.files)))]
            self.print_job(when(), u, path, sens, a.integers(1, 13))
        if habit % 8 == 0 and a.random() < 0.2:              # one person in eight carries a personal stick
            ts = when()
            self.access(ts, u, f"USB storage: SanDisk Ultra [{habit:08X}]", "internal", "usb_connect")
            for i in range(int(a.integers(0, 3))):
                path, sens = u.files[int(a.integers(len(u.files)))]
                self.access(ts + timedelta(minutes=1 + i), u, path, sens, "copy_to_usb")
        if u.is_admin:
            for _ in range(a.poisson(3)):
                self.access(when(), u, ADMIN_PRIVILEGES, "restricted", "admin_logon",
                            device=u.servers[int(a.integers(len(u.servers)))])
            if a.random() < 0.3:
                self.access(when(), u, f"run as svc_deploy on {u.servers[int(a.integers(len(u.servers)))]}",
                            "restricted", "runas")
        if u.dept in ("IT-Admin", "Engineering"):
            for _ in range(a.poisson(5 if u.is_admin else 1.2)):
                self.access(when(), u, PS_ROUTINE[int(a.integers(len(PS_ROUTINE)))], "internal", "powershell")

    def page(self, domain: str, download: bool = False) -> str:
        """A plausible page URL on ``domain`` (optionally a file download)."""
        w = self.web_rng
        pick = lambda xs: xs[int(w.integers(len(xs)))]  # noqa: E731
        tpl = pick(PAGES.get(domain, ["/{word}/{n}"]))
        path = tpl.format(org=pick(["acme-corp", "psf", "tiangolo", "apache"]), repo=pick(["api", "infra", "web",
                          "etl", "requests", "fastapi"]), n=int(w.integers(1000, 99999)), word=pick(PAGE_WORDS),
                          word2=pick(PAGE_WORDS), team=pick(["finance", "sales", "hr", "eng"]))
        if download:
            path = f"/download/{pick(PAGE_WORDS)}_{int(w.integers(1, 99)):02d}{pick(DOWNLOADS[domain])}"
        hosts = HOSTS.get(domain, [domain])
        return f"https://{hosts[zlib.crc32(path.encode()) % len(hosts)]}{path}"

    def net(self, ts, u, domain, port, bytes_out, bytes_in, device=None, internal=False, url=None,
            action="allowed"):
        dst_ip = _ip_for(domain, "10.20" if internal else "142")
        if internal:
            dst_ip = ".".join(dst_ip.split(".")[:4])
        if url is None:
            dl = not internal and domain in DOWNLOADS and self.web_rng.random() < 0.03
            url = "" if internal or port not in (80, 443) else self.page(domain, dl)
        self.s.network.append((ts, u.username, device or u.device, u.ip, dst_ip, int(port),
                               "tcp", int(bytes_out), int(bytes_in), domain, url,
                               web.site_category(domain, url), action))

    def web_noise(self, u: User, base: datetime, start: float, end: float):
        """Everyday web-filter hits: now and then someone tries a streaming / betting / gaming site at
        work and is blocked. Uses its own random stream (see ``web_rng``)."""
        w = self.web_rng
        if w.random() < 0.12:
            dom = POLICY_BLOCKED[int(w.integers(len(POLICY_BLOCKED)))]
            for _ in range(int(w.integers(1, 3))):
                ts = base + timedelta(hours=float(w.uniform(start, max(start + 0.1, end))))
                self.net(ts, u, dom, 443, 900, 0, url=f"https://{dom}/", action="blocked")

    def res(self, ts, device, user, cpu, mem, disk, procs):
        self.s.resource.append((ts, device, user, round(float(np.clip(cpu, 0, 100)), 1),
                                round(float(np.clip(mem, 0, 100)), 1), round(float(max(disk, 0)), 2),
                                int(procs)))

    def rand_time(self, base: datetime, start_h: float, end_h: float) -> datetime:
        h = self.rng.uniform(start_h, max(start_h + 0.05, end_h))
        return base + timedelta(hours=float(h))

    # ------------------------------------------------------------------
    # Normal behaviour
    # ------------------------------------------------------------------
    def normal_day(self, u: User, d: int, override_end: float | None = None):
        base = self.day(d)
        weekend = base.weekday() >= 5
        if weekend and self.rng.random() > 0.08:
            return
        if not weekend and self.rng.random() < 0.05:  # leave / sick day
            return
        start = u.work_start + self.rng.normal(0, 0.4)
        length = u.work_len + self.rng.normal(0, 0.5)
        if weekend:
            length *= 0.4
        end = override_end if override_end is not None else start + length
        act = u.activity * (0.5 if weekend else 1.0)

        # --- authentication ---
        t0 = base + timedelta(hours=start)
        if self.rng.random() < 0.06:  # typo
            self.auth(t0 - timedelta(seconds=40), u, u.device, "interactive", "failure")
        if u.remote:
            self.auth(t0 - timedelta(minutes=1), u, "vpn-gw01", "vpn", "success")
        self.auth(t0, u, u.device, "interactive", "success")
        for _ in range(self.rng.poisson(2.5 * act)):
            srv = u.servers[self.rng.integers(len(u.servers))]
            atype = "ssh" if u.dept in ("Engineering", "IT-Admin") and self.rng.random() < 0.5 \
                else ("rdp" if u.dept == "IT-Admin" and self.rng.random() < 0.3 else "kerberos")
            self.auth(self.rand_time(base, start, end), u, srv, atype, "success")
        if self.rng.random() < 0.5:  # re-login after lunch
            self.auth(base + timedelta(hours=start + 4 + self.rng.normal(0, .3)), u, u.device,
                      "interactive", "success")

        # --- file / system access ---
        n_files = len(u.files)
        weights = 1.0 / np.arange(1, n_files + 1) ** 0.8
        weights /= weights.sum()
        for _ in range(self.rng.poisson(35 * act)):
            path, sens = u.files[self.rng.choice(n_files, p=weights)]
            r = self.rng.random()
            action = "read" if r < 0.68 else "write" if r < 0.94 else "delete" if r < 0.97 else "execute"
            self.access(self.rand_time(base, start, end), u, path, sens, action)
        if self.rng.random() < 0.05:  # occasionally touch a new dept file
            path, sens = self.cfg_files(u.dept)[self.rng.integers(len(self.cfg_files(u.dept)))]
            self.access(self.rand_time(base, start, end), u, path, sens, "read")
        if u.is_admin:
            for _ in range(self.rng.poisson(3)):
                srv = u.servers[self.rng.integers(len(u.servers))]
                self.access(self.rand_time(base, start, end), u, f"sudo@{srv}", "confidential",
                            "priv_escalation")

        # --- network ---
        for _ in range(self.rng.poisson(40 * act)):
            dom = u.domains[self.rng.integers(len(u.domains))]
            port = 443 if self.rng.random() < 0.9 else u.ports[self.rng.integers(len(u.ports))]
            bo = self.rng.lognormal(np.log(15_000), 1.1) * u.bytes_scale
            bi = self.rng.lognormal(np.log(250_000), 1.2)
            self.net(self.rand_time(base, start, end), u, dom, port, bo, bi)
        if self.rng.random() < 0.10:  # legit larger upload (e.g. deck to SharePoint)
            self.net(self.rand_time(base, start, end), u, "office365.com", 443,
                     self.rng.uniform(20e6, 80e6), 50_000)
        self.web_noise(u, base, start, end)
        self.office_activity(u, base, start, end)

        # --- resource usage (hourly on the laptop) ---
        h = start
        while h < end:
            ts = base + timedelta(hours=h)
            self.res(ts, u.device, u.username, self.rng.normal(u.cpu_base, 8),
                     self.rng.normal(55, 8), self.rng.lognormal(np.log(40), 0.6),
                     self.rng.normal(140, 12))
            h += 1

    def server_day(self, srv: str, d: int):
        base = self.day(d)
        for h in range(24):
            busy = 9 <= h <= 19 and base.weekday() < 5
            cpu = self.rng.normal(45 if busy else 18, 7)
            if srv == "backup-srv01" and 1 <= h <= 3:
                cpu += 30
            self.res(base + timedelta(hours=h, minutes=float(self.rng.uniform(0, 5))), srv, "system",
                     cpu, self.rng.normal(60, 5), self.rng.lognormal(np.log(300 if busy else 80), 0.4),
                     self.rng.normal(260, 15))

    # ------------------------------------------------------------------
    # Attack scenarios (each records ground truth)
    # ------------------------------------------------------------------
    def truth(self, inc, scenario, entity, etype, d, mitre, desc):
        self.s.truth.append((inc, scenario, entity, etype, self.day(d).date().isoformat(), mitre, desc))

    def pick(self, dept, exclude=()):
        pool = [u for u in self.users if u.dept == dept and u.username not in exclude] \
            or [u for u in self.users if u.username not in exclude] or self.users
        return pool[self.rng.integers(len(pool))]

    def atk_brute_force(self, inc, u, d, success=True):
        self.normal_day(u, d)
        base = self.day(d) + timedelta(hours=3, minutes=10)
        ip = "185.220.101.47"
        n = 45 if success else 30
        for i in range(n):
            self.auth(base + timedelta(seconds=i * 9), u, "vpn-gw01", "vpn", "failure",
                      city="Moscow", src_ip=ip, src_device="UNKNOWN")
        if success:
            t = base + timedelta(seconds=n * 9 + 20)
            self.auth(t, u, "vpn-gw01", "vpn", "success", city="Moscow", src_ip=ip, src_device="UNKNOWN")
            for srv in u.servers:
                self.auth(t + timedelta(minutes=3), u, srv, "kerberos", "success", city="Moscow",
                          src_ip=ip, src_device="UNKNOWN")
            for i, (p, s) in enumerate([f for f in u.files if f[1] != "public"][:25]):
                self.access(t + timedelta(minutes=5, seconds=i * 20), u, p, s, "read", device="UNKNOWN")
            self.net(t + timedelta(minutes=15), u, "transfer.sh", 443, 400e6, 20_000, device="UNKNOWN")
            desc = "45 failed VPN logins from a Tor exit node at 03:10, then success and data pulled"
        else:
            desc = "Password-spray: 30 failed VPN logins from a Tor exit node at 03:10 (no success)"
        self.truth(inc, "brute_force", u.username, "user", d, "T1110 Brute Force", desc)

    def atk_impossible_travel(self, inc, u, d, foreign="Amsterdam", exfil=False):
        base = self.day(d)
        self.normal_day(u, d)
        t = base + timedelta(hours=u.work_start + 1.5)
        self.auth(t, u, u.device, "interactive", "success")
        t2 = t + timedelta(minutes=70)
        ip = _ip_for(foreign + "atk", "91")
        self.auth(t2, u, "vpn-gw01", "vpn", "success", city=foreign, src_ip=ip, src_device="UNKNOWN")
        for srv in u.servers[:2]:
            self.auth(t2 + timedelta(minutes=2), u, srv, "kerberos", "success", city=foreign,
                      src_ip=ip, src_device="UNKNOWN")
        files = [f for f in u.files if f[1] != "public"]
        for i, (p, s) in enumerate(files[: (30 if exfil else 8)]):
            self.access(t2 + timedelta(minutes=4, seconds=i * 15), u, p, s, "read", device="UNKNOWN")
        if exfil:
            self.net(t2 + timedelta(minutes=20), u, "anonfiles.io", 443, 1.2e9, 30_000, device="UNKNOWN")
        self.truth(inc, "impossible_travel", u.username, "user", d, "T1078 Valid Accounts",
                   f"Login from {u.city} then {foreign} 70 minutes later"
                   + (" followed by 1.2 GB upload" if exfil else ""))

    def atk_off_hours(self, inc, u, d):
        self.normal_day(u, d)
        base = self.day(d) + timedelta(hours=2, minutes=20)
        self.auth(base, u, u.device, "interactive", "success")
        targets = [f for f in self.cfg_files(u.dept) if f[1] in ("confidential", "restricted")]
        targets += [self.file_catalog["_restricted"][1]]
        for i in range(60):
            p, s = targets[i % len(targets)]
            self.access(base + timedelta(minutes=2, seconds=i * 50), u, p, s, "read")
        for i in range(3):
            self.print_job(base + timedelta(minutes=15 + i), u, "salaries_2026.xlsx", "restricted", 45)
        self.net(base + timedelta(minutes=55), u, "wetransfer.com", 443, 350e6, 40_000)
        self.truth(inc, "off_hours_access", u.username, "user", d, "T1078 Valid Accounts",
                   "Login at 02:20 and 60 confidential/restricted files read incl. payroll")
        self.truth(inc, "off_hours_access", u.device, "device", d, "T1078 Valid Accounts",
                   "Laptop used at 02:20 to read payroll and upload 350 MB to WeTransfer")

    def atk_exfiltration(self, inc, u, d):
        self.normal_day(u, d)
        base = self.day(d) + timedelta(hours=u.work_start + 5)
        files = self.cfg_files(u.dept)
        for i in range(90):
            p, s = files[i % len(files)]
            self.access(base + timedelta(seconds=i * 20), u, p, s, "read")
        self.access(base + timedelta(minutes=31), u, "/shares/engineering/secrets/prod_api_keys.json",
                    "restricted", "read")
        for i in range(6):
            self.net(base + timedelta(minutes=35 + i * 4), u, "mega.nz", 443, 550e6, 60_000)
        self.truth(inc, "data_exfiltration", u.username, "user", d, "T1567 Exfiltration Over Web Service",
                   "90 files + prod API keys read, 3.3 GB uploaded to mega.nz")
        self.truth(inc, "data_exfiltration", u.device, "device", d, "T1567 Exfiltration Over Web Service",
                   "3.3 GB uploaded to mega.nz from this laptop")

    def atk_insider_slow(self, inc, u, days):
        volumes = [120e6, 250e6, 500e6, 800e6, 1.3e9]
        n_reads = [15, 25, 40, 60, 80]
        files = self.cfg_files(u.dept)
        for k, d in enumerate(days):
            self.normal_day(u, d)
            base = self.day(d) + timedelta(hours=u.work_start + 6)
            for i in range(n_reads[k]):
                p, s = files[(i * 7 + k) % len(files)]
                self.access(base + timedelta(seconds=i * 30), u, p, s, "read")
            for dom in ["naukri.com", "linkedin.com/jobs", "indeed.com"]:
                self.net(base + timedelta(minutes=5), u, dom, 443, 30_000, 900_000)
            # the same files also leave on a personal USB stick and on paper, a little more each day
            self.access(base + timedelta(minutes=20), u, "USB storage: Kingston DataTraveler [E0D55EA574F1]",
                        "internal", "usb_connect")
            for i in range(8 + 4 * k):
                p, s = files[(i * 7 + k) % len(files)]
                self.access(base + timedelta(minutes=21, seconds=i * 10), u, p, s, "copy_to_usb")
            for i in range(3):
                p, s = files[(i * 7 + k) % len(files)]
                self.print_job(base + timedelta(minutes=30 + i), u, p, s, 20 + 15 * k)
            chunks = 3
            for c in range(chunks):
                self.net(base + timedelta(minutes=45 + c * 10), u, "dropbox.com", 443,
                         volumes[k] / chunks, 20_000)
            self.truth(inc, "insider_slow_exfiltration", u.username, "user", d,
                       "T1567.002 Exfiltration to Cloud Storage",
                       f"Day {k + 1}/5 of escalating Dropbox uploads ({volumes[k] / 1e6:.0f} MB) + job sites")
            self.truth(inc, "insider_slow_exfiltration", u.device, "device", d,
                       "T1567.002 Exfiltration to Cloud Storage",
                       f"Laptop used for Dropbox upload of {volumes[k] / 1e6:.0f} MB")

    def atk_priv_esc(self, inc, u, d):
        self.normal_day(u, d)
        base = self.day(d) + timedelta(hours=u.work_start + 3)
        for i, srv in enumerate(["dc01", "fs01", "fin-db01"]):
            self.auth(base + timedelta(minutes=i * 3), u, srv, "rdp", "success")
        for i, (p, s) in enumerate(self.file_catalog["_restricted"]):
            self.access(base + timedelta(minutes=10 + i), u, f"runas@{p}", s, "priv_escalation")
            self.access(base + timedelta(minutes=10 + i, seconds=30), u, p, s, "read")
        self.access(base + timedelta(minutes=20), u, "net group 'Domain Admins' /add", "restricted",
                    "priv_escalation")
        self.access(base + timedelta(minutes=4), u, ADMIN_PRIVILEGES, "restricted", "admin_logon", device="dc01")
        self.access(base + timedelta(minutes=6), u, "run as administrator on dc01", "restricted", "runas")
        self.access(base + timedelta(minutes=7), u, "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi"
                    "AGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA", "internal", "powershell", device="dc01")
        self.access(base + timedelta(minutes=8), u, "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'",
                    "internal", "powershell", device="dc01")
        self.access(base + timedelta(minutes=9), u, "\\\\dc01\\C$\\Windows\\NTDS\\ntds.dit", "restricted", "read",
                    device="dc01")
        self.truth(inc, "privilege_escalation", u.username, "user", d, "T1068 Exploitation for Privilege Escalation",
                   "Sales user RDPs to domain controller and runs privileged commands on restricted data")

    def atk_lateral(self, inc, u, d):
        self.normal_day(u, d)
        base = self.day(d) + timedelta(hours=u.work_start + 2)
        others = [x.device for x in self.users if x.dept != u.dept][:8]
        targets = others + ["dc01", "fs01", "backup-srv01", "fin-db01"]
        for i, h in enumerate(targets):
            atype = "rdp" if i % 2 else "ssh"
            if i % 3 == 0:
                self.auth(base + timedelta(minutes=i * 4), u, h, atype, "failure")
            self.auth(base + timedelta(minutes=i * 4, seconds=30), u, h, atype, "success")
            self.net(base + timedelta(minutes=i * 4, seconds=40), u, h, 3389 if atype == "rdp" else 22,
                     200_000, 800_000, internal=True)
            self.access(base + timedelta(minutes=i * 4, seconds=50), u, f"\\\\{h}\\ADMIN$\\svc_update.exe", "restricted",
                        "write", device=h)
            self.access(base + timedelta(minutes=i * 4, seconds=55), u,
                        f"Invoke-Command -ComputerName {h} -ScriptBlock {{ whoami; net localgroup administrators }}",
                        "internal", "powershell")
        self.net(base + timedelta(minutes=5), u, "internal-scan", 445, 5_000, 5_000, internal=True)
        self.truth(inc, "lateral_movement", u.username, "user", d, "T1021 Remote Services",
                   "SSH/RDP into 12 never-before-seen hosts inside 50 minutes")
        self.truth(inc, "lateral_movement", u.device, "device", d, "T1021 Remote Services",
                   "Laptop used as the pivot for SSH/RDP into 12 hosts")

    def atk_cryptomining(self, inc, u, days):
        for d in days:
            self.normal_day(u, d)
            base = self.day(d)
            for h in range(24):
                ts = base + timedelta(hours=h, minutes=30)
                self.res(ts, u.device, u.username, self.rng.normal(96, 2), self.rng.normal(78, 4),
                         self.rng.lognormal(np.log(35), 0.4), self.rng.normal(175, 5))
                self.net(ts, u, "pool.supportxmr.com", 3333, 2_000_000, 1_500_000)
            self.truth(inc, "cryptomining", u.device, "device", d, "T1496 Resource Hijacking",
                       "CPU pinned at ~96% for 24h and Stratum traffic to a Monero pool on port 3333")
            self.truth(inc, "cryptomining", u.username, "user", d, "T1496 Resource Hijacking",
                       "User's laptop mining cryptocurrency")

    def atk_admin_abuse(self, inc, u, d):
        self.normal_day(u, d)
        base = self.day(d) + timedelta(hours=3, minutes=5)
        self.auth(base, u, "dc01", "rdp", "success", src_ip="45.137.21.9", city="Frankfurt",
                  src_device="UNKNOWN")
        for i, (p, s) in enumerate(self.file_catalog["_restricted"]):
            self.access(base + timedelta(minutes=2 + i), u, p, s, "read", device="UNKNOWN")
        for i in range(4):
            self.access(base + timedelta(minutes=10 + i), u, f"New-ADUser svc_backup{i}", "restricted",
                        "priv_escalation", device="UNKNOWN")
        self.access(base + timedelta(minutes=8), u, "Set-MpPreference -DisableRealtimeMonitoring $true", "internal",
                    "powershell", device="UNKNOWN")
        self.access(base + timedelta(minutes=9), u, "vssadmin delete shadows /all /quiet", "internal", "powershell",
                    device="UNKNOWN")
        self.access(base + timedelta(minutes=16), u, "wevtutil cl Security", "restricted", "delete",
                    device="UNKNOWN")
        self.truth(inc, "admin_account_abuse", u.username, "user", d, "T1136 Create Account / T1070 Indicator Removal",
                   "Admin login from Frankfurt at 03:05, new AD accounts created, security log cleared")

    def atk_web_policy_evasion(self, inc, u, d):
        """Insider is blocked from file-sharing sites, switches to a web proxy to get round the filter,
        downloads hacking tools and pushes 1.2 GB out through the proxy. Added on top of a normal day."""
        base = self.day(d) + timedelta(hours=u.work_start + 4.5)
        for i, dom in enumerate(["anonfiles.io", "file.io", "transfer.sh", "anonfiles.io", "pastebin.com",
                                 "file.io", "transfer.sh"]):
            self.net(base + timedelta(minutes=2 * i), u, dom, 443, 1_200, 0, url=f"https://{dom}/upload",
                     action="blocked")
        self.net(base + timedelta(minutes=18), u, "croxyproxy.com", 443, 4_000, 90_000,
                 url="https://www.croxyproxy.com/")
        self.net(base + timedelta(minutes=21), u, "nmap.org", 443, 2_000, 31_000_000,
                 url="https://nmap.org/dist/nmap-7.94-setup.exe")
        self.net(base + timedelta(minutes=23), u, "gentilkiwi.com", 443, 2_000, 1_200_000,
                 url="https://gentilkiwi.com/downloads/mimikatz_trunk.zip")
        files = [f for f in self.cfg_files(u.dept) if f[1] != "public"][:15]
        for i, (p_, s_) in enumerate(files):
            self.access(base + timedelta(minutes=25, seconds=20 * i), u, p_, s_, "read")
        for i in range(3):
            self.net(base + timedelta(minutes=32 + 5 * i), u, "croxyproxy.com", 443, 400e6, 60_000,
                     url="https://www.croxyproxy.com/browse.php?u=https%3A%2F%2Fanonfiles.io%2Fupload")
        self.truth(inc, "web_policy_evasion", u.username, "user", d, "T1090 Proxy / T1105 Ingress Tool Transfer",
                   "Blocked 7 times on file-sharing sites, switched to a web proxy, downloaded nmap and mimikatz, "
                   "uploaded 1.2 GB through the proxy")
        self.truth(inc, "web_policy_evasion", u.device, "device", d, "T1567 Exfiltration Over Web Service",
                   "1.2 GB uploaded from this laptop to a web proxy never used before")

    # ------------------------------------------------------------------
    # Benign anomalies (NOT labelled) - realistic false-positive pressure
    # ------------------------------------------------------------------
    def benign_late_night(self, u, d):
        self.normal_day(u, d, override_end=u.work_start + 15)

    def benign_travel(self, u, days, city="Singapore"):
        for d in days:
            base = self.day(d) + timedelta(hours=u.work_start)
            self.auth(base, u, "vpn-gw01", "vpn", "success", city=city,
                      src_ip=_ip_for(city + u.username, "116"))
            self.auth(base + timedelta(minutes=1), u, u.device, "interactive", "success", city=city,
                      src_ip=_ip_for(city + u.username, "116"))
            for _ in range(20):
                p, s = u.files[self.rng.integers(len(u.files))]
                self.access(self.rand_time(self.day(d), u.work_start, u.work_start + 6), u, p, s, "read")

    def benign_backup(self, u, d):
        self.normal_day(u, d)
        base = self.day(d) + timedelta(hours=u.work_start + 2)
        for i in range(10):
            self.net(base + timedelta(minutes=i * 6), u, "backup-srv01", 445, 2e9, 100_000, internal=True)

    def benign_new_project(self, u, d):
        self.normal_day(u, d)
        other = [x for x in DEPARTMENTS if x != u.dept][0]
        for i, (p, s) in enumerate(self.cfg_files(other)[:12]):
            if s == "internal":
                self.access(self.rand_time(self.day(d), u.work_start, u.work_start + 7), u, p, s, "read")

    # ------------------------------------------------------------------
    def generate(self) -> dict:
        cfg = self.cfg
        T = cfg.train_days
        plan = {}  # (username, day) -> callable that replaces the normal day

        def claim(u, d, fn):
            plan[(u.username, d)] = fn

        used = set()

        def choose(dept):
            u = self.pick(dept, exclude=used)
            used.add(u.username)
            return u

        if cfg.n_days - T >= 28:
            # --- attacks ---
            u = choose("Sales");       claim(u, T + 3, lambda u=u: self.atk_brute_force("INC-01", u, T + 3))
            u = choose("Finance");     claim(u, T + 6, lambda u=u: self.atk_impossible_travel("INC-02", u, T + 6))
            u = choose("HR");          claim(u, T + 8, lambda u=u: self.atk_off_hours("INC-03", u, T + 8))
            u = choose("Engineering"); claim(u, T + 11, lambda u=u: self.atk_exfiltration("INC-04", u, T + 11))
            u = choose("Finance")
            days = list(range(T + 14, T + 19))
            for d in days:
                claim(u, d, (lambda u=u, days=days: self.atk_insider_slow("INC-05", u, days))
                      if d == days[0] else (lambda: None))
            u = choose("Sales");       claim(u, T + 16, lambda u=u: self.atk_priv_esc("INC-06", u, T + 16))
            u = choose("Engineering"); claim(u, T + 20, lambda u=u: self.atk_lateral("INC-07", u, T + 20))
            u = choose("Engineering")
            days = [T + 22, T + 23, T + 24]
            for d in days:
                claim(u, d, (lambda u=u, days=days: self.atk_cryptomining("INC-08", u, days))
                      if d == days[0] else (lambda: None))
            u = choose("IT-Admin");    claim(u, T + 25, lambda u=u: self.atk_brute_force("INC-09", u, T + 25, success=False))
            u = choose("Management");  claim(u, T + 27, lambda u=u: self.atk_impossible_travel("INC-10", u, T + 27, "Lagos", exfil=True))
            u = choose("IT-Admin");    claim(u, T + 28, lambda u=u: self.atk_admin_abuse("INC-11", u, T + 28))
            # --- benign oddities ---
            u = choose("Engineering"); claim(u, T + 10, lambda u=u: self.benign_late_night(u, T + 10))
            u = choose("Sales")
            for d in (T + 12, T + 13, T + 14):
                claim(u, d, (lambda u=u: self.benign_travel(u, [T + 12, T + 13, T + 14]))
                      if d == T + 12 else (lambda: None))
            u = choose("IT-Admin");    claim(u, T + 17, lambda u=u: self.benign_backup(u, T + 17))
            u = choose("HR");          claim(u, T + 21, lambda u=u: self.benign_new_project(u, T + 21))

        for d in range(cfg.n_days):
            for u in self.users:
                fn = plan.get((u.username, d))
                if fn is None:
                    self.normal_day(u, d)
                else:
                    fn()
            for srv in ALL_SERVERS:
                self.server_day(srv, d)
        if cfg.n_days - T >= 28:
            # web-filter evasion, layered on a normal day; victim chosen with the web stream so the rest
            # of the company (and every earlier incident) is generated exactly as before
            pool = [u for u in self.users if u.dept == "Finance" and u.username not in used]
            u = pool[int(self.web_rng.integers(len(pool)))]
            self.atk_web_policy_evasion("INC-12", u, T + 19)
        return self.to_frames()

    def to_frames(self) -> dict:
        s = self.s
        frames = {
            "auth": pd.DataFrame(s.auth, columns=["timestamp", "user", "src_device", "src_ip", "dest_host",
                                                  "auth_type", "result", "city", "country", "lat", "lon"]),
            "access": pd.DataFrame(s.access, columns=["timestamp", "user", "device", "resource", "action",
                                                      "sensitivity", "status", "pages", "printer"]),
            "network": pd.DataFrame(s.network, columns=["timestamp", "user", "device", "src_ip", "dst_ip",
                                                        "dst_port", "protocol", "bytes_out", "bytes_in",
                                                        "domain", "url", "category", "web_action"]),
            "resource": pd.DataFrame(s.resource, columns=["timestamp", "device", "user", "cpu_pct", "mem_pct",
                                                          "disk_io_mb", "process_count"]),
            "ground_truth": pd.DataFrame(s.truth, columns=["incident_id", "scenario", "entity", "entity_type",
                                                           "date", "mitre", "description"]),
        }
        for k in ("auth", "access", "network", "resource"):
            frames[k] = frames[k].sort_values("timestamp").reset_index(drop=True)
            frames[k]["timestamp"] = pd.to_datetime(frames[k]["timestamp"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        users = pd.DataFrame([dict(user=u.username, full_name=u.full_name, department=u.dept,
                                   is_admin=u.is_admin, device=u.device, home_city=u.city,
                                   remote=u.remote) for u in self.users])
        devices = pd.DataFrame(
            [dict(device=u.device, device_type="laptop", owner=u.username, department=u.dept)
             for u in self.users] +
            [dict(device=s_, device_type="server", owner="system", department="server") for s_ in ALL_SERVERS])
        frames["users"] = users
        frames["devices"] = devices
        return frames


def generate_dataset(out_dir: Path = DATA_DIR / "raw", cfg: Config = CONFIG,
                     n_users_scale: float = 1.0) -> dict:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    frames = LogGenerator(cfg, n_users_scale).generate()
    for name, df in frames.items():
        df.to_csv(out_dir / f"{name}.csv", index=False)
    return frames


if __name__ == "__main__":
    f = generate_dataset()
    for k, v in f.items():
        print(f"{k:13s} {len(v):>8,} rows")
