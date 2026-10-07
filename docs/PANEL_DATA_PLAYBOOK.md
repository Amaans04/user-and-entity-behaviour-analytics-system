# Playbook: analysing a dataset the panel gives you on the spot

## The 5-minute routine

1. `python launch.py` → open <http://localhost:8501> → sign in.
2. Sidebar → **New workspace** → name it (e.g. "Panel data"). Learning period:
   - logs cover **35+ days** → leave **30**;
   - **14-35 days** → about half the span (e.g. 21 days of logs → 10);
   - **under 14 days** → 7, and say so: *"a short baseline knows less about normal, expect more false alarms"*.
3. **Data sources → Add logs** → drop every file they give you (a ZIP is fine).
4. For each file (or each part of a mixed file), check two things:
   - **what it contains** - logins / file access / network / resource usage / staff list / labels;
   - **the column matches** - every field marked `*` must be matched; look at the *After mapping* preview.
5. **Import** → **Analyse now**.
6. Present: **Overview** → **Alerts → Cases** (open the top case, read the reasons aloud) → **What they did**
   (the User activity page: pages, downloads, blocked attempts, files - flagged steps only) → **Investigate** that
   person → if they told you which days were attacks, upload them as **Labels** and show **Model performance**.

## What the system reads by itself

| They give you | What happens |
|---|---|
| CSV / JSON / JSON-lines tables, any column names | log type and columns matched by name **and by content** (a column of URLs is the website, a column of IPs is an address) |
| One file mixing logins, file access, web traffic... | split by its event-type column; you can change what each value means; logoff events are skipped |
| Linux `auth.log`, `secure`, syslog text | sshd logins (accepted / failed), `sudo` / `su` (privilege use), `useradd` (account creation) |
| Web proxy: Squid `access.log`, web-gateway CSV (URL, category, action) | every page and subdomain, site category, allowed / blocked, downloaded files, estimated minutes per website; blocked attempts, filter bypass through a proxy / VPN site, tool downloads, random-subdomain tunnelling and clockwork beaconing are detected |
| Windows Event Viewer CSV export, PowerShell `Export-Csv`, raw `.evtx` | logons 4624/4625, process starts 4688, file access 4663, account / group changes 4720/4728/4732, log cleared 1102 |
| Only one kind of log | fine - the other features stay at zero |
| No staff list / asset list | fine - everyone is one peer group; privilege use is judged against each account's own history |

## Decisions you may need to make (and what to say)

| You see | Do | Say |
|---|---|---|
| A required field shows "not in file" | pick the right column from the dropdown | "Real logs never use the same column names; the system guesses, the analyst confirms." |
| "Host" could be the user's machine or the server | look at the values in the preview; pick accordingly | "This export calls the laptop Host and the server Target." |
| CPU values like 0.43 | nothing - converted to 43 % automatically | |
| "rows dropped" warning | read it; usually blank or unreadable timestamps | "Bad rows are reported, not silently used." |
| A file is rejected | read the error; usually a required column is missing | "Without a timestamp and a user there is no behaviour to profile." |
| Status stays "Learning" | lower the learning period in Settings, then Analyse | "It needs to know normal before it can judge abnormal." |
| No alerts at all | that can be the right answer - show Investigate for the riskiest person | "Silence is a result too; here is the riskiest entity and why it stayed below the threshold." |
| Many alerts on one person | open the case; if it is a known habit, **Suppress this pattern** with a reason | "One person, one case - and known habits can be silenced with an expiry, audited." |

## What it cannot do (say it before they ask)

* Binary formats other than `.evtx` (e.g. packet captures) - convert to CSV / JSON first.
* Pages of HTTPS sites are only visible if the proxy inspects TLS; otherwise only the site name is known.
* Content inspection - only metadata is analysed, by design (privacy).
* Per-event sequences - detection is per entity-day; gradual insiders are the known weak spot (CERT scenario 2).

## Practise

`python docs/data/make_rehearsal.py` builds two practice packs with answer keys:

* **corporate_siem_export.zip** - a different company; logins, file access and web traffic **mixed in one CSV**
  with unfamiliar column names, CPU as fractions with epoch timestamps, staff list as JSON.
  Correct two matches by hand in the logins part: *src_device ← Host*, *dest_host ← Target*.
  Expected: all 12 attacks found (answer_key_A.csv).
* **server_logs.zip** - a raw Linux `auth.log`, a Windows Event Viewer `Security.csv` and a Squid proxy `access.log`.
  Expected: 6 of 6 attacks found - SSH brute force, insider root + backdoor, password spray, account creation +
  log clearing, rhea getting round the web filter with a proxy site and downloading hacking tools, and malware
  on kiran's laptop calling home every minute through random subdomains (answer_key_B.csv). Open User activity
  -> Websites for any person to show subdomains (erp. / hrms. / wiki.acme-corp.in) and minutes per site.

Do each once, start to finish, before the viva.
