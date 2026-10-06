"""Update the project report for the operational system and the CERT r4.2 results.

Every new element is cloned from an existing one (paragraph, bullet, heading, table, caption,
figure) so fonts, spacing, numbering and table styling match the original exactly.
"""
import json
import sys
from copy import deepcopy

import docx
from docx.shared import Emu
from docx.oxml.ns import qn
from docx.text.paragraph import Paragraph
from docx.table import Table

SRC, OUT, RES = sys.argv[1], sys.argv[2], sys.argv[3]
R = json.load(open(RES))
d = docx.Document(SRC)
P = d.paragraphs


def find(prefix, style=None, start=0):
    for i, p in enumerate(d.paragraphs):
        if i >= start and p.text.strip().startswith(prefix) and (style is None or p.style.name == style):
            return p
    raise KeyError(prefix)


def set_runs(par, text, lead=None, keep_rpr=False):
    """Replace a paragraph's runs with [bold lead] + text."""
    rpr = None
    old = par._p.findall(qn("w:r"))
    if keep_rpr and old and old[-1].find(qn("w:rPr")) is not None:
        rpr = deepcopy(old[-1].find(qn("w:rPr")))
        for b in rpr.findall(qn("w:b")):
            rpr.remove(b)
    for r in old:
        par._p.remove(r)
    for h in par._p.findall(qn("w:hyperlink")):
        par._p.remove(h)
    if lead:
        r = par.add_run(lead)
        r.bold = True
        text = " " + text
    r = par.add_run(text)
    if rpr is not None:
        r._r.insert(0, rpr)
    return par


def clone_after(anchor, template, text, lead=None):
    el = deepcopy(template._p)
    anchor_el = anchor._p if isinstance(anchor, Paragraph) else anchor._tbl
    anchor_el.addnext(el)
    return set_runs(Paragraph(el, template._parent), text, lead)


def picture_after(anchor, template_img_par, path, width_emu):
    el = deepcopy(template_img_par._p)
    anchor._p.addnext(el)
    par = Paragraph(el, template_img_par._parent)
    for r in par._p.findall(qn("w:r")):
        par._p.remove(r)
    par.add_run().add_picture(path, width=Emu(width_emu))
    return par


def set_cell(cell, text):
    set_runs(cell.paragraphs[0], text, keep_rpr=True)
    for extra in cell.paragraphs[1:]:
        extra._p.getparent().remove(extra._p)


def add_row(table, after_row_idx, values, template_row_idx=None):
    tr = deepcopy(table.rows[template_row_idx if template_row_idx is not None else after_row_idx]._tr)
    table.rows[after_row_idx]._tr.addnext(tr)
    row = table.rows[after_row_idx + 1]
    for c, v in zip(row.cells, values):
        set_cell(c, v)
    return row


def table_after(anchor, template_table, rows):
    """Clone ``template_table`` after ``anchor`` and fill it with ``rows`` (first = header)."""
    tbl = deepcopy(template_table._tbl)
    anchor._p.addnext(tbl)
    t = Table(tbl, anchor._parent)
    while len(t.rows) > len(rows):
        t._tbl.remove(t.rows[-1]._tr)
    while len(t.rows) < len(rows):
        t.rows[-1]._tr.addnext(deepcopy(t.rows[-1]._tr))
    for r, vals in zip(t.rows, rows):
        for c, v in zip(r.cells, vals):
            set_cell(c, str(v))
    return t


def table_of(title_par):
    el = title_par._p.getnext()
    while el is not None and el.tag != qn("w:tbl"):
        el = el.getnext()
    return Table(el, title_par._parent)


def after_table(title_par):
    """The paragraph right after the table that follows ``title_par``."""
    t = table_of(title_par)
    return Paragraph(t._tbl.getnext(), title_par._parent)


body = find("The proposed solution is a layered")
bullet = find("Capture.")
h21 = find("1.1 Organisation of the Report", "Heading 21")
h31 = find("6.4.6 Dashboard and feedback", "Heading 31")
ttl = find("Table 10.1:", "Table Title")
cap = find("Figure 10.1:", "Caption Text")
img_wide = d.paragraphs[[i for i, p in enumerate(d.paragraphs) if p.text.startswith("Figure 6.1:")][0] - 1]
fig61_width = img_wide._p.findall(".//" + qn("wp:extent"))[0].get("cx")

# ---------------------------------------------------------------- abstract
p = find("The system was evaluated on 60 days of simulated logs")
p = clone_after(p, body, (
    "The system was then made to operate as a product rather than a one-off script. Logs arrive by upload "
    "with automatic column mapping, a drop folder, a token-authenticated ingest API or an endpoint agent; a "
    "collector service scores new data incrementally with saved models, which gives exactly the same result "
    "as a full re-run, and notifies analysts by webhook or e-mail. The console is protected by accounts with "
    "roles, salted password hashes, lock-out, scoped API tokens and an audit trail. Replaying the simulated "
    "organisation through the API as a live feed reproduced the batch result exactly (11/11 attacks, F1-score "
    "0.964). " + R["abstract_cert"]))

# ---------------------------------------------------------------- chapter 4
p = find("Three ideas make the solution practical")
clone_after(p, body, (
    "The solution also runs as a continuous system rather than a one-off script (Figure 6.6). Logs reach a "
    "workspace by upload, a drop folder, an authenticated HTTP API or an endpoint agent; a collector service "
    "imports them every few seconds, scores only what changed using the saved models, and notifies analysts "
    "of new or escalated alerts. The console requires sign-in, enforces viewer, analyst and administrator "
    "roles, and records every security-relevant action in an audit trail."))

# ---------------------------------------------------------------- objectives
p = find("To evaluate the system objectively")
p = clone_after(p, find("To provide an analyst dashboard"), (
    "To operate continuously and securely: collect logs automatically from several sources, score new data "
    "incrementally with the same result as a full re-analysis, notify analysts, and protect the console with "
    "accounts, roles, API tokens and an audit trail."))
clone_after(p, find("To provide an analyst dashboard"), (
    "To validate the system on an independent public benchmark (CMU CERT r4.2) in addition to the simulated "
    "organisation."))

# ---------------------------------------------------------------- 6.3 requirements
t = table_of(find("Table 6.4:", "Table Title"))
set_cell(t.rows[1].cells[1], "Accept authentication, access, network and resource logs as CSV, JSON or JSON-lines "
         "files (or ZIP archives), detect the log type, map and validate the columns, and normalise the values.")
set_cell(t.rows[8].cells[1], "Show overview, alerts, entity investigation, model performance, data sources, live "
         "host monitor, log explorer and administration pages, refreshed automatically when new results arrive.")
new_frs = [
    ("FR10", "Collect logs automatically from a drop folder, a token-authenticated HTTP ingest API and an endpoint "
             "agent, in addition to uploads."),
    ("FR11", "Keep independent workspaces, each moving from learning to monitoring once its learning period is covered."),
    ("FR12", "Score new data incrementally with the saved models, with exactly the same result as a full re-run."),
    ("FR13", "Notify analysts of new or escalated alerts by webhook or e-mail, without duplicates."),
    ("FR14", "Require sign-in with viewer, analyst and administrator roles; scope API tokens to a workspace; audit "
             "every security-relevant action."),
]
for i, (k, v) in enumerate(new_frs):
    add_row(t, len(t.rows) - 1, (k, v))
p = find("Performance: analyse about 205,000 events")
set_runs(p, "analyse about 205,000 events for 108 entities in about 5 seconds on a laptop; an incremental update "
            "takes about 3 seconds, and new data is analysed within one collector-service pass (10 seconds by "
            "default).", lead="Performance:")
p = find("Reliability: behaviour verified by")
set_runs(p, "behaviour verified by 24 automated tests; one malformed file or workspace never stops the collector "
            "service.", lead="Reliability:")
clone_after(p, p, "PBKDF2-hashed passwords with lock-out, workspace-scoped API tokens stored only as hashes, "
                  "role-based permissions, an audit trail, and services bound to the local machine by default.",
            lead="Security:")

# ---------------------------------------------------------------- 6.4.6 + new 6.4.7 / 6.4.8
p = find("The Streamlit dashboard has six pages")
set_runs(p, "The Streamlit console has eight pages behind a sign-in screen: an overview of alerts and risk, an "
            "alert queue with an explained detail view and verdict buttons, an entity investigation page "
            "(profile, risk timeline, biggest deviations, login hours and event timeline), a model performance "
            "page with a threshold slider, a data sources page (uploads with column mapping, automatic "
            "collection, notification settings), a live host monitor, a log explorer and an administration page "
            "(users, API tokens, audit log, service health). Pages refresh by themselves when new results "
            "arrive. Each workspace keeps its results in its own SQLite database.")
h = clone_after(p, h31, "6.4.7 Continuous operation")
p = clone_after(h, body, (
    "Each monitored environment is a workspace with its own logs, models, alerts and analyst verdicts. A "
    "workspace is learning until its logs cover the learning period (30 days by default) and monitoring "
    "afterwards. Logs reach it by four routes that all end in the same import step (log-type detection, "
    "column mapping, value normalisation and de-duplicated append):"))
routes = [
    ("Upload.", "CSV, JSON or ZIP exports in the dashboard, with automatic column mapping (for example "
                "TimeCreated to timestamp, TargetUserName to user) and a preview before import; the mapping is "
                "remembered for later files with the same columns."),
    ("Drop folder.", "Files copied into the workspace's inbox folder are imported automatically; rejected files "
                     "are moved aside with a file explaining why."),
    ("Ingest API.", "Agents and log shippers send batches over HTTP with a workspace-scoped token; the API only "
                    "authenticates and queues the batch, so all data follows one code path."),
    ("Endpoint agent.", "Streams a machine's CPU, memory, disk, process and connection data every 15 seconds and "
                        "keeps data while the server is unreachable."),
]
BULLET_NUM = find("Statistical layer:")._p.find(".//" + qn("w:numId")).get(qn("w:val"))


def as_bullet(par):
    """Use the bullet list of section 6.4.4 (the chapter-4 template is a numbered list)."""
    par._p.find(".//" + qn("w:numId")).set(qn("w:val"), BULLET_NUM)
    return par


for lead, txt in routes:
    p = as_bullet(clone_after(p, bullet, txt, lead=lead))
p = clone_after(p, body, (
    "The analysis is incremental. The first analysis after the learning period trains the baselines and the "
    "ML ensemble and saves them with a fingerprint of the settings. Later analyses reuse them: days already "
    "scored keep their scores and their accept or quarantine decisions, and only days from the earliest "
    "changed day onwards are scored (the last day always, because it may have been partial). Because every "
    "feature is computed only from earlier days, this gives exactly the same scores and alerts as a full "
    "re-run, which an automated test checks at a day boundary and in the middle of a day. A full re-training "
    "happens automatically when the settings, the learning period, the user directory or the asset inventory "
    "change. An analyst verdict on a day marks the following days for re-scoring, so a day cleared as benign "
    "is learned into the baseline for the days after it."))
p = clone_after(p, body, (
    "A collector service runs this loop every 10 seconds: import the inbox, analyse incrementally if anything "
    "changed, and send notifications. Notifications go to a webhook (Slack, Microsoft Teams, Discord or any "
    "JSON endpoint) or by e-mail; each alert is sent once and again only if its severity increases, and "
    "imported history older than seven days stays quiet. Workspace changes run under a file lock so the "
    "service and the dashboard cannot corrupt each other, and the service writes a heartbeat that the "
    "dashboard shows."))
h = clone_after(p, h31, "6.4.8 Security of the console")
p = clone_after(h, body, "A tool that holds an organisation's security logs must itself be secure:")
sec = [
    ("Accounts and roles.", "Viewers can only read, analysts can also record alert verdicts, and administrators "
                            "can also manage data, analyses, settings, users and tokens. The first start creates "
                            "the administrator account."),
    ("Passwords.", "Stored as PBKDF2-HMAC-SHA256 hashes (310,000 iterations, a random salt per user) and compared "
                   "in constant time; five failed logins lock the account for 15 minutes; sessions expire after "
                   "eight hours."),
    ("API tokens.", "256-bit random tokens shown once, stored only as SHA-256 hashes, limited to one workspace and "
                    "revocable."),
    ("Audit trail.", "Logins and failed logins, verdicts, uploads, analyses, setting changes, users and tokens are "
                     "recorded and can be exported."),
    ("Exposure.", "The console and the API listen only on the local machine by default; serving a team requires "
                  "a reverse proxy with TLS."),
]
for lead, txt in sec:
    p = as_bullet(clone_after(p, bullet, txt, lead=lead))

# ---------------------------------------------------------------- 6.5 figure 6.6
p = find("Figure 6.5:", "Caption Text")
p = picture_after(p, img_wide, R["fig_ops"], int(fig61_width))
clone_after(p, find("Figure 6.5:", "Caption Text"),
            "Figure 6.6: Operational architecture - how logs arrive, are scored continuously and reach analysts")

# ---------------------------------------------------------------- chapter 7
t = table_of(find("Table 7.2:", "Table Title"))
add_row(t, 8, ("Python standard library", "Bundled with Python",
               "Ingest API (http.server), password hashing (hashlib), notifications (smtplib, urllib), file locking"))
p = find("CMU CERT Insider Threat Test Dataset r4.2")
set_runs(p, R["dataset_cert"], lead="CMU CERT Insider Threat Test Dataset r4.2 [14]:")
p = find("Live host data:")
set_runs(p, "CPU, memory, process and connection samples captured from the machine running the dashboard and "
            "streamed by the endpoint agent.", lead="Live host data:")
t = table_of(find("Table 7.3:", "Table Title"))
add_row(t, 7, ("Service, API and security", "Python standard library: http.server, hashlib (PBKDF2, SHA-256), "
                                             "secrets, smtplib, urllib, fcntl"))

# ---------------------------------------------------------------- chapter 8
t = table_of(find("Table 8.1:", "Table Title"))
add_row(t, len(t.rows) - 1, ("Continuous operation with exact incremental scoring", "Offline batch evaluation in "
                             "most work", "Yes: saved models, only changed days re-scored, identical to a full re-run"))
add_row(t, len(t.rows) - 1, ("Secured console and ingestion", "Not addressed", "Roles, hashed passwords, lock-out, "
                             "scoped API tokens, audit trail"))
p = find("Designed from analyst needs.")
p = clone_after(p, p, "Saved models are reused and only the days touched by new data are scored, and because "
                      "all features are causal the result is provably identical to re-analysing everything - "
                      "a property checked by an automated test rather than assumed.", lead="Exact incremental scoring.")
clone_after(p, p, "Collection, scoring, notification and a secured console are delivered in one small Python "
                  "codebase using only the standard library beyond the analytics stack.",
            lead="Operable as a product.")

# ---------------------------------------------------------------- chapter 9
p = find("Threshold sweep:")
for lead, txt in [
    ("CERT r4.2 benchmark:", R["exp_cert"]),
    ("Incremental equivalence:", "the logs were cut at a day boundary and in the middle of a day, analysed, then "
                                 "completed and updated incrementally; scores, explanations and alerts were compared "
                                 "with a full re-run."),
    ("Live operation:", "the simulated organisation was streamed through the ingest API (30 days of history, then "
                        "one day every few seconds in slices) while the collector service imported, scored and "
                        "notified, and the result was compared with the batch run."),
]:
    p = clone_after(p, p, txt, lead=lead)
p = find("Functional tests:")
set_runs(p, "24 automated tests covering distance calculation, unusual-hour logic, rules, risk-score bounds and "
            "corroboration, the full pipeline, the analyst feedback loop, the CERT adapter, log-format mapping, "
            "partial log streams, incremental equivalence, the inbox, the ingest API, passwords, roles, lock-out "
            "and tokens, notification de-duplication, and a collector-service pass that learns, detects and "
            "notifies.", lead="Functional tests:")
p = find("All experiments were run in Python")
set_runs(p, "All experiments were run in Python 3.14 on a laptop (16 GB RAM). One full analysis of the simulated "
            "organisation (about 205,000 events) takes about 5 seconds and an incremental update about 3 seconds; "
            + R["timing_cert"])

# ---------------------------------------------------------------- chapter 10: new 10.5 / 10.6, renumber
dash = find("10.5 Dashboard", "Heading 21")
disc = find("10.6 Discussion", "Heading 21")
set_runs(dash, "10.7 Dashboard")
set_runs(disc, "10.8 Discussion")
# figures in the dashboard section move from 10.4/10.5 to 10.5/10.6
f4 = find("Figure 10.4:", "Caption Text")
f5 = find("Figure 10.5:", "Caption Text")
set_runs(f5, f5.text.replace("Figure 10.5", "Figure 10.6"))
set_runs(f4, f4.text.replace("Figure 10.4", "Figure 10.5"))
for par in d.paragraphs:                           # fix cross-references in the text
    if par.style.name in ("Normal",) and ("Figure 10.4" in par.text or "Figure 10.5" in par.text):
        set_runs(par, par.text.replace("Figure 10.5", "Figure 10.6").replace("Figure 10.4", "Figure 10.5"))

anchor = Paragraph(dash._p.getprevious(), dash._parent)          # end of 10.4
h = clone_after(anchor, h21, "10.5 Results on the CERT r4.2 Benchmark")
p = clone_after(h, body, R["cert_intro"])
tt = clone_after(p, ttl, "Table 10.6: Results on CERT r4.2 (detection window, user-days)")
t = table_after(tt, table_of(find("Table 10.2:", "Table Title")), R["cert_table"])
sp = Paragraph(deepcopy(after_table(ttl)._p), dash._parent)
t._tbl.addnext(sp._p)
p = clone_after(sp, body, R["cert_layers_intro"])
tt = clone_after(p, ttl, "Table 10.7: Ranking quality of each layer on CERT r4.2")
t = table_after(tt, table_of(find("Table 10.2:", "Table Title")), R["cert_layers"])
sp = Paragraph(deepcopy(after_table(ttl)._p), dash._parent)
t._tbl.addnext(sp._p)
p = picture_after(sp, find("Figure 10.1:", "Caption Text")._p.getprevious() is not None and
                  Paragraph(find("Figure 10.1:", "Caption Text")._p.getprevious(), dash._parent),
                  R["cert_fig"], int(R.get("cert_fig_width", 4023360)))
p = clone_after(p, cap, "Figure 10.4: CERT r4.2 - (a) ROC curve of each layer, (b) insiders found for a daily review budget (all 72 labelled accounts)")
for txt in R["cert_discussion"]:
    p = clone_after(p, body, txt)

h = clone_after(p, h21, "10.6 Continuous Operation")
p = clone_after(h, body, (
    "Two experiments checked that the operational system gives the same answers as the batch analysis. In the "
    "first, the logs were cut at a day boundary and in the middle of a day, analysed, then completed and updated "
    "incrementally: every score, explanation and alert was identical to a full re-run. In the second, the "
    "simulated organisation was streamed through the ingest API as a live feed while the collector service ran "
    "(Table 10.8)."))
tt = clone_after(p, ttl, "Table 10.8: Live replay of the simulated organisation through the ingest API")
t = table_after(tt, table_of(ttl), [
    ("Measure", "Value"),
    ("Data sent", "30 days of history, then 30 live days in slices of 8 hours"),
    ("Analyses run by the service", "2 full trainings (learning, first detection day) + 29 incremental updates"),
    ("Time per incremental update", "1.6 - 3.2 seconds"),
    ("Rejected files / service errors", "0 / 0"),
    ("Incidents detected", "11 / 11, each in the service pass after its data arrived"),
    ("Precision / Recall / F1-score", "0.964 / 0.964 / 0.964 (identical to the batch run)"),
])
sp = Paragraph(deepcopy(after_table(ttl)._p), dash._parent)
t._tbl.addnext(sp._p)
clone_after(sp, body, (
    "The live result equals the batch result because features are causal and the incremental engine re-scores "
    "exactly the days whose data changed. In a real deployment a day lasts a day, so the service, which needs "
    "about three seconds per update, is never the bottleneck; detection delay is bounded by how often logs are "
    "shipped, not by the analysis."))

p = find("The results show that the system meets its objectives")
clone_after(p, body, R["discussion_extra"])

# ---------------------------------------------------------------- chapter 11
p = find("On 60 days of simulated logs with 11 planted attacks")
clone_after(p, body, (
    "Beyond the analytics, the project delivers an operable system: logs arrive by upload, drop folder, "
    "authenticated API or endpoint agent; a collector service scores new data incrementally with exactly the "
    "same result as a full re-run and notifies analysts; and the console is protected by roles, hashed "
    "passwords, lock-out, scoped tokens and an audit trail. " + R["conclusion_cert"]))
set_runs(find("Evaluation on real and benchmark data:"), R["future_eval"], lead="Quiet insiders and more data:")
set_runs(find("Real-time detection:"), "the collector service already analyses new data within seconds of its "
         "arrival; per-event streaming (for example with Apache Kafka) would add intra-day sequence detection.",
         lead="Event-level streaming:")
set_runs(find("Real deployment:"), "parse native Windows Event (EVTX), Sysmon and syslog formats directly, serve "
         "the console and API through TLS, move storage to PostgreSQL for larger organisations, and adopt a "
         "monitoring policy compliant with data-protection law.", lead="Real deployment:")

# ---------------------------------------------------------------- source code + abbreviations
set_runs(find("The complete source code"), R["source_code"])
t = d.tables[1]
abbr = {"API": "Application Programming Interface", "PBKDF2": "Password-Based Key Derivation Function 2",
        "SHA-256": "Secure Hash Algorithm, 256-bit", "SMTP": "Simple Mail Transfer Protocol",
        "SOAR": "Security Orchestration, Automation and Response", "TLS": "Transport Layer Security"}
for k, v in abbr.items():
    keys = [r.cells[0].text for r in t.rows]
    pos = max(i for i, x in enumerate(keys) if i == 0 or x.lower() < k.lower())
    add_row(t, pos, (k, v), template_row_idx=1)

# ---------------------------------------------------------------- rule count 20 -> 21 (run level, keeps formatting)
def replace_in_runs(container_pars, old, new):
    n = 0
    for par in container_pars:
        for r in par.runs:
            if old in r.text:
                r.text = r.text.replace(old, new)
                n += 1
    return n


all_pars = list(d.paragraphs) + [p for t in d.tables for row in t.rows for c in row.cells for p in c.paragraphs]
for old, new in (("20 threat rules", "21 threat rules"), ("20 MITRE", "21 MITRE"), ("20 rules", "21 rules"),
                 ("first three of twenty", "first three of twenty-one")):
    print(old, "->", replace_in_runs(all_pars, old, new))
p = find("Threat rules: 21 rules")
p.add_run(" Rule R16 (removable-media use by an account that never used removable media in its learning period, "
          "T1052.001) was added after the CERT evaluation (Section 10.5).")

d.save(OUT)
print("saved", OUT)


# ---------------------------------------------------------------- contents page numbers (Word pagination)
import re as _re
d = docx.Document(OUT)
NEW_PAGES = {"7. Requirements": 24, "8. Novelty": 26, "9. Experimentation": 28, "10. Results": 30, "11. Conclusion": 37,
             "References": 39, "Source Code": 41, "Submission Page": 44, "Plagiarism Report": 45}
start = next(i for i, p in enumerate(d.paragraphs) if p.text.strip() == "CONTENTS")
done = 0
for p in d.paragraphs[start:start + 40]:
    for k, v in NEW_PAGES.items():
        if p.text.strip().startswith(k) and _re.search(r"\d+\s*$", p.text):
            r = [r for r in p.runs if _re.search(r"\d", r.text)][-1]
            r.text = _re.sub(r"\d+(\s*)$", rf"{v}\1", r.text)
            done += 1
print("contents entries updated:", done)
d.save(OUT)
