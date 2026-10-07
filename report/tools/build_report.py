"""Build the concise project report from the original document.

    python report/tools/build_report.py  ORIGINAL.docx  OUTPUT.docx

Keeps the front matter (title page, certificate, declaration, acknowledgement, abbreviations),
the references and the end pages exactly as they are, rewrites the abstract and chapters 1-11
concisely, and trims the source-code appendix. Every new element is cloned from an existing
one, so fonts, spacing, numbering and table styles stay those of the university template.
Figures are read from report/diagrams, report/screens and reports/figures.
"""
from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path

import docx
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Emu, Inches
from docx.table import Table
from docx.text.paragraph import Paragraph

ROOT = Path(__file__).resolve().parents[2]
SRC, OUT = sys.argv[1], sys.argv[2]
d = docx.Document(SRC)


# ---------------------------------------------------------------- helpers
def find(prefix, style=None):
    for p in d.paragraphs:
        if p.text.strip().startswith(prefix) and (style is None or p.style.name == style):
            return p
    raise KeyError(prefix)


def set_runs(par, text, lead=None, keep_rpr=False):
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


def set_cell(cell, text, bold=False):
    par = cell.paragraphs[0]
    set_runs(par, text, keep_rpr=True)
    if bold:
        for r in par.runs:
            r.bold = True
    for extra in cell.paragraphs[1:]:
        extra._p.getparent().remove(extra._p)


def table_of(title_par):
    el = title_par._p.getnext()
    while el is not None and el.tag != qn("w:tbl"):
        el = el.getnext()
    return Table(el, title_par._parent)


# ---------------------------------------------------------------- templates (cloned before deleting the body)
T = {
    "h1": deepcopy(find("1. INTRODUCTION", "Heading 1")._p),
    "h2": deepcopy(find("1.1 Organisation of the Report")._p),
    "h3": deepcopy(find("6.4.1 Log capture", "Heading 31")._p),
    "p": deepcopy(find("Organisations depend on user accounts")._p),
    "b": deepcopy(find("Statistical layer:")._p),
    "tt": deepcopy(find("Table 10.1:", "Table Title")._p),
    "cap": deepcopy(find("Figure 10.1:", "Caption Text")._p),
    "img": deepcopy(find("Figure 6.1:", "Caption Text")._p.getprevious()),
    "spacer": deepcopy(find("Table 10.1:", "Table Title")._p),
}
TABLES = {n: deepcopy(table_of(find(f"Table {t}:", "Table Title"))._tbl)
          for n, t in ((2, "10.1"), (3, "10.2"), (4, "9.1"), (5, "10.4"), (7, "2.1"))}
# a page-break paragraph: find the paragraph that holds the break before chapter 2
brk = None
for p in d.paragraphs:
    if not p.text.strip() and not p._p.xpath(".//pic:pic") and \
            any(b.get(qn("w:type")) == "page" for b in p._p.findall(".//" + qn("w:br"))):
        brk = deepcopy(p._p)          # an empty paragraph that only holds a page break
        break

body_parent = find("1. INTRODUCTION", "Heading 1")._parent
anchor_el = None


def emit(el):
    """Insert a cloned element after the previous one. Bookmarks copied from the template would
    duplicate ids, so they are stripped."""
    global anchor_el
    for tag in ("w:bookmarkStart", "w:bookmarkEnd"):
        for b in el.findall(".//" + qn(tag)):
            b.getparent().remove(b)
    anchor_el.addnext(el)
    anchor_el = el
    return el


def par(kind, text="", lead=None):
    el = deepcopy(T[kind])
    emit(el)
    return set_runs(Paragraph(el, body_parent), text, lead)


def page_break():
    if brk is not None:
        emit(deepcopy(brk))
    else:
        p = par("p")
        p.add_run().add_break(docx.enum.text.WD_BREAK.PAGE)


def h1(text):
    page_break()
    return par("h1", text)


def bullets(items):
    for it in items:
        if isinstance(it, tuple):
            par("b", it[1], lead=it[0])
        else:
            par("b", it)


def table(title, rows, header=True, widths=None):
    par("tt", title)
    n = len(rows[0])
    tbl = deepcopy(TABLES[n])
    emit(tbl)
    t = Table(tbl, body_parent)
    while len(t.rows) > len(rows):
        t._tbl.remove(t.rows[-1]._tr)
    while len(t.rows) < len(rows):
        t.rows[-1]._tr.addnext(deepcopy(t.rows[-1]._tr))
    for i, (r, vals) in enumerate(zip(t.rows, rows)):
        for c, v in zip(r.cells, vals):
            set_cell(c, str(v), bold=header and i == 0)
    if widths:                                 # relative widths -> keep the table's total width
        grid = t._tbl.find(qn("w:tblGrid"))
        cols = grid.findall(qn("w:gridCol"))
        total = sum(int(c.get(qn("w:w"))) for c in cols)
        new = [int(total * w / sum(widths)) for w in widths]
        for c, w in zip(cols, new):
            c.set(qn("w:w"), str(w))
        for r in t.rows:
            for c, w in zip(r._tr.findall(qn("w:tc")), new):
                tcw = c.find(qn("w:tcPr")).find(qn("w:tcW"))
                if tcw is not None:
                    tcw.set(qn("w:w"), str(w))
                    tcw.set(qn("w:type"), "dxa")
    sp = deepcopy(T["p"])
    emit(sp)
    set_runs(Paragraph(sp, body_parent), "")
    return t


def figure(path, caption, width_in=6.3):
    el = deepcopy(T["img"])
    emit(el)
    p = Paragraph(el, body_parent)
    for r in p._p.findall(qn("w:r")):
        p._p.remove(r)
    p.add_run().add_picture(str(ROOT / path), width=Inches(width_in))
    par("cap", caption)


# ---------------------------------------------------------------- delete the old body (chapter 1 .. before REFERENCES)
start = find("1. INTRODUCTION", "Heading 1")._p
end = find("REFERENCES", "Heading 1")._p
el = start.getprevious()          # the page break / spacer before chapter 1 stays
anchor_el = el
cur = start
while cur is not None and cur is not end:
    nxt = cur.getnext()
    cur.getparent().remove(cur)
    cur = nxt

# ================================================================= 1. INTRODUCTION
par("h1", "1. INTRODUCTION")
par("p", "Most breaches now start with valid credentials or with an insider, not with malware: credential abuse is the "
         "most common initial access vector in the 2025 Verizon DBIR and the human element is involved in about 60% of "
         "breaches [1], while insider incidents cost organisations US$17.4 million a year on average [2]. Tools that "
         "look for known-bad signatures cannot see these attacks, because every individual log line looks legitimate. "
         "What gives them away is behaviour: a salesperson logging in at 3 a.m. from abroad, an engineer opening ninety "
         "files instead of fifteen, a laptop uploading gigabytes to a site it has never used.")
par("p", "User and Entity Behaviour Analytics (UEBA) learns what is normal for every user and device and flags "
         "deviations [3]. Its practical difficulty is false alarms: analysts already report being flooded by alerts "
         "that turn out to be harmless [4]. A useful UEBA system therefore has to be accurate, quiet, explain itself, "
         "and fit into how a security team actually works.")
par("p", "This project builds such a system in Python and takes it from analytics to an operable product. It captures "
         "authentication, system-access, network and resource-usage logs; profiles users and devices against their own "
         "history and their department; detects deviations with statistics, an unsupervised machine-learning ensemble "
         "and MITRE ATT&CK rules [5]; and turns the evidence into explained, risk-ranked alerts. Around this core it "
         "collects logs continuously, scores new data incrementally, groups alerts into cases for analysts, sends "
         "notifications and protects itself with accounts, roles and an audit trail. It is evaluated on a simulated "
         "organisation with planted attacks and on the public CMU CERT r4.2 insider-threat benchmark [14].")
par("h2", "1.1 Organisation of the Report")
par("p", "Chapter 2 reviews related research; Chapters 3-5 define the problem, the solution and the objectives; Chapter 6 "
         "describes the methodology and design, and gives the reason for every feature; Chapters 7 and 8 list the "
         "requirements and the novelty; Chapters 9 and 10 present the experiments and results; Chapter 11 concludes.")

# ================================================================= 2. LITERATURE REVIEW
h1("2. LITERATURE REVIEW")
PAPERS = [
    ("A User and Entity Behavior Analytics Log Data Set for Anomaly Detection in Cloud Computing [3]", "IEEE BigData 2022",
     "Publishes CLUE-LDS, real logs of 5,000+ users of a cloud file-sharing service over five years, injects account "
     "hijacking by swapping similar users, and proposes an adaptive detector that retrains when behaviour changes.",
     "A rare real UEBA data set; 65% true positives at a 4.6% false positive rate. Uses event-type counts from one source, "
     "simulated attacks, and no explanation or prioritisation; warns that synthetic data under-states false alarms.",
     "Supports our adaptive baseline and our caution about synthetic results."),
    ("Multi-homed Abnormal Behavior Detection Algorithm Based on Fuzzy Particle Swarm Cluster in UEBA [6]", "Scientific Reports 2022",
     "MAD-FPC clusters entity behaviour with fuzzy clustering tuned by particle-swarm optimisation and weights rare "
     "behaviour with a TF-IDF-like measure.",
     "F1 0.93 on data derived from NSL-KDD. The data is an old intrusion set rather than behaviour logs, the model is "
     "static, and anomalies are not explained.",
     "Supports profiling entities (devices) as well as users, and weighting rare behaviour (our novelty features)."),
    ("Cybersecurity Threat Detection Based on a UEBA Framework Using Deep Autoencoders [7]", "AIMS Mathematics 2025",
     "A deep autoencoder over numeric and Doc2Vec-embedded text fields of a bank's logs; reconstruction residuals explain "
     "which fields were anomalous.",
     "Handles mixed logs and gives feature-level explanations, but the data had no labels, so no detection metrics; a "
     "single model and no risk score.",
     "The closest explainable UEBA; supports the autoencoder in our ensemble."),
    ("Hunting for Insider Threats Using LSTM-Based Anomaly Detection [8]", "IEEE TDSC 2023",
     "LADOHD learns the expected order of endpoint events with LSTMs and flags sequences that do not fit, even across days.",
     "97.29% true positives at 0.38% false positives on 38.9 M events from 30 computers; one data source, one "
     "organisation, unexplained alerts.",
     "Shows what sequence models achieve; our results on gradual CERT insiders point to it as future work."),
    ("Dual-Domain Graph Convolutional Network for Insider Threat Detection (DD-GCN) [9]", "IEEE TIFS 2023",
     "Builds graphs of users' features and relationships and applies graph convolution in two domains.",
     "98.2% / 98.7% accuracy on CERT r4.2 / r6.2, but semi-supervised (needs labelled users), users only, no explanation.",
     "Supports comparing users with related users; we use simpler, label-free department peer baselines."),
    ("LAN: Learning Adaptive Neighbors for Real-Time Insider Threat Detection [10]", "IEEE TIFS 2024",
     "Detects malicious activities in real time with graph structure learning over activity sequences and a hybrid "
     "self-supervised / supervised loss.",
     "At least 9.9% higher AUC than nine baselines on CERT r4.2 / r5.2; uses labels from abnormal activities, users only, "
     "no explanation.",
     "Shows the move to real-time detection; our collector service scores new data within seconds."),
    ("AUTH: An Adversarial Autoencoder Based Unsupervised Insider Threat Detection Scheme [11]", "IEEE TII 2024",
     "A fully unsupervised adversarial autoencoder (TCN + LSTM encoder) over time and event features from several logs.",
     "AUC 0.932 on a public insider data set; users only, no explanation or ranking, no protection against baseline "
     "poisoning.",
     "Supports unsupervised learning and time-of-day features."),
    ("Euler: Detecting Network Lateral Movement via Scalable Temporal Link Prediction [12]", "ACM TOPS 2023",
     "Treats lateral movement as unlikely new edges in a series of host graphs (GNN + recurrent model).",
     "AUC 0.99 on 1.6 B real LANL events, yet precision only about 0.006 - almost every alert false. Hosts only, no "
     "explanation.",
     "Strong evidence that ranking quality is not enough: our design requires corroboration before alerting."),
    ("DEEPCASE: Semi-Supervised Contextual Analysis of Security Events [13]", "IEEE S&P 2022",
     "Learns the context of security events with attention, clusters similar sequences, and lets analysts label a few "
     "per cluster.",
     "Cut analysts' manual work by 90.5% on 10.5 M events from 20 organisations; works on existing alerts, needs labels.",
     "Supports explained alerts, analyst feedback and our grouping of alerts into cases."),
]
for i, (title, venue, abstract, acc, scope) in enumerate(PAPERS, 1):
    par("h2", f"2.{i} Paper {i}: {title}")
    par("p", f"{venue}. {abstract}", lead="Abstract:")
    par("p", acc, lead="Accomplishments and limitations:")
    par("p", scope, lead="Scope:")
par("h2", "2.10 Comparison and Research Gap")
table("Table 2.1: Comparison of the reviewed papers", [
    ("Paper", "Data", "Technique", "Profiles", "Labels", "Explained", "Key result"),
    ("[3] 2022", "Real cloud logs", "Adaptive similarity", "Users", "No", "No", "TPR 65%, FPR 4.6%"),
    ("[6] 2022", "NSL-KDD", "Fuzzy PSO clusters", "Users+entities", "No", "No", "F1 0.93"),
    ("[7] 2025", "Real bank logs", "Autoencoder", "Users+entities", "No", "Yes", "no labelled metrics"),
    ("[8] 2023", "Real EDR, 30 PCs", "LSTM", "Endpoints", "No", "No", "TPR 97.3%, FPR 0.38%"),
    ("[9] 2023", "CERT r4.2, r6.2", "Graph conv.", "Users", "Some", "No", "Acc. 98.2%"),
    ("[10] 2024", "CERT r4.2, r5.2", "Graph + sequence", "Users", "Some", "No", "+9.9% AUC"),
    ("[11] 2024", "Public insider", "Adversarial AE", "Users", "No", "No", "AUC 0.932"),
    ("[12] 2023", "LANL, 1.6 B", "Temporal GNN", "Hosts", "No", "No", "precision 0.006"),
    ("[13] 2022", "20 orgs", "Attention", "Alerts", "Some", "Yes", "workload -90%"),
    ("This work", "Simulated + CERT", "Stats + ML + rules", "Users+devices", "No", "Yes", "Ch. 10"),
], widths=[1.0, 1.55, 1.55, 1.45, 0.8, 1.05, 1.6])
par("p", "Accuracy on public benchmarks is already high [9]-[11], but these systems profile users only, often need "
         "labels, and stop at an unexplained score. Entity profiling [6], [12], explanation [7], [13] and adaptive "
         "baselines [3] exist separately. None protects its baseline against slow poisoning, none corroborates "
         "machine-learning anomalies with rules to cut false alarms - although [12] shows the cost - and none is "
         "delivered as a system a security team can operate. The gap addressed here is integration and usability: "
         "users and devices profiled together, adaptive but poisoning-resistant baselines, corroborated and explained "
         "risk scores, and the collection, workflow and security needed to use them.")
par("h2", "2.11 Any Other Sources")
par("p", "MITRE ATT&CK [5] for rule technique IDs; the Verizon DBIR [1] and Cost of Insider Risks report [2] for "
         "statistics; the CMU CERT data set [14] as benchmark; studies of SOC analysts [4], [15]-[17] for the personas; "
         "and scikit-learn and the original model papers [18]-[21].")

# ================================================================= 3. PROBLEM / SCOPE
h1("3. IDENTIFICATION OF THE PROBLEM / SCOPE OF THE PROJECT")
par("h2", "3.1 Problem Identification")
par("p", "Attacks through valid accounts - stolen credentials, account takeover, malicious insiders - look legitimate "
         "event by event, so signature tools miss them and damage is found weeks later [2]. Behaviour-based detection "
         "can find them, but in practice it:")
bullets([("raises too many false alarms", "- analysts report most alerts are benign [4]; a high AUC can still mean "
                                           "precision below 1% [12];"),
         ("does not explain itself", "- analysts distrust scores they cannot understand [17];"),
         ("profiles users only", "- although cryptomining or a pivot laptop shows up on machines;"),
         ("uses static or unprotected baselines", "- stale as habits change, or slowly poisoned by an attacker;"),
         ("stops at a score", "- with no ranking, case handling, collection or protection of the tool itself.")])
par("p", "Problem statement: develop a Python-based UEBA system that captures authentication, system-access, network "
         "and resource-usage logs, builds behavioural profiles for users and devices, identifies deviations from normal "
         "behaviour, and generates accurate, explained, risk-based alerts that a security team can operate on real logs.")
par("h2", "3.2 Scope of the Project")
par("p", "In scope: four log streams from uploads, a drop folder, an authenticated API and an endpoint agent; user and "
         "device profiles; three detection layers with risk fusion; cases, suppression and notifications; a secured "
         "web console; evaluation on a simulated organisation and on CERT r4.2. Out of scope: per-event streaming, "
         "automated response (e.g. disabling an account), parsing native binary formats such as EVTX, and inspecting "
         "file or e-mail content - only metadata is analysed, for privacy.")

# ================================================================= 4. PROPOSED SOLUTION
h1("4. PROPOSED IDEA / SOLUTION")
par("p", "A layered pipeline turns raw logs into a short list of explained, risk-ranked alerts, and an operational "
         "layer runs it continuously (Figures 6.1 and 6.3):")
bullets([("Capture.", "Logs arrive by upload, drop folder, ingest API or agent and are mapped to one schema."),
         ("Features.", "Each user-day becomes 44 numbers and each device-day 19 (failed logins, unusual hours, MB to new "
                       "domains, USB use ...), computed only from earlier days, as a live system would. When web-proxy "
                       "logs are present, seven more describe what the user did online: pages, blocked attempts, risky "
                       "sites, new kinds of site and downloads."),
         ("Profiles.", "Every entity has a personal and a department-peer baseline that adapt over time, but suspicious "
                       "days are never learned."),
         ("Detection.", "Robust statistics, an unsupervised ensemble (Isolation Forest, LOF, autoencoder) and 28 "
                        "ATT&CK-mapped rules score every day independently."),
         ("Risk and response.", "Scores are fused into a 0-100 risk weighted by asset criticality and accumulated over "
                                "days; alerts carry plain-English reasons, are grouped into cases and notified, and "
                                "the analyst can open exactly what the person did that day."),
         ("Operation.", "A collector service imports new data and scores only what changed with the saved models; the "
                        "console requires sign-in and records every action.")])
par("p", "Three principles run through the design. Corroboration: statistics alone can never raise an alert - the ML "
         "ensemble or a rule must agree - which removes most false alarms. Explanation: every alert states what was "
         "unusual compared with the entity's own history. Learning with protection: profiles adapt to legitimate "
         "change, while high-risk days, rule matches and confirmed threats are never learned.")

# ================================================================= 5. OBJECTIVES
h1("5. OBJECTIVES")
bullets(["To capture and normalise authentication, system-access, network and resource-usage logs from files, an API "
         "and an endpoint agent into one schema.",
         "To build adaptive, poisoning-resistant behavioural profiles for both users and devices.",
         "To detect deviations without attack labels, using complementary statistical, machine-learning and rule layers.",
         "To produce one explained 0-100 risk score per entity-day and turn alerts into cases analysts can work.",
         "To show, for any user and day, what the person actually did - pages visited, downloads, blocked attempts, "
         "files and logins - with every out-of-character step flagged.",
         "To operate continuously and securely: incremental scoring identical to a full re-run, notifications, roles, "
         "API tokens and an audit trail.",
         "To evaluate honestly: detect every planted attack with precision above 0.9 and about one alert a day, check "
         "robustness, and validate on the independent CERT r4.2 benchmark."])

# ================================================================= 6. METHODOLOGY
h1("6. PROCESS / METHODOLOGY")
par("h2", "6.1 Identify the Needs of Customer and Users through Design Thinking Methods")
par("p", "The personas are composites of four published studies of SOC analysts, as interviews were not possible: "
         "analysts are buried in benign alarms [4], judge rules by their noise [15], are 2.5 times more accurate with a "
         "structured process [16], and mistrust ML scores they cannot reason about [17].")
table("Table 6.1: Personas (composites of published studies)", [
    ("Persona", "Goal and pain points", "Needs from the system"),
    ("Priya, tier-1 SOC analyst", "Triage fast, never miss an attack; flooded by benign alerts with no reasons",
     "Few ranked alerts, a reason for each, context and history in one place"),
    ("Rahul, SOC manager", "Balance workload and coverage; sceptical of black-box AI",
     "Risk ranking, ATT&CK coverage, measurable performance, control of the threshold"),
    ("Ananya, employee", "Not be wrongly accused; worried about intrusive monitoring",
     "Metadata only, fair comparison with her own history, quick clearing of false alerts"),
], widths=[1.6, 2.6, 2.6])
par("p", "Define: help an analyst spot account misuse early without adding to the flood of false alarms, and show why. "
         "Ideate: rules alone are blind to new behaviour, one deep model is a black box, so a hybrid was chosen. "
         "Prototype and test: the first prototype had precision 0.31; the P95-aware spread, quarantine and the "
         "corroboration threshold raised it above 0.9.")
par("h2", "6.2 Translate the Needs of Customer into Product")
table("Table 6.2: Needs translated into features - and why each feature exists", [
    ("Need", "Feature", "Why it is there"),
    ("Fewer false alarms", "Corroboration threshold 45; P95-aware spread",
     "One unusual number must not raise an alert; personal monthly peaks are normal"),
    ("Know why", "Plain-English reasons, layer scores, ATT&CK IDs", "Analysts act on alerts they understand [4], [17]"),
    ("Know what to open first", "0-100 risk, criticality, severity", "Queues are ranked, not flat"),
    ("Catch slow attacks", "Accumulated risk, 3-day half-life", "Small daily signals add up"),
    ("Not drown in repeats", "Cases; suppression with expiry", "One person = one work item; known patterns go quiet"),
    ("Learn from analysts", "Verdicts feed the baselines", "Cleared days are learned, threats never"),
    ("Use real logs", "Upload with column mapping; drop folder; API; agent", "Logs come in many formats and continuously"),
    ("Timely alerts", "Collector service; incremental engine; notifications", "Nobody watches a dashboard all day"),
    ("Trust in the tool", "Roles, hashed passwords, tokens, audit", "A tool holding security logs must be secure"),
    ("Privacy, fairness", "Metadata only; own and peer baselines", "Compare people with themselves, not a global norm"),
], widths=[1.4, 2.4, 2.8])
par("h2", "6.3 Specification of the Product")
table("Table 6.3: Main functional requirements", [
    ("ID", "Requirement"),
    ("FR1", "Accept the four log streams as CSV, JSON, ZIP, Linux auth.log / syslog text, Windows event exports (CSV, .evtx) or web-proxy logs (Squid, gateway CSV); split mixed files; map columns by name and content; normalise values."),
    ("FR2", "Collect continuously from a drop folder, a token-authenticated HTTP API and an endpoint agent."),
    ("FR3", "Compute 44 user (+7 web-activity) and 19 device features per day; learn personal and peer baselines over a rolling 45 days."),
    ("FR4", "Score each day with statistics, the ML ensemble and 28 rules; fuse into a 0-100 risk with criticality and decay."),
    ("FR5", "After the learning period, score new data incrementally with saved models, identical to a full re-run."),
    ("FR6", "Raise explained alerts; group them into cases with status, assignee and notes; allow audited suppression."),
    ("FR7", "Notify analysts of new or escalated alerts by webhook or e-mail, without duplicates."),
    ("FR8", "Require sign-in with viewer / analyst / administrator roles; scope API tokens; audit every action."),
    ("FR9", "Measure precision, recall, F1, false positive rate, ROC-AUC and PR-AUC against labelled incidents."),
    ("FR10", "Show each user's day as a timeline of websites (with subdomains and time spent), pages, downloads, blocked attempts, files and logins, flagging what is new or risky for that person."),
], widths=[0.6, 6.0])
table("Table 6.4: Key parameters", [
    ("Parameter", "Value", "Purpose"),
    ("Learning period", "30 days (configurable)", "Learn normal behaviour before alerting"),
    ("Adaptive window", "last 45 accepted days", "Keep profiles current"),
    ("Layer weights", "stats 0.28, peer 0.10, ML 0.30", "Fusion into daily risk"),
    ("Alert threshold", "45 (per workspace)", "Statistics alone (max 43.8) cannot alert"),
    ("Quarantine", "risk >= 60 or a rule hit", "Protect baselines from poisoning"),
    ("Criticality", "admin/server 1.3, finance 1.2, HR 1.1", "Weight by impact of compromise"),
    ("Risk half-life", "3 days", "Accumulate slow behaviour"),
    ("Case gap", "7 days", "Alerts closer than this form one case"),
], widths=[1.6, 2.5, 2.5])
par("h2", "6.4 Designing the Solution for the Customer Needs")
par("h3", "6.4.1 Features and profiles")
par("p", "Each user-day is summarised into 44 features in four groups - authentication (failed logins, failures in "
         "10 minutes followed by success, new hosts and countries, logins at hours rare for this user, impossible "
         "travel), system access (sensitive and restricted files, privilege escalation, new resources, account "
         "creation, log clearing, USB use), network (MB uploaded, MB to new domains and to cloud storage, mining-pool "
         "connections, job sites) and resource use (CPU, memory, disk) - and each device-day into 19. Web-proxy logs "
         "add seven web-activity features: pages visited, blocked requests, distinct blocked sites, requests to "
         "hacking / anonymizer / malware sites, kinds of site never visited before, downloads and executable "
         "downloads. The page, the site category (from the gateway or a built-in list), allowed or blocked, and the "
         "downloaded file are read from the URL and the proxy's verdict; each request also keeps its subdomain "
         "(erp.ibm.com) under the organisation's domain (ibm.com), and time spent per website is estimated as "
         "web-analytics tools do (requests less than 5 minutes apart form one visit). They join the models only when the logs "
         "carry this detail, so flow-only data such as CERT is scored exactly as before; blocked attempts and tool "
         "downloads are early warning signs that byte counts miss. Why: daily "
         "aggregates are cheap, private and explainable, and novelty features are computed only from earlier days, so "
         "the system behaves the same in a test as in live use.")
par("p", "For each entity and feature the profile stores centre = median and spread = max(1.4826 x MAD, (P95 - median) "
         "/ 1.645, floor); deviation is z = (today - centre) / spread. Why robust statistics: behaviour is spiky, and "
         "the P95 term stops a person's own occasional peaks from being flagged. The same profile is built for the "
         "department (peer baseline). During detection each profile is rebuilt from the last 45 accepted days; days "
         "with risk 60 or more, a rule hit or a confirmed-threat verdict are quarantined. Why: profiles must follow "
         "legitimate change without letting an attacker teach the model that the attack is normal.")
par("h3", "6.4.2 Detection layers and risk")
bullets([("Statistics:", "the three largest positive deviations above z = 3, for the personal and the peer baseline."),
         ("ML ensemble:", "Isolation Forest [19], LOF [20] and an autoencoder [21] (scikit-learn [18]) trained on "
                          "normal days only and calibrated so that 1 = the 99th percentile of normal. Why three: they "
                          "fail differently; why unsupervised: real organisations have almost no labelled attacks."),
         ("Rules:", "28 rules mapped to ATT&CK, e.g. brute force (T1110), impossible travel (T1078), privilege "
                    "escalation by a non-admin (T1068), upload to a new domain (T1048), mining pools (T1496), log "
                    "clearing (T1070), removable media used by an account with no such history (T1052.001, added "
                    "after the CERT evaluation, Section 10.3) and a successful login from an address that just failed "
                    "against several accounts (password spraying, T1110.003). Privilege escalation is judged against "
                    "the account's own history, so routine administrator sudo is not flagged even without a staff list. "
                    "Four web rules cover a burst of blocked requests compared with the person's usual rate, an "
                    "anonymizer or proxy site reached within an hour of a block (filter bypass, T1090), an executable "
                    "downloaded from a site never used before (T1105) and first visits to hacking or anonymizer sites "
                    "(T1588.002); two more use subdomains and timing: hundreds of random-looking subdomains of one site "
                    "(DNS / HTTP tunnelling, T1071.004) and a new site contacted at clockwork intervals all day "
                    "(malware beaconing, T1071.001)."),
         ("Fusion:", "A = 1 - (1 - 0.28 stat)(1 - 0.10 peer)(1 - 0.30 ml)(1 - rules); daily risk = 100 x min(1, A x "
                     "criticality); entity risk(t) = entity risk(t-1) x 0.5^(days/3) + max(0, daily risk - 15). An "
                     "alert is raised at daily risk 45 (critical at 80, high at 60) or when accumulated risk reaches 60. "
                     "Why 45: the statistical layers alone reach at most 43.8, so an alert always needs the ML "
                     "ensemble or a rule to agree.")])
par("h3", "6.4.3 Continuous operation")
par("p", "Each monitored environment is a workspace with its own logs, models, alerts and verdicts, moving from "
         "learning to monitoring once its learning period is covered. Logs arrive by upload (automatic column "
         "mapping by column name and content, such as TimeCreated to timestamp, with a preview), a drop folder, a "
         "token-authenticated ingest API or an endpoint agent that keeps data while the server is unreachable. Linux "
         "auth.log / syslog text and Windows Security events (Event Viewer CSV, PowerShell export, .evtx) are read "
         "directly, and a file mixing several event types is split by its event-type column. Why four routes: real logs come from "
         "exports, scripts, shippers and machines, and all of them end in the same import step.")
par("p", "The engine trains the baselines and ML models once and saves them with a fingerprint of the settings; later "
         "analyses reuse them and score only the days from the earliest changed day onwards. Because every feature "
         "is causal, the result is identical to a full re-run - checked by an automated test at a day boundary and "
         "mid-day. Why: re-training on all history at every update does not scale and would change past scores. A "
         "collector service runs every 10 seconds (import, incremental analysis, notification) under a file lock, and "
         "an analyst verdict marks the following days for re-scoring so that cleared behaviour is learned.")
par("h3", "6.4.4 Analyst workflow and security")
bullets([("Cases:", "alerts on one entity within 7 days form a case with status, assignee and a notes timeline; "
                    "closing it records a verdict for every day. Why: an analyst should handle a person once, not 30 times."),
         ("User activity:", "for any user and day the console lists the websites visited with their subdomains and "
                            "minutes spent, the pages, downloads, blocked attempts, files and logins as one story, folds routine repeats and flags each step that is new or "
                            "risky for that person (a new site, a block, a hacking or proxy site, an executable, a "
                            "first-time sensitive file, a large upload). Why: a score says how unusual a day was; the "
                            "analyst also needs to see what happened."),
         ("Suppression:", "a known-benign pattern can be silenced for one entity and alert type until an expiry date, "
                          "with a mandatory reason; suppressed alerts are kept and audited. Why: on CERT one user produced "
                          "91 alerts for one habit."),
         ("Notifications:", "webhook (Slack, Teams) or e-mail for new or escalated alerts, never twice, quiet for "
                            "imported history. Why: detection is useless if nobody sees it in time."),
         ("Security:", "viewer / analyst / administrator roles; PBKDF2 password hashes with lock-out after five failures; "
                       "256-bit API tokens stored only as hashes and scoped to a workspace; an audit trail of every "
                       "login, verdict and setting; services bound to the local machine by default. Why: the console "
                       "holds the organisation's security logs.")])
par("h2", "6.5 Process / Flow / Design Diagram")
figure("report/diagrams/1_architecture.png", "Figure 6.1: Analytics architecture", 6.6)
figure("report/diagrams/3_dfd_level1.png", "Figure 6.2: Data flow diagram, level 1", 5.6)
figure("report/diagrams/6_operational_architecture.png", "Figure 6.3: Operational architecture - how logs arrive, are "
       "scored continuously and reach analysts", 6.6)
figure("report/diagrams/5_use_case.png", "Figure 6.4: Use case diagram", 6.2)

# ================================================================= 7. REQUIREMENTS
h1("7. REQUIREMENTS")
par("h2", "7.1 Hardware Requirements")
par("p", "Any 64-bit dual-core computer with 4 GB of RAM and 1 GB of disk runs the simulated organisation; the full CERT "
         "benchmark needs 16 GB of RAM (6.4 GB peak) and 25 GB of disk. No GPU is needed. Development used a 16 GB "
         "Apple-silicon laptop.")
par("h2", "7.2 Software Requirements")
table("Table 7.1: Software", [
    ("Software", "Version", "Purpose"),
    ("Python", "3.10 or later (3.14 used)", "Language"),
    ("pandas, NumPy", "2.0+, 1.24+", "Log processing and features"),
    ("scikit-learn", "1.3+", "Isolation Forest, LOF, autoencoder"),
    ("Streamlit, Plotly", "1.50+, 5.18+", "Analyst console and charts"),
    ("SQLite", "bundled", "Logs, scores, alerts, cases, users, audit"),
    ("Python standard library", "bundled", "Ingest API, password hashing, notifications, locking"),
    ("psutil, Matplotlib, pytest", "5.9+, 3.7+, 7.4+", "Agent telemetry, report figures, 35 tests"),
], widths=[2.0, 2.0, 2.6])
par("h2", "7.3 Datasets")
bullets([("Simulated organisation (primary):", "48 employees and 12 servers over 60 days, 205,483 events, 11 planted "
                                               "attacks (28 attack entity-days) and 4 harmless but unusual events. Why: "
                                               "real logs are confidential and never labelled."),
         ("CMU CERT r4.2 [14]:", "1,000 simulated employees over 17 months with 70 insiders in three scenarios; the full "
                                 "16 GB data set was converted into 12.8 million events. Why: an independent benchmark the "
                                 "author did not design."),
         ("Live data:", "the endpoint agent and the replay of a data set as a live feed.")])
par("h2", "7.4 Technologies and Tools")
par("p", "Python, pandas, NumPy, scikit-learn, Streamlit, Plotly, SQLite and the standard library (http.server, "
         "hashlib, smtplib, fcntl); MITRE ATT&CK for rule mapping; Git for version control; pytest for testing.")

# ================================================================= 8. NOVELTY
h1("8. NOVELTY OF THE PROPOSED IDEA / PROJECT")
par("p", "The individual techniques are established; the novelty is how they are combined and delivered (Table 8.1).")
table("Table 8.1: Comparison with the reviewed work", [
    ("Capability", "Reviewed work", "This project"),
    ("Users and devices profiled together", "users [9]-[11] or hosts [12]", "44 (+7 web) user + 19 device features"),
    ("What the user actually did", "score only", "timeline of pages, downloads, blocks, files, logins"),
    ("Protection against baseline poisoning", "not addressed", "quarantine of risky days and confirmed threats"),
    ("No attack labels needed", "labels in [9], [10], [13]", "unsupervised + rules"),
    ("Corroborated, explained risk score", "single model, score only", "threshold needs agreement; plain-English reasons"),
    ("Exact incremental scoring", "offline batch evaluation", "saved models; identical to a full re-run (tested)"),
    ("Operable and secured", "not addressed", "collection, cases, notifications, roles, tokens, audit"),
], widths=[2.3, 2.0, 2.6])
bullets([("Poisoning-resistant adaptive baselines:", "profiles follow legitimate change, but risky days, rule hits and "
                                                     "confirmed threats are never learned, while cleared days are."),
         ("Corroboration by design:", "the threshold is derived from the score formula so that one statistical "
                                      "deviation can never alert - the main reason precision rose from 0.31 to above 0.9."),
         ("Exact incremental scoring:", "because every feature is causal, scoring only new days is provably the same "
                                        "as re-analysing everything, and an automated test checks it."),
         ("Honest validation:", "an independent benchmark with a held-out split and a documented negative result.")])

# ================================================================= 9. EXPERIMENTATION
h1("9. EXPERIMENTATION")
par("h2", "9.1 Experimental Setup")
par("p", "The simulated organisation has 48 employees in six departments, each with a laptop and personal habits, "
         "plus 12 servers (108 entities); its web traffic is logged by a proxy with page, site category and allowed / "
         "blocked, and people are occasionally blocked from streaming or betting sites. Days 1-5 are warm-up, days 6-30 the attack-free baseline, days 31-60 the "
         "detection window, which contains the 12 attacks of Table 9.1 and four harmless oddities (working until 1 "
         "a.m., a business trip, a 20 GB backup, a new project) that create realistic false-alarm pressure.")
table("Table 9.1: Planted attacks", [
    ("ID", "Scenario", "What appears in the logs", "ATT&CK"),
    ("INC-01", "Brute force + takeover", "45 failed VPN logins from Tor, then success and upload", "T1110"),
    ("INC-02 / 10", "Impossible travel", "Bengaluru, then Amsterdam / Lagos 70 minutes later", "T1078"),
    ("INC-03", "Off-hours access", "02:20 login, payroll read, WeTransfer upload", "T1078"),
    ("INC-04 / 05", "Exfiltration / slow insider", "3.3 GB to mega.nz; five days of growing Dropbox uploads", "T1567"),
    ("INC-06", "Privilege escalation", "Sales user runs admin commands on the domain controller", "T1068"),
    ("INC-07", "Lateral movement", "SSH/RDP into 12 new hosts in 50 minutes", "T1021"),
    ("INC-08", "Cryptomining", "Laptop CPU ~96% for three days, mining-pool traffic", "T1496"),
    ("INC-09", "Password spray", "30 failed logins on an admin account", "T1110"),
    ("INC-11", "Admin account abuse", "Accounts created, security log cleared", "T1136, T1070"),
    ("INC-12", "Web-filter evasion", "Blocked 7 times on file-sharing sites, web proxy, nmap and mimikatz downloaded, 1.2 GB out", "T1090, T1105"),
], widths=[1.0, 1.7, 3.3, 1.0])
par("h2", "9.2 Evaluation Protocol and Metrics")
par("p", "Every entity-day of the detection window is a test case, positive if labelled as an attack. Labels are used "
         "only for scoring, never for training. Metrics: precision, recall, F1-score, false positive rate, ROC-AUC and "
         "PR-AUC (which matters because attacks are about 1% of days), incidents detected, and - for CERT - insiders "
         "found within a fixed daily analyst review budget.")
par("h2", "9.3 Experiments Conducted")
bullets([("Main run, robustness and ablation:", "seed 42; five differently generated organisations; layers switched off."),
         ("CERT r4.2:", "learning January-May 2010 (before any attack); users split at random into a development half and "
                        "a held-out test half; the out-of-the-box result frozen first; one change (R16) chosen on the "
                        "development half only; a 7-day trend layer evaluated the same way."),
         ("Operation:", "incremental update compared with a full re-run; the organisation replayed through the ingest "
                        "API as a live feed."),
         ("Tests:", "35 automated tests of detection, ingestion, the incremental engine, the API, security, cases and "
                    "notifications.")])

# ================================================================= 10. RESULTS
h1("10. RESULTS AND DISCUSSION")
par("h2", "10.1 Simulated Organisation")
table("Table 10.1: Detection results (detection window, seed 42)", [
    ("Metric", "Value"),
    ("Incidents detected", "12 of 12, all on the day they started"),
    ("Precision / recall / F1-score", "0.935 / 0.967 / 0.951 (TP 29, FP 2, FN 1)"),
    ("False positive rate / alerts per day", "0.09% / about 1.0 for 108 entities"),
    ("Fused ROC-AUC / PR-AUC", "1.000 / 0.998"),
    ("Five organisations (mean)", "precision 0.923, recall 0.967, F1 0.945; 60 of 60 incidents"),
    ("Behavioural layers only (no rules)", "F1 0.854, PR-AUC 0.953"),
    ("Rules only / ML only / statistics only", "F1 0.983 / 0.856 / 0.468"),
], widths=[2.6, 4.0])
par("p", "The two false positives were planted oddities - the new project (risk 49) and the 20 GB backup server (49) - "
         "and the only false negative the pivot laptop of the lateral movement (43.6, just below the threshold). The "
         "ablation needs careful reading: rules look best only because they were written for these attack types; "
         "without any rule the behavioural layers still reach F1 0.854 with no prior knowledge of the attacks. "
         "Profiling web activity raised the ML ensemble on its own from F1 0.789 to 0.856, at the cost of one more "
         "borderline false alarm. Statistics alone flag nearly everything unusual (precision 0.31), which is why the "
         "threshold requires corroboration.")
figure("reports/figures/roc_curves.png", "Figure 10.1: ROC curves of each detection layer (simulated organisation)", 4.4)
par("h2", "10.2 Continuous Operation")
par("p", "Cutting the logs at a day boundary and in the middle of a day, then updating incrementally, gave scores, "
         "explanations and alerts identical to a full re-run. Replaying the organisation as a live feed through the "
         "collector's import path (30 days of history, then 30 live days in 8-hour slices) took one full training and 89 "
         "incremental updates of 1.8-5.7 seconds (median 2.6), with no rejected file or error, and reproduced the batch "
         "result exactly: 12 of 12 incidents and F1 0.951. A full analysis of the organisation takes about 5 "
         "seconds; CERT, with 12.8 million events, about 8 minutes.")
par("h2", "10.3 CERT r4.2 Benchmark")
table("Table 10.2: CERT r4.2, held-out half of the users (36 labelled accounts)", [
    ("Measure", "Out-of-the-box", "With R16"),
    ("Insiders alerted on a malicious day", "3 / 36", "22 / 36"),
    ("  Scenario 1: new USB user leaks data", "1 / 18", "18 / 18"),
    ("  Scenario 2: job seeker steals data", "1 / 14", "1 / 14"),
    ("  Scenario 3: administrator, keylogger", "1 / 4", "3 / 4"),
    ("Alerts per day (about 500 users)", "0.66", "0.84"),
    ("Day-level precision / recall", "0.017 / 0.008", "0.146 / 0.091"),
    ("Fused ROC-AUC", "0.699", "0.733"),
    ("Insiders among the 3 riskiest users per day", "12 / 36", "28 / 36"),
], widths=[3.2, 1.7, 1.7])
par("p", "Out of the box the system generalised poorly: 3 of 36 held-out insiders. The cause is calibration. The "
         "behavioural layers were tuned on loud simulated attacks and deliberately ignore deviations below three "
         "robust standard deviations and ML scores below the 99th percentile - which is what keeps false alarms to "
         "about one a day - but CERT insiders are quiet (a first USB connection, a few job-site visits), so the "
         "statistical and ML layers rank CERT days barely better than chance (ROC-AUC about 0.54). The answer key "
         "labels 72 accounts: the 70 insiders and two supervisors whose accounts scenario-3 insiders misused.")
par("p", "One generic insider indicator was then added: removable-media use by an account that never used removable "
         "media in its learning period (R16, T1052.001, weight 0.45 like comparable rules). It never fires on the "
         "simulated organisation and was chosen on the development half (4 to 17 of 36). On the untouched test half it "
         "raised detection to 22 of 36 - every scenario-1 insider - at 0.84 alerts a day, and an analyst reviewing the "
         "three riskiest users each day (0.3%) would see 28 of 36. Job seekers who steal data gradually (scenario 2) "
         "remain largely undetected because they already used USB drives and only used them more.")
figure("reports/figures/cert_r4.2.png", "Figure 10.2: CERT r4.2 - (a) ROC curve of each layer, (b) insiders found for "
       "a daily review budget (all 72 labelled accounts)", 6.6)
par("p", "A 7-day trend layer was tried for these gradual insiders. It raised ROC-AUC by about 0.1, but at a weight "
         "that keeps about one alert a day it caught no additional insider, at a weight that caught half of the "
         "scenario-2 insiders it multiplied alerts by eleven at 3-4% precision, and every weight lowered the number of "
         "insiders in the analysts' daily top five. It was therefore not adopted; gradual insiders need sequence-aware "
         "models [8], [10].")
par("h2", "10.4 Analyst Console")
figure("report/screens/02_case.png", "Figure 10.3: A case - five daily alerts of the slow-insider attack grouped into one "
       "work item with actions, notes and explained alert detail", 6.3)
figure("report/screens/03_entity.png", "Figure 10.4: Investigating an entity - learned baseline, risk over time with "
       "alerts and the labelled attack days", 6.3)
figure("report/screens/05_activity.png", "Figure 10.5: User activity - the web-filter evasion (INC-12) as a flagged "
       "story: seven blocks, a proxy site, two hacking-tool downloads, first-time files and 1.2 GB uploaded", 6.3)
figure("report/screens/06_websites.png", "Figure 10.6: Websites tab - each site with its subdomains and estimated "
       "minutes, against the person's usual minutes per site", 6.3)
par("h2", "10.5 Discussion")
par("p", "On the simulated organisation the system meets its objectives: every attack on its first day, about one alert "
         "a day, and a reason for each. CERT shows that this should be read as an upper bound - the organisation was "
         "designed together with the detector, and on independent data the conservative calibration that keeps false "
         "alarms low also hides quiet insiders. One generic indicator recovered most of them at under one alert a day, "
         "and the analyst-budget view shows the ranking is useful even where alerts are not raised. The threshold, "
         "weights and calibration should therefore be tuned per organisation, which the console supports, and "
         "gradual insiders remain the main open problem.")

# ================================================================= 11. CONCLUSION
h1("11. CONCLUSION AND FUTURE DIRECTIONS")
par("h2", "11.1 Conclusion")
par("p", "The project delivers a Python UEBA system that meets the problem statement and runs as a product. It captures "
         "four log streams from uploads, a drop folder, an authenticated API and an endpoint agent; profiles users and "
         "devices against adaptive, poisoning-resistant personal and peer baselines; detects deviations with robust "
         "statistics, an unsupervised ensemble and 28 ATT&CK rules; and turns the evidence into explained, risk-ranked "
         "alerts grouped into cases, notified to analysts and handled in a secured console, where the analyst can see "
         "exactly what a person browsed, downloaded, was blocked from and opened. Incremental scoring is identical to a "
         "full re-run.")
par("p", "On the simulated organisation it detected all 12 attacks on their first day with precision 0.935, recall "
         "0.967 and F1 0.951 (mean F1 0.945 over five organisations), and the behavioural layers alone reached 0.854. On the "
         "independent CERT r4.2 benchmark the out-of-the-box system found only 3 of 36 held-out insiders; with one "
         "generic indicator it found 22 of 36 at under one alert a day, while gradual job-seeker theft remained largely "
         "undetected - an honest result that defines the next step.")
par("h2", "11.2 Future Directions")
bullets([("Quiet insiders:", "behavioural scores that let many small deviations add up, calibrated per organisation, and "
                             "sequence models [8], [10] for gradual behaviour."),
         ("More validation:", "CERT r5.2 / r6.2 and the real CLUE-LDS logs [3]."),
         ("Formats and scale:", "Sysmon, Zeek and DNS logs (EVTX, syslog and Squid are read today), PostgreSQL "
                                "storage, TLS in front of the console."),
         ("Automated response:", "SOAR integration to disable an account or isolate a host once a threat is confirmed.")])

# ---------------------------------------------------------------- abstract
ab = find("ABSTRACT", "Heading 1")
nxt = ab._p.getnext()
kw = None
while nxt is not None:
    t = "".join(nxt.itertext())
    if t.strip().startswith("Keywords"):
        kw = nxt
        break
    after = nxt.getnext()
    nxt.getparent().remove(nxt)
    nxt = after
anchor_el = ab._p
for text in [
    "Most breaches now start with stolen credentials or an insider, whose actions look legitimate to signature-based "
    "tools. User and Entity Behaviour Analytics (UEBA) instead learns how each user and device normally behaves and "
    "flags deviations. This project builds a Python UEBA system and takes it from analytics to an operable product.",
    "Four kinds of logs (authentication, system access, network and web-proxy, resource usage) are turned into 44 daily "
    "features per user (seven more for web activity when proxy logs are present) and 19 per device and compared with adaptive personal and department baselines that never learn suspicious "
    "days. Robust statistics, an unsupervised ensemble (Isolation Forest, Local Outlier Factor, autoencoder) and 28 "
    "MITRE ATT&CK rules are fused into a 0-100 risk score that requires agreement between layers, and every alert "
    "explains itself. Around this core, logs arrive by upload, drop folder, an authenticated API or an endpoint agent; "
    "a collector service scores new data incrementally - provably identical to a full re-run - and notifies analysts; "
    "alerts are grouped into cases; analysts see what each person actually did - pages, downloads, blocked attempts and "
    "files - with the out-of-character steps flagged; and the console is protected by roles, hashed passwords, scoped tokens and an "
    "audit trail.",
    "On a simulated 48-person organisation with 12 planted attacks, all were detected on their first day with "
    "precision 0.935, recall 0.967 and F1 0.951 (mean F1 0.945 over five organisations), and a live replay "
    "reproduced this exactly. On the independent CERT r4.2 benchmark the out-of-the-box system found only 3 of 36 "
    "held-out insiders because its behavioural layers ignore small deviations; one generic indicator raised this to 22 "
    "of 36 at under one alert a day, while gradual data theft by job seekers remained largely undetected.",
]:
    el = deepcopy(T["p"])
    emit(el)
    set_runs(Paragraph(el, ab._parent), text)
if kw is not None:
    set_runs(Paragraph(kw, ab._parent), "UEBA, insider threat, anomaly detection, Isolation Forest, autoencoder, risk "
             "scoring, explainable alerts, web activity, SOC, CERT.", lead="Keywords:")

# ---------------------------------------------------------------- abbreviations
t = None
for tb in d.tables:
    if tb.rows[0].cells[0].text.strip() == "Abbreviation":
        t = tb
        break
abbr = {"API": "Application Programming Interface", "PBKDF2": "Password-Based Key Derivation Function 2",
        "SHA-256": "Secure Hash Algorithm, 256-bit", "SMTP": "Simple Mail Transfer Protocol",
        "SOAR": "Security Orchestration, Automation and Response", "TLS": "Transport Layer Security"}
for k, v in abbr.items():
    keys = [r.cells[0].text.strip() for r in t.rows]
    if k in keys:
        continue
    pos = max(i for i, x in enumerate(keys) if i == 0 or x.lower() < k.lower())
    tr = deepcopy(t.rows[1]._tr)
    t.rows[pos]._tr.addnext(tr)
    row = t.rows[pos + 1]
    set_cell(row.cells[0], k)
    set_cell(row.cells[1], v)

# ---------------------------------------------------------------- source code appendix: keep the first three excerpts
sc = find("SOURCE CODE", "Heading 1")
set_runs(Paragraph(sc._p.getnext(), sc._parent),
         "The complete source code - about 7,000 lines of Python in 23 modules, the analyst console and 35 automated "
         "tests - is in the project folder and its Git repository. Three key parts of the detection logic are "
         "reproduced below.")
code_heads = []
el = sc._p.getnext()
stop = find("SUBMISSION PAGE", "Heading 1")._p
while el is not None and el is not stop:
    if el.tag == qn("w:p"):
        p = Paragraph(el, sc._parent)
        if p.style.name == "Heading 31":
            code_heads.append(el)
    el = el.getnext()
CODE3 = Path(ROOT / "ueba" / "pipeline.py").read_text().splitlines()
start_i = next(i for i, l in enumerate(CODE3) if l.startswith("    def accept(idx):"))
kept_i = next(i for i, l in enumerate(CODE3) if l.startswith("    kept = np.zeros(len(F)"))
excerpt = CODE3[start_i:start_i + 11] + ["    ..."] + CODE3[kept_i:kept_i + 6] + ["        ..."]
if len(code_heads) >= 3:
    h3 = Paragraph(code_heads[2], sc._parent)
    set_runs(h3, "Quarantine, analyst feedback and incremental reuse (excerpt of score_entities, ueba/pipeline.py)")
    el = code_heads[2].getnext()
    tmpl = deepcopy(el)                    # a code line paragraph (Courier New)
    stop_el = code_heads[3] if len(code_heads) > 3 else stop
    while el is not None and el is not stop_el:
        nxt = el.getnext()
        is_break = el.tag == qn("w:p") and any(b.get(qn("w:type")) == "page" for b in el.findall(".//" + qn("w:br")))
        if not is_break:
            el.getparent().remove(el)
        el = nxt
    at = code_heads[2]
    for line in excerpt:
        ln = deepcopy(tmpl)
        at.addnext(ln)
        at = ln
        set_runs(Paragraph(ln, sc._parent), line.replace("    ", "    ", 1), keep_rpr=True)
if len(code_heads) > 3:
    cut = code_heads[3]
    while cut is not None and cut is not stop:
        nxt = cut.getnext()
        # keep the page break that precedes the submission page
        is_break = cut.tag == qn("w:p") and any(b.get(qn("w:type")) == "page" for b in cut.findall(".//" + qn("w:br")))
        if not is_break:
            cut.getparent().remove(cut)
        cut = nxt

# ---------------------------------------------------------------- contents: live page numbers
# Every chapter heading gets a bookmark and its contents entry a PAGEREF field, so LibreOffice
# fills in the numbers when exporting the PDF and Word refreshes them on opening the document.
ENTRIES = {"1. Introduction": "1. INTRODUCTION", "2. Literature Review": "2. LITERATURE REVIEW",
           "3. Identification": "3. IDENTIFICATION", "4. Proposed Idea": "4. PROPOSED IDEA",
           "5. Objectives": "5. OBJECTIVES", "6. Process": "6. PROCESS", "7. Requirements": "7. REQUIREMENTS",
           "8. Novelty": "8. NOVELTY", "9. Experimentation": "9. EXPERIMENTATION", "10. Results": "10. RESULTS",
           "11. Conclusion": "11. CONCLUSION", "References": "REFERENCES", "Source Code": "SOURCE CODE",
           "Submission Page": "SUBMISSION PAGE", "Plagiarism Report": "PLAGIARISM REPORT"}
contents_at = next(i for i, p in enumerate(d.paragraphs) if p.text.strip() == "CONTENTS")
heading_pars = [p for p in d.paragraphs if p.style.name == "Heading 1"]
bm_id = 9000


def run_el(text=None, rpr=None, fld=None, instr=None):
    r = OxmlElement("w:r")
    if rpr is not None:
        r.append(deepcopy(rpr))
    if fld:
        fc = OxmlElement("w:fldChar")
        fc.set(qn("w:fldCharType"), fld)
        r.append(fc)
    elif instr:
        it = OxmlElement("w:instrText")
        it.set(qn("xml:space"), "preserve")
        it.text = instr
        r.append(it)
    else:
        t = OxmlElement("w:t")
        t.text = text
        r.append(t)
    return r


for p in d.paragraphs[contents_at + 1:contents_at + 45]:
    txt = p.text.strip()
    key = next((k for k in ENTRIES if txt.startswith(k)), None)
    if not key:
        continue
    target = next((h for h in heading_pars if h.text.strip().startswith(ENTRIES[key])), None)
    if target is None:
        continue
    name = "_Ch_" + "".join(ch for ch in key if ch.isalnum())[:30]
    if not target._p.findall(qn("w:bookmarkStart")):
        bs, be = OxmlElement("w:bookmarkStart"), OxmlElement("w:bookmarkEnd")
        bs.set(qn("w:id"), str(bm_id)); bs.set(qn("w:name"), name); be.set(qn("w:id"), str(bm_id))
        bm_id += 1
        target._p.insert(1 if target._p.pPr is not None else 0, bs)
        target._p.append(be)
    runs = p.runs
    num_run = next((r for r in reversed(runs) if r.text.strip().isdigit()), None)
    if num_run is None:
        continue
    cached = num_run.text.strip()
    rpr = num_run._r.find(qn("w:rPr"))
    seq = [run_el(rpr=rpr, fld="begin"), run_el(rpr=rpr, instr=f" PAGEREF {name} \\h "),
           run_el(rpr=rpr, fld="separate"), run_el(text=cached, rpr=rpr), run_el(rpr=rpr, fld="end")]
    anchor_r = num_run._r
    for el in seq:
        anchor_r.addnext(el)
        anchor_r = el
    num_run._r.getparent().remove(num_run._r)

settings = d.settings.element
if settings.find(qn("w:updateFields")) is None:
    uf = OxmlElement("w:updateFields")
    uf.set(qn("w:val"), "true")
    # schema order: updateFields comes right before these elements
    after = ("hdrShapeDefaults", "footnotePr", "endnotePr", "compat", "docVars", "rsids", "mathPr", "attachedSchema",
             "themeFontLang", "clrSchemeMapping", "doNotIncludeSubdocsInStats", "doNotAutoCompressPictures",
             "forceUpgrade", "captions", "readModeInkLockDown", "smartTagType", "schemaLibrary", "shapeDefaults",
             "doNotEmbedSmartTags", "decimalSymbol", "listSeparator")
    nxt = next((c for c in settings if c.tag in {qn(f"w:{t}") for t in after}), None)
    if nxt is not None:
        nxt.addprevious(uf)
    else:
        settings.append(uf)

# never two page breaks in a row (they make blank pages)
prev_break = False
for p in list(d.paragraphs):
    is_break = not p.text.strip() and any(b.get(qn("w:type")) == "page" for b in p._p.findall(".//" + qn("w:br")))
    if is_break and prev_break:
        p._p.getparent().remove(p._p)
        continue
    if p.text.strip() or p._p.xpath(".//pic:pic"):
        prev_break = False
    if is_break:
        prev_break = True

d.save(OUT)
print("saved", OUT)
