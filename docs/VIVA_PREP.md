# Viva preparation

## 1. Before the viva (10 minutes, once)

```bash
source .venv/bin/activate
python run_pipeline.py                 # demo workspace analysed (also regenerates reports/)
python -m pytest -q                    # 22 passed - say so if asked about testing
python launch.py                       # console on http://localhost:8501 + service + ingest API
```

In the console: sign in, create a workspace **Viva live** (learning period 30), and in
Data sources → 🔔 Notifications add a webhook (e.g. a free https://webhook.site URL open on your
phone or a second tab) with minimum severity *high*. Keep a terminal ready with:

```bash
python -m ueba.replay --workspace viva-live --seconds-per-day 8 --labels
```

## 2. Five-minute demo script

| Time | Show | Say |
|---|---|---|
| 0:00 | Sign-in screen | "A security tool has to be secure itself: roles, hashed passwords, lock-out after 5 failures, and every action is audited." |
| 0:30 | **Demo** workspace → Overview | "A simulated 48-person company, 205k events over 60 days, 11 planted attacks and 4 harmless-but-odd events. All 11 caught on the first day, 1 false alert in 30 days." |
| 1:15 | Alerts → open the **impossible travel** or **exfiltration** alert | "Every alert explains itself: *3,300 MB uploaded vs usual 1.2* - and shows which layers agreed. The threshold is set so statistics alone can never alert; ML or a rule must corroborate." |
| 2:00 | **Investigate →** | "Each user's learned baseline - hours, countries, hosts - the risk timeline, and the exact deviations that day." |
| 2:30 | Start the replay in the terminal, switch to **Viva live** → Overview | "Now as a live system: 30 days of history arrive, it learns, then one day every 8 seconds. Nobody clicks anything." |
| 3:30 | Wait for INC-01 (day 4): alert appears, webhook fires on the phone | "Brute force from a Tor exit node - detected and notified within one service pass. The models were trained once; each update scores only the new data in ~2 s, and that is provably identical to re-running everything." |
| 4:15 | **CERT r4.2** workspace → Model performance | "And on the public CMU CERT insider-threat benchmark, which I did not design: … (see §4)." |
| 4:45 | Data sources → Automatic collection tabs | "Real logs come in by upload with automatic column mapping, a drop folder, an authenticated API, or the endpoint agent." |

## 3. Likely questions and answers

**Why unsupervised and not a classifier?**
Real organisations have almost no labelled attacks, and the next attack is not like the last one.
The models learn only what *normal* looks like for each person, so they need no attack labels and can
flag new techniques. Labels are used only to measure performance.

**Your results are on data you generated yourself - isn't that circular?**
Yes, that is the main limitation, which is why: (1) the attacks are realistic MITRE ATT&CK techniques
mixed with benign oddities that look suspicious; (2) results hold over five differently generated
companies (mean F1 0.951); (3) the ablation shows the behavioural layers alone reach F1 0.857 without
any rules; and (4) the system was run on CERT r4.2, a benchmark built by CMU that I had no part in.

**Rules alone score F1 0.98 - so why the ML?**
Because I wrote those rules for the attack types I also simulated; on synthetic data that is close to
cheating. The behavioural layers need no prior knowledge of the attack. On CERT, where none of the
rules were written for the scenarios, behaviour carries the detection (see §4). Combined, the system
also ranks best (PR-AUC 0.996).

**Can an attacker slowly teach the baseline to accept the attack (poisoning)?**
Profiles adapt over a rolling 45-day window, but a day is never learned if its risk is ≥ 60, if any
threat rule matched, or if an analyst confirmed it as a threat. The ML models are trained once on the
learning period and are not updated by detection days.

**Why robust statistics (median/MAD) instead of mean/standard deviation?**
Behaviour data is spiky; one large legitimate upload would inflate a standard deviation and hide the
next real anomaly. Median and MAD ignore outliers. The P95 term in the spread respects each person's own
normal peaks (a monthly 60 MB report), which removed most false positives.

**How does the incremental engine stay correct?**
Every feature is *causal* - computed only from earlier days - so a day's score never depends on later
data. The engine reuses the saved models and the previous accept/quarantine decisions, and re-scores
from the earliest day that changed (always including the last day, which may have been partial). A test
cuts the data at a day boundary and mid-day and checks the result is identical to a full re-run.

**What happens with real, messy logs?**
Upload or ship them: column names are mapped automatically (`TimeCreated` → timestamp,
`TargetUserName` → user), values normalised (`4625` → failure, `CORP\alice` → alice), bad rows reported.
Missing streams are allowed - the features of a missing stream stay at zero.

**What would you need for a real deployment?**
TLS through a reverse proxy, the service run as a system service, native parsers for EVTX/syslog,
PostgreSQL for larger organisations, and SOAR integration for automated response. All listed in
README §7 and §9.

**What is the false-positive rate and why does it matter?**
0.04 % of normal entity-days on the demo (≈ 1 alert per day for 108 entities). SOC studies report
analysts overwhelmed by false positives (Alahmadi et al., "99% false positives"); the corroboration
threshold, explanations and feedback loop were designed around that.

## 4. CERT r4.2 results

_To be filled in after the CERT run._
