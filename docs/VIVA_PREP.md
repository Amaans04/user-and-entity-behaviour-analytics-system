# Viva preparation

## 1. Before the viva (10 minutes, once)

```bash
source .venv/bin/activate
python run_pipeline.py                 # demo workspace analysed (also regenerates reports/)
python -m pytest -q                    # 24 passed - say so if asked about testing
python launch.py                       # console on http://localhost:8501 + service + ingest API
```

In the console: sign in, create a workspace **Viva live** (learning period 30), and in
Data sources → Notifications add a webhook (e.g. a free https://webhook.site URL open on your
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
| 4:15 | **CERT r4.2** workspace → Model performance (or `reports/figures/cert_r4.2.png`) | "And on the public CMU CERT benchmark, which I did not design: out of the box it found only 3 of 36 held-out insiders - the behavioural layers were tuned on loud attacks. One generic indicator, first-time USB use, chosen on a separate development half, raised that to 22 of 36 at under one alert a day. Job-hunting insiders are still mostly missed - that's my main future work." |
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

## 4. CERT r4.2 results (know these by heart)

* Data: 1,000 users, 17 months, 70 insiders in 3 scenarios; 12.8 M events after conversion; ~8 min analysis.
* Protocol: unsupervised; learning Jan-May 2010 (attack-free); random development / **held-out test** split
  of users; out-of-the-box result frozen **before** any change.
* Out of the box (held-out): **3 / 36** insiders, 0.66 alerts/day, ROC-AUC 0.70.
* Why: statistical and ML layers ignore deviations under 3σ / the 99th percentile - built to keep false alarms
  at ~1/day on loud attacks; CERT insiders are quiet (layer ROC-AUC ≈ 0.54).
* One generic indicator (R16: removable-media use by an account with no such history, MITRE T1052.001,
  chosen on the development half): **22 / 36** held-out insiders, 0.84 alerts/day; scenario 1 18/18,
  scenario 3 3/4, scenario 2 1/14.
* Analyst budget: reviewing the 3 riskiest users a day (0.3 %) finds 28 / 36 held-out insiders.
* 72 labelled accounts = 70 insiders + 2 supervisors whose accounts were misused in scenario 3.

**Likely follow-up: "Isn't adding R16 after seeing CERT just tuning on the test set?"**
That's why I split the users first: R16 was chosen on the development half (4 → 17 of 36) and the number I
quote is the untouched test half (3 → 22 of 36). It is a generic indicator used by commercial UEBA tools, it
never fires on my synthetic data, and the out-of-the-box result is reported as the honest generalisation number.

**Likely follow-up: "Why so much worse than published CERT results?"**
Most published models in my literature review use labels or per-session sequences; mine uses no labels and
daily aggregates, and its thresholds were calibrated on different data. The fix is continuous behavioural
scores calibrated per organisation, so many small deviations add up - that's my main future work.
