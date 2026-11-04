# UEBA evaluation report

Detection window: **2026-07-31 to 2026-08-29**  
Entity-days scored: **2,363** (attack entity-days: 30)

## Alert quality

| Metric | Value |
|---|---|
| Precision | 0.935 |
| Recall | 0.967 |
| F1 | 0.951 |
| False-positive rate | 0.0009 |
| Alerts per day | 1.03 |
| Incidents detected | 12 / 12 |

Confusion matrix: TP=29, FP=2, FN=1, TN=2331

## Detector comparison

| Detector | ROC-AUC | PR-AUC |
|---|---|---|
| Fused risk score | 1.000 | 0.998 |
| Personal baseline (z-score) | 0.997 | 0.933 |
| Peer-group baseline | 0.983 | 0.959 |
| ML ensemble | 0.999 | 0.945 |
| Isolation Forest | 0.878 | 0.572 |
| Local Outlier Factor | 0.949 | 0.853 |
| Autoencoder | 0.996 | 0.625 |
| Threat rules | 0.983 | 0.967 |

## Incident-level results

| Incident | Scenario | Detected | First alert | Delay (days) | Peak risk | Caught by |
|---|---|---|---|---|---|---|
| INC-01 | brute_force | yes | 2026-08-03 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-02 | impossible_travel | yes | 2026-08-06 | 0 | 100 | ML ensemble, threat rules |
| INC-03 | off_hours_access | yes | 2026-08-08 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-04 | data_exfiltration | yes | 2026-08-11 | 0 | 91 | ML ensemble, peer group, personal baseline, threat rules |
| INC-05 | insider_slow_exfiltration | yes | 2026-08-14 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-06 | privilege_escalation | yes | 2026-08-16 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-07 | lateral_movement | yes | 2026-08-20 | 0 | 96 | ML ensemble, peer group, personal baseline, threat rules |
| INC-08 | cryptomining | yes | 2026-08-22 | 0 | 97 | ML ensemble, peer group, personal baseline, threat rules |
| INC-09 | brute_force | yes | 2026-08-25 | 0 | 92 | ML ensemble, peer group, personal baseline, threat rules |
| INC-10 | impossible_travel | yes | 2026-08-27 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-11 | admin_account_abuse | yes | 2026-08-28 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-12 | web_policy_evasion | yes | 2026-08-19 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |

## False positives

- 2026-08-17 LT-ITA-040: Behavioural anomaly (risk 49)
- 2026-08-21 diya.joshi: Behavioural anomaly (risk 49)

## Threshold sweep

| Threshold | Precision | Recall | F1 | Alerts |
|---|---|---|---|---|
| 20 | 0.288 | 1.0 | 0.448 | 104 |
| 25 | 0.337 | 1.0 | 0.504 | 89 |
| 30 | 0.517 | 1.0 | 0.682 | 58 |
| 35 | 0.769 | 1.0 | 0.87 | 39 |
| 40 | 0.909 | 1.0 | 0.952 | 33 |
| 45 | 0.935 | 0.967 | 0.951 | 31 |
| 50 | 1.0 | 0.967 | 0.983 | 29 |
| 55 | 1.0 | 0.967 | 0.983 | 29 |
| 60 | 1.0 | 0.967 | 0.983 | 29 |
| 65 | 1.0 | 0.967 | 0.983 | 29 |
| 70 | 1.0 | 0.967 | 0.983 | 29 |
| 75 | 1.0 | 0.967 | 0.983 | 29 |
| 80 | 1.0 | 0.967 | 0.983 | 29 |
