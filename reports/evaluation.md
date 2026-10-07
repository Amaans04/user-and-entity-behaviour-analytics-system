# UEBA evaluation report

Detection window: **2026-07-31 to 2026-08-29**  
Entity-days scored: **2,358** (attack entity-days: 30)

## Alert quality

| Metric | Value |
|---|---|
| Precision | 0.935 |
| Recall | 0.967 |
| F1 | 0.951 |
| False-positive rate | 0.0009 |
| Alerts per day | 1.03 |
| Incidents detected | 12 / 12 |

Confusion matrix: TP=29, FP=2, FN=1, TN=2326

## Detector comparison

| Detector | ROC-AUC | PR-AUC |
|---|---|---|
| Fused risk score | 1.000 | 0.996 |
| Personal baseline (z-score) | 0.997 | 0.938 |
| Peer-group baseline | 0.998 | 0.942 |
| ML ensemble | 1.000 | 0.968 |
| Isolation Forest | 0.879 | 0.644 |
| Local Outlier Factor | 0.966 | 0.912 |
| Autoencoder | 0.998 | 0.789 |
| Threat rules | 0.983 | 0.967 |

## Incident-level results

| Incident | Scenario | Detected | First alert | Delay (days) | Peak risk | Caught by |
|---|---|---|---|---|---|---|
| INC-01 | brute_force | yes | 2026-08-03 | 0 | 99 | ML ensemble, peer group, personal baseline, threat rules |
| INC-02 | impossible_travel | yes | 2026-08-06 | 0 | 100 | ML ensemble, threat rules |
| INC-03 | off_hours_access | yes | 2026-08-08 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-04 | data_exfiltration | yes | 2026-08-11 | 0 | 91 | ML ensemble, peer group, personal baseline, threat rules |
| INC-05 | insider_slow_exfiltration | yes | 2026-08-14 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-06 | privilege_escalation | yes | 2026-08-16 | 0 | 96 | ML ensemble, peer group, personal baseline, threat rules |
| INC-07 | lateral_movement | yes | 2026-08-20 | 0 | 76 | ML ensemble, peer group, personal baseline, threat rules |
| INC-08 | cryptomining | yes | 2026-08-22 | 0 | 93 | ML ensemble, peer group, personal baseline, threat rules |
| INC-09 | brute_force | yes | 2026-08-25 | 0 | 92 | ML ensemble, peer group, personal baseline, threat rules |
| INC-10 | impossible_travel | yes | 2026-08-27 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-11 | admin_account_abuse | yes | 2026-08-28 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-12 | web_policy_evasion | yes | 2026-08-19 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |

## False positives

- 2026-08-10 neha.rao: Off-hours sensitive access (risk 56)
- 2026-08-21 ayaan.sharma: Behavioural anomaly (risk 50)

## Threshold sweep

| Threshold | Precision | Recall | F1 | Alerts |
|---|---|---|---|---|
| 20 | 0.4 | 1.0 | 0.571 | 75 |
| 25 | 0.417 | 1.0 | 0.588 | 72 |
| 30 | 0.526 | 1.0 | 0.69 | 57 |
| 35 | 0.577 | 1.0 | 0.732 | 52 |
| 40 | 0.811 | 1.0 | 0.896 | 37 |
| 45 | 0.935 | 0.967 | 0.951 | 31 |
| 50 | 0.967 | 0.967 | 0.967 | 30 |
| 55 | 0.967 | 0.967 | 0.967 | 30 |
| 60 | 1.0 | 0.967 | 0.983 | 29 |
| 65 | 1.0 | 0.967 | 0.983 | 29 |
| 70 | 1.0 | 0.967 | 0.983 | 29 |
| 75 | 1.0 | 0.967 | 0.983 | 29 |
| 80 | 1.0 | 0.933 | 0.966 | 28 |
