# UEBA evaluation report

Detection window: **2026-07-31 to 2026-08-29**  
Entity-days scored: **2,363** (attack entity-days: 28)

## Alert quality

| Metric | Value |
|---|---|
| Precision | 0.964 |
| Recall | 0.964 |
| F1 | 0.964 |
| False-positive rate | 0.0004 |
| Alerts per day | 0.93 |
| Incidents detected | 11 / 11 |

Confusion matrix: TP=27, FP=1, FN=1, TN=2334

## Detector comparison

| Detector | ROC-AUC | PR-AUC |
|---|---|---|
| Fused risk score | 1.000 | 0.999 |
| Personal baseline (z-score) | 0.997 | 0.926 |
| Peer-group baseline | 0.982 | 0.956 |
| ML ensemble | 0.998 | 0.855 |
| Isolation Forest | 0.869 | 0.455 |
| Local Outlier Factor | 0.909 | 0.734 |
| Autoencoder | 0.996 | 0.633 |
| Threat rules | 0.982 | 0.965 |

## Incident-level results

| Incident | Scenario | Detected | First alert | Delay (days) | Peak risk | Caught by |
|---|---|---|---|---|---|---|
| INC-01 | brute_force | yes | 2026-08-03 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-02 | impossible_travel | yes | 2026-08-06 | 0 | 100 | ML ensemble, threat rules |
| INC-03 | off_hours_access | yes | 2026-08-08 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-04 | data_exfiltration | yes | 2026-08-11 | 0 | 91 | ML ensemble, peer group, personal baseline, threat rules |
| INC-05 | insider_slow_exfiltration | yes | 2026-08-14 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-06 | privilege_escalation | yes | 2026-08-16 | 0 | 96 | ML ensemble, peer group, personal baseline, threat rules |
| INC-07 | lateral_movement | yes | 2026-08-20 | 0 | 77 | ML ensemble, peer group, personal baseline, threat rules |
| INC-08 | cryptomining | yes | 2026-08-22 | 0 | 93 | ML ensemble, peer group, personal baseline, threat rules |
| INC-09 | brute_force | yes | 2026-08-25 | 0 | 92 | ML ensemble, peer group, personal baseline, threat rules |
| INC-10 | impossible_travel | yes | 2026-08-27 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |
| INC-11 | admin_account_abuse | yes | 2026-08-28 | 0 | 100 | ML ensemble, peer group, personal baseline, threat rules |

## False positives

- 2026-08-21 diya.joshi: Behavioural anomaly (risk 49)

## Threshold sweep

| Threshold | Precision | Recall | F1 | Alerts |
|---|---|---|---|---|
| 20 | 0.277 | 1.0 | 0.434 | 101 |
| 25 | 0.311 | 1.0 | 0.475 | 90 |
| 30 | 0.509 | 1.0 | 0.675 | 55 |
| 35 | 0.778 | 1.0 | 0.875 | 36 |
| 40 | 0.903 | 1.0 | 0.949 | 31 |
| 45 | 0.964 | 0.964 | 0.964 | 28 |
| 50 | 1.0 | 0.964 | 0.982 | 27 |
| 55 | 1.0 | 0.964 | 0.982 | 27 |
| 60 | 1.0 | 0.964 | 0.982 | 27 |
| 65 | 1.0 | 0.964 | 0.982 | 27 |
| 70 | 1.0 | 0.964 | 0.982 | 27 |
| 75 | 1.0 | 0.964 | 0.982 | 27 |
| 80 | 1.0 | 0.929 | 0.963 | 26 |
