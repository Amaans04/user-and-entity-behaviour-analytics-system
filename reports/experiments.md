# Experiments

## Robustness across random seeds

Each seed generates a different company (people, habits, victims, timing).

| Seed | Incidents | Precision | Recall | F1 | FPR | Alerts/day | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|
| 42 | 11/11 | 0.964 | 0.964 | 0.964 | 0.0004 | 0.93 | 1.000 | 0.999 |
| 7 | 11/11 | 0.931 | 0.964 | 0.947 | 0.0009 | 0.97 | 1.000 | 0.997 |
| 123 | 11/11 | 0.964 | 0.964 | 0.964 | 0.0004 | 0.93 | 1.000 | 0.999 |
| 2024 | 11/11 | 0.931 | 0.964 | 0.947 | 0.0008 | 0.97 | 1.000 | 0.993 |
| 99 | 11/11 | 0.900 | 0.964 | 0.931 | 0.0013 | 1.0 | 1.000 | 0.996 |
| **mean** | | **0.938** | **0.964** | **0.951** | 0.0008 | 0.96 | 1.000 | 0.997 |

## Ablation (mean ± std over seeds, daily-risk alerts only)

| Variant | ROC-AUC | PR-AUC | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Full system (baseline + peer + ML + rules) | 1.000 ± 0.000 | 0.996 ± 0.002 | 0.938 ± 0.027 | 0.964 ± 0.000 | 0.951 ± 0.014 |
| Without threat rules (behaviour only) | 0.999 ± 0.000 | 0.951 ± 0.007 | 0.774 ± 0.124 | 0.971 ± 0.016 | 0.857 ± 0.086 |
| Without ML ensemble | 1.000 ± 0.000 | 0.984 ± 0.001 | 0.979 ± 0.020 | 0.964 ± 0.000 | 0.971 ± 0.010 |
| Personal baseline only | 0.988 ± 0.007 | 0.457 ± 0.047 | 0.295 ± 0.027 | 0.971 ± 0.016 | 0.451 ± 0.031 |
| ML ensemble only | 0.998 ± 0.001 | 0.856 ± 0.074 | 0.763 ± 0.080 | 0.821 ± 0.036 | 0.789 ± 0.048 |
| Threat rules only | 0.982 ± 0.000 | 0.965 ± 0.000 | 1.000 ± 0.000 | 0.964 ± 0.000 | 0.982 ± 0.000 |
