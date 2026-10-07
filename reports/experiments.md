# Experiments

## Robustness across random seeds

Each seed generates a different company (people, habits, victims, timing).

| Seed | Incidents | Precision | Recall | F1 | FPR | Alerts/day | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|
| 42 | 12/12 | 0.935 | 0.967 | 0.951 | 0.0009 | 1.03 | 1.000 | 0.998 |
| 7 | 12/12 | 0.906 | 0.967 | 0.935 | 0.0013 | 1.07 | 1.000 | 0.996 |
| 123 | 12/12 | 0.906 | 0.967 | 0.935 | 0.0013 | 1.07 | 1.000 | 0.997 |
| 2024 | 12/12 | 0.935 | 0.967 | 0.951 | 0.0008 | 1.03 | 1.000 | 0.995 |
| 99 | 12/12 | 0.935 | 0.967 | 0.951 | 0.0009 | 1.03 | 1.000 | 0.996 |
| **mean** | | **0.923** | **0.967** | **0.945** | 0.0010 | 1.05 | 1.000 | 0.996 |

## Ablation (mean ± std over seeds, daily-risk alerts only)

| Variant | ROC-AUC | PR-AUC | Precision | Recall | F1 |
|---|---|---|---|---|---|
| Full system (baseline + peer + ML + rules) | 1.000 ± 0.000 | 0.996 ± 0.001 | 0.924 ± 0.016 | 0.967 ± 0.000 | 0.945 ± 0.008 |
| Without threat rules (behaviour only) | 0.999 ± 0.000 | 0.953 ± 0.015 | 0.767 ± 0.114 | 0.973 ± 0.015 | 0.854 ± 0.077 |
| Without ML ensemble | 1.000 ± 0.000 | 0.986 ± 0.001 | 0.980 ± 0.018 | 0.967 ± 0.000 | 0.973 ± 0.009 |
| Personal baseline only | 0.988 ± 0.007 | 0.487 ± 0.044 | 0.309 ± 0.028 | 0.973 ± 0.015 | 0.468 ± 0.031 |
| ML ensemble only | 0.996 ± 0.008 | 0.917 ± 0.044 | 0.821 ± 0.082 | 0.900 ± 0.033 | 0.856 ± 0.041 |
| Threat rules only | 0.983 ± 0.000 | 0.967 ± 0.000 | 1.000 ± 0.000 | 0.967 ± 0.000 | 0.983 ± 0.000 |
