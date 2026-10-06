# Trend layer (7-day windows) on CERT r4.2 - not adopted

Weight 0 = the system as used (with R16). Decided on the development half.

| weight | split | roc_auc | alerts_per_day | precision | insiders | scenario2 | top5_budget |
|---|---|---|---|---|---|---|---|
| 0.0 | dev | 0.731 | 0.37 | 0.277 | 17/36 | 0/16 | 28/36 |
| 0.0 | test | 0.733 | 0.84 | 0.146 | 22/36 | 1/14 | 33/36 |
| 0.25 | dev | 0.832 | 0.67 | 0.153 | 17/36 | 0/16 | 22/36 |
| 0.25 | test | 0.854 | 1.44 | 0.089 | 22/36 | 1/14 | 28/36 |
| 0.35 | dev | 0.834 | 4.25 | 0.035 | 26/36 | 8/16 | 20/36 |
| 0.35 | test | 0.859 | 5.0 | 0.037 | 30/36 | 9/14 | 28/36 |
| 0.5 | dev | 0.837 | 14.37 | 0.021 | 29/36 | 11/16 | 17/36 |
| 0.5 | test | 0.86 | 14.6 | 0.024 | 32/36 | 11/14 | 27/36 |

Ranking (ROC-AUC) improves by about 0.1, but a weight small enough to keep alerts near one a day catches no additional insider, a weight that catches half of the scenario-2 insiders multiplies alerts by about 11 at 3-4 % precision, and every weight lowers the number of insiders an analyst finds in the five riskiest users per day. Gradual insiders need sequence-aware models rather than longer windows.
