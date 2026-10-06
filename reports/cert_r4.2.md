# CERT r4.2 benchmark

1,000 users, 70 insiders in three scenarios (r4.2-1: first-time USB user leaks data; r4.2-2: job-hunter steals data before leaving; r4.2-3: disgruntled admin plants a keylogger). Learning period Jan-May 2010 (attack-free); detection window Jun 2010 - May 2011; user-days. See `experiments_cert.py` for the protocol.

## Held-out test half (quoted)

| Measure | Out-of-the-box | With R16 |
|---|---|---|
| Insiders alerted on a malicious day | 3/36 | 22/36 |
|   r4.2-1 | 1/18 | 18/18 |
|   r4.2-2 | 1/14 | 1/14 |
|   r4.2-3 | 1/4 | 3/4 |
| Alerts per day | 0.66 | 0.84 |
| Day-level precision | 0.017 | 0.146 |
| Day-level recall | 0.008 | 0.091 |
| False-positive rate | 0.2020% | 0.2220% |
| Fused ROC-AUC | 0.699 | 0.733 |
| Fused PR-AUC | 0.0096 | 0.0212 |
| Insiders in the top-1 users per day | 1/36 | 12/36 |
| Insiders in the top-3 users per day | 12/36 | 28/36 |
| Insiders in the top-5 users per day | 19/36 | 33/36 |

## Development half

| Measure | Out-of-the-box | With R16 |
|---|---|---|
| Insiders alerted on a malicious day | 4/36 | 17/36 |
|   r4.2-1 | 2/12 | 12/12 |
|   r4.2-2 | 0/16 | 0/16 |
|   r4.2-3 | 2/8 | 5/8 |
| Alerts per day | 0.24 | 0.37 |
| Day-level precision | 0.048 | 0.277 |
| Day-level recall | 0.008 | 0.070 |
| False-positive rate | 0.0720% | 0.0840% |
| Fused ROC-AUC | 0.703 | 0.731 |
| Fused PR-AUC | 0.0111 | 0.0296 |
| Insiders in the top-1 users per day | 10/36 | 21/36 |
| Insiders in the top-3 users per day | 17/36 | 25/36 |
| Insiders in the top-5 users per day | 20/36 | 28/36 |

## All users

| Measure | Out-of-the-box | With R16 |
|---|---|---|
| Insiders alerted on a malicious day | 7/72 | 39/72 |
|   r4.2-1 | 3/30 | 30/30 |
|   r4.2-2 | 1/30 | 1/30 |
|   r4.2-3 | 3/12 | 8/12 |
| Alerts per day | 0.9 | 1.21 |
| Day-level precision | 0.025 | 0.186 |
| Day-level recall | 0.008 | 0.080 |
| False-positive rate | 0.1370% | 0.1540% |
| Fused ROC-AUC | 0.701 | 0.732 |
| Fused PR-AUC | 0.0100 | 0.0232 |
| Insiders in the top-1 users per day | 5/72 | 23/72 |
| Insiders in the top-3 users per day | 21/72 | 48/72 |
| Insiders in the top-5 users per day | 28/72 | 54/72 |

## Ranking quality of each layer (ROC-AUC, all users)

| Layer | Out-of-the-box | With R16 |
|---|---|---|
| stat | 0.54 | 0.54 |
| peer | 0.499 | 0.499 |
| ml | 0.547 | 0.547 |
| ml_iforest | 0.521 | 0.521 |
| ml_lof | 0.504 | 0.504 |
| ml_autoencoder | 0.543 | 0.543 |
| rule | 0.673 | 0.711 |
| daily_risk | 0.701 | 0.732 |
