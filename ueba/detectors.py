"""Anomaly detectors.

Three complementary layers:

1. **Statistical** - robust z-score of today's features against the entity's
   own baseline (``stat``) and against its department peers (``peer``).
2. **Machine learning** - an ensemble of unsupervised models trained only on
   baseline behaviour: Isolation Forest, Local Outlier Factor (novelty mode)
   and an Autoencoder (neural network that learns to reconstruct *normal*
   behaviour; high reconstruction error = unusual).
3. **Rules** - high-confidence threat signatures mapped to MITRE ATT&CK
   (brute force, impossible travel, mining, exfiltration ...).

Each layer returns a score in [0, 1]; ``risk.py`` fuses them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from .config import CONFIG, Config

LABELS = {
    "logins": "successful logins", "failed_logins": "failed logins",
    "max_fail_10min": "failed logins in 10 min", "fail_then_success": "success after failure burst",
    "distinct_src_ips": "source IPs", "new_src_ips": "new source IPs",
    "distinct_dest_hosts": "hosts logged into", "new_dest_hosts": "never-seen hosts logged into",
    "remote_admin_logins": "SSH/RDP sessions", "unregistered_device_logins": "logins from unregistered devices",
    "off_hours_logins": "logins at unusual hours", "countries": "countries", "new_countries": "new countries",
    "impossible_travel": "impossible-travel hops", "access_events": "file/system accesses",
    "sensitive_access": "confidential/restricted accesses", "restricted_access": "restricted accesses",
    "priv_esc": "privilege escalations", "deletes": "deletions", "distinct_resources": "distinct resources",
    "new_resources": "never-seen resources", "new_sensitive_resources": "never-seen sensitive resources",
    "off_hours_access": "accesses at unusual hours", "account_changes": "account creations/changes",
    "log_tamper": "log-clearing actions", "removable_media": "USB / removable-media events", "connections": "network connections",
    "bytes_out_mb": "MB uploaded", "bytes_in_mb": "MB downloaded", "max_upload_mb": "largest single upload (MB)",
    "distinct_domains": "domains contacted", "new_domains": "new domains",
    "new_domain_upload_mb": "MB uploaded to new domains", "cloud_upload_mb": "MB uploaded to cloud storage",
    "new_ports": "new destination ports", "mining_conns": "crypto-mining connections",
    "job_site_visits": "job-site visits", "internal_hosts": "internal hosts contacted",
    "cpu_mean": "avg CPU %", "cpu_max": "peak CPU %", "cpu_high_hours": "hours with CPU > 85%",
    "mem_mean": "avg memory %", "disk_io_mb": "disk I/O (MB)", "active_hours": "active hours",
    "proc_max": "max processes", "logins_to_device": "logins into this device",
    "failed_logins_to_device": "failed logins into this device",
    "distinct_users_on_device": "distinct users on device", "new_users_on_device": "new users on device",
}


def _fmt(v: float) -> str:
    return f"{v:,.0f}" if abs(v) >= 10 else f"{v:,.1f}".rstrip("0").rstrip(".")


# --------------------------------------------------------------------------
# 1. Statistical
# --------------------------------------------------------------------------
def deviation_score(z: pd.DataFrame, z_alert: float) -> np.ndarray:
    """Combine the three largest positive deviations into one 0-1 score."""
    excess = np.clip(np.asarray(z, dtype=float) - z_alert, 0, None)
    if excess.shape[1] < 3:
        excess = np.pad(excess, ((0, 0), (0, 3 - excess.shape[1])))
    top = -np.sort(-excess, axis=1)[:, :3]
    raw = top[:, 0] + 0.5 * top[:, 1] + 0.25 * top[:, 2]
    return 1 - np.exp(-raw / 4.0)


def explain(df: pd.DataFrame, zp: pd.DataFrame, zpeer: pd.DataFrame, cols, z_alert,
            usual: pd.DataFrame, max_items: int = 4) -> list[list[str]]:
    """Human-readable reasons: the largest deviations, with today's value vs the usual value."""
    out = []
    for i in range(len(df)):
        row = df.iloc[i]
        zrow = zp.iloc[i]
        cand = zrow[zrow >= z_alert].sort_values(ascending=False).head(max_items)
        items = []
        for f in cand.index:
            u = float(usual.iloc[i][f])
            val = float(row[f])
            ratio = f" ({val / u:.0f}x usual)" if u > 0 and val / u >= 3 else ""
            peer = " - also unusual vs peers" if zpeer.iloc[i][f] >= z_alert else ""
            items.append(f"{_fmt(val)} {LABELS.get(f, f)} vs usual {_fmt(u)}{ratio}{peer}")
        out.append(items)
    return out


# --------------------------------------------------------------------------
# 2. Machine learning ensemble
# --------------------------------------------------------------------------
class MLEnsemble:
    def __init__(self, cfg: Config = CONFIG):
        self.cfg = cfg
        self.scaler = StandardScaler()
        self.iforest = IsolationForest(n_estimators=cfg.iforest_trees, random_state=cfg.seed)
        self.lof = LocalOutlierFactor(n_neighbors=cfg.lof_neighbors, novelty=True)
        self.ae = MLPRegressor(hidden_layer_sizes=cfg.autoencoder_layers, activation="tanh",
                               max_iter=800, random_state=cfg.seed, early_stopping=True,
                               validation_fraction=0.15, alpha=1e-3)
        self.calib: dict[str, tuple[float, float]] = {}

    def _raw(self, X: np.ndarray) -> dict:
        Xs = self.scaler.transform(X)
        rec = self.ae.predict(Xs)
        return {"iforest": -self.iforest.score_samples(Xs),
                "lof": -self.lof.score_samples(Xs),
                "autoencoder": np.mean((Xs - rec) ** 2, axis=1)}

    def fit(self, X: np.ndarray) -> "MLEnsemble":
        Xs = self.scaler.fit_transform(X)
        self.iforest.fit(Xs)
        self.lof.fit(Xs)
        self.ae.fit(Xs, Xs)
        for k, s in self._raw(X).items():
            med, q99 = np.median(s), np.quantile(s, 0.99)
            self.calib[k] = (med, max(q99 - med, 1e-9))
        return self

    def score(self, X: np.ndarray) -> pd.DataFrame:
        out = {}
        for k, s in self._raw(X).items():
            med, spread = self.calib[k]
            norm = (s - med) / spread               # 1.0 == 99th percentile of normal behaviour
            out[f"ml_{k}"] = np.clip((norm - 1.0) / 3.0, 0, 1)
            out[f"raw_{k}"] = s
        df = pd.DataFrame(out)
        df["ml"] = df[["ml_iforest", "ml_lof", "ml_autoencoder"]].mean(axis=1)
        return df


# --------------------------------------------------------------------------
# 3. Rules (threat signatures)
# --------------------------------------------------------------------------
@dataclass
class Rule:
    rule_id: str
    name: str
    severity: float                           # 0-1 contribution to daily risk
    mitre: str
    applies_to: str                           # "user" or "device"
    when: Callable[[pd.DataFrame], pd.Series]
    message: Callable[[pd.Series], str]


RULES = [
    Rule("R01", "Brute-force success", 0.80, "T1110 Brute Force", "user",
         lambda d: (d["max_fail_10min"] >= 10) & (d["fail_then_success"] > 0),
         lambda r: f"{r.max_fail_10min:.0f} failed logins within 10 min followed by a successful login"),
    Rule("R02", "Brute-force / password spray attempt", 0.45, "T1110 Brute Force", "user",
         lambda d: (d["max_fail_10min"] >= 10) & (d["fail_then_success"] == 0),
         lambda r: f"{r.max_fail_10min:.0f} failed logins within 10 minutes"),
    Rule("R03", "Impossible travel", 0.70, "T1078 Valid Accounts", "user",
         lambda d: d["impossible_travel"] > 0,
         lambda r: "Logins from locations too far apart to travel between in the time elapsed"),
    Rule("R04", "Login from new country", 0.25, "T1078 Valid Accounts", "user",
         lambda d: d["new_countries"] > 0,
         lambda r: f"Login from {r.new_countries:.0f} country never seen for this user"),
    Rule("R05", "Privilege escalation by non-admin", 0.80, "T1068 Exploitation for Privilege Escalation", "user",
         lambda d: (d["priv_esc"] > 0) & (~d["is_admin"].astype(bool)),
         lambda r: f"{r.priv_esc:.0f} privilege-escalation actions by a non-admin account"),
    Rule("R06", "Account manipulation", 0.50, "T1136 Create Account", "user",
         lambda d: d["account_changes"] > 0,
         lambda r: f"{r.account_changes:.0f} account creation / group change commands"),
    Rule("R07", "Security log tampering", 0.80, "T1070 Indicator Removal", "user",
         lambda d: d["log_tamper"] > 0,
         lambda r: "Security/audit logs cleared"),
    Rule("R08", "Large upload to new external domain", 0.55, "T1048 Exfiltration Over Alternative Protocol", "user",
         lambda d: d["new_domain_upload_mb"] >= 100,
         lambda r: f"{r.new_domain_upload_mb:,.0f} MB sent to a domain this user never used before"),
    Rule("R09", "Upload to personal cloud storage", 0.45, "T1567.002 Exfiltration to Cloud Storage", "user",
         lambda d: d["cloud_upload_mb"] >= 50,
         lambda r: f"{r.cloud_upload_mb:,.0f} MB uploaded to file-sharing / cloud storage sites"),
    Rule("R10", "Crypto-mining traffic", 0.80, "T1496 Resource Hijacking", "user",
         lambda d: d["mining_conns"] > 0,
         lambda r: f"{r.mining_conns:.0f} connections to crypto-mining pools / Stratum ports"),
    Rule("R11", "Lateral movement burst", 0.55, "T1021 Remote Services", "user",
         lambda d: d["new_dest_hosts"] >= 5,
         lambda r: f"Logged into {r.new_dest_hosts:.0f} never-seen hosts in one day"),
    Rule("R12", "Off-hours sensitive access", 0.35, "T1078 Valid Accounts", "user",
         lambda d: (d["off_hours_access"] >= 10) & (d["sensitive_access"] > 0),
         lambda r: f"{r.off_hours_access:.0f} file accesses at hours this user is never active"),
    Rule("R13", "Access from unregistered device", 0.25, "T1078 Valid Accounts", "user",
         lambda d: d["unregistered_device_logins"] > 0,
         lambda r: f"{r.unregistered_device_logins:.0f} logins from a device not in the asset inventory"),
    Rule("R14", "Job-site browsing (flight risk)", 0.10, "Insider-risk indicator", "user",
         lambda d: (d["job_site_visits"] > 0) & (d["department"] != "HR"),
         lambda r: f"{r.job_site_visits:.0f} visits to job portals"),
    Rule("R15", "First-time restricted access", 0.30, "T1213 Data from Information Repositories", "user",
         lambda d: (d["new_sensitive_resources"] >= 3) & (d["baseline_restricted"] == 0) & (d["restricted_access"] > 0),
         lambda r: f"{r.new_sensitive_resources:.0f} sensitive resources opened for the first time"),
    # ---- device rules ----
    Rule("D01", "Crypto-mining host", 0.80, "T1496 Resource Hijacking", "device",
         lambda d: d["mining_conns"] > 0,
         lambda r: f"{r.mining_conns:.0f} connections to mining pools"),
    Rule("D02", "Sustained CPU saturation", 0.35, "T1496 Resource Hijacking", "device",
         lambda d: d["cpu_high_hours"] >= 6,
         lambda r: f"CPU above 85% for {r.cpu_high_hours:.0f} hours"),
    Rule("D03", "Large upload to new external domain", 0.55, "T1048 Exfiltration Over Alternative Protocol", "device",
         lambda d: d["new_domain_upload_mb"] >= 100,
         lambda r: f"{r.new_domain_upload_mb:,.0f} MB sent to a new external domain"),
    Rule("D04", "Upload to personal cloud storage", 0.45, "T1567.002 Exfiltration to Cloud Storage", "device",
         lambda d: d["cloud_upload_mb"] >= 50,
         lambda r: f"{r.cloud_upload_mb:,.0f} MB uploaded to cloud storage"),
    Rule("D05", "Brute force against host", 0.45, "T1110 Brute Force", "device",
         lambda d: d["failed_logins_to_device"] >= 10,
         lambda r: f"{r.failed_logins_to_device:.0f} failed logins into this host"),
]


def apply_rules(df: pd.DataFrame, entity_type: str) -> tuple[np.ndarray, list[list[dict]]]:
    """Return the combined rule score per row and the list of rule hits per row."""
    hits: list[list[dict]] = [[] for _ in range(len(df))]
    survive = np.ones(len(df))
    for rule in RULES:
        if rule.applies_to != entity_type:
            continue
        mask = rule.when(df).fillna(False).to_numpy(dtype=bool)
        for i in np.flatnonzero(mask):
            hits[i].append(dict(rule_id=rule.rule_id, name=rule.name, severity=rule.severity,
                                mitre=rule.mitre, message=rule.message(df.iloc[i])))
        survive *= np.where(mask, 1 - rule.severity, 1.0)
    return 1 - survive, hits
