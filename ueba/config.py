"""Central configuration for the UEBA system.

All tunable numbers live here so they can be explained (and changed) in one place.
"""
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports"
DB_PATH = DATA_DIR / "ueba.db"


@dataclass
class Config:
    # ---- data generation -------------------------------------------------
    seed: int = 42
    start_date: str = "2026-07-01"
    n_days: int = 60
    train_days: int = 30          # first N days = baseline (attack free)
    warmup_days: int = 5          # first days used only to seed "seen before" sets

    # ---- behaviour profiling ---------------------------------------------
    off_hours_prob: float = 0.02  # login hour with < 2% historical probability = unusual
    z_clip: float = 10.0          # cap on robust z-scores
    z_alert: float = 3.0          # a feature counts as deviating above this z
    history_days: int = 45        # adaptive baseline: last N accepted days per entity
    quarantine_risk: float = 60.0 # days at/above this risk never enter the baseline

    # ---- ML detectors ----------------------------------------------------
    iforest_trees: int = 300
    lof_neighbors: int = 25
    autoencoder_layers: tuple = (16, 6, 16)

    # ---- risk scoring ----------------------------------------------------
    w_stat: float = 0.28          # personal-baseline deviation
    w_peer: float = 0.10          # deviation from department peers
    w_ml: float = 0.30            # ML ensemble
    # rule scores are added directly (see detectors.RULES)
    risk_half_life_days: float = 3.0
    # Daily risk needed to alert. Chosen so that the personal+peer baselines alone
    # (max score 0.953 each -> A = 0.337, x1.3 criticality = 43.8) can NOT alert:
    # an alert needs corroboration from the ML ensemble or a threat rule.
    alert_threshold: float = 45.0
    criticality: dict = field(default_factory=lambda: {
        "IT-Admin": 1.3, "Finance": 1.2, "Management": 1.2, "HR": 1.1,
        "Engineering": 1.0, "Sales": 1.0, "server": 1.3, "laptop": 1.0,
    })

    # ---- rules ---------------------------------------------------------------
    disabled_rules: tuple = ()     # rule ids to switch off (ablations / "out-of-the-box" comparisons)

    # ---- impossible travel -----------------------------------------------
    max_travel_kmh: float = 900.0  # faster than a commercial jet = impossible


CONFIG = Config()
