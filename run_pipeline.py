"""Command-line entry point.

Examples
--------
    python run_pipeline.py                     # generate synthetic logs + run everything
    python run_pipeline.py --skip-generate     # re-run analytics on existing data/raw logs
    python run_pipeline.py --cert path/to/r4.2 # run on the CERT insider-threat dataset
    python run_pipeline.py --logs my_logs/     # run on your own CSV/JSONL logs
    python run_pipeline.py --workspace "Lab"   # analyse new data in a dashboard workspace (incremental)
"""
import argparse
from pathlib import Path

import pandas as pd

from ueba.config import CONFIG, DATA_DIR, DB_PATH


def main():
    ap = argparse.ArgumentParser(description="AI-based User & Entity Behaviour Analytics")
    ap.add_argument("--skip-generate", action="store_true", help="use existing logs in data/raw")
    ap.add_argument("--logs", type=Path, help="folder with auth/access/network/resource logs")
    ap.add_argument("--cert", type=Path, help="folder of the CMU CERT insider-threat dataset (e.g. r4.2)")
    ap.add_argument("--workspace", help="name of a dashboard workspace to analyse (incremental)")
    ap.add_argument("--retrain", action="store_true", help="with --workspace: re-train the models from scratch")
    ap.add_argument("--cert-users", type=int, default=1000, help="max CERT users to analyse (r4.2 has 1000)")
    ap.add_argument("--seed", type=int, default=CONFIG.seed)
    ap.add_argument("--days", type=int, default=CONFIG.n_days)
    ap.add_argument("--threshold", type=float, default=CONFIG.alert_threshold)
    args = ap.parse_args()

    CONFIG.seed, CONFIG.n_days, CONFIG.alert_threshold = args.seed, args.days, args.threshold

    from ueba.pipeline import run
    if args.workspace:
        from ueba import workspace
        ws = workspace.find(args.workspace)
        res = ws.analyse() if args.retrain else ws.update()
        print(f"{ws.name}: {res['mode']} analysis - {len(res['alerts'])} alerts - state {ws.status()['state']}")
        return
    if args.cert:
        # CERT gets its own workspace, so the demo results stay untouched and both can be
        # compared side by side in the dashboard
        from ueba import workspace
        from ueba.cert_loader import convert_cert
        out = DATA_DIR / "cert_converted" / args.cert.name
        info = convert_cert(args.cert, out, max_users=args.cert_users)
        print(f"Converted CERT dataset -> {out}\n  {info}")
        name = f"CERT {args.cert.name}"
        try:
            ws = workspace.find(name)
        except KeyError:
            ws = workspace.create(name)
        ws.update_settings(auto_ingest=False)        # a benchmark, not a live feed
        ws.import_folder(out, source="cert")
        first = min(pd.Timestamp(v["first"]) for k, v in ws.reload().meta["streams"].items() if "first" in v)
        ws.set_learning_days((pd.Timestamp(info["train_end"]) - first.normalize()).days)
        res = ws.analyse()
        _report(res.get("metrics"))
        print(f"Workspace '{ws.name}' - open it in the dashboard; reports in {ws.reports_dir}")
        return
    raw = args.logs or DATA_DIR / "raw"
    if not args.logs and not args.skip_generate:
        from ueba.generator import generate_dataset
        print("Generating synthetic enterprise logs ...")
        for k, v in generate_dataset(raw, CONFIG).items():
            print(f"  {k:13s} {len(v):>8,} rows")
    res = run(raw, DB_PATH, CONFIG)
    _report(res.get("metrics"))
    print("\nLaunch the dashboard with:  python launch.py")


def _report(m):
    if m:
        print("\n=== Evaluation (detection window) ===")
        print(f"Incidents detected : {m['incidents_detected']}/{m['incidents_total']}")
        print(f"Precision / Recall : {m['precision']:.3f} / {m['recall']:.3f}   F1 {m['f1']:.3f}")
        print(f"False-positive rate: {m['false_positive_rate']:.4f}   alerts/day {m['alerts_per_day']}")
        print(f"Fused ROC-AUC      : {m['detectors']['Fused risk score']['roc_auc']:.3f}")
        print("Full report: evaluation.md in the reports folder")


if __name__ == "__main__":
    main()
