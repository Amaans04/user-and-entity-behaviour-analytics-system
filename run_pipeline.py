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

from ueba.config import CONFIG, DATA_DIR, DB_PATH


def main():
    ap = argparse.ArgumentParser(description="AI-based User & Entity Behaviour Analytics")
    ap.add_argument("--skip-generate", action="store_true", help="use existing logs in data/raw")
    ap.add_argument("--logs", type=Path, help="folder with auth/access/network/resource logs")
    ap.add_argument("--cert", type=Path, help="folder of the CMU CERT insider-threat dataset (e.g. r4.2)")
    ap.add_argument("--workspace", help="name of a dashboard workspace to analyse (incremental)")
    ap.add_argument("--retrain", action="store_true", help="with --workspace: re-train the models from scratch")
    ap.add_argument("--cert-users", type=int, default=150, help="max CERT users to analyse")
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
        from ueba.cert_loader import convert_cert
        out = DATA_DIR / "cert_converted"
        info = convert_cert(args.cert, out, max_users=args.cert_users)
        print(f"Converted CERT dataset -> {out} ({info})")
        run(out, DB_PATH, CONFIG, train_start=info["train_start"], train_end=info["train_end"])
        return
    raw = args.logs or DATA_DIR / "raw"
    if not args.logs and not args.skip_generate:
        from ueba.generator import generate_dataset
        print("Generating synthetic enterprise logs ...")
        for k, v in generate_dataset(raw, CONFIG).items():
            print(f"  {k:13s} {len(v):>8,} rows")
    res = run(raw, DB_PATH, CONFIG)
    m = res.get("metrics")
    if m:
        print("\n=== Evaluation (detection window) ===")
        print(f"Incidents detected : {m['incidents_detected']}/{m['incidents_total']}")
        print(f"Precision / Recall : {m['precision']:.3f} / {m['recall']:.3f}   F1 {m['f1']:.3f}")
        print(f"False-positive rate: {m['false_positive_rate']:.4f}   alerts/day {m['alerts_per_day']}")
        print(f"Fused ROC-AUC      : {m['detectors']['Fused risk score']['roc_auc']:.3f}")
        print("Full report: reports/evaluation.md")
    print("\nLaunch the dashboard with:  streamlit run dashboard/app.py")


if __name__ == "__main__":
    main()
