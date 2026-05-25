#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


def compute(rows: list[dict[str, str]], tau: int) -> dict[str, int | float]:
    stats = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "n": 0}
    for row in rows:
        label = (row.get("label") or "").lower()
        if label not in {"benign", "malicious"}:
            continue
        try:
            score = int(float(row.get("cgr_max_score") or 0))
        except ValueError:
            score = 0
        predicted_block = score >= tau
        stats["n"] += 1
        if label == "malicious":
            stats["tp" if predicted_block else "fn"] += 1
        else:
            stats["fp" if predicted_block else "tn"] += 1
    tp, fp, tn, fn = stats["tp"], stats["fp"], stats["tn"], stats["fn"]
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        **stats,
        "tau_v2": tau,
        "recall": recall,
        "fpr": fpr,
        "precision": precision,
        "f1": f1,
    }


def main() -> None:
    csv.field_size_limit(sys.maxsize)
    ap = argparse.ArgumentParser(description="Evaluate virtual tau_v2 from analyze_audit_log audit_joined.csv.")
    ap.add_argument("--joined-csv", type=Path, default=Path("results/audit_joined.csv"))
    ap.add_argument("--tau", type=int, action="append", default=None)
    ap.add_argument("--out-csv", type=Path, default=Path("results/tau_sweep.csv"))
    ap.add_argument("--out-json", type=Path, default=Path("results/tau_sweep.json"))
    args = ap.parse_args()

    if not args.joined_csv.exists():
        raise SystemExit(f"joined CSV not found: {args.joined_csv}")

    with args.joined_csv.open("r", encoding="utf-8", errors="replace", newline="") as f:
        rows = list(csv.DictReader(f))

    taus = args.tau or [12, 8, 5]
    results = [compute(rows, tau) for tau in taus]
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["tau_v2", "n", "tp", "fp", "tn", "fn", "recall", "fpr", "precision", "f1"])
        writer.writeheader()
        writer.writerows(results)
    args.out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")
    for item in results:
        print(
            f"tau_v2={item['tau_v2']}: n={item['n']} "
            f"Recall={item['recall'] * 100:.4f}% FPR={item['fpr'] * 100:.4f}%"
        )


if __name__ == "__main__":
    main()
