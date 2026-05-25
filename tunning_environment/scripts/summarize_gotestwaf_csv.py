#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path


def pct(value: float) -> float:
    return round(value * 100.0, 6)


def empty_stats() -> dict[str, int]:
    return {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "unresolved": 0, "failed": 0, "n": 0}


def add_row(stats: dict[str, int], label: str, prediction: str) -> None:
    stats["n"] += 1
    if prediction == "unresolved":
        stats["unresolved"] += 1
        return
    if prediction == "failed":
        stats["failed"] += 1
        return
    if label == "malicious":
        if prediction == "blocked":
            stats["tp"] += 1
        elif prediction == "passed":
            stats["fn"] += 1
    elif label == "benign":
        if prediction == "blocked":
            stats["fp"] += 1
        elif prediction == "passed":
            stats["tn"] += 1


def metrics(stats: dict[str, int]) -> dict[str, float]:
    tp, fp, tn, fn = stats["tp"], stats["fp"], stats["tn"], stats["fn"]
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "recall_pct": pct(recall),
        "fpr_pct": pct(fpr),
        "precision_pct": pct(precision),
        "f1_pct": pct(f1),
    }


def main() -> None:
    csv.field_size_limit(sys.maxsize)
    ap = argparse.ArgumentParser(description="Summarize GoTestWAF detail CSV into TP/FP/TN/FN metrics.")
    ap.add_argument("--detail-csv", type=Path, default=Path("results/tunning-dataset_detail.csv"))
    ap.add_argument("--out-json", type=Path, default=Path("results/gotestwaf_summary.json"))
    ap.add_argument("--out-md", type=Path, default=Path("results/gotestwaf_summary.md"))
    args = ap.parse_args()

    if not args.detail_csv.exists():
        raise SystemExit(f"detail CSV not found: {args.detail_csv}")

    aggregate = empty_stats()
    per_set: dict[str, dict[str, int]] = defaultdict(empty_stats)
    per_type: dict[str, dict[str, int]] = defaultdict(empty_stats)

    with args.detail_csv.open("r", encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            label = (row.get("label") or "").lower()
            prediction = (row.get("prediction") or "").lower()
            test_set = row.get("set") or "unknown"
            test_type = row.get("type") or "unknown"
            add_row(aggregate, label, prediction)
            add_row(per_set[test_set], label, prediction)
            add_row(per_type[test_type], label, prediction)

    out = {
        "detail_csv": str(args.detail_csv),
        "aggregate": {**aggregate, **metrics(aggregate)},
        "per_set": {k: {**v, **metrics(v)} for k, v in sorted(per_set.items())},
        "per_type": {k: {**v, **metrics(v)} for k, v in sorted(per_type.items())},
    }

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(out, indent=2), encoding="utf-8")

    lines = [
        "# GoTestWAF Summary",
        "",
        "| scope | n | TP | FP | TN | FN | unresolved | failed | Recall % | FPR % |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    def line(scope: str, s: dict[str, int]) -> str:
        m = metrics(s)
        return (
            f"| {scope} | {s['n']} | {s['tp']} | {s['fp']} | {s['tn']} | {s['fn']} | "
            f"{s['unresolved']} | {s['failed']} | {m['recall_pct']:.4f} | {m['fpr_pct']:.4f} |"
        )

    lines.append(line("aggregate", aggregate))
    for name, stats in sorted(per_set.items()):
        lines.append(line(name, stats))

    args.out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(out["aggregate"], indent=2))
    print(f"wrote {args.out_json}")
    print(f"wrote {args.out_md}")


if __name__ == "__main__":
    main()
