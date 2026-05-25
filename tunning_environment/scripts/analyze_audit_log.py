#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEBUG_HEADER = "x-gotestwaf-test"
BLOCKING_RULE_PREFIXES = ("949", "959", "980")


def severity_score(value: str) -> int:
    value = str(value).upper()
    if value in {"2", "CRITICAL"}:
        return 5
    if value in {"3", "ERROR"}:
        return 4
    if value in {"4", "WARNING"}:
        return 3
    if value in {"5", "NOTICE"}:
        return 2
    return 0


def debug_hash(row: dict[str, str]) -> str:
    raw = row.get("raw_payload") or row.get("Payload") or ""
    chain = row.get("encoder_chain") or row.get("Encoder") or row.get("encoder") or ""
    value = "".join([
        row.get("set") or "",
        row.get("case") or "",
        row.get("placeholder") or "",
        chain,
        raw,
    ])
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def load_detail(path: Path) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    rows: list[dict[str, Any]] = []
    by_debug: dict[str, list[dict[str, Any]]] = defaultdict(list)
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            item: dict[str, Any] = dict(row)
            item["_debug"] = debug_hash(row)
            item["_audit_seen"] = False
            item["_audit_status"] = ""
            item["_uri"] = ""
            item["_method"] = ""
            item["_cgr_xss_score"] = 0
            item["_cgr_sqli_score"] = 0
            item["_cgr_max_score"] = 0
            item["_all_detection_score"] = 0
            item["_rule_ids"] = []
            item["_rule_messages"] = []
            rows.append(item)
            by_debug[item["_debug"]].append(item)
    return rows, by_debug


def header_lookup(headers: dict[str, Any]) -> str:
    for key, value in headers.items():
        if str(key).lower() == DEBUG_HEADER:
            return str(value)
    return ""


def parse_messages(messages: list[dict[str, Any]]) -> tuple[list[dict[str, str]], int, int, int, int]:
    rules: list[dict[str, str]] = []
    seen: set[str] = set()
    xss_score = 0
    sqli_score = 0
    all_detection_score = 0

    for msg in messages:
        details = msg.get("details", {}) or {}
        rule_id = str(details.get("ruleId", ""))
        if not rule_id or rule_id in seen:
            continue
        seen.add(rule_id)

        sev = str(details.get("severity", ""))
        score = severity_score(sev)
        message = str(msg.get("message", ""))
        file_name = str(details.get("file", ""))
        data = str(details.get("data", ""))
        tags = details.get("tags", []) or []
        rules.append({
            "rule_id": rule_id,
            "severity": sev,
            "score": str(score),
            "message": message,
            "file": file_name,
            "data": data,
            "tags": ";".join(str(t) for t in tags),
        })

        if rule_id.startswith("9942"):
            xss_score += score
        elif rule_id.startswith("9943"):
            sqli_score += score

        if not rule_id.startswith(BLOCKING_RULE_PREFIXES):
            all_detection_score += score

    return rules, xss_score, sqli_score, max(xss_score, sqli_score), all_detection_score


def parse_audit(audit_log: Path, by_debug: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    stats = {
        "events": 0,
        "events_with_debug_header": 0,
        "events_matched_detail": 0,
        "events_unmatched_detail": 0,
        "json_errors": 0,
    }

    with audit_log.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                stats["json_errors"] += 1
                continue

            stats["events"] += 1
            tx = event.get("transaction", {}) or {}
            request = tx.get("request", {}) or {}
            response = tx.get("response", {}) or {}
            headers = request.get("headers", {}) or {}
            debug = header_lookup(headers)
            if not debug:
                continue
            stats["events_with_debug_header"] += 1

            targets = by_debug.get(debug)
            if not targets:
                stats["events_unmatched_detail"] += 1
                continue
            stats["events_matched_detail"] += 1

            rules, xss_score, sqli_score, max_score, all_detection_score = parse_messages(tx.get("messages", []) or [])
            rule_ids = [r["rule_id"] for r in rules]
            rule_messages = [f"{r['rule_id']}:{r['message']}" for r in rules]
            for row in targets:
                row["_audit_seen"] = True
                row["_audit_status"] = str(response.get("http_code", ""))
                row["_uri"] = str(request.get("uri", ""))
                row["_method"] = str(request.get("method", ""))
                row["_cgr_xss_score"] = xss_score
                row["_cgr_sqli_score"] = sqli_score
                row["_cgr_max_score"] = max_score
                row["_all_detection_score"] = all_detection_score
                row["_rule_ids"] = rule_ids
                row["_rule_messages"] = rule_messages
                row["_rules_detail"] = rules

    return stats


def classify(row: dict[str, Any], prediction_key: str = "prediction") -> str:
    label = str(row.get("label", "")).lower()
    prediction = str(row.get(prediction_key, "")).lower()
    if prediction not in {"blocked", "passed"}:
        status = str(row.get("_audit_status") or row.get("response_status_code") or "")
        prediction = "blocked" if status == "403" else "passed"
    if label == "malicious":
        return "tp" if prediction == "blocked" else "fn"
    if label == "benign":
        return "fp" if prediction == "blocked" else "tn"
    return "unknown"


def metric_dict(counts: Counter[str]) -> dict[str, int | float]:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "n": tp + fp + tn + fn,
        "recall": recall,
        "fpr": fpr,
        "precision": precision,
        "f1": f1,
    }


def write_joined(rows: list[dict[str, Any]], out: Path) -> None:
    fields = [
        "test_id",
        "payload_id",
        "label",
        "expected_action",
        "prediction",
        "outcome",
        "response_status_code",
        "audit_status",
        "type",
        "set",
        "case",
        "placeholder",
        "encoder_chain",
        "cgr_xss_score",
        "cgr_sqli_score",
        "cgr_max_score",
        "all_detection_score",
        "audit_seen",
        "rule_ids",
        "uri",
        "raw_payload",
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                "test_id": row.get("test_id", ""),
                "payload_id": row.get("payload_id", ""),
                "label": row.get("label", ""),
                "expected_action": row.get("expected_action", ""),
                "prediction": row.get("prediction", ""),
                "outcome": row.get("outcome", ""),
                "response_status_code": row.get("response_status_code", ""),
                "audit_status": row.get("_audit_status", ""),
                "type": row.get("type", ""),
                "set": row.get("set", ""),
                "case": row.get("case", ""),
                "placeholder": row.get("placeholder", ""),
                "encoder_chain": row.get("encoder_chain", ""),
                "cgr_xss_score": row.get("_cgr_xss_score", 0),
                "cgr_sqli_score": row.get("_cgr_sqli_score", 0),
                "cgr_max_score": row.get("_cgr_max_score", 0),
                "all_detection_score": row.get("_all_detection_score", 0),
                "audit_seen": row.get("_audit_seen", False),
                "rule_ids": ";".join(row.get("_rule_ids", [])),
                "uri": row.get("_uri", ""),
                "raw_payload": row.get("raw_payload", ""),
            })


def write_score_distribution(rows: list[dict[str, Any]], out: Path) -> None:
    dist: Counter[tuple[str, int]] = Counter()
    for row in rows:
        label = str(row.get("label", "")).lower()
        score = int(row.get("_cgr_max_score", 0))
        dist[(label, score)] += 1
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["label", "cgr_max_score", "count"])
        for (label, score), count in sorted(dist.items(), key=lambda x: (x[0][0], x[0][1])):
            writer.writerow([label, score, count])


def write_rule_hits(rows: list[dict[str, Any]], out: Path, target_class: str) -> None:
    counter: Counter[str] = Counter()
    examples: dict[str, dict[str, str]] = {}
    for row in rows:
        if classify(row) != target_class:
            continue
        for rule in row.get("_rules_detail", []) or []:
            rule_id = rule["rule_id"]
            if rule_id.startswith(BLOCKING_RULE_PREFIXES):
                continue
            counter[rule_id] += 1
            examples.setdefault(rule_id, rule)

    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["rule_id", "hits", "severity", "score", "message", "file", "tags"])
        writer.writeheader()
        for rule_id, hits in counter.most_common():
            ex = examples[rule_id]
            writer.writerow({
                "rule_id": rule_id,
                "hits": hits,
                "severity": ex.get("severity", ""),
                "score": ex.get("score", ""),
                "message": ex.get("message", ""),
                "file": ex.get("file", ""),
                "tags": ex.get("tags", ""),
            })


def write_examples(rows: list[dict[str, Any]], out: Path, target_class: str, limit: int = 100) -> None:
    fields = [
        "class",
        "label",
        "prediction",
        "response_status_code",
        "audit_status",
        "type",
        "set",
        "payload_id",
        "cgr_xss_score",
        "cgr_sqli_score",
        "cgr_max_score",
        "rule_ids",
        "raw_payload",
    ]
    selected = [row for row in rows if classify(row) == target_class][:limit]
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in selected:
            writer.writerow({
                "class": target_class,
                "label": row.get("label", ""),
                "prediction": row.get("prediction", ""),
                "response_status_code": row.get("response_status_code", ""),
                "audit_status": row.get("_audit_status", ""),
                "type": row.get("type", ""),
                "set": row.get("set", ""),
                "payload_id": row.get("payload_id", ""),
                "cgr_xss_score": row.get("_cgr_xss_score", 0),
                "cgr_sqli_score": row.get("_cgr_sqli_score", 0),
                "cgr_max_score": row.get("_cgr_max_score", 0),
                "rule_ids": ";".join(row.get("_rule_ids", [])),
                "raw_payload": row.get("raw_payload", ""),
            })


def tau_sweep(rows: list[dict[str, Any]], taus: list[int]) -> list[dict[str, int | float]]:
    output = []
    for tau in taus:
        counts: Counter[str] = Counter()
        for row in rows:
            label = str(row.get("label", "")).lower()
            if label not in {"benign", "malicious"}:
                continue
            score = int(row.get("_cgr_max_score", 0))
            prediction = "blocked" if score >= tau else "passed"
            virtual = {"label": label, "prediction": prediction}
            counts[classify(virtual)] += 1
        output.append({"tau_v2": tau, **metric_dict(counts)})
    return output


def write_tau(rows: list[dict[str, Any]], taus: list[int], out_csv: Path, out_json: Path) -> list[dict[str, int | float]]:
    data = tau_sweep(rows, taus)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["tau_v2", "n", "tp", "fp", "tn", "fn", "recall", "fpr", "precision", "f1"])
        writer.writeheader()
        writer.writerows(data)
    out_json.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def write_recommendations(rows: list[dict[str, Any]], tau_data: list[dict[str, int | float]], audit_stats: dict[str, int], out: Path) -> None:
    counts: Counter[str] = Counter(classify(row) for row in rows)
    actual = metric_dict(counts)

    fp_rules: Counter[str] = Counter()
    fp_cgr_rules: Counter[str] = Counter()
    fp_crs_rules: Counter[str] = Counter()
    fn_sets: Counter[str] = Counter()

    for row in rows:
        cls = classify(row)
        if cls == "fp":
            for rule_id in row.get("_rule_ids", []):
                if rule_id.startswith(BLOCKING_RULE_PREFIXES):
                    continue
                fp_rules[rule_id] += 1
                if rule_id.startswith(("9942", "9943")):
                    fp_cgr_rules[rule_id] += 1
                else:
                    fp_crs_rules[rule_id] += 1
        elif cls == "fn":
            fn_sets[str(row.get("set", "unknown"))] += 1

    lines = [
        "# Tuning Recommendations",
        "",
        "## Actual GoTestWAF result",
        "",
        f"- Total classified requests: {actual['n']}",
        f"- TP/FP/TN/FN: {actual['tp']}/{actual['fp']}/{actual['tn']}/{actual['fn']}",
        f"- Recall: {actual['recall'] * 100:.4f}%",
        f"- FPR: {actual['fpr'] * 100:.4f}%",
        f"- Audit events: {audit_stats['events']}",
        f"- Audit events matched to GoTestWAF detail CSV: {audit_stats['events_matched_detail']}",
        "",
        "## Virtual tau_v2 sweep",
        "",
        "| tau_v2 | n | TP | FP | TN | FN | Recall % | FPR % |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in tau_data:
        lines.append(
            f"| {item['tau_v2']} | {item['n']} | {item['tp']} | {item['fp']} | {item['tn']} | {item['fn']} | "
            f"{item['recall'] * 100:.4f} | {item['fpr'] * 100:.4f} |"
        )

    lines.extend(["", "## FP rule candidates", ""])
    if not fp_rules:
        lines.append("- No FP rule hits found in the joined audit data.")
    else:
        lines.append("- High FP CGR rules should be tightened first: add context, narrow variables, or lower severity if the signal is weak.")
        lines.append("- High FP CRS rules should only be removed with `SecRuleRemoveById` when the log evidence is clear and CGR already covers the thesis scope.")
        lines.append("")
        lines.append("| rule_id | FP hits | candidate action |")
        lines.append("|---:|---:|---|")
        for rule_id, hits in fp_rules.most_common(15):
            action = "tighten CGR pattern / review severity" if rule_id.startswith(("9942", "9943")) else "review for TUNING-EXCLUSIONS.conf"
            lines.append(f"| {rule_id} | {hits} | {action} |")

    lines.extend(["", "## FN guardrail", ""])
    if not fn_sets:
        lines.append("- No FN found in GoTestWAF detail CSV.")
    else:
        lines.append("- FN means malicious payload passed. Use `fn_examples.csv` to inspect payload families before adding rules.")
        lines.append("- Do not tune purely for attack recall if it increases benign FPR beyond the Chapter 3 stopping rule.")
        lines.append("")
        lines.append("| source set | FN count |")
        lines.append("|---|---:|")
        for name, hits in fn_sets.most_common():
            lines.append(f"| {name} | {hits} |")

    lines.extend([
        "",
        "## Decision rule",
        "",
        "- Continue tuning while FPR is above 0.5%.",
        "- Reject a change if recall drops by more than 1 percentage point compared with the previous round.",
        "- Prefer CGR pattern tightening for FP caused by `9942xxx` or `9943xxx`.",
        "- Prefer scoped `SecRuleRemoveById` only for CRS rules with repeated FP evidence.",
    ])
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    csv.field_size_limit(sys.maxsize)
    ap = argparse.ArgumentParser(description="Analyze ModSecurity audit JSON and GoTestWAF detail CSV for Chapter 3 tuning.")
    ap.add_argument("--audit-log", type=Path, default=Path("logs/modsec_audit.log"))
    ap.add_argument("--detail-csv", type=Path, default=Path("results/tunning-dataset_detail.csv"))
    ap.add_argument("--out-dir", type=Path, default=Path("results"))
    ap.add_argument("--tau", type=int, action="append", default=None)
    args = ap.parse_args()

    if not args.audit_log.exists():
        raise SystemExit(f"audit log not found: {args.audit_log}")
    if not args.detail_csv.exists():
        raise SystemExit(f"detail CSV not found: {args.detail_csv}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows, by_debug = load_detail(args.detail_csv)
    collision_count = sum(len(items) - 1 for items in by_debug.values() if len(items) > 1)
    audit_stats = parse_audit(args.audit_log, by_debug)
    audit_stats["debug_hash_collisions"] = collision_count
    audit_stats["detail_rows"] = len(rows)
    audit_stats["detail_rows_seen_in_audit"] = sum(1 for row in rows if row.get("_audit_seen"))

    write_joined(rows, args.out_dir / "audit_joined.csv")
    write_score_distribution(rows, args.out_dir / "score_distribution.csv")
    write_rule_hits(rows, args.out_dir / "rule_hits_fp.csv", "fp")
    write_rule_hits(rows, args.out_dir / "rule_hits_fn.csv", "fn")
    write_examples(rows, args.out_dir / "fp_examples.csv", "fp")
    write_examples(rows, args.out_dir / "fn_examples.csv", "fn")
    taus = args.tau or [12, 8, 5]
    tau_data = write_tau(rows, taus, args.out_dir / "tau_sweep.csv", args.out_dir / "tau_sweep.json")
    write_recommendations(rows, tau_data, audit_stats, args.out_dir / "tuning_recommendations.md")
    (args.out_dir / "audit_analysis_summary.json").write_text(json.dumps(audit_stats, indent=2), encoding="utf-8")

    counts: Counter[str] = Counter(classify(row) for row in rows)
    actual = metric_dict(counts)
    print(json.dumps({"actual": actual, "audit": audit_stats}, indent=2))
    print(f"wrote analysis files to {args.out_dir}")


if __name__ == "__main__":
    main()
