#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DATASETS = Path("/home/quan3054/coreruleset-with-custom-rules/benchmark/datasets")
DEFAULT_OUT = Path("/home/quan3054/gotestwaf/testcases/tunning-dataset")


def read_payloads(path: Path, label: str | None = None) -> list[str]:
    rows: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return rows

        normalized = [h.strip().strip('"').lower() for h in header]
        payload_idx = next((i for i, h in enumerate(normalized) if h in {"payload", "payloads"}), 0)
        label_idx = next((i for i, h in enumerate(normalized) if h == "label"), len(header) - 1)

        for rec in reader:
            if not rec:
                continue
            if len(header) == 2 and len(rec) > 2:
                payload = ",".join(rec[:-1])
                row_label = rec[-1]
            else:
                if payload_idx >= len(rec):
                    continue
                payload = rec[payload_idx]
                row_label = rec[label_idx] if label_idx < len(rec) else ""

            if label is not None and row_label.strip().lower() != label.lower():
                continue
            if payload == "":
                continue
            rows.append(payload)
    return rows


def deterministic_subset(rows: list[str], limit: int) -> list[str]:
    if limit <= 0 or len(rows) <= limit:
        return rows
    ranked = sorted(
        enumerate(rows),
        key=lambda item: hashlib.sha1(f"{item[0]}\0{item[1]}".encode("utf-8", "replace")).hexdigest(),
    )[:limit]
    return [payload for _, payload in sorted(ranked, key=lambda item: item[0])]


def yaml_quote(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def write_case(
    output: Path,
    test_type: str,
    label: str,
    expected_action: str,
    id_prefix: str,
    payloads: list[str],
    encoder: str,
    placeholder: str,
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        f.write(f"type: {test_type}\n")
        f.write(f"default_label: {label}\n")
        f.write(f"expected_action: {expected_action}\n")
        f.write("metrics:\n  unresolved_policy: exclude\n")
        f.write("encoder:\n")
        f.write(f"  - {encoder}\n")
        f.write("placeholder:\n")
        f.write(f"  - {placeholder}\n\n")
        f.write("payload:\n")
        for i, payload in enumerate(payloads):
            f.write(f"  - id: {id_prefix}_{i:06d}\n")
            f.write(f"    value: {yaml_quote(payload)}\n")
            f.write(f"    label: {label}\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Create GoTestWAF tuning dataset for Chapter 3 CGR tuning.")
    ap.add_argument("--datasets-dir", type=Path, default=DEFAULT_DATASETS)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--mereani-xss-limit", type=int, default=5000)
    ap.add_argument("--encoder", default="URL")
    ap.add_argument("--placeholder", default="URLParam")
    args = ap.parse_args()

    datasets = {
        "csic2010_benign": {
            "path": args.datasets_dir / "csic2010_benign.csv",
            "label_filter": "Benign",
            "test_type": "BENIGN",
            "label": "benign",
            "expected": "allow",
            "set": "tunning-benign-csic2010",
            "case": "benign",
            "id_prefix": "csic2010_benign",
        },
        "ecml_benign": {
            "path": args.datasets_dir / "ecml_benign.csv",
            "label_filter": "Benign",
            "test_type": "BENIGN",
            "label": "benign",
            "expected": "allow",
            "set": "tunning-benign-ecml",
            "case": "benign",
            "id_prefix": "ecml_benign",
        },
        "mereani_xss_5k": {
            "path": args.datasets_dir / "Mereani-XSS-Dataset" / "Payloads.csv",
            "label_filter": "Malicious",
            "test_type": "XSS",
            "label": "malicious",
            "expected": "block",
            "set": "tunning-attack-mereani-xss-5k",
            "case": "attack",
            "id_prefix": "mereani_xss_5k",
            "limit": args.mereani_xss_limit,
        },
        "ecml_sqli": {
            "path": args.datasets_dir / "ecml_sqli.csv",
            "label_filter": "Malicious",
            "test_type": "SQLI",
            "label": "malicious",
            "expected": "block",
            "set": "tunning-attack-ecml-sqli",
            "case": "attack",
            "id_prefix": "ecml_sqli",
        },
    }

    manifest: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "output": str(args.out),
        "encoder": args.encoder,
        "placeholder": args.placeholder,
        "datasets": {},
    }

    for name, spec in datasets.items():
        path = Path(spec["path"])
        payloads = read_payloads(path, str(spec["label_filter"]))
        before_limit = len(payloads)
        if "limit" in spec:
            payloads = deterministic_subset(payloads, int(spec["limit"]))

        output = args.out / str(spec["set"]) / f"{spec['case']}.yml"
        write_case(
            output=output,
            test_type=str(spec["test_type"]),
            label=str(spec["label"]),
            expected_action=str(spec["expected"]),
            id_prefix=str(spec["id_prefix"]),
            payloads=payloads,
            encoder=args.encoder,
            placeholder=args.placeholder,
        )
        manifest["datasets"][name] = {
            "source": str(path),
            "rows_after_label_filter": before_limit,
            "rows_written": len(payloads),
            "output": str(output),
        }
        print(f"wrote {len(payloads):>7} rows -> {output}")

    manifest_path = args.out / "tunning-dataset-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"manifest -> {manifest_path}")


if __name__ == "__main__":
    main()
