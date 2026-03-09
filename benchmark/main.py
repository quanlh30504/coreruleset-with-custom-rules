#!/usr/bin/env python3
"""
WAF Auto-Test Runner — Main CLI Entry Point

Sends payloads from CSV datasets to a target Nginx ModSecurity WAF,
evaluates detection results, and generates benchmark reports comparing
WAF performance against an AI model (CNN-BiLSTM-Attention).

Usage:
    python main.py --config config.yaml
    python main.py --dataset datasets/xssed_dmoz.csv --dataset-name "XSSed-DMOZ"
    python main.py --target-url http://192.168.1.100:8080 --workers 100
"""

import argparse
import asyncio
import logging
import os
import sys
import time
from datetime import datetime

# Ensure the project root is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config_loader import ConfigLoader
from core.dataset_reader import DatasetReader
from core.metrics_calculator import MetricsCalculator
from core.models import TestSession
from core.payload_dispatcher import PayloadDispatcher
from report.report_generator import ReportGenerator


def setup_logging(level: str, log_file: str):
    """Configure logging to console and file."""
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)

    # File handler
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    root_logger.addHandler(console)
    root_logger.addHandler(file_handler)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="WAF Auto-Test Runner — Benchmark ModSecurity against AI models",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --config config.yaml
  python main.py --dataset datasets/xssed_dmoz.csv --dataset-name "XSSed-DMOZ"
  python main.py --target-url http://192.168.1.100:8080 --method POST --workers 100
        """,
    )
    parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )
    parser.add_argument(
        "--dataset", "-d",
        help="Path to CSV dataset (overrides config)",
    )
    parser.add_argument(
        "--dataset-name",
        help="Dataset display name (overrides config)",
    )
    parser.add_argument(
        "--target-url", "-t",
        help="Target WAF URL (overrides config)",
    )
    parser.add_argument(
        "--method", "-m",
        choices=["GET", "POST"],
        help="HTTP method (overrides config)",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        help="Number of concurrent workers (overrides config)",
    )
    parser.add_argument(
        "--delay",
        type=int,
        help="Delay between requests in ms (overrides config)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Output directory for reports (overrides config)",
    )
    return parser.parse_args()


async def run(config):
    """Main async execution flow."""
    logger = logging.getLogger("main")

    # ---- Step 1: Read Dataset ----
    logger.info("=" * 60)
    logger.info("WAF Auto-Test Runner v1.0.0")
    logger.info("=" * 60)

    reader = DatasetReader()
    payloads = reader.read(config.dataset.filepath, config.dataset.encoding)

    total = len(payloads)
    malicious = sum(1 for p in payloads if p.label == 1)
    benign = total - malicious

    logger.info("Dataset: %s", config.dataset.name)
    logger.info("Total payloads: %d (Malicious: %d, Benign: %d)", total, malicious, benign)
    logger.info("Target: %s (%s)", config.target.url, config.target.method)
    logger.info("Workers: %d | Delay: %dms", config.performance.max_workers, config.performance.delay_ms)

    # ---- Step 2: Dispatch Payloads ----
    start_time = time.time()
    start_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    dispatcher = PayloadDispatcher(config)
    results = await dispatcher.dispatch_all(payloads)

    end_time = time.time()
    end_dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = end_time - start_time

    logger.info("Test completed in %.1f seconds (%.1f req/s)", duration, len(results) / duration if duration > 0 else 0)

    # ---- Step 3: Calculate Metrics ----
    metrics = MetricsCalculator.calculate(results)

    logger.info("-" * 40)
    logger.info("RESULTS:")
    logger.info("  TP: %d | TN: %d | FP: %d | FN: %d | Errors: %d", metrics.tp, metrics.tn, metrics.fp, metrics.fn, metrics.errors)
    logger.info("  Accuracy:  %.2f%%", metrics.accuracy * 100)
    logger.info("  Precision: %.2f%%", metrics.precision * 100)
    logger.info("  Recall:    %.2f%%", metrics.recall * 100)
    logger.info("  F1-Score:  %.2f%%", metrics.f1_score * 100)
    logger.info("  FPR:       %.2f%%", metrics.fpr * 100)
    logger.info("-" * 40)

    # ---- Step 4: Generate Report ----
    session = TestSession(
        dataset_name=config.dataset.name or os.path.basename(config.dataset.filepath),
        dataset_filepath=config.dataset.filepath,
        target_url=config.target.url,
        http_method=config.target.method,
        total_payloads=total,
        total_malicious=malicious,
        total_benign=benign,
        start_time=start_dt,
        end_time=end_dt,
        duration_seconds=duration,
    )

    report_gen = ReportGenerator(config)
    report_path = report_gen.generate(results, metrics, session)

    logger.info("=" * 60)
    logger.info("✅ Report saved: %s", report_path)
    logger.info("=" * 60)

    return report_path


def main():
    """CLI entry point."""
    args = parse_args()

    # Build CLI overrides dict
    overrides = {}
    if args.dataset:
        overrides["dataset"] = args.dataset
    if args.dataset_name:
        overrides["dataset_name"] = args.dataset_name
    if args.target_url:
        overrides["target_url"] = args.target_url
    if args.method:
        overrides["method"] = args.method
    if args.workers:
        overrides["workers"] = args.workers
    if args.delay is not None:
        overrides["delay"] = args.delay
    if args.output:
        overrides["output"] = args.output

    # Load config
    config = ConfigLoader.load(args.config, overrides or None)

    # Validate required fields
    if not config.dataset.filepath:
        print("ERROR: No dataset specified. Use --dataset or set in config.yaml", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(config.dataset.filepath):
        print(f"ERROR: Dataset file not found: {config.dataset.filepath}", file=sys.stderr)
        sys.exit(1)

    # Setup logging
    setup_logging(config.logging.level, config.logging.file)

    # Run
    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        print("\n⚠ Interrupted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        logging.getLogger("main").exception("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
