"""
HTML report generator for the WAF Auto-Test Runner.

Renders test results into a professional dashboard HTML report
using Jinja2 templates with Chart.js visualizations.
"""

import csv
import html
import logging
import os
from datetime import datetime
from typing import List, Optional

from jinja2 import Environment, FileSystemLoader

from core.config_loader import AIDatasetBenchmark, AppConfig
from core.models import (
    AIBenchmark,
    MetricComparison,
    MetricsReport,
    TestResult,
    TestSession,
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates HTML reports and CSV exports from test results."""

    def __init__(self, config: AppConfig):
        self.config = config
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True,
        )

    def generate(
        self,
        results: List[TestResult],
        metrics: MetricsReport,
        session: TestSession,
    ) -> str:
        """
        Generate the full HTML report and optional CSV exports.

        Args:
            results: All test results.
            metrics: Computed metrics.
            session: Test session metadata.

        Returns:
            Path to the generated HTML report file.
        """
        output_dir = self.config.output.report_dir
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ds_slug = session.dataset_name.replace(" ", "_").replace("-", "_").lower()

        # --- Generate HTML report ---
        report_path = os.path.join(
            output_dir, f"report_{ds_slug}_{timestamp}.html"
        )
        self._render_html(results, metrics, session, report_path)
        logger.info("HTML report saved: %s", report_path)

        # --- Export raw results CSV ---
        if self.config.output.export_csv:
            csv_path = os.path.join(
                output_dir, f"results_{ds_slug}_{timestamp}.csv"
            )
            self._export_results_csv(results, csv_path)
            logger.info("Results CSV saved: %s", csv_path)

        # --- Export false negatives CSV ---
        if self.config.output.export_false_negatives:
            fn_path = os.path.join(
                output_dir, f"false_negatives_{ds_slug}_{timestamp}.csv"
            )
            fn_results = [r for r in results if r.classification == "FN"]
            self._export_results_csv(fn_results, fn_path)
            logger.info(
                "False negatives CSV saved: %s (%d entries)",
                fn_path, len(fn_results),
            )

        return report_path

    def _render_html(
        self,
        results: List[TestResult],
        metrics: MetricsReport,
        session: TestSession,
        output_path: str,
    ):
        """Render the Jinja2 HTML template with all data."""
        template = self.env.get_template("report_template.html")

        # Build AI benchmark comparison
        ai_ref = self._get_ai_benchmark(session.dataset_name)
        comparisons = self._build_comparisons(metrics, ai_ref)

        # Collect false negatives (bypassed payloads)
        false_negatives = [r for r in results if r.classification == "FN"]
        false_positives = [r for r in results if r.classification == "FP"]

        top_fn_count = self.config.output.top_fn_count

        # Format duration
        mins = int(session.duration_seconds // 60)
        secs = int(session.duration_seconds % 60)
        duration_str = f"{mins}m {secs}s"

        context = {
            # Session metadata
            "session": session,
            "duration_str": duration_str,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            # Metrics
            "metrics": metrics,
            "accuracy_pct": round(metrics.accuracy * 100, 2),
            "precision_pct": round(metrics.precision * 100, 2),
            "recall_pct": round(metrics.recall * 100, 2),
            "f1_pct": round(metrics.f1_score * 100, 2),
            "fpr_pct": round(metrics.fpr * 100, 2),

            # AI benchmark
            "ai_benchmark": ai_ref,
            "comparisons": comparisons,

            # Chart data (percentages for radar)
            "waf_accuracy": round(metrics.accuracy * 100, 2),
            "waf_precision": round(metrics.precision * 100, 2),
            "waf_recall": round(metrics.recall * 100, 2),
            "waf_f1": round(metrics.f1_score * 100, 2),
            "ai_accuracy": round(ai_ref.accuracy * 100, 2) if ai_ref else 0,
            "ai_precision": round(ai_ref.precision * 100, 2) if ai_ref else 0,
            "ai_recall": round(ai_ref.recall * 100, 2) if ai_ref else 0,
            "ai_f1": round(ai_ref.f1_score * 100, 2) if ai_ref else 0,

            # Tables
            "false_negatives": false_negatives[:top_fn_count],
            "false_negatives_total": len(false_negatives),
            "false_positives": false_positives[:20],
            "false_positives_total": len(false_positives),

            # Summary counts
            "total_malicious": session.total_malicious,
            "total_benign": session.total_benign,
        }

        rendered = template.render(**context)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered)

    def _get_ai_benchmark(
        self, dataset_name: str
    ) -> Optional[AIBenchmark]:
        """Look up AI benchmark values for the given dataset."""
        ai_cfg = self.config.ai_benchmark
        ds_benchmarks = ai_cfg.datasets

        # Try exact match, then fuzzy match
        ref = ds_benchmarks.get(dataset_name)
        if ref is None:
            for key, val in ds_benchmarks.items():
                if key.lower().replace("-", "").replace("_", "") in \
                   dataset_name.lower().replace("-", "").replace("_", ""):
                    ref = val
                    break

        if ref is None:
            logger.warning(
                "No AI benchmark found for dataset '%s'", dataset_name
            )
            return None

        return AIBenchmark(
            model_name=ai_cfg.model_name,
            dataset_name=dataset_name,
            accuracy=ref.accuracy,
            precision=ref.precision,
            recall=ref.recall,
            f1_score=ref.f1_score,
        )

    @staticmethod
    def _build_comparisons(
        metrics: MetricsReport,
        ai_ref: Optional[AIBenchmark],
    ) -> List[MetricComparison]:
        """Build metric comparison rows for the executive summary."""
        if ai_ref is None:
            return [
                MetricComparison("Accuracy", metrics.accuracy, 0, 0),
                MetricComparison("Precision", metrics.precision, 0, 0),
                MetricComparison("Recall", metrics.recall, 0, 0),
                MetricComparison("F1-Score", metrics.f1_score, 0, 0),
            ]

        pairs = [
            ("Accuracy", metrics.accuracy, ai_ref.accuracy),
            ("Precision", metrics.precision, ai_ref.precision),
            ("Recall", metrics.recall, ai_ref.recall),
            ("F1-Score", metrics.f1_score, ai_ref.f1_score),
        ]
        return [
            MetricComparison(name, waf, ai, round(waf - ai, 6))
            for name, waf, ai in pairs
        ]

    @staticmethod
    def _export_results_csv(results: List[TestResult], path: str):
        """Export test results to a CSV file."""
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Index", "Payload", "Label", "StatusCode", "Classification"]
            )
            for r in results:
                writer.writerow(
                    [r.index, r.payload, r.label, r.status_code, r.classification]
                )
