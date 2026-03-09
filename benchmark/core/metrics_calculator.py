"""
Metrics calculator for the WAF Auto-Test Runner.

Computes Accuracy, Precision, Recall, F1-Score and FPR from test results.
"""

from typing import List

from .models import MetricsReport, TestResult


class MetricsCalculator:
    """Calculates evaluation metrics from classified test results."""

    @staticmethod
    def calculate(results: List[TestResult]) -> MetricsReport:
        """
        Calculate all evaluation metrics from a list of test results.

        Args:
            results: List of classified TestResult objects.

        Returns:
            MetricsReport containing all computed metrics.
        """
        tp = sum(1 for r in results if r.classification == "TP")
        tn = sum(1 for r in results if r.classification == "TN")
        fp = sum(1 for r in results if r.classification == "FP")
        fn = sum(1 for r in results if r.classification == "FN")
        errors = sum(1 for r in results if r.classification == "ERR")
        total = tp + tn + fp + fn

        def safe_div(a: float, b: float) -> float:
            return round(a / b, 6) if b != 0 else 0.0

        accuracy = safe_div(tp + tn, total)
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        f1_score = safe_div(2 * precision * recall, precision + recall)
        fpr = safe_div(fp, fp + tn)

        return MetricsReport(
            tp=tp,
            tn=tn,
            fp=fp,
            fn=fn,
            errors=errors,
            total=total,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            fpr=fpr,
        )
