"""
Unit tests for the WAF Auto-Test Runner core modules.
"""

import os
import sys
import tempfile

import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.response_evaluator import ResponseEvaluator
from core.metrics_calculator import MetricsCalculator
from core.dataset_reader import DatasetReader
from core.models import TestResult


# ============================================================
# ResponseEvaluator Tests
# ============================================================

class TestResponseEvaluator:
    """Tests for the confusion matrix classification logic."""

    def test_true_positive(self):
        """Label=1 (Malicious) + HTTP 403 → TP"""
        assert ResponseEvaluator.classify(1, 403) == "TP"

    def test_false_negative(self):
        """Label=1 (Malicious) + HTTP 200 → FN (Bypass!)"""
        assert ResponseEvaluator.classify(1, 200) == "FN"

    def test_false_negative_404(self):
        """Label=1 (Malicious) + HTTP 404 → FN"""
        assert ResponseEvaluator.classify(1, 404) == "FN"

    def test_false_negative_500(self):
        """Label=1 (Malicious) + HTTP 500 → FN"""
        assert ResponseEvaluator.classify(1, 500) == "FN"

    def test_true_negative(self):
        """Label=0 (Benign) + HTTP 200 → TN"""
        assert ResponseEvaluator.classify(0, 200) == "TN"

    def test_false_positive(self):
        """Label=0 (Benign) + HTTP 403 → FP (False alarm!)"""
        assert ResponseEvaluator.classify(0, 403) == "FP"

    def test_error_timeout(self):
        """Status -1 (timeout/error) → ERR"""
        assert ResponseEvaluator.classify(1, -1) == "ERR"
        assert ResponseEvaluator.classify(0, -1) == "ERR"

    def test_invalid_label(self):
        """Invalid label → ERR"""
        assert ResponseEvaluator.classify(2, 200) == "ERR"
        assert ResponseEvaluator.classify(-1, 403) == "ERR"


# ============================================================
# MetricsCalculator Tests
# ============================================================

class TestMetricsCalculator:
    """Tests for metrics calculation formulas."""

    def _make_results(self, tp=0, tn=0, fp=0, fn=0, err=0):
        """Helper to create a list of TestResult with given counts."""
        results = []
        for i in range(tp):
            results.append(TestResult(i, "p", 1, 403, "TP"))
        for i in range(tn):
            results.append(TestResult(i, "p", 0, 200, "TN"))
        for i in range(fp):
            results.append(TestResult(i, "p", 0, 403, "FP"))
        for i in range(fn):
            results.append(TestResult(i, "p", 1, 200, "FN"))
        for i in range(err):
            results.append(TestResult(i, "p", 1, -1, "ERR"))
        return results

    def test_perfect_score(self):
        """All correct → Accuracy=1.0"""
        results = self._make_results(tp=50, tn=50)
        m = MetricsCalculator.calculate(results)
        assert m.accuracy == 1.0
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1_score == 1.0
        assert m.fpr == 0.0

    def test_known_values(self):
        """TP=90, TN=5, FP=2, FN=3 → Accuracy=0.95"""
        results = self._make_results(tp=90, tn=5, fp=2, fn=3)
        m = MetricsCalculator.calculate(results)
        assert m.accuracy == 0.95
        assert m.total == 100

    def test_precision(self):
        """TP=80, FP=20 → Precision=0.8"""
        results = self._make_results(tp=80, fp=20)
        m = MetricsCalculator.calculate(results)
        assert m.precision == 0.8

    def test_recall(self):
        """TP=80, FN=20 → Recall=0.8"""
        results = self._make_results(tp=80, fn=20)
        m = MetricsCalculator.calculate(results)
        assert m.recall == 0.8

    def test_division_by_zero(self):
        """No results → all metrics = 0.0"""
        m = MetricsCalculator.calculate([])
        assert m.accuracy == 0.0
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1_score == 0.0
        assert m.fpr == 0.0

    def test_errors_not_counted_in_metrics(self):
        """ERR results should not affect TP/TN/FP/FN counts."""
        results = self._make_results(tp=10, tn=10, err=5)
        m = MetricsCalculator.calculate(results)
        assert m.errors == 5
        assert m.total == 20  # Only TP+TN+FP+FN
        assert m.accuracy == 1.0


# ============================================================
# DatasetReader Tests
# ============================================================

class TestDatasetReader:
    """Tests for CSV dataset reading and validation."""

    def _write_csv(self, content: str) -> str:
        """Write CSV content to a temp file and return path."""
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False, encoding="utf-8"
        )
        f.write(content)
        f.close()
        return f.name

    def test_basic_read(self):
        """Read a simple valid CSV."""
        path = self._write_csv("Payload,Label\n<script>alert(1)</script>,1\nhello world,0\n")
        records = DatasetReader.read(path)
        os.unlink(path)
        assert len(records) == 2
        assert records[0].label == 1
        assert records[1].label == 0

    def test_case_insensitive_columns(self):
        """Column names should be case-insensitive."""
        path = self._write_csv("payload,label\ntest,1\n")
        records = DatasetReader.read(path)
        os.unlink(path)
        assert len(records) == 1

    def test_skip_empty_payloads(self):
        """Empty payloads should be filtered out."""
        path = self._write_csv("Payload,Label\n,1\nhello,0\n   ,1\n")
        records = DatasetReader.read(path)
        os.unlink(path)
        assert len(records) == 1
        assert records[0].payload == "hello"

    def test_invalid_labels_dropped(self):
        """Non-binary labels should be dropped."""
        path = self._write_csv("Payload,Label\ntest1,1\ntest2,0\ntest3,2\ntest4,abc\n")
        records = DatasetReader.read(path)
        os.unlink(path)
        assert len(records) == 2

    def test_missing_columns_raises(self):
        """Missing required columns should raise ValueError."""
        path = self._write_csv("Data,Type\ntest,1\n")
        with pytest.raises(ValueError):
            DatasetReader.read(path)
        os.unlink(path)

    def test_file_not_found(self):
        """Non-existent file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            DatasetReader.read("/nonexistent/path.csv")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
