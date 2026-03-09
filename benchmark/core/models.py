"""
Data models for the WAF Auto-Test Runner.

Defines dataclasses used across all modules for type-safe data passing.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PayloadRecord:
    """A single payload entry from the CSV dataset."""
    index: int
    payload: str
    label: int  # 0 = Benign, 1 = Malicious


@dataclass
class TestResult:
    """Result of testing a single payload against the WAF."""
    index: int
    payload: str
    label: int
    status_code: int  # -1 = Error/Timeout
    classification: str  # TP, TN, FP, FN, ERR


@dataclass
class MetricsReport:
    """Aggregated metrics from all test results."""
    tp: int
    tn: int
    fp: int
    fn: int
    errors: int
    total: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    fpr: float  # False Positive Rate


@dataclass
class AIBenchmark:
    """AI model benchmark results from the reference paper."""
    model_name: str
    dataset_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float


@dataclass
class MetricComparison:
    """Single metric comparison row for the executive summary."""
    name: str
    waf_value: float
    ai_value: float
    delta: float


@dataclass
class TestSession:
    """Metadata about a complete test session."""
    dataset_name: str
    dataset_filepath: str
    target_url: str
    http_method: str
    total_payloads: int
    total_malicious: int
    total_benign: int
    start_time: str
    end_time: str
    duration_seconds: float
    tool_version: str = "1.0.0"
