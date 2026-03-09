"""
Configuration loader for the WAF Auto-Test Runner.

Parses config.yaml and provides typed access to all settings.
Supports CLI argument overrides.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, Optional

import yaml


@dataclass
class TargetConfig:
    """Target WAF server configuration."""
    url: str = "http://localhost:8080"
    method: str = "GET"
    param_name: str = "payload"


@dataclass
class DatasetConfig:
    """Dataset configuration."""
    filepath: str = ""
    name: str = ""
    encoding: str = "utf-8"


@dataclass
class PerformanceConfig:
    """Performance and rate limiting configuration."""
    max_workers: int = 50
    max_connections: int = 100
    delay_ms: int = 0
    batch_size: int = 1000
    request_timeout: int = 10
    connect_timeout: int = 5
    max_retries: int = 2


@dataclass
class AIDatasetBenchmark:
    """AI benchmark values for a single dataset."""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0


@dataclass
class AIBenchmarkConfig:
    """AI model benchmark reference from the paper."""
    model_name: str = "CNN-BiLSTM-Attention"
    paper_title: str = "XSS Attack Detection Method Based on CNN-BiLSTM-Attention"
    paper_doi: str = "10.3390/app15168924"
    datasets: Dict[str, AIDatasetBenchmark] = field(default_factory=dict)


@dataclass
class OutputConfig:
    """Output and report configuration."""
    report_dir: str = "results"
    report_format: str = "html"
    export_csv: bool = True
    export_false_negatives: bool = True
    top_fn_count: int = 50


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    file: str = "results/test_run.log"


@dataclass
class AppConfig:
    """Root application configuration."""
    target: TargetConfig = field(default_factory=TargetConfig)
    dataset: DatasetConfig = field(default_factory=DatasetConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    ai_benchmark: AIBenchmarkConfig = field(default_factory=AIBenchmarkConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


class ConfigLoader:
    """Loads and merges configuration from YAML file and CLI overrides."""

    @staticmethod
    def load(config_path: str, cli_overrides: Optional[dict] = None) -> AppConfig:
        """
        Load configuration from YAML file with optional CLI overrides.

        Args:
            config_path: Path to config.yaml
            cli_overrides: Dict of CLI argument overrides

        Returns:
            Fully resolved AppConfig instance
        """
        raw = {}
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}

        config = AppConfig()

        # --- Target ---
        target = raw.get("target", {})
        config.target = TargetConfig(
            url=target.get("url", config.target.url),
            method=target.get("method", config.target.method).upper(),
            param_name=target.get("param_name", config.target.param_name),
        )

        # --- Dataset ---
        ds = raw.get("dataset", {})
        config.dataset = DatasetConfig(
            filepath=ds.get("filepath", config.dataset.filepath),
            name=ds.get("name", config.dataset.name),
            encoding=ds.get("encoding", config.dataset.encoding),
        )

        # --- Performance ---
        perf = raw.get("performance", {})
        config.performance = PerformanceConfig(
            max_workers=perf.get("max_workers", config.performance.max_workers),
            max_connections=perf.get("max_connections", config.performance.max_connections),
            delay_ms=perf.get("delay_ms", config.performance.delay_ms),
            batch_size=perf.get("batch_size", config.performance.batch_size),
            request_timeout=perf.get("request_timeout", config.performance.request_timeout),
            connect_timeout=perf.get("connect_timeout", config.performance.connect_timeout),
            max_retries=perf.get("max_retries", config.performance.max_retries),
        )

        # --- AI Benchmark ---
        ai = raw.get("ai_benchmark", {})
        ai_datasets = {}
        for ds_name, ds_vals in ai.get("datasets", {}).items():
            ai_datasets[ds_name] = AIDatasetBenchmark(
                accuracy=ds_vals.get("accuracy", 0.0),
                precision=ds_vals.get("precision", 0.0),
                recall=ds_vals.get("recall", 0.0),
                f1_score=ds_vals.get("f1_score", 0.0),
            )
        config.ai_benchmark = AIBenchmarkConfig(
            model_name=ai.get("model_name", config.ai_benchmark.model_name),
            paper_title=ai.get("paper_title", config.ai_benchmark.paper_title),
            paper_doi=ai.get("paper_doi", config.ai_benchmark.paper_doi),
            datasets=ai_datasets,
        )

        # --- Output ---
        out = raw.get("output", {})
        config.output = OutputConfig(
            report_dir=out.get("report_dir", config.output.report_dir),
            report_format=out.get("report_format", config.output.report_format),
            export_csv=out.get("export_csv", config.output.export_csv),
            export_false_negatives=out.get("export_false_negatives", config.output.export_false_negatives),
            top_fn_count=out.get("top_fn_count", config.output.top_fn_count),
        )

        # --- Logging ---
        log = raw.get("logging", {})
        config.logging = LoggingConfig(
            level=log.get("level", config.logging.level),
            file=log.get("file", config.logging.file),
        )

        # --- Apply CLI overrides ---
        if cli_overrides:
            if cli_overrides.get("dataset"):
                config.dataset.filepath = cli_overrides["dataset"]
            if cli_overrides.get("dataset_name"):
                config.dataset.name = cli_overrides["dataset_name"]
            if cli_overrides.get("target_url"):
                config.target.url = cli_overrides["target_url"]
            if cli_overrides.get("method"):
                config.target.method = cli_overrides["method"].upper()
            if cli_overrides.get("workers"):
                config.performance.max_workers = cli_overrides["workers"]
            if cli_overrides.get("output"):
                config.output.report_dir = cli_overrides["output"]
            if cli_overrides.get("delay"):
                config.performance.delay_ms = cli_overrides["delay"]

        return config
