"""
Dataset reader for the WAF Auto-Test Runner.

Reads and validates CSV datasets containing payloads and labels.
"""

import logging
from typing import List

import pandas as pd

from .models import PayloadRecord

logger = logging.getLogger(__name__)


class DatasetReader:
    """Reads CSV datasets with Payload and Label columns."""

    @staticmethod
    def read(filepath: str, encoding: str = "utf-8") -> List[PayloadRecord]:
        """
        Read a CSV file and return a list of PayloadRecord objects.

        Args:
            filepath: Path to the CSV file.
            encoding: File encoding (default: utf-8).

        Returns:
            List of PayloadRecord with validated data.

        Raises:
            FileNotFoundError: If the CSV file does not exist.
            ValueError: If required columns are missing or labels are invalid.
        """
        logger.info("Reading dataset from: %s", filepath)

        try:
            df = pd.read_csv(
                filepath,
                encoding=encoding,
                dtype=str,
                keep_default_na=False,
                on_bad_lines="warn",
            )
        except UnicodeDecodeError:
            logger.warning(
                "UTF-8 decoding failed for %s, falling back to latin-1", filepath
            )
            df = pd.read_csv(
                filepath,
                encoding="latin-1",
                dtype=str,
                keep_default_na=False,
                on_bad_lines="warn",
            )

        # Case-insensitive column matching with aliases
        col_map = {c.strip().lower(): c for c in df.columns}

        # Support multiple column name variants
        PAYLOAD_ALIASES = ["payload", "payloads"]
        LABEL_ALIASES = ["label", "class"]

        payload_col = None
        for alias in PAYLOAD_ALIASES:
            if alias in col_map:
                payload_col = col_map[alias]
                break

        label_col = None
        for alias in LABEL_ALIASES:
            if alias in col_map:
                label_col = col_map[alias]
                break

        if payload_col is None or label_col is None:
            available = list(df.columns)
            raise ValueError(
                f"CSV must have a Payload column ({PAYLOAD_ALIASES}) "
                f"and a Label column ({LABEL_ALIASES}). Found: {available}"
            )

        logger.info("Detected columns: payload='%s', label='%s'", payload_col, label_col)

        # Rename for uniform access
        df = df.rename(columns={payload_col: "Payload", label_col: "Label"})

        # Convert string labels to int (support both formats)
        # Format 1: Integer 0/1
        # Format 2: String "Malicious"/"Benign" (Mereani-XSS format)
        STRING_LABEL_MAP = {
            "malicious": 1, "xss": 1, "attack": 1, "1": 1,
            "benign": 0, "safe": 0, "normal": 0, "legitimate": 0, "0": 0,
        }

        def convert_label(val):
            """Convert label to int, supporting both int and string formats."""
            val_stripped = str(val).strip().lower()
            if val_stripped in STRING_LABEL_MAP:
                return STRING_LABEL_MAP[val_stripped]
            try:
                return int(float(val))
            except (ValueError, TypeError):
                return None

        df["Label"] = df["Label"].apply(convert_label)
        invalid_labels = df["Label"].isna()
        if invalid_labels.any():
            logger.warning(
                "Dropping %d rows with unrecognized labels", invalid_labels.sum()
            )
            df = df[~invalid_labels]
        df["Label"] = df["Label"].astype(int)

        # Validate labels
        valid_labels = df["Label"].isin([0, 1])
        if not valid_labels.all():
            invalid_count = (~valid_labels).sum()
            logger.warning(
                "Dropping %d rows with labels not in {0, 1}", invalid_count
            )
            df = df[valid_labels]

        # Filter empty payloads
        empty_mask = df["Payload"].str.strip() == ""
        if empty_mask.any():
            logger.warning("Dropping %d rows with empty payloads", empty_mask.sum())
            df = df[~empty_mask]

        records = [
            PayloadRecord(index=i, payload=row.Payload, label=int(row.Label))
            for i, row in enumerate(df.itertuples(index=False))
        ]

        total = len(records)
        malicious = sum(1 for r in records if r.label == 1)
        benign = total - malicious
        logger.info(
            "Dataset loaded: %d total (%d malicious, %d benign)",
            total, malicious, benign,
        )

        return records
