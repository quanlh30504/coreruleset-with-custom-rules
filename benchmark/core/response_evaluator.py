"""
Response evaluator for the WAF Auto-Test Runner.

Classifies test results into TP, TN, FP, FN based on the Confusion Matrix.
"""


class ResponseEvaluator:
    """
    Classifies WAF responses against ground truth labels.

    Confusion Matrix:
                         WAF Blocked (403)  |  WAF Passed (200/404/500/...)
    Label=1 (Malicious)       TP             |        FN  (Bypass!)
    Label=0 (Benign)          FP (False alarm)|        TN
    """

    BLOCKED_CODES = frozenset({403})

    @staticmethod
    def classify(label: int, status_code: int) -> str:
        """
        Classify a single test result.

        Args:
            label: Ground truth (1=Malicious, 0=Benign).
            status_code: HTTP response status code. -1 indicates error/timeout.

        Returns:
            Classification string: "TP", "TN", "FP", "FN", or "ERR".
        """
        if status_code == -1:
            return "ERR"

        is_blocked = status_code in ResponseEvaluator.BLOCKED_CODES

        if label == 1:
            return "TP" if is_blocked else "FN"
        elif label == 0:
            return "FP" if is_blocked else "TN"
        else:
            return "ERR"
