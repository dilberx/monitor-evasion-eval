"""Monitor package for evaluating suspicion and evasion metrics."""

from monitor_evasion.monitor.extractor import VisibilityMode, extract_visibility_view
from monitor_evasion.monitor.metrics import (
    bootstrap_ci,
    clustered_bootstrap_ci,
    clustered_bootstrap_macro_auroc_ci,
    compute_auroc,
    compute_catch_rate_at_fpr,
    compute_within_env_macro_auroc,
)
from monitor_evasion.monitor.scorer import score_transcript

__all__ = [
    "VisibilityMode",
    "extract_visibility_view",
    "compute_auroc",
    "compute_catch_rate_at_fpr",
    "compute_within_env_macro_auroc",
    "bootstrap_ci",
    "clustered_bootstrap_ci",
    "clustered_bootstrap_macro_auroc_ci",
    "score_transcript",
]

