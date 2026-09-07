"""Active validation (opt-in, bounded, stdlib-only): strategies, probes, runner, SARIF."""

from .correlate import apply_correlation, correlate_finding
from .models import CORRELATION_STATUSES, VALIDATION_STATUSES, VALIDATOR_VERSION, ValidationResult
from .runner import run_validations
from .safety import ValidationPolicy, check_host_port, check_url, is_loopback_host
from .sarif import to_sarif
from .strategies import strategy_for

__all__ = ["CORRELATION_STATUSES", "VALIDATION_STATUSES", "VALIDATOR_VERSION",
           "ValidationResult", "ValidationPolicy", "apply_correlation", "check_host_port",
           "check_url", "correlate_finding", "is_loopback_host", "run_validations",
           "strategy_for", "to_sarif"]
