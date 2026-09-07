"""Active validation model: structured, evidence-first, bounded.

A ValidationResult records what a deterministic validator OBSERVED — never a
claim that a static finding equals a vulnerability. Severity/priority stay
with the risk engine; validation only adds correlation context.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha1
from time import time

VALIDATOR_VERSION = "1"

# Per-validation outcome. Precise words only: OBSERVED means "seen on the
# wire/under the probe"; CONFIRMED means observed AND correlated to the
# exact static finding. Nothing here means "exploited".
VALIDATION_STATUSES = (
    "CONFIRMED",          # observed + correlated to the static finding
    "OBSERVED",           # observed, correlation to a finding not established
    "PARTIALLY_CONFIRMED",
    "NOT_CONFIRMED",      # probed, expected evidence absent (not proof of safety)
    "NOT_APPLICABLE",     # no validator or no in-scope target for this finding
    "INCONCLUSIVE",       # probe errored or evidence ambiguous
    "BLOCKED",            # refused by safety policy (incl. dry runs)
    "ERROR",              # validator failure (timeout, TLS error, budget hit)
)

# Per-finding roll-up shown in reports and UI.
CORRELATION_STATUSES = (
    "STATIC_ONLY",                 # no active validation attempted/applicable
    "RUNTIME_OBSERVED",            # runtime evidence exists, link not established
    "RUNTIME_CORRELATED",          # linked to validation evidence (same family/host)
    "RUNTIME_CONFIRMED",           # observed evidence matches this exact finding
    "UNRELATED_RUNTIME_OBSERVATION",
    "NOT_APPLICABLE",
)


@dataclass
class ValidationResult:
    validation_id: str = ""
    finding_id: str = ""          # "" when the probe is target-level, not finding-level
    target: str = ""              # endpoint or probe name that was exercised
    validation_type: str = ""     # tls | http | runtime | static-review
    status: str = "INCONCLUSIVE"
    confidence: float = 0.5       # validator self-confidence, NOT finding confidence
    evidence: dict = field(default_factory=dict)  # structured, redacted observations
    observed_algorithm: str = ""
    observed_protocol: str = ""
    observed_cipher: str = ""
    observed_key_size: int | None = None
    endpoint: str = ""
    duration_s: float = 0.0
    timestamp: float = field(default_factory=time)
    correlation_status: str = "STATIC_ONLY"
    error: str = ""
    validator_version: str = VALIDATOR_VERSION

    def __post_init__(self) -> None:
        if self.status not in VALIDATION_STATUSES:
            raise ValueError(f"unknown validation status: {self.status}")
        if self.correlation_status not in CORRELATION_STATUSES:
            raise ValueError(f"unknown correlation status: {self.correlation_status}")
        if not self.validation_id:
            seed = (f"{self.finding_id}|{self.target}|{self.validation_type}|"
                    f"{self.timestamp:.3f}").encode()
            self.validation_id = "v" + sha1(seed).hexdigest()[:11]

    def to_dict(self) -> dict:
        return asdict(self)
