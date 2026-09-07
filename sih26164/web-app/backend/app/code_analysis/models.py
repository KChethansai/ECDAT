"""CodeFinding: engineering findings, deliberately separate from CryptoFinding.

Security severity (Mosca, crypto risk) never mixes with engineering impact.
A CodeFinding has engineering `impact`; `security_risk` stays "NONE" unless an
analyzer has concrete security evidence (none do today — stated, not inferred).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha1

CATEGORIES = ("DEAD_CODE", "DUPLICATION", "COMPLEXITY", "EFFICIENCY", "DEPENDENCY",
              "STRUCTURE", "MAINTAINABILITY", "RESOURCE_USAGE", "CONFIGURATION",
              "TEST_QUALITY")
CONFIDENCES = ("HIGH", "MEDIUM", "LOW")
VERDICTS = ("DEAD_CODE", "POTENTIAL_DEAD_CODE", "POTENTIAL_PERFORMANCE_ISSUE",
            "COMPLEXITY_OBSERVATION", "OBSERVATION")
PRIORITY_LABELS = ("QUICK_WIN", "LOW_RISK", "HIGH_IMPACT", "LARGE_REFACTOR",
                   "REQUIRES_REVIEW", "DO_NOT_AUTOMATE")


@dataclass
class CodeFinding:
    analyzer: str           # e.g. "dead_code", "efficiency"
    category: str           # one of CATEGORIES
    file_path: str
    line: int = 0
    end_line: int = 0
    symbol: str = ""
    title: str = ""
    description: str = ""
    evidence: str = ""      # truncated snippet (<=160 chars), secrets redacted
    confidence: str = "MEDIUM"
    verdict: str = "OBSERVATION"  # precise words only (see VERDICTS)
    impact: str = "LOW"     # engineering impact: LOW|MEDIUM|HIGH
    security_risk: str = "NONE"
    effort: str = "SMALL"   # SMALL|MEDIUM|LARGE (relative t-shirt size, not hours)
    risk: str = "LOW"       # remediation risk: LOW|MEDIUM|HIGH
    rationale: str = ""
    related_files: list = field(default_factory=list)
    related_symbols: list = field(default_factory=list)
    verification: str = ""  # how to confirm the finding / the fix
    remediation_options: list = field(default_factory=list)
    priority: str = "REQUIRES_REVIEW"
    deterministic: bool = True
    status: str = "OPEN"    # OPEN|RESOLVED|REMAINS|REGRESSION|INCONCLUSIVE (verification writes the rest)
    id: str = field(default="")

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown code category: {self.category}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"unknown confidence: {self.confidence}")
        if self.verdict not in VERDICTS:
            raise ValueError(f"unknown verdict: {self.verdict}")
        if self.priority not in PRIORITY_LABELS:
            raise ValueError(f"unknown priority: {self.priority}")
        if not self.id:
            seed = (f"{self.analyzer}|{self.category}|{self.file_path}|{self.line}|"
                    f"{self.symbol}|{self.title}").encode()
            self.id = "c" + sha1(seed).hexdigest()[:11]  # noqa: S324 (non-security id)

    def to_dict(self) -> dict:
        return asdict(self)
