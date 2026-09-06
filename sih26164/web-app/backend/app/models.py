"""Normalized domain model: every scanner emits CryptoFinding; risk/rec/CBOM consume it."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha1


@dataclass
class CryptoFinding:
    scanner: str            # e.g. "source", "binary", "hsm" (all REAL); future placeholders use "name(MOCK)")
    file_path: str
    line: int               # 1-based; 0 if N/A
    algorithm: str          # canonical name, e.g. "RSA", "AES-256", "TLS1.0"
    category: str           # symmetric|asymmetric|hash|protocol|library|certificate|key
    evidence: str = ""      # truncated source snippet (metadata only, never key material dumps)
    key_size: int | None = None
    mode: str = ""          # e.g. "CBC", "GCM" where detectable
    protocol_version: str = ""
    library: str = ""
    curve: str = ""
    signature_algorithm: str = ""
    expires_at: str = ""
    usage: str = "direct"  # direct source use|dependency reference|certificate metadata
    rationale: str = ""
    confidence: float = 0.8
    is_mock: bool = False
    id: str = field(default="")

    def __post_init__(self) -> None:
        if not self.id:
            seed = (f"{self.scanner}|{self.file_path}|{self.line}|{self.algorithm}|"
                    f"{self.category}|{self.key_size}|{self.curve}|{self.usage}").encode()
            self.id = sha1(seed).hexdigest()[:12]  # noqa: S324 (non-security id)

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_findings(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    """Remove only identical scanner hits; preserve distinct file/line occurrences."""
    unique: dict[tuple, CryptoFinding] = {}
    for finding in findings:
        key = (finding.scanner, finding.is_mock, finding.file_path, finding.line,
               finding.algorithm, finding.category, finding.key_size, finding.curve,
               finding.mode, finding.protocol_version, finding.library, finding.usage)
        unique.setdefault(key, finding)
    return list(unique.values())
