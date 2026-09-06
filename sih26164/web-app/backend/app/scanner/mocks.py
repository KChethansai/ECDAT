"""Extensible interfaces with clearly-marked MOCK implementations.

HSM/cloud connectors remain future work beyond current scope (source, binary,
container, and dependency scanning are REAL: see source_scanner.py,
binary_scanner.py, container_scanner.py, dependency_scanner.py). Each mock
returns static illustrative findings with is_mock=True so the GUI/CBOM can badge
them and nobody mistakes them for discovery.
"""

from __future__ import annotations

from ..models import CryptoFinding
from .base import Scanner


class _MockBase(Scanner):
    is_mock = True
    label: str = "MOCK"

    def _finding(self, target, algorithm, category, **kw) -> CryptoFinding:
        return CryptoFinding(scanner=f"{self.name}({self.label})", file_path=str(target),
                             line=0, algorithm=algorithm, category=category,
                             evidence=f"[{self.label}] illustrative placeholder — not discovered",
                             confidence=0.1, is_mock=True, **kw)


class HSMScanner(_MockBase):
    name = "hsm"

    def scan(self, target) -> list[CryptoFinding]:
        return [self._finding(target, "AES-256-HSM", "key")]


class CloudCryptoScanner(_MockBase):
    name = "cloud"

    def scan(self, target) -> list[CryptoFinding]:
        return [self._finding(target, "KMS-AES-256", "key")]
