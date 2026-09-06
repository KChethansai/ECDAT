"""Mock-scanner base for future (not yet real) scanners.

Source, binary, container, dependency, HSM, cloud, and runtime scanning are all
REAL (see *_scanner.py). This base remains for any future scanner that starts
as an explicitly labeled placeholder. Mocks must always set is_mock=True so the
GUI/CBOM badge them and nobody mistakes them for discovery.
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


__all__ = ["_MockBase"]
