"""Scanner interface. Real and mock scanners share this contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..models import CryptoFinding


class Scanner(ABC):
    name: str = "base"
    is_mock: bool = False

    @abstractmethod
    def scan(self, target: str | Path) -> list[CryptoFinding]:
        """Scan target (file or dir); return normalized findings (possibly empty)."""
