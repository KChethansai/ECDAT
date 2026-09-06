"""Extensible interfaces with clearly-marked MOCK implementations.

Real connectors (binary parsing, image layer inspection, HSM/cloud APIs) remain
future work beyond current scope. Each mock returns static illustrative findings
with is_mock=True so the GUI/CBOM can badge them and nobody mistakes them for
discovery.
"""

from __future__ import annotations

from pathlib import Path

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


class BinaryScanner(_MockBase):
    name = "binary"

    def scan(self, target) -> list[CryptoFinding]:
        if not Path(target).exists():
            raise FileNotFoundError(target)
        return [self._finding(target, "AES-256", "symmetric"),
                self._finding(target, "RSA", "asymmetric", key_size=2048)]


class ContainerScanner(_MockBase):
    name = "container"

    def scan(self, target) -> list[CryptoFinding]:
        return [self._finding(target, "SHA-256", "hash"),
                self._finding(target, "TLS1.2", "protocol", protocol_version="TLS1.2")]


class LibraryScanner(_MockBase):
    name = "library"

    def scan(self, target) -> list[CryptoFinding]:
        return [self._finding(target, "OpenSSL", "library", library="openssl 3.x (illustrative)")]


class HSMScanner(_MockBase):
    name = "hsm"

    def scan(self, target) -> list[CryptoFinding]:
        return [self._finding(target, "AES-256-HSM", "key")]


class CloudCryptoScanner(_MockBase):
    name = "cloud"

    def scan(self, target) -> list[CryptoFinding]:
        return [self._finding(target, "KMS-AES-256", "key")]
