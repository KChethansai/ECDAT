"""REAL HSM integration-evidence scanner (static configuration only, stdlib only).

Scope: evidence of HSM *integration* (PKCS#11 URIs/config, provider modules,
vendor references, HSM-backed key configuration). It NEVER connects to an HSM,
authenticates, enumerates keys, handles PINs, or requires hardware/vendor SDKs.
Safe metadata only: PKCS#11 URI attributes beyond token/manufacturer/model are
redacted, and secret-looking values are never retained.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import CryptoFinding
from .base import Scanner
from .source_scanner import MAX_FILE_BYTES, MAX_FILES, SENSITIVE_VALUE_RE, SKIP_DIRS, _is_text

STATIC_LIMIT = ("Static configuration evidence only; an HSM integration reference "
                "does not inventory HSM contents or prove runtime use.")

PKCS11_URI_RE = re.compile(r"pkcs11:[^\s\"']+", re.I)
KEEP_ATTRS = {"token", "manufacturer", "model", "library", "slot-description"}
# Token-aware vendor matching: a vendor name must not be glued to ASCII letters on
# either side, so `nShield` matches "Thales nShield" but not "IconShield", and
# `Luna` matches a partition reference but not "lunar". Digits, underscores and
# punctuation still count as separators (`my_nshield`, `nshield2`, `aws_cloudhsm`
# keep matching) to avoid missing snake_case identifiers and versioned references.
VENDOR_RE = re.compile(
    r"(?<![A-Za-z])(YubiHSM|Yubico|libyubihsm|yubihsm-connector|softhsm|libsofthsm|"
    r"opensc-pkcs11|libeTPkcs11|SafeNet|Luna|libCryptoki|nShield|nfast|ncipher|"
    r"Utimaco|libcs_pkcs11|Securosys|Entrust|Fortanix|Marvell|LiquidSecurity|"
    r"libcloudhsm|cloudhsm|pkcs11-tool|p11tool|tpm2-pkcs11|opencryptoki|coolkey|"
    r"libcoolkey)(?![A-Za-z])", re.I)
MODULE_RE = re.compile(
    r"(?<![A-Za-z0-9_])[\w\-./\\]*?(?:pkcs11|cryptoki)[\w\-./\\]*\.(?:so|dylib|dll)\b|"
    r"\b(?:libyubihsm|libsofthsm2|libCryptoki2_64|libLunaAPI|libcs_pkcs11)\b", re.I)
PROVIDER_RE = re.compile(
    r"\bSunPKCS11\b|provider\s*=\s*pkcs11|pkcs11-provider|PKCS11 provider|"
    r"HSM_PROVIDER|PKCS11_PROVIDER", re.I)
CONFIG_KEY_RE = re.compile(
    r"\b(HSM_SLOT|HSM_TOKEN|HSM_PIN|HSM_MODULE|PKCS11_MODULE|PKCS11_TOKEN|PKCS11_PIN|"
    r"CRYPTOKI_[A-Z_]+|CKA_TOKEN)\b")


def _redact_uri(uri: str) -> str:
    """Keep scheme + token/manufacturer/model; redact every other attribute value."""
    head, _, query = uri.partition("?")
    if ";" in head:
        scheme_path, _, attrs = head.partition(";")
        kept = [part for part in attrs.split(";")
                if "=" in part and part.split("=", 1)[0].strip().lower() in KEEP_ATTRS]
        head = scheme_path + (";" + ";".join(kept) if kept else ";[ATTRIBUTES-REDACTED]")
    if query:
        head += "?[QUERY-REDACTED]"
    return head[:160]


def _evidence(line: str) -> str:
    if match := PKCS11_URI_RE.search(line):
        return _redact_uri(match.group(0))
    return SENSITIVE_VALUE_RE.sub(r"\1\2[REDACTED]", line.strip())[:160]


class HSMScanner(Scanner):
    """Real HSM integration-evidence scanner. is_mock=False — genuine discovery."""

    name = "hsm"
    is_mock = False

    def scan(self, target: str | Path) -> list[CryptoFinding]:
        root = Path(target)
        if not root.exists():
            raise FileNotFoundError(f"scan target missing: {target}")
        findings: list[CryptoFinding] = []
        for path in self._iter_files(root):
            if not _is_text(path):
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                findings.extend(self._scan_line(str(path), lineno, line))
        return findings

    def _iter_files(self, root: Path):
        if root.is_file():
            if not root.is_symlink():
                try:
                    if root.stat().st_size <= MAX_FILE_BYTES:
                        yield root
                except OSError:
                    pass
            return
        count = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink() or any(d in path.parts for d in SKIP_DIRS):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            if count > MAX_FILES:
                break
            yield path

    def _scan_line(self, fpath: str, lineno: int, line: str) -> list[CryptoFinding]:
        out: list[CryptoFinding] = []

        def hit(algorithm: str, category: str, confidence: float, detail: str) -> None:
            out.append(CryptoFinding(
                scanner=self.name, file_path=fpath, line=lineno, algorithm=algorithm,
                category=category, library=detail[:64], usage="hsm integration reference",
                rationale="HSM-backed cryptographic integration detected in configuration. "
                          + STATIC_LIMIT,
                evidence=_evidence(line), confidence=confidence, is_mock=False))

        matched = False
        if PKCS11_URI_RE.search(line):
            hit("PKCS11", "key", 0.85, "PKCS#11 URI")
            matched = True
        if match := MODULE_RE.search(line):
            # keep the module path itself, not a VARNAME= prefix the match may span
            path = re.search(r"[\w\-./\\]+\.(?:so|dylib|dll)\b", match.group(0), re.I)
            hit("PKCS11", "library", 0.8, path.group(0) if path else match.group(0))
            matched = True
        elif match := VENDOR_RE.search(line):
            hit("HSM", "library", 0.6, match.group(0))
            matched = True
        if PROVIDER_RE.search(line):
            hit("PKCS11", "library", 0.75, "provider configuration")
            matched = True
        if not matched:  # one config-key pointer per line is enough alongside stronger hits
            for match in CONFIG_KEY_RE.finditer(line):
                hit("HSM", "key", 0.55, match.group(0))
        return out
