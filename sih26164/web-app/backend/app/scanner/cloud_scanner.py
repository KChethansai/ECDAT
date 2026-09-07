"""REAL cloud crypto-configuration scanner (static evidence only, stdlib only).

Scope: cryptographic service/configuration references in infrastructure and
application config (Terraform, YAML, JSON, env/config files). It NEVER contacts
cloud APIs, NEVER uses credentials, and NEVER enumerates accounts. Findings are
safe identifiers (ARNs with account IDs masked, vault/key resource IDs);
credential values are never retained.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import CryptoFinding
from .base import Scanner
from .source_scanner import MAX_FILE_BYTES, MAX_FILES, SKIP_DIRS, _is_text

STATIC_LIMIT = ("Static configuration evidence only; a cloud service reference does "
                "not prove runtime use and is not a live account inventory.")

ACCOUNT_RE = re.compile(r"\b\d{12}\b")
AWS_KMS_RE = re.compile(r"arn:aws[a-z-]*:kms:[a-z0-9-]+:\d{12}:(?:key|alias)/[A-Za-z0-9/_+=,.@-]+")
AWS_CLOUDHSM_RE = re.compile(r"arn:aws[a-z-]*:cloudhsm:[a-z0-9-]+:\d{12}:[A-Za-z0-9/_+=,.@-]+|"
                             r"aws_cloudhsm_[a-z_]+|AWS CloudHSM", re.I)
AWS_KMS_RESOURCE_RE = re.compile(r'resource\s+"aws_kms_(?:key|alias|grant|ciphertext)"')
AZURE_VAULT_RE = re.compile(r"https://[A-Za-z0-9-]+\.(?:vault|managedhsm)\.azure\.net"
                            r"(?:/[A-Za-z0-9/_.-]*)?")
AZURE_RESOURCE_RE = re.compile(r"azurerm_key_vault[_a-z]*|Microsoft\.KeyVault|"
                               r"Azure Key Vault|Azure Managed HSM", re.I)
GCP_KMS_RE = re.compile(r"projects/[A-Za-z0-9:._-]+/locations/[A-Za-z0-9_-]+/"
                        r"keyRings/[A-Za-z0-9_-]+(?:/cryptoKeys/[A-Za-z0-9_-]+"
                        r"(?:/cryptoKeyVersions/[A-Za-z0-9_-]+)?)?")
GCP_RESOURCE_RE = re.compile(r'resource\s+"google_kms_(?:key_ring|crypto_key)"|'
                             r"google\.cloud\.kms|Cloud KMS|Cloud HSM", re.I)
TLS_POLICY_RE = re.compile(r"\bTLS_[A-Z0-9_]{4,}\b|\"TLSv?1\.[23]\"|'TLSv?1\.[23]'")
KEY_REF_RE = re.compile(
    r"\b([A-Za-z0-9_]*(?:KMS|HSM)[A-Za-z0-9_]*|"
    r"[A-Za-z0-9_]*(?:KEY[_-]?(?:ID|ARN|URL|VAULT)|SECRET[_-]?(?:ARN|URL)))\b"
    r"\s*[:=]\s*(\"[^\"]*\"|'[^']*'|[^\s#,;]+)")

PROVIDERS: list[tuple[str, str]] = [
    ("aws", "AWS"), ("azure", "Azure"), ("gcp", "GCP"),
]


def _mask_account(value: str) -> str:
    """Mask AWS-style 12-digit account IDs; keep the identifier structure."""
    return ACCOUNT_RE.sub("****", value)[:160]


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


class CloudScanner(Scanner):
    """Real cloud crypto-configuration scanner. is_mock=False — genuine discovery."""

    name = "cloud"
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

        def hit(algorithm: str, provider: str, confidence: float, evidence: str) -> None:
            out.append(CryptoFinding(
                scanner=self.name, file_path=fpath, line=lineno, algorithm=algorithm,
                category="key", library=provider, usage="cloud crypto configuration",
                rationale="Cloud-managed cryptographic service reference detected in "
                          "configuration. " + STATIC_LIMIT,
                evidence=evidence[:160], confidence=confidence, is_mock=False))

        if match := AWS_KMS_RE.search(line):
            hit("KMS", "aws:kms", 0.85, _mask_account(match.group(0)))
        elif match := AWS_CLOUDHSM_RE.search(line):
            hit("CLOUDHSM", "aws:cloudhsm", 0.8, _mask_account(match.group(0)[:160]))
        elif AWS_KMS_RESOURCE_RE.search(line):
            hit("KMS", "aws:kms", 0.8, line.strip()[:160])
        if match := AZURE_VAULT_RE.search(line):
            hit("KEYVAULT", "azure:keyvault", 0.85, match.group(0)[:160])
        elif AZURE_RESOURCE_RE.search(line):
            hit("KEYVAULT", "azure:keyvault", 0.7, line.strip()[:160])
        if match := GCP_KMS_RE.search(line):
            hit("KMS", "gcp:kms", 0.85, match.group(0)[:160])
        elif GCP_RESOURCE_RE.search(line):
            hit("KMS", "gcp:kms", 0.7, line.strip()[:160])
        if match := TLS_POLICY_RE.search(line):
            hit("TLS", "tls-policy", 0.6, match.group(0)[:160])
        if match := KEY_REF_RE.search(line):
            name, raw_value = match.group(1), _strip_quotes(match.group(2))
            if re.search(r"arn:|vault\.azure\.|keyRings/|/(keys)/|alias/", raw_value):
                evidence = f"{name} = {_mask_account(raw_value)[:96]}"
            else:
                evidence = f"{name} = [REDACTED]"
            hit("KMS", "config-reference", 0.55, evidence)
        return out

    @staticmethod
    def providers() -> list[tuple[str, str]]:
        """Provider-neutral detector registry (prefix, display name)."""
        return list(PROVIDERS)
