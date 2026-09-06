"""REAL source/configuration crypto scanner (regex + heuristics, stdlib only).

Detects: symmetric/asymmetric/hash algorithms, protocol versions, certificate &
key-material references, key sizes, and crypto-library imports. Emits REAL
(is_mock=False) findings. Evidence is redacted for key material and common secret values,
then truncated to 160 chars.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import CryptoFinding
from .base import Scanner
from .cert_metadata import read_certificate_metadata

MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 2000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
             ".idea", "vendor", "target", "out", "coverage", ".next", ".nuxt", ".tox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache"}
TEXT_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".c", ".h", ".cpp",
             ".cs", ".rb", ".php", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
             ".json", ".xml", ".properties", ".env", ".pem", ".crt", ".key", ".cnf",
             ".sh", ".ps1", ".tf", ".dockerfile", "Dockerfile"}

# (regex, algorithm, category, confidence, extra-field-hint)
RULES: list[tuple[str, str, str, float, str]] = [
    (r"\bAES[-_ ]?(128|192|256)\b", "AES", "symmetric", 0.9, "size"),
    (r"\b3DES\b|\bDESede\b|\bTriple[ -]?DES\b", "3DES", "symmetric", 0.85, ""),
    (r"(?<![A-Za-z0-9])DES(?![A-Za-z0-9])", "DES", "symmetric", 0.6, ""),
    (r"\bChaCha20\b", "ChaCha20", "symmetric", 0.9, ""),
    (r"\bRC4\b", "RC4", "symmetric", 0.9, ""),
    (r"\bBlowfish\b", "Blowfish", "symmetric", 0.8, ""),
    (r"\bRSA\b", "RSA", "asymmetric", 0.85, "rsasize"),
    (r"\bECDSA\b", "ECDSA", "asymmetric", 0.9, "curve"),
    (r"\bEd25519\b|\bEd448\b", "ECC", "asymmetric", 0.9, "curve"),
    (r"\bECDH\b|\bX25519\b|\bX448\b", "ECDH", "asymmetric", 0.85, ""),
    (r"\bDHE?\b|\bDiffie[- ]?Hellman\b", "DH", "asymmetric", 0.7, ""),
    (r"\bDSA\b", "DSA", "asymmetric", 0.8, ""),
    (r"\bMD5\b", "MD5", "hash", 0.9, ""),
    (r"\bSHA[-_ ]?1\b(?!.*256)", "SHA-1", "hash", 0.8, ""),
    (r"\bSHA[-_ ]?(224|256|384|512)\b", "SHA-2", "hash", 0.85, ""),
    (r"\bSHA[-_ ]?3\b", "SHA-3", "hash", 0.9, ""),
    (r"\bHMAC\b", "HMAC", "hash", 0.7, ""),
    (r"\bbcrypt\b|\bscrypt\b|\bArgon2\b|\bPBKDF2\b", "KDF", "hash", 0.8, ""),
    (r"\bSSLv2\b|\bSSLv3\b", "SSL", "protocol", 0.95, "proto"),
    (r"\bTLSv?1\.0\b|\bTLS_VERSION_1_0\b", "TLS1.0", "protocol", 0.9, "proto"),
    (r"\bTLSv?1\.1\b", "TLS1.1", "protocol", 0.9, "proto"),
    (r"\bTLSv?1\.2\b", "TLS1.2", "protocol", 0.85, "proto"),
    (r"\bTLSv?1\.3\b", "TLS1.3", "protocol", 0.85, "proto"),
    (r"-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY|OPENSSH PRIVATE KEY|CERTIFICATE)-----",
     "PEM", "certificate", 0.99, "pem"),
    (r"\.(pem|p12|pfx|jks|keystore)\b", "KEYFILE", "key", 0.6, ""),
    # Bare `.key` alone is usually code attribute access (`args.key` is lexically
    # identical to `= server.key`), so only fire for path-like (`certs/service.key`)
    # or quoted (`"server.key"`) refs. Unquoted bare filenames are the accepted miss.
    (r"[\w\-.]+/[\w\-.]*\.key\b|[\"'`][\w\-]+\.key\b", "KEYFILE", "key", 0.6, ""),
    (r"\bkey[_-]?size\b|\bkey[_-]?length\b", "KEYSIZE", "key", 0.5, ""),
    (r"\bopenssl\b|\blibcrypto\b|\bboringssl\b", "OpenSSL", "library", 0.7, "lib"),
    (r"\bfrom cryptography\b|\bimport cryptography\b|\bCrypto\.(Cipher|PublicKey)\b", "PyCA", "library", 0.75, "lib"),
    (r"\bhashlib\b|\bnode:crypto\b|\brequire\(['\"]crypto['\"]\)", "STDLIB", "library", 0.6, "lib"),
    (r"\bjavax\.crypto\b|\bjava\.security\b", "JCA", "library", 0.75, "lib"),
    (r"\bsubtle\.(encrypt|digest|generateKey)\b|\bWebCrypto\b", "WebCrypto", "library", 0.7, "lib"),
    (r"\bopenpgp\b|\blibsodium\b|\bsodium\b", "NaCl/PGP", "library", 0.7, "lib"),
]

SIZE_RE = re.compile(r"\b(512|1024|2048|3072|4096)\b")
CURVE_RE = re.compile(r"(secp256r1|secp384r1|secp521r1|P-256|P-384|P-521|Curve25519|prime256v1)", re.I)
MODE_RE = re.compile(r"\b(CBC|ECB|GCM|CTR|OFB|CFB|XTS)\b", re.I)
COMPILED = [(re.compile(p, re.I), a, c, conf, hint) for p, a, c, conf, hint in RULES]
SENSITIVE_VALUE_RE = re.compile(
    r"\b(password|passwd|secret|token|api[_-]?key|private[_-]?key)\b\s*([:=])\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^,\s#;]+)", re.I)
PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN (?:RSA PRIVATE KEY|PRIVATE KEY|OPENSSH PRIVATE KEY)-----", re.I)
DEPENDENCIES = {
    "cryptography": "PyCA cryptography", "pycryptodome": "PyCryptodome",
    "pyopenssl": "PyOpenSSL", "bcrypt": "bcrypt", "passlib": "passlib",
    "jsonwebtoken": "jsonwebtoken", "jose": "JOSE", "node-forge": "node-forge",
    "crypto-js": "crypto-js", "bouncycastle": "Bouncy Castle",
    "bcprov": "Bouncy Castle", "tink": "Google Tink",
}


def _evidence(line: str) -> str:
    """Keep evidence useful without returning key material or obvious secret values."""
    if PRIVATE_KEY_HEADER_RE.search(line):
        return "[REDACTED PRIVATE KEY MATERIAL]"
    return SENSITIVE_VALUE_RE.sub(r"\1\2[REDACTED]", line.strip())[:160]


def _is_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTS or path.name == "Dockerfile":
        return True
    try:
        with open(path, "rb") as fh:
            return b"\x00" not in fh.read(8192)
    except OSError:
        return False


def _size_ok(path: Path) -> bool:
    try:
        return path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False  # unreadable metadata: skip, never crash a scan


def _iter_files(target: Path):
    if target.is_file():
        if not target.is_symlink() and _size_ok(target):
            yield target
        return
    count = 0
    for p in sorted(target.rglob("*")):
        if not p.is_file() or p.is_symlink() or any(d in p.parts for d in SKIP_DIRS):
            continue
        if not _size_ok(p):
            continue
        count += 1
        if count > MAX_FILES:
            break
        yield p


class SourceScanner(Scanner):
    """Real scanner for source/config text. is_mock=False — genuine discovery."""

    name = "source"
    is_mock = False

    def scan(self, target: str | Path) -> list[CryptoFinding]:
        root = Path(target)
        if not root.exists():
            raise FileNotFoundError(f"scan target missing: {target}")
        findings: list[CryptoFinding] = []
        for path in _iter_files(root):
            if not _is_text(path):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            metadata = read_certificate_metadata(text)
            if metadata:
                findings.append(CryptoFinding(
                    scanner=self.name, file_path=str(path), line=0,
                    algorithm=metadata["algorithm"], category="certificate",
                    key_size=metadata["key_size"], curve=metadata["curve"],
                    signature_algorithm=metadata["signature_algorithm"],
                    expires_at=metadata["expires_at"], usage="certificate metadata",
                    rationale="X.509 PEM public metadata; no private key material read",
                    evidence="PEM certificate metadata", confidence=0.95, is_mock=False))
            lines = text.splitlines()
            for i, line in enumerate(lines, 1):
                findings.extend(self._scan_line(str(path), i, line))
        return findings

    def _scan_line(self, fpath: str, lineno: int, line: str) -> list[CryptoFinding]:
        out: list[CryptoFinding] = []
        dependency = self._dependency(fpath, line)
        if dependency:
            out.append(CryptoFinding(scanner=self.name, file_path=fpath, line=lineno,
                                    algorithm=dependency, category="dependency",
                                    library=dependency, usage="dependency reference",
                                    rationale=("Manifest dependency/reference; it does not prove "
                                               "a specific algorithm is used"),
                                    evidence=_evidence(line), confidence=0.75, is_mock=False))
        for rx, algo, cat, conf, hint in COMPILED:
            m = rx.search(line)
            if not m:
                continue
            name, size, mode, proto, lib = algo, None, "", "", ""
            if hint == "size" and m.lastindex:
                try:
                    size = int(m.group(1))
                    name = f"AES-{size}"
                except (ValueError, IndexError):
                    pass
            elif hint == "rsasize":
                sm = SIZE_RE.search(line)
                size = int(sm.group(1)) if sm else None
            elif hint == "curve":
                cm = CURVE_RE.search(line)
                if cm:
                    lib = cm.group(1)
            elif hint == "proto":
                proto = name
            elif hint == "lib":
                lib = m.group(0)
            elif hint == "pem":
                name = "PEM-" + m.group(1).replace(" ", "")
                cat = "certificate" if "CERTIFICATE" in m.group(1) else "key"
            mm = MODE_RE.search(line)
            if mm:
                mode = mm.group(1).upper()
            out.append(CryptoFinding(scanner=self.name, file_path=fpath, line=lineno,
                                    algorithm=name, category=cat, key_size=size, mode=mode,
                                    protocol_version=proto, library=lib,
                                    evidence=_evidence(line), confidence=conf,
                                    is_mock=False))
        return out

    @staticmethod
    def _dependency(fpath: str, line: str) -> str:
        filename = Path(fpath).name.lower()
        if not (filename.startswith("requirements") or filename in {"pyproject.toml", "package.json",
                "package-lock.json", "pom.xml", "build.gradle", "build.gradle.kts"}):
            return ""
        low = line.lower()
        for token, name in DEPENDENCIES.items():
            if re.search(rf"(?<![a-z0-9_.-]){re.escape(token)}(?![a-z0-9_.-])", low):
                return name
        return ""
