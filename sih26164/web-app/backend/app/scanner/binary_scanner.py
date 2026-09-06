"""REAL static binary crypto-indicator scanner (stdlib only).

Safety: pure bounded reads — the target is NEVER executed, imported, or launched,
no subprocesses, no temp files. Untrusted input is handled defensively:
unknown/truncated/oversized/unreadable files are skipped, never crash a scan.

Method: identify ELF/PE/Mach-O by magic bytes, extract printable-ASCII strings
(bounded), and match conservative indicator tables. A matched string proves the
indicator is *present*, not that it is used at runtime — every finding says so.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import CryptoFinding
from .base import Scanner
from .cert_metadata import read_certificate_metadata
from .source_scanner import MAX_FILE_BYTES, MAX_FILES, SKIP_DIRS

STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")
MAX_STRINGS = 20000
MAX_FINDINGS_PER_FILE = 100
STATIC_LIMIT = ("Static string evidence only; presence in a binary does not prove "
                "runtime cryptographic use.")

# Magic prefix -> format label. We do not parse structure; strings carry the evidence.
FORMATS: list[tuple[bytes, str]] = [
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "Mach-O"),
    (b"\xca\xfe\xba\xbf", "Mach-O"),
]

# (regex, algorithm, category, confidence, usage, field-fill)
# field-fill: "lib" puts the match in library, "proto" in protocol_version.
LIBRARIES: list[tuple[str, str]] = [
    (r"libcrypto[\w.+-]*", "OpenSSL"), (r"libssl[\w.+-]*", "OpenSSL"),
    (r"libtls[\w.+-]*", "LibreSSL"), (r"boringssl", "BoringSSL"),
    (r"libsodium[\w.+-]*", "libsodium"), (r"libtomcrypt[\w.+-]*", "LibTomCrypt"),
    (r"mbedtls", "mbedTLS"), (r"wolfssl", "wolfSSL"), (r"wolfcrypt", "wolfSSL"),
    (r"botan[\w.+-]*", "Botan"), (r"cryptopp", "Crypto++"),
    (r"nettle", "Nettle"), (r"hogweed", "Nettle"), (r"gcrypt", "libgcrypt"),
    (r"libeay32", "OpenSSL"), (r"ssleay32", "OpenSSL"),
    (r"bcrypt\.dll", "CNG"), (r"ncrypt\.dll", "CNG"), (r"crypt32\.dll", "CAPI"),
    (r"schannel\.dll", "SChannel"),
]
SYMBOLS: list[tuple[str, str]] = [  # prefix, canonical label
    ("EVP_", "OpenSSL"), ("AES_", "AES"), ("RSA_", "RSA"), ("EC_", "EC"),
    ("ECDSA_", "ECDSA"), ("DSA_", "DSA"), ("DH_", "DH"), ("SHA", "SHA"),
    ("MD5", "MD5"), ("HMAC_", "HMAC"), ("PEM_", "PEM"), ("X509_", "X509"),
    ("SSL_", "SSL"), ("TLS_", "TLS"), ("CRYPTO_", "OpenSSL"), ("RAND_", "RAND"),
    ("PKCS", "PKCS"), ("OCSP_", "OCSP"), ("mbedtls_", "mbedTLS"),
    ("wolfSSL_", "wolfSSL"), ("wc_", "wolfSSL"), ("sodium_", "libsodium"),
    ("crypto_box", "libsodium"), ("crypto_sign", "libsodium"),
    ("crypto_secretbox", "libsodium"), ("crypto_scalarmult", "libsodium"),
    ("BCrypt", "CNG"), ("NCrypt", "CNG"), ("CryptAcquireContext", "CAPI"),
]
ALGORITHMS: list[tuple[str, str, str]] = [  # regex, canonical name, category
    (r"\bAES[-_ ]?(128|192|256)\b", "AES", "symmetric"),
    (r"\bChaCha20\b", "ChaCha20", "symmetric"),
    (r"\bRSA[-_ ]?(1024|2048|3072|4096)\b", "RSA", "asymmetric"),
    (r"\bECDSA\b", "ECDSA", "asymmetric"),
    (r"\bEd25519\b", "ECC", "asymmetric"),
    (r"\bX25519\b", "ECDH", "asymmetric"),
    (r"\bMD5\b", "MD5", "hash"),
    (r"\bSHA[-_ ]?(224|256|384|512)\b", "SHA-2", "hash"),
    (r"\bSHA[-_ ]?3\b", "SHA-3", "hash"),
    (r"\bML-KEM\b", "ML-KEM", "asymmetric"),
    (r"\bML-DSA\b", "ML-DSA", "asymmetric"),
    (r"\bP-(256|384|521)\b", "ECC", "asymmetric"),
    (r"\bTLSv?1\.[23]\b", "TLS", "protocol"),
    (r"\bTLS_[A-Z0-9_]{4,}\b", "TLS", "protocol"),
]
SIZE_RE = re.compile(r"\b(512|1024|2048|3072|4096)\b")
CURVE_RE = re.compile(r"(P-256|P-384|P-521|Curve25519)", re.I)
COMPILED_LIBS = [(re.compile(p, re.I), name) for p, name in LIBRARIES]
COMPILED_SYMBOLS = [(re.compile(r"\b" + re.escape(prefix), re.I), label)
                    for prefix, label in SYMBOLS]
COMPILED_ALGOS = [(re.compile(p, re.I), name, cat) for p, name, cat in ALGORITHMS]


def identify(data: bytes) -> str:
    """Return the container format label, or '' when unsupported/truncated."""
    for magic, label in FORMATS:
        if len(data) >= len(magic) and data.startswith(magic):
            return label
    return ""


def extract_strings(data: bytes) -> list[str]:
    """Bounded printable-ASCII string extraction; never decodes binary as text."""
    out = []
    for match in STRING_RE.finditer(data):
        out.append(match.group().decode("ascii"))
        if len(out) >= MAX_STRINGS:
            break
    return out


class BinaryScanner(Scanner):
    """Real static binary scanner. is_mock=False — genuine discovery."""

    name = "binary"
    is_mock = False

    def scan(self, target: str | Path) -> list[CryptoFinding]:
        root = Path(target)
        if not root.exists():
            raise FileNotFoundError(f"scan target missing: {target}")
        return self._scan_many(self._iter_files(root)) if root.is_dir() else self._scan_many(
            [root] if self._readable_binary(root) else [])

    def _iter_files(self, root: Path):
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

    @staticmethod
    def _readable_binary(path: Path) -> bool:
        try:
            return not path.is_symlink() and path.stat().st_size <= MAX_FILE_BYTES
        except OSError:
            return False

    def _scan_many(self, paths) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        for path in paths:
            try:
                with open(path, "rb") as handle:
                    data = handle.read(MAX_FILE_BYTES + 1)
            except OSError:
                continue
            if len(data) > MAX_FILE_BYTES:
                continue
            fmt = identify(data[:16])
            if not fmt:
                continue  # not a supported binary; source scanner owns text
            findings.extend(self._scan_binary(str(path), fmt, extract_strings(data)))
        return findings

    def _scan_binary(self, fpath: str, fmt: str, strings: list[str]) -> list[CryptoFinding]:
        out: list[CryptoFinding] = []
        metadata = read_certificate_metadata("\n".join(strings))
        if metadata:
            out.append(CryptoFinding(
                scanner=self.name, file_path=fpath, line=0,
                algorithm=metadata["algorithm"], category="certificate",
                key_size=metadata["key_size"], curve=metadata["curve"],
                signature_algorithm=metadata["signature_algorithm"],
                expires_at=metadata["expires_at"], usage="certificate metadata",
                rationale=f"X.509 PEM public metadata embedded in {fmt} binary; "
                          "no private key material read",
                evidence="PEM certificate metadata", confidence=0.95, is_mock=False))

        def hit(algorithm: str, category: str, usage: str, confidence: float,
                evidence: str, **fields) -> None:
            if len(out) >= MAX_FINDINGS_PER_FILE:
                return
            out.append(CryptoFinding(
                scanner=self.name, file_path=fpath, line=0, algorithm=algorithm,
                category=category, usage=usage, evidence=evidence[:160],
                confidence=confidence, is_mock=False,
                rationale=f"{STATIC_LIMIT} [{fmt} container]", **fields))

        seen: set[tuple[str, str, str]] = set()

        def once(kind: str, algorithm: str, evidence: str) -> bool:
            key = (kind, algorithm, evidence)
            if key in seen:
                return False
            seen.add(key)
            return True

        # One finding per distinct matching string: repeated strings collapse,
        # genuinely different evidence stays separate. Strings arrive in file
        # order, so results are deterministic.
        for string in strings:
            for pattern, lib in COMPILED_LIBS:
                if match := pattern.search(string):
                    if once("lib", lib, match.group(0)):
                        hit(lib, "library", "binary library reference", 0.8,
                            match.group(0), library=match.group(0)[:64])
            for pattern, label in COMPILED_SYMBOLS:
                if match := pattern.search(string):
                    token = match.group(0)
                    if once("sym", label, token):
                        hit(label, "library", "binary symbol reference", 0.7,
                            string, library=token[:64])
            for pattern, name, category in COMPILED_ALGOS:
                if match := pattern.search(string):
                    if not once("str", name, string):
                        continue
                    algo, size, curve, proto = name, None, "", ""
                    if name == "AES" and match.lastindex:
                        size = int(match.group(1))
                        algo = f"AES-{size}"
                    elif name == "RSA" and match.lastindex:
                        size = int(match.group(1))
                    elif name == "ECC":
                        if found := CURVE_RE.search(match.group(0)):
                            curve = found.group(1)
                        else:
                            window = string[max(0, match.start() - 16):match.end() + 16]
                            if found := SIZE_RE.search(window):
                                size = int(found.group(1))
                    elif name == "TLS":
                        proto = match.group(0)
                    hit(algo, category, "binary string reference", 0.55,
                        string, key_size=size, curve=curve, protocol_version=proto)
        return out
