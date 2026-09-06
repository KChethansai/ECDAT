"""REAL dependency/library metadata scanner (stdlib only).

Safe static manifest analysis: reads manifest files as data, never installs
packages, never invokes package managers, never touches the network. Reports
only conservatively recognized cryptographic dependencies with versions —
never vulnerability judgments (this is discovery, not CVE scanning).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

try:
    import tomllib
except ImportError:  # Python < 3.11: fall back to line matching
    tomllib = None  # type: ignore[assignment]

from ..models import CryptoFinding
from .base import Scanner
from .source_scanner import MAX_FILE_BYTES, SKIP_DIRS

STATIC_LIMIT = ("Static manifest evidence only; a listed dependency is not proof "
                "of runtime cryptographic use. Versions are inventory, not verdicts.")

# normalized name -> (display name, confidence). Exact matches only: packages merely
# containing "auth"/"security"/"crypto" as substrings are NOT flagged.
CRYPTO_DEPS: dict[str, tuple[str, float]] = {
    "openssl": ("OpenSSL", 0.8), "boringssl": ("BoringSSL", 0.8),
    "libressl": ("LibreSSL", 0.8), "mbedtls": ("mbedTLS", 0.8),
    "cryptography": ("PyCA cryptography", 0.8),
    "pycrypto": ("PyCrypto", 0.75), "pycryptodome": ("PyCryptodome", 0.8),
    "pycryptodomex": ("PyCryptodome", 0.8), "pyopenssl": ("PyOpenSSL", 0.8),
    "bcrypt": ("bcrypt", 0.8), "passlib": ("passlib", 0.75),
    "argon2-cffi": ("argon2-cffi", 0.8), "asn1crypto": ("asn1crypto", 0.7),
    "certifi": ("certifi CA bundle", 0.6), "pyca-cryptography": ("PyCA cryptography", 0.8),
    "jsonwebtoken": ("jsonwebtoken", 0.8), "jose": ("JOSE", 0.8),
    "python-jose": ("JOSE", 0.8), "node-forge": ("node-forge", 0.8),
    "crypto-js": ("crypto-js", 0.8), "openpgp": ("OpenPGP", 0.8),
    "tweetnacl": ("TweetNaCl", 0.8), "libsodium-wrappers": ("libsodium", 0.8),
    "sodium-native": ("libsodium", 0.8), "elliptic": ("elliptic", 0.7),
    "bcprov-jdk18": ("Bouncy Castle", 0.8), "bcprov": ("Bouncy Castle", 0.8),
    "bcpkix": ("Bouncy Castle", 0.8), "bctls": ("Bouncy Castle", 0.8),
    "tink": ("Google Tink", 0.8), "conscrypt": ("Conscrypt", 0.75),
    "spongycastle": ("Spongy Castle", 0.75),
    "ring": ("ring", 0.8), "rustls": ("rustls", 0.8),
    "rustls-native-certs": ("rustls-native-certs", 0.6),
    "openssl-crate": ("OpenSSL", 0.8), "sodiumoxide": ("libsodium", 0.8),
    "orion": ("Orion", 0.8), "aes": ("AES", 0.7), "rsa": ("RSA", 0.7),
    "sha2": ("SHA-2", 0.7), "sha3": ("SHA-3", 0.7), "ed25519-dalek": ("ECC", 0.8),
    "x25519-dalek": ("ECDH", 0.8), "p256": ("ECC", 0.75), "k256": ("ECC", 0.75),
    "chacha20poly1305": ("ChaCha20", 0.75), "hkdf": ("KDF", 0.7), "hmac": ("HMAC", 0.7),
    "md5": ("MD5", 0.7), "blake3": ("BLAKE3", 0.7),
    "x-crypto": ("x/crypto", 0.8), "go-jose": ("JOSE", 0.8), "jwx": ("JWX", 0.8),
}

MANIFESTS = {"requirements.txt", "pyproject.toml", "setup.cfg", "package.json",
             "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pom.xml",
             "build.gradle", "build.gradle.kts", "cargo.toml", "cargo.lock",
             "go.mod", "go.sum"}
REQUIREMENTS_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*([^;#\s]*)\s*(?:[#;].*)?$")
GRADLE_RE = re.compile(r"""['"]([^'":\s]+):([^'":\s]+):([^'":\s]+)['"]""")
GOMOD_RE = re.compile(r"^\s*(?:require\s+)?([\w.\-/]+(?:/[\w.\-]+)+)\s+(v[\w.+-]+)")
CARGODEP_RE = re.compile(r"^\s*([A-Za-z0-9_\-]+)\s*=\s*[\"'{]")
INCLUDE_RE = re.compile(r"^\s*-[rc]\s+(\S+)")
GENERIC_VERSION_RE = re.compile(r"version\s*[:=]\s*[\"']([^\"']+)[\"']", re.I)


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def short_module(path: str) -> str:
    """golang.org/x/crypto -> x-crypto so ecosystem names hit one map."""
    parts = path.split("/")
    if len(parts) >= 3 and parts[-2] == "x":
        return "x-" + parts[-1]
    return parts[-1]


class DependencyScanner(Scanner):
    """Real manifest scanner. is_mock=False — genuine discovery."""

    name = "dependency"
    is_mock = False

    def scan(self, target: str | Path) -> list[CryptoFinding]:
        root = Path(target)
        if not root.exists():
            raise FileNotFoundError(f"scan target missing: {target}")
        files = [root] if root.is_file() else self._iter_manifests(root)
        findings: list[CryptoFinding] = []
        for path in files:
            try:
                findings.extend(self._scan_manifest(path))
            except OSError:
                continue
        return findings

    def _iter_manifests(self, root: Path):
        count = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink() or any(d in path.parts for d in SKIP_DIRS):
                continue
            name = path.name.lower()
            if name not in MANIFESTS and not name.startswith("requirements"):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            if count > 200:
                break
            yield path

    def _scan_manifest(self, path: Path) -> list[CryptoFinding]:
        text = path.read_text(encoding="utf-8", errors="replace")
        name = path.name.lower()
        pairs: list[tuple[str, str]] = []  # (raw name, version)
        if name.startswith("requirements") or name == "requirements.txt":
            pairs = self._requirements(text, path.parent, depth=0, seen=set())
        elif name == "package.json":
            pairs = self._package_json(text)
        elif name in {"package-lock.json"}:
            pairs = self._package_lock(text)
        elif name in {"pyproject.toml", "cargo.toml", "cargo.lock"} and tomllib is not None:
            pairs = self._toml_pairs(text, name)
        elif name == "pom.xml":
            pairs = self._pom(text)
        elif name in {"build.gradle", "build.gradle.kts"}:
            pairs = self._gradle(text)
        elif name == "go.mod":
            pairs = self._gomod(text)
        else:
            pairs = self._generic_lines(text)
        out = []
        for raw, version in pairs:
            display, confidence = self._lookup(raw)
            if display is None:
                continue
            out.append(CryptoFinding(
                scanner=self.name, file_path=str(path), line=0, algorithm=display,
                category="dependency", library=raw.strip()[:64],
                usage="dependency reference",
                rationale="Manifest-listed cryptographic dependency. " + STATIC_LIMIT,
                evidence=f"{raw.strip()[:64]} {version.strip()[:32]}".strip()[:160],
                confidence=confidence, is_mock=False))
        return out

    @staticmethod
    def _lookup(raw: str) -> tuple[str | None, float]:
        short = short_module(raw)
        if short in CRYPTO_DEPS:
            return CRYPTO_DEPS[short]
        return CRYPTO_DEPS.get(normalize(raw), (None, 0.0))

    def _requirements(self, text: str, base: Path, depth: int, seen: set) -> list:
        pairs = []
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            include = INCLUDE_RE.match(stripped)
            if include and depth < 3:  # follow same-dir -r/-c includes, cycle-guarded
                child = (base / include.group(1)).resolve()
                if child.is_file() and child not in seen and base.resolve() in child.parents:
                    seen.add(child)
                    try:
                        pairs.extend(self._requirements(
                            child.read_text(encoding="utf-8", errors="replace"),
                            child.parent, depth + 1, seen))
                    except OSError:
                        continue
                continue
            if stripped.startswith(("-", "!")):
                continue
            if match := REQUIREMENTS_RE.match(stripped):
                pairs.append((match.group(1), match.group(2) or ""))
        return pairs

    @staticmethod
    def _package_json(text: str) -> list:
        try:
            data = json.loads(text)
        except ValueError:
            return []
        pairs = []
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for dep, version in (data.get(section) or {}).items():
                pairs.append((dep, str(version)))
        return pairs

    @staticmethod
    def _package_lock(text: str) -> list:
        try:
            data = json.loads(text)
        except ValueError:
            return []
        pairs = []
        for section in ("packages", "dependencies"):
            for key, meta in (data.get(section) or {}).items():
                dep = key.split("node_modules/")[-1] if key else ""
                if dep and isinstance(meta, dict) and meta.get("version"):
                    pairs.append((dep, str(meta["version"])))
        return pairs

    @staticmethod
    def _toml_pairs(text: str, name: str) -> list:
        try:
            data = tomllib.loads(text)
        except ValueError:
            return []
        pairs = []
        if name == "cargo.lock":
            for package in data.get("package", []):
                pairs.append((str(package.get("name", "")), str(package.get("version", ""))))
            return pairs
        project = data.get("project", {})
        for entry in project.get("dependencies", []) or []:
            if match := REQUIREMENTS_RE.match(str(entry)):
                pairs.append((match.group(1), match.group(2) or ""))
        for section in ("tool",):
            poetry = ((data.get(section) or {}).get("poetry") or {}).get("dependencies", {})
            for dep, version in poetry.items():
                if dep != "python":
                    pairs.append((dep, version if isinstance(version, str) else ""))
        for dep, spec in (data.get("dependencies") or {}).items():
            pairs.append((dep, spec.get("version", "") if isinstance(spec, dict) else str(spec)))
        return pairs

    @staticmethod
    def _pom(text: str) -> list:
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []
        namespace = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        prefix = "m:" if namespace else ""
        pairs = []
        for dep in root.findall(f".//{prefix}dependency", namespace):
            def find(tag: str) -> str:
                node = dep.find(f"{prefix}{tag}", namespace)
                return (node.text or "").strip() if node is not None else ""
            artifact, version = find("artifactId"), find("version")
            if artifact:
                pairs.append((artifact, version))
        return pairs

    @staticmethod
    def _gradle(text: str) -> list:
        pairs = []
        for match in GRADLE_RE.finditer(text):
            pairs.append((match.group(2), match.group(3)))
        return pairs

    @staticmethod
    def _gomod(text: str) -> list:
        pairs = []
        for line in text.splitlines():
            if match := GOMOD_RE.match(line):
                if "=>" in line:  # replace directives: not the resolved dependency
                    continue
                pairs.append((match.group(1), match.group(2)))
        return pairs

    @staticmethod
    def _generic_lines(text: str) -> list:
        pairs = []
        for line in text.splitlines():
            for token in re.findall(r"[A-Za-z0-9_.\-/~^<>=! ]{3,80}", line):
                name = token.strip().strip("\"' ,")
                if normalize(name) in CRYPTO_DEPS:
                    version = ""
                    if found := GENERIC_VERSION_RE.search(line):
                        version = found.group(1)
                    pairs.append((name, version))
                    break
        return pairs
