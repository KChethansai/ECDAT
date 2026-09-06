"""REAL container scanner: safe static inspection (stdlib only).

Supported inputs (never executed, never extracted to disk):
- `docker save` tarballs (manifest.json + config + layer tars)
- extracted docker-save directories / OCI layouts (index.json + blobs)
- single layer tarballs (.tar, .tar.gz, .tgz)
- Dockerfiles (directives + crypto keyword pass)

Safety: archives are streamed, never extracted — Zip-Slip/symlink attacks have
no filesystem target. Members are matched by name; only interesting members are
read (bounded). Gzip bombs are capped by a decompressed-bytes budget. Nothing
inside an artifact is executed, installed, or treated as instructions.
"""

from __future__ import annotations

import gzip
import io
import json
import re
import tarfile
from pathlib import Path

from ..models import CryptoFinding
from .base import Scanner
from .binary_scanner import BinaryScanner, extract_strings, identify
from .cert_metadata import read_certificate_metadata
from .source_scanner import MAX_FILE_BYTES, SKIP_DIRS, SourceScanner

OUTER_MAX_BYTES = 512 * 1024 * 1024  # images are big; streaming keeps memory bounded
MAX_LAYERS = 10
MAX_MEMBERS = 2000
MEMBER_PEEK_BYTES = 64 * 1024
DECOMPRESSED_BUDGET = 64 * 1024 * 1024
STATIC_LIMIT = ("Static container evidence only; presence inside an image does not "
                "prove runtime cryptographic use.")
SECRET_ENV_RE = re.compile(r"password|passwd|secret|token|private|credential", re.I)
HEX_RE = re.compile(r"^[0-9a-f]{8,128}$")

_KEYWORDS = SourceScanner()
_BINARY = BinaryScanner()


def _adopt(finding: CryptoFinding, usage: str) -> CryptoFinding:
    """Re-home a reused finding: container provenance, honest rationale."""
    finding.scanner = "container"
    finding.usage = usage
    note = "Observed inside container artifact. " + STATIC_LIMIT
    finding.rationale = (finding.rationale + "; " + note if finding.rationale else note)
    return finding


def _safe_member(root: Path, name: str) -> Path | None:
    """Resolve an archive-referenced name strictly inside root (Zip-Slip guard)."""
    if not name or name.startswith(("/", "\\")) or ".." in Path(name).parts:
        return None
    target = (root / name).resolve()
    if target != root and root.resolve() not in target.parents:
        return None
    return target

# member path fragments worth opening (bounded peek, then keyword/cert analysis)
INTERESTING = (".pem", ".crt", ".cer", ".key", ".p12", ".pfx", ".jks",
               "openssl.cnf", "ssl", "tls", "crypto", "requirements", "package.json",
               "package-lock.json", "pyproject.toml", "pom.xml", "cargo.toml",
               "go.mod", "Dockerfile")
MANIFEST_NAMES = ("requirements.txt", "package.json", "package-lock.json",
                  "pyproject.toml", "pom.xml", "cargo.toml", "cargo.lock", "go.mod")


def _safe_name(name: str) -> str:
    """Provenance-only name: single line, bounded, never used as a filesystem path."""
    return re.sub(r"\s+", " ", name).strip()[:200]


class ContainerScanner(Scanner):
    """Real static container scanner. is_mock=False — genuine discovery."""

    name = "container"
    is_mock = False

    def scan(self, target: str | Path) -> list[CryptoFinding]:
        root = Path(target)
        if not root.exists():
            raise FileNotFoundError(f"scan target missing: {target}")
        if root.is_file():
            return self._scan_file(root, str(root))
        return self._scan_dir(root)

    # -- dispatch ----------------------------------------------------------
    def _scan_dir(self, root: Path) -> list[CryptoFinding]:
        if (root / "manifest.json").is_file():
            return self._scan_docker_layout(root)
        if (root / "oci-layout").is_file() and (root / "index.json").is_file():
            return self._scan_oci_layout(root)
        findings: list[CryptoFinding] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink() or any(d in path.parts for d in SKIP_DIRS):
                continue
            low = path.name.lower()
            if low.startswith("dockerfile") or low.endswith((".tar", ".tar.gz", ".tgz")):
                try:
                    findings.extend(self._scan_file(path, str(path)))
                except OSError:
                    continue
        return findings

    def _scan_file(self, path: Path, provenance: str) -> list[CryptoFinding]:
        if path.is_symlink():
            return []
        try:
            if path.stat().st_size > OUTER_MAX_BYTES:
                return []
        except OSError:
            return []
        low = path.name.lower()
        if low.startswith("dockerfile") or low.endswith("dockerfile"):
            return self._scan_dockerfile(path, provenance)
        if low.endswith(".tar"):
            return self._scan_tar(path, provenance)
        if low.endswith((".tar.gz", ".tgz")):
            # gzipped single layer (a gzipped docker-save is out of scope)
            return self._scan_members_stream(path, provenance)
        return []  # not a supported container artifact; other scanners own it

    def _open_tar(self, path: Path, mode: str):
        try:
            if path.stat().st_size > OUTER_MAX_BYTES or path.is_symlink():
                return None
        except OSError:
            return None
        try:
            return tarfile.open(path, mode=mode)
        except (tarfile.TarError, OSError):
            return None

    def _scan_tar(self, path: Path, provenance: str) -> list[CryptoFinding]:
        """Plain tar: docker-save archive (manifest.json) or single layer."""
        tar = self._open_tar(path, "r:")
        if tar is None:
            return []
        with tar:
            try:
                manifest_member = tar.getmember("manifest.json")
                is_save = manifest_member.isreg()
            except KeyError:
                is_save = False
            if is_save:
                return self._scan_save(tar, manifest_member, provenance)
            return self._scan_member_stream(
                tar, provenance, DECOMPRESSED_BUDGET, gzipped=False)

    def _scan_save(self, tar: tarfile.TarFile, manifest_member, provenance: str) -> list[CryptoFinding]:
        """docker save layout inside one tarball: manifest + config + layer blobs."""
        try:
            raw = tar.extractfile(manifest_member)
            entries = json.loads(self._bounded_read(raw, MEMBER_PEEK_BYTES).decode("utf-8"))
            layers = entries[0].get("Layers", [])[:MAX_LAYERS]
            config_name = entries[0].get("Config", "")
        except (ValueError, IndexError, AttributeError, KeyError):
            return []
        findings: list[CryptoFinding] = []
        if config_name and not config_name.startswith(("/", "\\")) and ".." not in Path(config_name).parts:
            try:
                member = tar.getmember(config_name)
                if member.isreg():
                    raw = tar.extractfile(member)
                    data = self._bounded_read(raw, MEMBER_PEEK_BYTES)
                    findings.extend(self._scan_config_bytes(data, f"{provenance}>config"))
            except KeyError:
                pass
        for layer in layers:
            if not layer or layer.startswith(("/", "\\")) or ".." in Path(layer).parts:
                continue
            try:
                member = tar.getmember(layer)
            except KeyError:
                continue
            if not member.isreg():
                continue
            blob = tar.extractfile(member)
            if blob is None:
                continue
            stream: io.BufferedReader | gzip.GzipFile = blob
            if layer.endswith(".gz") or blob.peek(2)[:2] == b"\x1f\x8b":
                stream = gzip.GzipFile(fileobj=blob)
            try:
                with tarfile.open(fileobj=stream, mode="r|*") as inner:
                    findings.extend(self._scan_member_stream(
                        inner, f"{provenance}>{_safe_name(layer)}",
                        DECOMPRESSED_BUDGET, gzipped=False))
            except (tarfile.TarError, EOFError, OSError):
                continue
        return findings

    # -- docker save / OCI layouts ------------------------------------------
    def _scan_docker_layout(self, root: Path) -> list[CryptoFinding]:
        try:
            entries = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            config_name = entries[0].get("Config", "")
            layers = entries[0].get("Layers", [])[:MAX_LAYERS]
        except (ValueError, IndexError, AttributeError, OSError):
            return []
        findings = []
        if config_name:
            config_path = _safe_member(root, config_name)
            if config_path is not None:
                findings.extend(self._scan_config(config_path, f"{root}>config"))
        for layer in layers:
            layer_path = _safe_member(root, layer)
            if layer_path is not None:
                findings.extend(self._scan_file(layer_path, f"{root}>{_safe_name(layer)}"))
        return findings

    def _digest(self, value) -> str | None:
        try:
            digest = str(value).split(":", 1)[1]
        except (IndexError, AttributeError):
            return None
        return digest if HEX_RE.match(digest) else None

    def _scan_oci_layout(self, root: Path) -> list[CryptoFinding]:
        try:
            index = json.loads((root / "index.json").read_text(encoding="utf-8"))
            manifest_digest = index["manifests"][0]["digest"].split(":", 1)[1]
            if not HEX_RE.match(manifest_digest):
                return []
            manifest = json.loads((root / "blobs" / "sha256" / manifest_digest).read_text(
                encoding="utf-8"))
        except (ValueError, KeyError, IndexError, OSError):
            return []
        findings = []
        config_digest = self._digest((manifest.get("config") or {}).get("digest"))
        if config_digest:
            findings.extend(self._scan_config(root / "blobs" / "sha256" / config_digest,
                                              f"{root}>config"))
        for layer in manifest.get("layers", [])[:MAX_LAYERS]:
            digest = self._digest((layer or {}).get("digest"))
            if digest is None:
                continue
            findings.extend(self._scan_file(root / "blobs" / "sha256" / digest,
                                            f"{root}>layer:{digest[:12]}"))
        return findings

    # -- image config (Env only; values never retained) ----------------------
    def _scan_config(self, path: Path, provenance: str) -> list[CryptoFinding]:
        try:
            if path.stat().st_size > MAX_FILE_BYTES or path.is_symlink():
                return []
            data = path.read_bytes()
        except OSError:
            return []
        return self._scan_config_bytes(data, provenance)

    def _scan_config_bytes(self, data: bytes, provenance: str) -> list[CryptoFinding]:
        try:
            config = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return []
        out = []
        env = ((config.get("config") or {}).get("Env") or [])
        for entry in env:
            name = str(entry).split("=", 1)[0]
            if SECRET_ENV_RE.search(name):
                out.append(CryptoFinding(
                    scanner=self.name, file_path=provenance, line=0,
                    algorithm="ENV-SECRET", category="key", usage="container config reference",
                    rationale="Secret-looking environment variable baked into image config. "
                              "Hygiene pointer only; value never read. " + STATIC_LIMIT,
                    evidence=f"ENV {name[:64]} present in image config (value withheld)",
                    confidence=0.6, is_mock=False))
        return out

    # -- tar members: shared bounded loop over any open tar object -------------
    def _scan_members_stream(self, path: Path, provenance: str) -> list[CryptoFinding]:
        """Gzipped single layer straight from disk (streamed, never extracted)."""
        try:
            raw = open(path, "rb")
        except OSError:
            return []
        with raw:
            stream = raw
            if path.name.endswith((".tgz", ".tar.gz")) or raw.peek(2)[:2] == b"\x1f\x8b":
                stream = gzip.GzipFile(fileobj=raw)
            try:
                with tarfile.open(fileobj=stream, mode="r|*") as tar:
                    return self._scan_member_stream(tar, provenance, DECOMPRESSED_BUDGET,
                                                    gzipped=isinstance(stream, gzip.GzipFile))
            except (tarfile.TarError, EOFError, OSError):
                return []

    def _scan_member_stream(self, tar: tarfile.TarFile, provenance: str,
                            budget: int, gzipped: bool) -> list[CryptoFinding]:
        findings: list[CryptoFinding] = []
        try:
            for count, member in enumerate(tar):
                if count >= MAX_MEMBERS or budget <= 0:
                    break
                if gzipped and tar.fileobj is not None and tar.fileobj.tell() > budget * 2:
                    break  # decompression bomb: stop even header iteration
                # Never extract: symlinks/hardlinks/devices are skipped by type.
                if not member.isreg():
                    continue
                name = _safe_name(member.name)
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                if self._interesting(name):
                    data = self._bounded_read(extracted, min(MEMBER_PEEK_BYTES, budget))
                else:
                    # Only other case worth opening: embedded binaries (magic sniff).
                    head = extracted.read(16)
                    if not identify(head):
                        continue
                    data = head + self._bounded_read(
                        extracted, min(MEMBER_PEEK_BYTES, budget) - len(head))
                budget -= len(data)
                findings.extend(self._scan_member(data, f"{provenance}>{name}"))
        except (tarfile.TarError, EOFError, OSError):
            pass  # malformed/truncated archive: keep what parsed
        return findings

    @staticmethod
    def _bounded_read(stream, limit: int) -> bytes:
        chunks, total = [], 0
        while total < limit:
            chunk = stream.read(min(65536, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _interesting(name: str) -> bool:
        low = name.lower()
        base = low.rsplit("/", 1)[-1]
        return (any(fragment in low for fragment in INTERESTING)
                or base in MANIFEST_NAMES or base.startswith("dockerfile"))

    # -- member content: binary delegates to the binary scanner, text gets a
    # -- keyword pass + cert metadata ------------------------------------------
    def _scan_member(self, data: bytes, provenance: str) -> list[CryptoFinding]:
        if b"\x00" in data[:4096] and b"-----BEGIN" not in data:
            fmt = identify(data[:16])
            if not fmt:
                return []  # unknown binary: binary scanner owns supported formats
            return [_adopt(f, "container binary reference")
                    for f in _BINARY._scan_binary(provenance, fmt, extract_strings(data))]
        try:
            text = data.decode("utf-8", errors="replace")
        except ValueError:
            return []
        out: list[CryptoFinding] = []
        metadata = read_certificate_metadata(text)
        if metadata:
            out.append(CryptoFinding(
                scanner=self.name, file_path=provenance, line=0,
                algorithm=metadata["algorithm"], category="certificate",
                key_size=metadata["key_size"], curve=metadata["curve"],
                signature_algorithm=metadata["signature_algorithm"],
                expires_at=metadata["expires_at"], usage="certificate metadata",
                rationale="X.509 PEM public metadata embedded in container layer; "
                          "no private key material read. " + STATIC_LIMIT,
                evidence="PEM certificate metadata", confidence=0.95, is_mock=False))
        for lineno, line in enumerate(text.splitlines(), 1):
            for finding in _KEYWORDS._scan_line(provenance, lineno, line):
                out.append(_adopt(finding, "container file reference"))
        return out

    # -- Dockerfiles -----------------------------------------------------------
    def _scan_dockerfile(self, path: Path, provenance: str) -> list[CryptoFinding]:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                return []
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        out: list[CryptoFinding] = []
        for lineno, line in enumerate(lines, 1):
            for finding in _KEYWORDS._scan_line(provenance, lineno, line):
                out.append(_adopt(finding, "container file reference"))
        return out
