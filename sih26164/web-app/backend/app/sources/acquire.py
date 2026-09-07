"""Safe GitHub acquisition: bounded download, hostile-archive extraction, isolated workspace.

stdlib only (urllib + tarfile + tempfile). No git binary, no scraping, no execution.
"""

from __future__ import annotations

import io
import ipaddress
import json
import os
import shutil
import socket
import tarfile
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

API_HOST = "api.github.com"
CODELOAD_HOST = "codeload.github.com"
# codeload redirects downloads here; allowed as a download origin only.
OBJECT_HOST = "objects.githubusercontent.com"
FETCH_HOSTS = {CODELOAD_HOST, OBJECT_HOST}
USER_AGENT = "ECDAT-source-acquisition/1"

# Conservative web-app defaults; configurable through AcquisitionPolicy.
CONNECT_TIMEOUT_S = 10.0
READ_TIMEOUT_S = 30.0
TOTAL_DEADLINE_S = 300.0
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_FILES = 50_000
MAX_PATH_CHARS = 512
MAX_SINGLE_FILE_BYTES = 64 * 1024 * 1024
MAX_REDIRECTS = 3


class AcquisitionError(Exception):
    """User-facing acquisition failure (safe message, no internals)."""


class AcquisitionPolicy:
    def __init__(self, raw: object = None) -> None:
        data = raw if isinstance(raw, dict) else {}
        try:
            self.max_download_bytes = int(data.get("max_download_bytes", MAX_DOWNLOAD_BYTES))
            self.max_extracted_bytes = int(data.get("max_extracted_bytes", MAX_EXTRACTED_BYTES))
            self.max_files = int(data.get("max_files", MAX_FILES))
            self.total_deadline_s = float(data.get("total_deadline_s", TOTAL_DEADLINE_S))
            self.connect_timeout_s = float(data.get("connect_timeout_s", CONNECT_TIMEOUT_S))
        except (TypeError, ValueError):
            raise AcquisitionError("invalid acquisition policy")
        if not (1_048_576 <= self.max_download_bytes <= 1024 * 1024 * 1024):
            raise AcquisitionError("max_download_bytes must be within [1 MiB, 1 GiB]")
        if not (1_048_576 <= self.max_extracted_bytes <= 4 * 1024 * 1024 * 1024):
            raise AcquisitionError("max_extracted_bytes must be within [1 MiB, 4 GiB]")
        if not (100 <= self.max_files <= 500_000):
            raise AcquisitionError("max_files must be within [100, 500000]")
        if not (10 <= self.total_deadline_s <= 900):
            raise AcquisitionError("total_deadline_s must be within [10, 900]")

    def summary(self) -> dict:
        return {"max_download_bytes": self.max_download_bytes,
                "max_extracted_bytes": self.max_extracted_bytes,
                "max_files": self.max_files,
                "total_deadline_s": self.total_deadline_s,
                "connect_timeout_s": self.connect_timeout_s}


def _assert_routable_host(host: str, allowed: set[str]) -> str:
    """Allowlisted host that does not resolve to loopback/private/link-local space."""
    name = (host or "").lower().rstrip(".")
    if name not in allowed:
        raise AcquisitionError(f"refusing to fetch from '{name}'")
    try:
        infos = socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise AcquisitionError(f"cannot resolve '{name}'")
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved:
            raise AcquisitionError(f"refusing non-public address for '{name}'")
    return name


def _read_bounded(resp, limit: int, deadline: float) -> bytes:
    out = bytearray()
    while True:
        if time.monotonic() > deadline:
            raise AcquisitionError("acquisition timed out")
        chunk = resp.read(min(65536, limit - len(out) + 1))
        if not chunk:
            break
        out += chunk
        if len(out) > limit:
            raise AcquisitionError(
                f"download exceeds the {limit // 1048576} MiB limit for repository archives")
    return bytes(out)


def fetch_bytes(url: str, policy: AcquisitionPolicy, deadline: float,
                allowed_hosts: set[str] | None = None) -> tuple[bytes, str]:
    """GET an allowlisted URL with validated redirects. Returns (body, final_url)."""
    allowed = allowed_hosts or FETCH_HOSTS
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(current)
        if parts.scheme != "https":
            raise AcquisitionError("refusing non-https fetch during acquisition")
        _assert_routable_host(parts.hostname or "", allowed)
        req = Request(current, headers={"User-Agent": USER_AGENT,
                                        "Accept": "application/x-gzip, application/json"})
        try:
            with urlopen(req, timeout=policy.connect_timeout_s) as resp:  # noqa: S310 (allowlisted)
                status = getattr(resp, "status", 200)
                if status in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if not location:
                        raise AcquisitionError("empty redirect during acquisition")
                    if location.startswith("/"):
                        location = f"https://{parts.hostname}{location}"
                    current = location
                    continue
                if status == 404:
                    raise AcquisitionError("repository or ref not found (404)")
                if status == 403:
                    raise AcquisitionError("access refused (403): private or rate-limited repository")
                if status == 429:
                    raise AcquisitionError("GitHub rate limit reached (429); retry later")
                if status != 200:
                    raise AcquisitionError(f"GitHub fetch failed (HTTP {status})")
                return _read_bounded(resp, policy.max_download_bytes, deadline), resp.url
        except AcquisitionError:
            raise
        except OSError as exc:
            raise AcquisitionError(f"network failure during acquisition: {type(exc).__name__}")
    raise AcquisitionError("too many redirects during acquisition")


def api_json(path: str, policy: AcquisitionPolicy, deadline: float) -> dict:
    """Best-effort GitHub API read. Raises AcquisitionError when unavailable."""
    body, _ = fetch_bytes(f"https://{API_HOST}{path}", policy, deadline, {API_HOST})
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise AcquisitionError("GitHub API returned an unreadable response")
    if not isinstance(data, dict):
        raise AcquisitionError("GitHub API returned an unexpected response")
    return data


def resolve_ref(owner: str, repo: str, ref: str | None, ref_kind: str | None,
                policy: AcquisitionPolicy, deadline: float) -> dict:
    """Resolve requested ref -> {resolved_ref, ref_kind, sha?, default_branch, visibility, via}."""
    if ref_kind == "commit":
        return {"requested_ref": ref, "ref_kind": "commit", "sha": (ref or "").lower(),
                "default_branch": "", "visibility": "public (unverified)",
                "via": "explicit-sha"}
    if ref:
        # Try the API for an exact answer; fall back to archive probing at fetch time.
        sha = _commit_sha(owner, repo, ref, policy, deadline)
        if sha:
            return {"requested_ref": ref, "ref_kind": ref_kind or "branch",
                    "sha": sha, "default_branch": "", "visibility": "public",
                    "via": "api"}
        return {"requested_ref": ref, "ref_kind": ref_kind or "branch", "sha": "",
                "default_branch": "", "visibility": "public (unverified)",
                "via": "archive-probe"}
    # No ref: default branch via API (plus its SHA), else main→master probing.
    try:
        data = api_json(f"/repos/{quote(owner)}/{quote(repo)}", policy, deadline)
        default = str(data.get("default_branch", "") or "")
        visibility = "private" if data.get("private") else "public"
        if visibility == "private":
            raise AcquisitionError("private repositories are not supported in V1")
        if default:
            sha = _commit_sha(owner, repo, default, policy, deadline)
            if sha:
                return {"requested_ref": default, "ref_kind": "branch", "sha": sha,
                        "default_branch": default, "visibility": visibility, "via": "api"}
    except AcquisitionError as exc:
        if "private" in str(exc):
            raise
    return {"requested_ref": "", "ref_kind": "branch", "sha": "",
            "default_branch": "", "visibility": "public (unverified)",
            "via": "default-probe"}


def _commit_sha(owner: str, repo: str, ref: str, policy: AcquisitionPolicy,
                deadline: float) -> str:
    """Branch/tag -> 40-hex SHA via the API, or '' when unavailable."""
    try:
        data = api_json(f"/repos/{quote(owner)}/{quote(repo)}/commits/{quote(ref, safe='')}",
                        policy, deadline)
    except AcquisitionError:
        return ""
    sha = str(data.get("sha", "")).lower()
    if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
        return sha
    return ""


def candidate_archives(owner: str, repo: str, resolved: dict) -> list[str]:
    """Codeload URLs to try in order (first 200 wins)."""
    base = f"https://{CODELOAD_HOST}/{quote(owner)}/{quote(repo)}/tar.gz"
    sha = resolved.get("sha", "")
    if resolved.get("via") == "explicit-sha" and sha:
        return [f"{base}/{sha}"]
    ref = resolved.get("requested_ref") or ""
    if ref and resolved.get("via") == "api" and sha:
        return [f"{base}/{sha}"]
    if ref:
        quoted = quote(ref, safe="/")
        return [f"{base}/{quoted}", f"{base}/refs/heads/{quoted}", f"{base}/refs/tags/{quoted}"]
    return [f"{base}/refs/heads/main", f"{base}/refs/heads/master"]


def _check_member(name: str) -> str:
    if not name or len(name) > MAX_PATH_CHARS:
        raise AcquisitionError("archive has an overlong or empty path")
    if name.startswith(("/", "\\")) or "\x00" in name:
        raise AcquisitionError("archive has an unsafe absolute path")
    parts = name.replace("\\", "/").split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise AcquisitionError("archive has a path-traversal member")
    return name


def extract_archive(body: bytes, dest: Path, policy: AcquisitionPolicy) -> str:
    """Extract a tar.gz into dest. Returns the top-level directory name.

    Rejects traversal, absolute paths, device nodes, and all symlinks/hardlinks
    (scanners skip symlinks; silently re-creating link structure is riskier than
    dropping it). Aborts — never truncates — on any limit breach.
    """
    try:
        tar = tarfile.open(fileobj=io.BytesIO(body), mode="r:gz")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise AcquisitionError(f"archive is malformed: {type(exc).__name__}")
    with tar:
        members = tar.getmembers()
        if len(members) > policy.max_files:
            raise AcquisitionError(
                f"archive has too many files ({len(members)} > {policy.max_files})")
        total = 0
        tops: set[str] = set()
        for member in members:
            _check_member(member.name)
            tops.add(member.name.replace("\\", "/").split("/")[0])
            if member.issym() or member.islnk():
                continue  # dropped, counted below as skipped
            if not member.isfile():
                if member.isdir():
                    continue
                raise AcquisitionError(f"archive has an unsafe member: {member.name[:128]}")
            total += member.size
            if member.size > MAX_SINGLE_FILE_BYTES:
                raise AcquisitionError(f"archive member too large: {member.name[:128]}")
        if total > policy.max_extracted_bytes:
            raise AcquisitionError(
                f"archive extracts too much ({total // 1048576} MiB > "
                f"{policy.max_extracted_bytes // 1048576} MiB)")
        if not tops or len(tops) != 1:
            raise AcquisitionError("archive must contain exactly one top-level directory")
        skipped = 0
        for member in members:
            if member.issym() or member.islnk() or not member.isfile():
                if member.issym() or member.islnk():
                    skipped += 1
                continue
            target = dest / member.name
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src, open(target, "wb") as fh:
                    shutil.copyfileobj(src, fh, length=65536)
            except OSError as exc:
                raise AcquisitionError(f"extraction failed: {type(exc).__name__}")
        # Defense in depth: no symlinks may exist in the workspace, period.
        for path in sorted(dest.rglob("*")):
            if path.is_symlink():
                path.unlink()
                skipped += 1
        return next(iter(tops)), skipped


@contextmanager
def isolated_workspace():
    """Unique temp dir outside the project tree, always cleaned up."""
    dest = Path(tempfile.mkdtemp(prefix="ecdat-src-"))
    try:
        yield dest
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def topdir_sha(topdir: str, repo: str) -> str:
    """GitHub names SHA-download tarball roots <repo>-<40-hex-sha>.

    Branch/tag downloads are rooted <repo>-<ref> instead and carry no SHA —
    callers must resolve those through the API first.
    """
    prefix = f"{repo}-"
    if not topdir.startswith(prefix):
        return ""
    sha = topdir[len(prefix):].lower()
    if len(sha) == 40 and all(c in "0123456789abcdef" for c in sha):
        return sha
    return ""
