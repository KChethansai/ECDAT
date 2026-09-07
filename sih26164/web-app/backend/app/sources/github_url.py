"""Strict GitHub repository URL parsing. Public repos only, no credentials, no tricks."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

GITHUB_HOSTS = {"github.com", "www.github.com"}
_NAME_RE = re.compile(r"[A-Za-z0-9_.-]+")
_SHA_RE = re.compile(r"[0-9a-f]{40}")


def parse_github_url(raw_url: str) -> dict:
    """Parse a GitHub repo URL into {host, owner, repo, ref, ref_kind, canonical_url}.

    Accepts root URLs plus /tree/<ref>, /commit/<sha>, /releases/tag/<tag>.
    Raises ValueError with a safe, actionable message otherwise.
    """
    if not isinstance(raw_url, str) or not raw_url or len(raw_url) > 1024:
        raise ValueError("repository URL must be a non-empty string under 1024 chars")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_url):
        raise ValueError("repository URL contains control characters")
    try:
        parts = urlsplit(raw_url.strip())
    except ValueError:
        raise ValueError("repository URL is not parseable")
    if parts.scheme != "https":
        raise ValueError("only https GitHub URLs are accepted")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise ValueError("URLs with credentials are never accepted")
    host = (parts.hostname or "").lower().rstrip(".")
    if host not in GITHUB_HOSTS:
        raise ValueError("only github.com repository URLs are accepted")
    try:
        port = parts.port
    except ValueError:
        raise ValueError("URL port is invalid")
    if port is not None and port != 443:
        raise ValueError("explicit ports are not accepted in repository URLs")
    segments = [s for s in parts.path.split("/") if s and s != "."]
    if ".." in parts.path.split("/") or len(segments) < 2:
        raise ValueError("URL must look like https://github.com/owner/repository")
    owner, repo = segments[0], segments[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    for label, value in (("owner", owner), ("repository", repo)):
        if not value or not _NAME_RE.fullmatch(value) or value in (".", ".."):
            raise ValueError(f"invalid GitHub {label} name")
    if owner.lower() in ("login", "join", "pricing", "features", "marketplace",
                         "settings", "notifications", "explore", "topics"):
        raise ValueError("that path is a github.com feature page, not a repository")
    ref, ref_kind = None, None
    rest = segments[2:]
    if rest:
        head = rest[0].lower()
        if head == "tree" and len(rest) >= 2:
            ref, ref_kind = "/".join(rest[1:]), "branch"
        elif head == "commit" and len(rest) == 2:
            ref, ref_kind = rest[1], "commit"
        elif head == "releases" and len(rest) == 3 and rest[1].lower() == "tag":
            ref, ref_kind = rest[2], "tag"
        elif head in ("archive", "blob", "raw", "pull", "issues", "actions", "wiki"):
            raise ValueError(f"github.com/{head}/… URLs are not repository sources")
        else:
            raise ValueError("unsupported GitHub URL form (use the repository root, "
                             "/tree/<branch>, /commit/<sha>, or /releases/tag/<tag>)")
        if not ref or len(ref) > 256 or ".." in ref or ref.startswith(("/", ".")):
            raise ValueError("invalid ref in repository URL")
        if ref_kind == "commit" and not _SHA_RE.fullmatch(ref.lower()):
            raise ValueError("commit URLs need the full 40-character SHA")
    return {"host": "github.com", "owner": owner, "repo": repo,
            "ref": ref, "ref_kind": ref_kind,
            "canonical_url": f"https://github.com/{owner}/{repo}"}
