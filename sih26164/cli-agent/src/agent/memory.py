"""Memory abstraction: MemoryProvider -> ObsidianVaultProvider (Markdown files only).

Vault content is UNTRUSTED DATA: it is read as text and never executed.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path

KV_NOTE = Path("00-Inbox/KV Store.md")
KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_NOTE_BYTES = 1_000_000


class MemoryProvider(ABC):
    @abstractmethod
    def initialize(self) -> None: ...
    @abstractmethod
    def search(self, query: str, top_n: int = 5) -> list[tuple[str, str]]: ...
    @abstractmethod
    def read(self, relpath: str) -> str: ...
    @abstractmethod
    def write(self, relpath: str, content: str) -> str: ...
    @abstractmethod
    def update(self, relpath: str, content: str) -> str: ...
    @abstractmethod
    def list(self, subdir: str = "") -> list[str]: ...
    @abstractmethod
    def link(self, src: str, dst: str) -> str: ...


class ObsidianVaultProvider(MemoryProvider):
    """All state lives in .md files under the vault root. No cache, no DB."""

    def __init__(self, vault: str | Path) -> None:
        self.vault = Path(vault).expanduser().resolve()

    # -- internals ---------------------------------------------------------
    def _resolve(self, relpath: str) -> Path:
        raw = relpath.strip()
        if not raw or raw.startswith("/") or raw.startswith(".") or ".." in Path(raw).parts:
            raise ValueError(f"unsafe note path: {relpath!r}")
        rel = raw.strip("/")
        if not rel or ".." in Path(rel).parts:
            raise ValueError(f"unsafe note path: {relpath!r}")
        if not rel.endswith(".md"):
            rel += ".md"
        target = (self.vault / rel).resolve()
        if target != self.vault and self.vault not in target.parents:
            raise ValueError(f"path escapes vault: {relpath!r}")
        return target

    def _all_md(self) -> list[Path]:
        if not self.vault.is_dir():
            return []
        return sorted(self.vault.rglob("*.md"))

    # -- API ---------------------------------------------------------------
    def initialize(self) -> None:
        for sub in ("00-Inbox", "01-Project", "02-Architecture", "03-Decisions",
                    "04-Agents", "05-Tasks", "06-Research", "07-Sessions", "08-Reference"):
            (self.vault / sub).mkdir(parents=True, exist_ok=True)

    def search(self, query: str, top_n: int = 5) -> list[tuple[str, str]]:
        terms = [t.lower() for t in query.split() if t.strip()]
        scored: list[tuple[int, str, str]] = []
        for fp in self._all_md():
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(fp.relative_to(self.vault))
            low = text.lower()
            score = sum(3 for t in terms if t in rel.lower()) + sum(low.count(t) for t in terms)
            if score > 0:
                snippet = next((ln.strip()[:160] for ln in text.splitlines()
                                if any(t in ln.lower() for t in terms)), "")
                scored.append((score, rel, snippet))
        scored.sort(reverse=True)
        return [(rel, snip) for _, rel, snip in scored[: max(1, top_n)]]

    def read(self, relpath: str) -> str:
        try:
            return self._resolve(relpath).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return self._resolve(relpath).read_text(encoding="utf-8", errors="replace")

    def write(self, relpath: str, content: str) -> str:
        if len(content.encode("utf-8")) > MAX_NOTE_BYTES:
            raise ValueError("note too large")
        target = self._resolve(relpath)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return str(target.relative_to(self.vault))

    def update(self, relpath: str, content: str) -> str:
        target = self._resolve(relpath)
        if not target.exists():
            raise FileNotFoundError(f"note does not exist: {relpath!r} (use write to create)")
        return self.write(relpath, content)

    def list(self, subdir: str = "") -> list[str]:
        if not subdir:
            base = self.vault
        else:
            raw = subdir.strip()
            if not raw or raw.startswith("/") or raw.startswith(".") or ".." in Path(raw).parts:
                raise ValueError(f"unsafe note dir: {subdir!r}")
            base = ((self.vault / raw.strip("/")).resolve())
            if base != self.vault and self.vault not in base.parents:
                raise ValueError(f"dir escapes vault: {subdir!r}")
        if not base.is_dir():
            return []
        return sorted(str(p.relative_to(self.vault)) for p in base.rglob("*.md"))

    def link(self, src: str, dst: str) -> str:
        body = self.read(src)
        tag = dst if dst.startswith("[[") else f"[[{dst}]]"
        if tag not in body:
            body = body.rstrip() + f"\n\n{tag}\n"
            self.write(src, body)
        return tag

    # -- dotted-key convenience, backed by a single Markdown note -----------
    def kv_set(self, key: str, value: str) -> str:
        if not KEY_RE.match(key):
            raise ValueError(f"bad key: {key!r}")
        if "\n" in value or len(value) > 4000:
            raise ValueError("value must be a single line <= 4000 chars")
        store = self._resolve(str(KV_NOTE))
        pairs: dict[str, str] = {}
        if store.exists():
            for line in store.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    pairs[k.strip()] = v.strip()
        pairs[key] = value.strip()
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text("# KV Store (dotted keys — one per line)\n\n" + "".join(
            f"{k} = {v}\n" for k, v in sorted(pairs.items())), encoding="utf-8")
        return key

    def kv_get(self, key: str) -> str:
        store = self._resolve(str(KV_NOTE))
        if store.exists():
            for line in store.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    if k.strip() == key:
                        return v.strip()
        raise KeyError(key)
