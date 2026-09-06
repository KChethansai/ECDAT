"""Provider-neutral adapter layer. Only real subprocess execution; no fabricated APIs.

`run` executes the provider's own binary with caller-supplied args (passed after `--`
on the CLI). With no args it reports the prepared context and exits non-zero with
an honest "not enough info" message instead of faking a provider call.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from . import registry

ALLOWLIST = {"codex", "claude", "cursor-agent", "agent", "agy", "gemini"}

# Documented example invocations (verify against provider docs; not executed blindly).
EXAMPLES = {
    "codex": "codex exec - < prompt.txt",
    "claude": "claude -p \"$(cat prompt.txt)\"",
    "cursor": "cursor-agent < prompt.txt   # verify flags with `cursor-agent --help`",
    "antigravity": "agy < prompt.txt   # verify flags with `agy --help`",
}


class AgentAdapter(ABC):
    name: str

    @abstractmethod
    def discover(self) -> dict: ...
    @abstractmethod
    def status(self) -> dict: ...
    @abstractmethod
    def run(self, task: str, context: str, provider_args: list[str]) -> dict: ...


class SubprocessAdapter(AgentAdapter):
    def __init__(self, name: str, registry_path: Path | None = None) -> None:
        self.name = name
        self._reg = registry_path

    def discover(self) -> dict:
        return registry.get(self.name, self._reg)

    def status(self) -> dict:
        info = self.discover()
        return {"name": info["name"], "available": info["available"],
                "resolved": info.get("resolved"), "capabilities": info.get("capabilities", [])}

    def run(self, task: str, context: str, provider_args: list[str]) -> dict:
        info = self.discover()
        if not info["available"]:
            return {"ok": False, "error": f"agent '{self.name}' not installed ({info['command']})"}
        exe = Path(str(info["resolved"])).name
        if exe not in ALLOWLIST:
            return {"ok": False, "error": f"executable {exe!r} not in allowlist"}
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                          prefix="ecdat-prompt-") as fh:
            fh.write(f"# Task\n{task}\n\n# Vault context\n{context}\n")
            prompt_file = fh.name
        env = dict(os.environ, ECDAT_CONTEXT_FILE=prompt_file)
        if not provider_args:
            return {"ok": False, "prompt_file": prompt_file,
                    "error": ("no provider args given; pass the provider's own CLI args after `--`. "
                              f"Example: agent run --agent {self.name} -- {EXAMPLES.get(self.name, '--help')}")}
        try:
            proc = subprocess.run([str(info["resolved"]), *provider_args], capture_output=True,
                                  text=True, timeout=300, shell=False, env=env)  # noqa: S603 (allowlisted)
        except subprocess.TimeoutExpired:
            return {"ok": False, "prompt_file": prompt_file, "error": "provider timed out (300s)"}
        if proc.returncode == 0:
            Path(prompt_file).unlink(missing_ok=True)  # context served its purpose; don't hoard vault text in /tmp
            prompt_file = ""
        return {"ok": proc.returncode == 0, "returncode": proc.returncode,
                "stdout": proc.stdout[-6000:], "stderr": proc.stderr[-2000:],
                "prompt_file": prompt_file}
