"""Route-drift guard: backend/app/main.py <-> frontend/src/lib/api.js must agree.

Parses @app.<method>("/...") declarations from main.py and every apiFetch
path from api.js, then fails with an explicit diff when a backend route has
no frontend counterpart or vice versa. Runs in the normal pytest suite, so
drift breaks the build instead of 404ing at runtime.

Path params are shape-compared ({rid} == ${...} == {x}); query strings are
stripped (/triage?scope=.. is still the /triage route).
"""

from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve()
MAIN_PY = HERE.parent.parent / "app" / "main.py"
API_JS = HERE.parent.parent.parent / "frontend" / "src" / "lib" / "api.js"

# Backend routes with deliberately no frontend caller (internal/debug only).
# Empty today: every route is UI-reachable. Add a "METHOD /path" entry here
# instead of deleting this test when a backend-only route appears.
BACKEND_ONLY_ROUTES = frozenset()


def backend_routes() -> set[str]:
    src = MAIN_PY.read_text()
    found = set()
    for method, path in re.findall(r'@app\.(get|post|put|delete|patch|options|head)\(\s*"([^"]+)"', src):
        shape = re.sub(r"\{[^}]+\}", "{x}", path)
        found.add(f"{method.upper()} {shape}")
    return found


def _call_span(src: str, open_idx: int) -> int:
    """End index of the paren-balanced call starting at open_idx (the `(`)."""
    depth = 0
    in_str: str | None = None
    i = open_idx
    while i < len(src):
        ch = src[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        elif ch in "\"'`":
            in_str = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(src)


def frontend_routes() -> set[str]:
    src = API_JS.read_text()
    found = set()
    # Every /path-like literal inside an apiFetch(...) call span counts, so
    # conditional URLs (e.g. listTriage's scope ? `/triage?scope=..` : "/triage")
    # are covered too. Method comes from the same call (default GET).
    for match in re.finditer(r"apiFetch\s*\(", src):
        open_idx = match.end() - 1
        span = src[match.start():_call_span(src, open_idx)]
        method = re.search(r'method:\s*"([A-Z]+)"', span)
        http = method.group(1) if method else "GET"
        for lit in re.findall(r"[`\"'](/[a-z][^`\"']*)[`\"']", span):
            raw = lit.split("?")[0].split("#")[0]
            shape = re.sub(r"\$\{[^}]+\}", "{x}", raw)
            shape = re.sub(r"\{[^}]+\}", "{x}", shape)
            found.add(f"{http} {shape}")
    return found


def test_route_inventory_in_sync():
    assert MAIN_PY.is_file(), f"backend main not found at {MAIN_PY}"
    assert API_JS.is_file(), f"frontend api layer not found at {API_JS}"
    backend = backend_routes()
    assert len(backend) >= 15, f"expected the full ECDAT inventory, parsed only {sorted(backend)}"
    frontend = frontend_routes()
    missing_frontend = {r for r in backend - frontend if r not in BACKEND_ONLY_ROUTES}
    # A frontend path is covered when its METHOD + shape equals a backend route.
    missing_backend = {r for r in frontend if r not in backend}
    problems = []
    if missing_frontend:
        problems.append("backend routes with no api.js caller:\n  " + "\n  ".join(sorted(missing_frontend)))
    if missing_backend:
        problems.append("api.js paths with no backend route:\n  " + "\n  ".join(sorted(missing_backend)))
    assert not problems, (
        "frontend/backend route drift detected (sync main.py, api.js, "
        "vite.config.js proxy, README):\n" + "\n".join(problems)
    )
