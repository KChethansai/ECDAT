"""Deterministic codebase relationship graphs (stdlib only, offline, no AI).

ONE unified model (nodes + relationships with evidence/confidence) built from
existing ECDAT analysis — shared AST parses via code_analysis.symbols, crypto
data from scan reports. Three projections derive from the same model:

- component graph  (broad connectivity)
- relationship/blast-radius graph (per-finding context for planning)
- Obsidian Canvas JSON (curated human overview) + linked Markdown notes

Node IDs are `type:path#symbol` (stable); relationship IDs are
`sha1(src|type|dst)[:12]` (stable). Timestamps never enter IDs.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from pathlib import Path

from .code_analysis.scope import CONFIG_NAMES, iter_files
from .code_analysis.structure import ENTRY_FILES
from .code_analysis.symbols import ModuleInfo, build_graph, cross_references

SCHEMA_VERSION = 1
LIMITS = {"nodes": 800, "relationships": 3000, "notes": 60,
          "canvas_nodes": 60, "edges_per_node": 25, "depth": 6}

# Confidence ladder: HIGH = direct evidence; MEDIUM = strong structural
# inference; LOW = never shown as fact (omitted from projections).
HIGH, MEDIUM = "HIGH", "MEDIUM"

# Python route decorators: @app.get("/x") / @router.post('/y').
ROUTE_RE = re.compile(
    r"""@[\w.]+\.(get|post|put|delete|patch|head|options)\(\s*['"]([^'"]+)['"]""")
# Secret-looking assignments are never stored in graph metadata.
SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|password|passwd|secret|token|private[_-]?key)\b\s*[:=]")


def _rel_id(src: str, rtype: str, dst: str) -> str:
    return "r" + hashlib.sha256(f"{src}|{rtype}|{dst}".encode()).hexdigest()[:11]


def _nid(ntype: str, path: str, name: str = "") -> str:
    base = f"{ntype}:{path}" + (f"#{name}" if name else "")
    return base


def _node(nid: str, ntype: str, label: str, path: str, scan_id: str,
          **meta) -> dict:
    node = {"id": nid, "type": ntype, "label": label, "path": path,
            "scan_id": scan_id, "confidence": meta.pop("confidence", HIGH)}
    node["metadata"] = meta
    return node


def _rel(src: str, rtype: str, dst: str, evidence: str,
         confidence: str = HIGH, **meta) -> dict:
    rel = {"id": _rel_id(src, rtype, dst), "source": src, "target": dst,
           "type": rtype, "evidence": evidence, "confidence": confidence}
    rel["metadata"] = meta
    return rel


def _redact_evidence(text: str) -> str:
    if SECRET_RE.search(text):
        return "[REDACTED: sensitive content omitted]"
    return text[:300]


# -- context --------------------------------------------------------------------

class Context:
    """Unified relationship model for one analyzed root."""

    def __init__(self, root: str, scan_id: str = "", source: str = "local",
                 commit: str = "", branch: str = "") -> None:
        self.root = root
        self.scan_id = scan_id
        self.source = source
        self.commit = commit
        self.branch = branch
        self.nodes: dict[str, dict] = {}
        self.relationships: list[dict] = []
        self._rel_keys: set[str] = set()
        self.truncation: dict = {}
        self.generated_at: str = ""

    def add_node(self, node: dict) -> dict:
        return self.nodes.setdefault(node["id"], node)

    def add_rel(self, rel: dict) -> None:
        if rel["id"] in self._rel_keys:
            return
        if len(self.relationships) >= LIMITS["relationships"]:
            self.truncation["relationships_omitted"] = \
                self.truncation.get("relationships_omitted", 0) + 1
            return
        self._rel_keys.add(rel["id"])
        self.relationships.append(rel)

    def by_type(self, ntype: str) -> list[dict]:
        return sorted((n for n in self.nodes.values() if n["type"] == ntype),
                      key=lambda n: n["id"])

    def out_edges(self, nid: str) -> list[dict]:
        return sorted((r for r in self.relationships if r["source"] == nid),
                      key=lambda r: (r["type"], r["target"]))

    def in_edges(self, nid: str) -> list[dict]:
        return sorted((r for r in self.relationships if r["target"] == nid),
                      key=lambda r: (r["type"], r["source"]))

    def to_dict(self) -> dict:
        return {"schema_version": SCHEMA_VERSION, "root": self.root,
                "scan_id": self.scan_id, "source": self.source,
                "commit": self.commit, "branch": self.branch,
                "generated_at": self.generated_at,
                "nodes": [self.nodes[k] for k in sorted(self.nodes)],
                "relationships": sorted(self.relationships,
                                        key=lambda r: (r["source"], r["type"], r["target"])),
                "truncation": self.truncation}


def _resolve_import(mod_rel: str, source: str,
                    modules: dict[str, ModuleInfo]) -> str:
    """Map an import source to a repo-relative module path (or '')."""
    if not source:
        return ""
    level = len(source) - len(source.lstrip("."))
    dotted = source.lstrip(".")
    if level:
        # relative: walk up (level-1) packages from the importing module
        parts = mod_rel.split("/")[:-1]
        base = parts[:max(0, len(parts) - level + 1)]
        dotted_path = "/".join(base + dotted.split(".")) if dotted else "/".join(base)
        candidates = [dotted_path + ".py", dotted_path + "/__init__.py"]
        for cand in candidates:
            if cand in modules:
                return cand
        return ""
    stem = dotted.split(".")[0]
    if not stem or stem in ("os", "sys", "re", "json", "pathlib", "typing",
                            "hashlib", "time", "datetime", "collections",
                            "itertools", "functools", "io", "ast", "abc"):
        return ""
    base = Path(mod_rel).parent
    candidates = [str((base / (source.replace(".", "/") + ".py")).as_posix()),
                  f"{source.replace('.', '/')}.py", f"{stem}.py"]
    by_stem = {Path(rel).stem: rel for rel in modules}
    for cand in candidates:
        if cand in modules:
            return cand
    if stem in by_stem and by_stem[stem] != mod_rel:
        return by_stem[stem]
    return ""


def build_context(root: str | Path, scan_id: str = "", source: str = "local",
                  commit: str = "", branch: str = "",
                  report: dict | None = None) -> Context:
    """Build the unified model. Reuses the shared symbol parse (no re-parse)."""
    root_path = Path(root).resolve()
    ctx = Context(str(root_path), scan_id, source, commit, branch)
    files = iter_files(root_path)
    modules = build_graph(root_path, files)  # one shared parse
    refs = cross_references(modules)
    defined_in: dict[str, str] = {}
    for rel, mod in modules.items():
        for name in mod.defs:
            defined_in.setdefault(name, rel)

    ctx.add_node(_node("repo:", "REPOSITORY", root_path.name, "", scan_id))
    subsystems: dict[str, str] = {}
    for rel in sorted(modules):
        top = rel.split("/")[0] if "/" in rel else "(root)"
        if top not in subsystems:
            sid = _nid("subsystem", top)
            subsystems[top] = sid
            ctx.add_node(_node(sid, "SUBSYSTEM", top, top, scan_id))
            ctx.add_rel(_rel("repo:", "CONTAINS", sid,
                             f"top-level directory {top}", HIGH))
        # directories + file
        parts = Path(rel).parts[:-1]
        parent = "repo:"
        acc = ""
        for part in parts:
            acc = f"{acc}/{part}" if acc else part
            did = _nid("directory", acc)
            if did not in ctx.nodes:
                ctx.add_node(_node(did, "DIRECTORY", part, acc, scan_id))
                ctx.add_rel(_rel(parent, "CONTAINS", did,
                                 f"directory {acc}", HIGH))
            parent = did
        fid = _nid("file", rel)
        ctx.add_node(_node(fid, "FILE", Path(rel).name, rel, scan_id,
                           language=modules[rel].language,
                           content_sha=_content_sha(modules[rel].path)))
        ctx.add_rel(_rel(parent, "CONTAINS", fid, f"file {rel}", HIGH))
        ctx.add_rel(_rel(fid, "BELONGS_TO", subsystems[top],
                         f"{rel} lives under {top}", HIGH))
        mod = modules[rel]
        # symbols
        for name in sorted(mod.defs):
            kind = str(mod.defs[name].get("kind", "function")).upper()
            ntype = {"CLASS": "CLASS", "FUNCTION": "FUNCTION",
                     "METHOD": "METHOD"}.get(kind, "FUNCTION")
            sid = _nid("symbol", rel, name)
            ctx.add_node(_node(sid, ntype, name, rel, scan_id,
                               lineno=mod.defs[name].get("lineno", 0)))
            ctx.add_rel(_rel(fid, "CONTAINS", sid, f"{rel} defines {name}", HIGH))
        # imports (HIGH: direct statement; target resolved or external note)
        for local, info in sorted(mod.imports.items()):
            target = _resolve_import(rel, str(info.get("source", "")), modules)
            ev = _redact_evidence(f"{rel}:{info.get('lineno', 0)} imports "
                                  f"{info.get('source', '')}")
            if target:
                ctx.add_rel(_rel(fid, "IMPORTS", _nid("file", target), ev, HIGH))
            # unresolved/external imports carry no edge (no invented links)
        # entry points
        if mod.path.name in ENTRY_FILES and (mod.has_main_guard or
                                             mod.path.name == "__main__.py"):
            eid = _nid("entry", rel)
            ctx.add_node(_node(eid, "ENTRY_POINT",
                               f"entry:{Path(rel).name}", rel, scan_id))
            ctx.add_rel(_rel(fid, "EXPOSES", eid,
                             f"{rel} is an executable entry point", HIGH))
            ctx.add_rel(_rel(eid, "ENTRY_POINT_FOR", "repo:",
                             f"{rel} starts the application", HIGH))
        # config referenced by filename in strings (MEDIUM, real evidence)
        for cfg in sorted(CONFIG_NAMES):
            if any(cfg in s for s in mod.strings):
                cid = _nid("config", cfg)
                if cid not in ctx.nodes:
                    ctx.add_node(_node(cid, "CONFIGURATION", cfg, cfg, scan_id))
                ctx.add_rel(_rel(_nid("file", rel), "CONFIGURED_BY", cid,
                                 _redact_evidence(
                                     f"{rel} references {cfg} in a string literal"),
                                 MEDIUM))
        # API routes from decorators (python only, MEDIUM)
        if mod.language == "python":
            text = _module_text(mod)
            for verb, route in sorted(set(ROUTE_RE.findall(text or ""))):
                aid = _nid("api", f"{verb.upper()} {route}")
                if aid not in ctx.nodes:
                    ctx.add_node(_node(aid, "API_ENDPOINT",
                                       f"{verb.upper()} {route}", rel, scan_id))
                ctx.add_rel(_rel(_nid("file", rel), "EXPOSES", aid,
                                 f"{rel} declares {verb.upper()} {route}", MEDIUM))
    # symbol references across files: file-level CALLS edges (HIGH when the
    # referenced module is also directly imported, else MEDIUM inference).
    for rel in sorted(modules):
        mod = modules[rel]
        imported_targets = {_resolve_import(rel, str(i.get("source", "")), modules)
                            for i in mod.imports.values()}
        for name in sorted(mod.names_used):
            target_rel = defined_in.get(name)
            if not target_rel or target_rel == rel:
                continue
            src, dst = _nid("file", rel), _nid("file", target_rel)
            if dst not in ctx.nodes:
                continue
            backed = target_rel in imported_targets
            ctx.add_rel(_rel(src, "CALLS", dst, _redact_evidence(
                f"{rel} references {name} defined in {target_rel}"),
                HIGH if backed else MEDIUM))
    # tests: TESTS edges (HIGH when the test imports the module)
    for rel in sorted(modules):
        stem = Path(rel).stem
        if not (stem.startswith("test_") or stem.endswith("_test") or
                stem == "conftest"):
            continue
        mod = modules[rel]
        imported = {_resolve_import(rel, str(i.get("source", "")), modules)
                    for i in mod.imports.values()}
        tested = {t for t in imported if t} | {
            m for m in modules
            if Path(m).stem in {s.strip("_") for s in
                                re.findall(r"[A-Za-z_]\w+", " ".join(mod.strings))}
            and m != rel}
        for target in sorted(tested):
            ctx.add_rel(_rel(_nid("file", rel), "TESTS", _nid("file", target),
                             _redact_evidence(
                                 f"{rel} exercises {target}"), HIGH
                             if target in imported else MEDIUM))
    if report:
        attach_report(ctx, report)
    ctx.generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return ctx


def _content_sha(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()[:16]
    except OSError:
        return ""


def _module_text(mod: ModuleInfo) -> str:
    try:
        return mod.path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def attach_report(ctx: Context, report: dict) -> None:
    """Link crypto/code findings as nodes (no new scanning)."""
    try:
        root = Path(ctx.root).resolve()
    except OSError:
        root = None

    def _relpath(fpath: str) -> str:
        if not fpath:
            return fpath
        try:
            abs_guess = (root / fpath).resolve() if root else None
            cand = Path(fpath)
            if cand.is_absolute() and root and (cand == root or root in cand.parents):
                return str(cand.relative_to(root))
            if abs_guess is not None and (abs_guess == root or root in abs_guess.parents):
                return str(abs_guess.relative_to(root))
        except (OSError, ValueError):
            pass
        return fpath

    for row in report.get("components", []) or []:
        if row.get("is_mock"):
            continue
        fpath = _relpath(str(row.get("file_path", "")))
        fid = str(row.get("id", ""))
        if not fid:
            continue
        nid = _nid("finding", fpath, fid)
        ctx.add_node(_node(nid, "CRYPTO_FINDING",
                           f"{row.get('algorithm', '?')} in {Path(fpath).name}",
                           fpath, ctx.scan_id, severity=row.get("severity", ""),
                           algorithm=row.get("algorithm", "")))
        fnode = _nid("file", fpath)
        if fnode in ctx.nodes:
            ctx.add_rel(_rel(fnode, "PRODUCES_FINDING", nid,
                             f"scanner {row.get('scanner', '?')} reported {fid}",
                             HIGH))
        algo = str(row.get("algorithm", ""))
        if algo:
            uid = _nid("crypto", algo)
            if uid not in ctx.nodes:
                ctx.add_node(_node(uid, "CRYPTO_USAGE", algo, fpath, ctx.scan_id))
            if fnode in ctx.nodes:
                ctx.add_rel(_rel(fnode, "USES_CRYPTO", uid,
                                 f"{fpath} uses {algo}", HIGH))
    for row in (report.get("codeAnalysis") or {}).get("findings", []) or []:
        fpath = _relpath(str(row.get("file_path", "")))
        fid = str(row.get("id") or row.get("title", ""))
        if not fid:
            continue
        nid = _nid("codefinding", fpath, fid)
        ctx.add_node(_node(nid, "CODE_FINDING",
                           str(row.get("title", fid))[:80], fpath, ctx.scan_id,
                           category=row.get("category", "")))
        fnode = _nid("file", fpath)
        if fnode in ctx.nodes:
            ctx.add_rel(_rel(fnode, "PRODUCES_FINDING", nid,
                             f"analyzer reported {fid}", HIGH))


# -- blast radius / affected surface ----------------------------------------------

BUCKETS = ("DIRECTLY_AFFECTED", "INDIRECTLY_AFFECTED", "TEST_AFFECTED",
           "CONFIGURATION_AFFECTED", "DEPENDENCY_AFFECTED", "API_AFFECTED",
           "OPTIONAL_REVIEW")


def blast_radius(ctx: Context, finding_id: str, depth: int = 2) -> dict:
    """Focused context for one finding: location, callers, config, tests,
    subsystem, and a classified affected surface with evidence/confidence."""
    target = next((n for n in ctx.nodes.values()
                   if n["type"] in ("CRYPTO_FINDING", "CODE_FINDING") and
                   n["id"].endswith(f"#{finding_id}")), None)
    if target is None:
        return {"finding_id": finding_id, "status": "UNKNOWN",
                "reason": "finding not present in this context"}
    file_nid = next((r["source"] for r in ctx.in_edges(target["id"])
                     if r["type"] == "PRODUCES_FINDING"), None)
    surface: dict[str, list[dict]] = {b: [] for b in BUCKETS}
    seen_files = {file_nid} if file_nid else set()

    def _add(bucket: str, path: str, reason: str, rel: str, conf: str) -> None:
        entry = {"path": path, "reason": reason, "relationship": rel,
                 "confidence": conf}
        if entry not in surface[bucket]:
            surface[bucket].append(entry)

    if file_nid:
        _add("DIRECTLY_AFFECTED", target["path"], "finding location",
             "PRODUCES_FINDING", HIGH)
        for edge in ctx.in_edges(file_nid):
            if edge["type"] in ("CALLS",):
                caller_file = _symbol_file(ctx, edge["source"])
                if caller_file and caller_file not in seen_files:
                    seen_files.add(caller_file)
                    _add("DIRECTLY_AFFECTED", caller_file,
                         f"references code in {target['path']}", "CALLS",
                         edge["confidence"])
        for edge in ctx.out_edges(file_nid):
            t = ctx.nodes.get(edge["target"], {})
            if edge["type"] == "CALLS" and t.get("path") not in seen_files:
                seen_files.add(t.get("path", ""))
                _add("INDIRECTLY_AFFECTED", t.get("path", ""),
                     f"called by {target['path']}", "CALLS", edge["confidence"])
            elif edge["type"] == "IMPORTS" and t.get("path") not in seen_files:
                seen_files.add(t.get("path", ""))
                _add("INDIRECTLY_AFFECTED", t.get("path", ""),
                     f"imported by {target['path']}", "IMPORTS", edge["confidence"])
            elif edge["type"] in ("CONFIGURED_BY",):
                _add("CONFIGURATION_AFFECTED", t.get("path", ""),
                     f"configures {target['path']}", "CONFIGURED_BY",
                     edge["confidence"])
            elif edge["type"] == "EXPOSES" and t.get("type") == "API_ENDPOINT":
                _add("API_AFFECTED", t.get("label", ""),
                     f"API exposed from {target['path']}", "EXPOSES",
                     edge["confidence"])
        for edge in [e for e in ctx.relationships
                     if e["type"] == "TESTS" and (e["target"] == file_nid or
                         _symbol_file(ctx, e["target"]) in seen_files)]:
            tested_path = ctx.nodes.get(edge["target"], {}).get("path",
                                                                edge["target"])
            _add("TEST_AFFECTED", ctx.nodes.get(edge["source"], {}).get("path", ""),
                 f"tests {tested_path}", "TESTS", edge["confidence"])
        subs = [e["target"] for e in ctx.out_edges(file_nid)
                if e["type"] == "BELONGS_TO"]
        for edge in ctx.relationships:
            if (edge["type"] == "BELONGS_TO" and edge["target"] in subs
                    and edge["source"] != file_nid):
                peer = ctx.nodes.get(edge["source"], {}).get("path", "")
                if peer and peer not in seen_files:
                    seen_files.add(peer)
                    _add("OPTIONAL_REVIEW", peer,
                         "same subsystem, no direct link", "BELONGS_TO", MEDIUM)
    surface = {k: sorted(v, key=lambda e: e["path"]) for k, v in surface.items()}
    return {"finding_id": finding_id, "status": "KNOWN",
            "finding": {"id": target["id"], "type": target["type"],
                        "label": target["label"], "path": target["path"],
                        "severity": target["metadata"].get("severity", ""),
                        "category": target["metadata"].get("category", "")},
            "affected_surface": surface}


def _symbol_file(ctx: Context, symbol_nid: str) -> str:
    node = ctx.nodes.get(symbol_nid, {})
    if node.get("type") == "FILE":
        return node.get("path", "")
    for edge in ctx.in_edges(symbol_nid):
        if edge["type"] == "CONTAINS":
            return ctx.nodes.get(edge["source"], {}).get("path", "")
    return ""


# -- component graph projection -----------------------------------------------------

def component_graph(ctx: Context) -> dict:
    """Broad machine-readable connectivity (bounded; truncation recorded)."""
    nodes = [ctx.nodes[k] for k in sorted(ctx.nodes)
             if ctx.nodes[k]["type"] not in ("CLASS", "FUNCTION", "METHOD")]
    capped = len(nodes) > LIMITS["nodes"]
    nodes = nodes[:LIMITS["nodes"]]
    keep = {n["id"] for n in nodes}
    rels = [r for r in ctx.relationships
            if r["source"] in keep and r["target"] in keep
            and r["confidence"] in (HIGH, MEDIUM)]
    by_design = sum(1 for r in ctx.relationships
                    if r not in rels and (r["source"] not in keep or
                                          r["target"] not in keep))
    truncation = dict(ctx.truncation)
    if capped:
        truncation["nodes_capped"] = {"limit": LIMITS["nodes"],
                                      "actual": len(ctx.nodes)}
    return {"scan_id": ctx.scan_id, "root": ctx.root, "source": ctx.source,
            "commit": ctx.commit, "branch": ctx.branch,
            "nodes": nodes, "relationships": rels,
            "counts": {"nodes": len(nodes), "relationships": len(rels)},
            "truncation": {"symbol_edges_excluded_by_design": by_design,
                           **truncation}}


# -- canvas projection ---------------------------------------------------------------

def _canvas_node(node_id: str, x: int, y: int, w: int = 280, h: int = 100,
                 color: str = "") -> dict:
    node: dict = {"id": node_id, "x": x, "y": y, "width": w, "height": h,
                  "type": "text", "text": node_id}
    if color:
        node["color"] = color
    return node


def canvas(ctx: Context, kind: str = "system",
           finding_id: str = "") -> dict:
    """Curated human overview (NOT a graph dump). Deterministic grid layout."""
    if kind not in ("system", "crypto", "migration"):
        raise ValueError(f"unknown canvas kind: {kind}")
    comp = component_graph(ctx)
    by_type: dict[str, list[dict]] = {}
    for node in comp["nodes"]:
        by_type.setdefault(node["type"], []).append(node)
    subsystems = by_type.get("SUBSYSTEM", [])[:8]
    if kind == "crypto":
        core = [n for n in comp["nodes"] if n["type"] in (
            "CRYPTO_USAGE", "CRYPTO_FINDING")]
        degree: dict[str, int] = {}
        for rel in comp["relationships"]:
            if rel["type"] in ("USES_CRYPTO", "PRODUCES_FINDING"):
                degree[rel["source"]] = degree.get(rel["source"], 0) + 1
                degree[rel["target"]] = degree.get(rel["target"], 0) + 1
        core.sort(key=lambda n: (-degree.get(n["id"], 0), n["id"]))
        core = core[:24]
        core_ids = {n["id"] for n in core}
        linked = [n for n in comp["nodes"]
                  if n["type"] == "FILE" and any(
                      (r["source"] == n["id"] and r["target"] in core_ids) or
                      (r["target"] == n["id"] and r["source"] in core_ids)
                      for r in comp["relationships"])][:20]
        wanted = (core + linked + by_type.get("SUBSYSTEM", [])[:4]
                  + by_type.get("CONFIGURATION", [])[:4])[:LIMITS["canvas_nodes"]]
    elif kind == "migration" and finding_id:
        blast = blast_radius(ctx, finding_id)
        paths = {blast["finding"]["path"]} | {
            e["path"] for bucket in blast["affected_surface"].values()
            for e in bucket if e["path"] and not e["path"].startswith(("GET", "POST",
                  "PUT", "DELETE", "PATCH"))} if blast["status"] == "KNOWN" else set()
        wanted = [n for n in comp["nodes"]
                  if n.get("path") in paths][:LIMITS["canvas_nodes"]]
        if blast["status"] != "KNOWN":
            wanted = []
    else:
        if len(subsystems) < 1:
            return {"nodes": [], "edges": [],
                    "note": "INSUFFICIENT EVIDENCE: no subsystems detected"}
        wanted = subsystems[:]
        for sub in subsystems:
            members = [n for n in comp["nodes"]
                       if n["type"] == "FILE" and any(
                           r["source"] == n["id"] and r["target"] == sub["id"]
                           and r["type"] == "BELONGS_TO"
                           for r in comp["relationships"])][:4]
            wanted.extend(members)
        wanted.extend(by_type.get("CRYPTO_FINDING", [])[:6])
        wanted.extend(by_type.get("API_ENDPOINT", [])[:6])
        wanted.extend(by_type.get("CONFIGURATION", [])[:4])
        wanted = wanted[:LIMITS["canvas_nodes"]]
    # deterministic grid: 3 columns, row per band
    nodes, edges = [], []
    seen: set[str] = set()
    for i, node in enumerate(wanted):
        if node["id"] in seen:
            continue
        seen.add(node["id"])
        col, row = i % 3, i // 3
        label = f"{node['label']}\n{node['type']}"
        canvas_node = _canvas_node(node["id"], col * 340, row * 170,
                                   color=_color(node["type"]))
        canvas_node["text"] = label
        # Vault writer rewrites `note` into a [[link|label]] when the
        # corresponding entity note is generated (keeps links resolving).
        canvas_node["note"] = _entity_note_name(ctx.scan_id, node)
        nodes.append(canvas_node)
    ids = {n["id"] for n in nodes}
    for rel in comp["relationships"]:
        if rel["source"] in ids and rel["target"] in ids:
            edges.append({"id": rel["id"], "fromNode": rel["source"],
                          "toNode": rel["target"],
                          "label": rel["type"]})
            if len(edges) >= LIMITS["canvas_nodes"] * 2:
                break
    void = {"nodes": nodes, "edges": sorted(edges, key=lambda e: e["id"])}
    void["metadata"] = {"kind": kind, "scan_id": ctx.scan_id,
                        "commit": ctx.commit, "node_count": len(nodes),
                        "edge_count": len(edges),
                        "truncated": len(wanted) > len(nodes)}
    _validate_canvas(void)
    return void


def _color(ntype: str) -> str:
    return {"SUBSYSTEM": "1", "CRYPTO_FINDING": "4", "CRYPTO_USAGE": "4",
            "API_ENDPOINT": "2", "CONFIGURATION": "5", "FILE": "",
            "CODE_FINDING": "3"}.get(ntype, "")


def _entity_note_name(scan_id: str, node: dict) -> str:
    """Deterministic vault note path for a graph node (scan-scoped)."""
    scope = f"Graphs/{scan_id or 'adhoc'}"
    path = (node.get("path") or node["id"]).strip("/") or "root"
    if node["type"] in ("API_ENDPOINT", "CRYPTO_USAGE"):
        path = f"shared/{node['label'].replace(' ', '_')[:60]}"
    return f"{scope}/entities/{path}.md"
    return {"SUBSYSTEM": "1", "CRYPTO_FINDING": "4", "CRYPTO_USAGE": "4",
            "API_ENDPOINT": "2", "CONFIGURATION": "5", "FILE": "",
            "CODE_FINDING": "3"}.get(ntype, "")


def _validate_canvas(void: dict) -> None:
    ids = {n["id"] for n in void["nodes"]}
    if len(ids) != len(void["nodes"]):
        raise ValueError("canvas has duplicate node ids")
    for edge in void["edges"]:
        if edge["fromNode"] not in ids or edge["toNode"] not in ids:
            raise ValueError("canvas edge references missing node")
    json.dumps(void)  # must be JSON-serializable


# -- delta ----------------------------------------------------------------------------

def diff_graphs(before: dict, after: dict) -> dict:
    """Graph A vs B by stable IDs. Ties to scan IDs carried in payloads."""
    b_nodes = {n["id"]: n for n in before.get("nodes", [])}
    a_nodes = {n["id"]: n for n in after.get("nodes", [])}
    b_rels = {r["id"]: r for r in before.get("relationships", [])}
    a_rels = {r["id"]: r for r in after.get("relationships", [])}
    changed_nodes = sorted(nid for nid in set(b_nodes) & set(a_nodes)
                           if {k: b_nodes[nid].get(k) for k in ("label", "path", "type")}
                           != {k: a_nodes[nid].get(k) for k in ("label", "path", "type")}
                           or b_nodes[nid].get("metadata", {}).get("content_sha")
                           != a_nodes[nid].get("metadata", {}).get("content_sha"))
    changed_rels = sorted(rid for rid in set(b_rels) & set(a_rels)
                          if b_rels[rid].get("confidence") != a_rels[rid].get("confidence"))
    return {"before_scan": before.get("scan_id", ""),
            "after_scan": after.get("scan_id", ""),
            "added_nodes": sorted(set(a_nodes) - set(b_nodes)),
            "removed_nodes": sorted(set(b_nodes) - set(a_nodes)),
            "changed_nodes": changed_nodes,
            "added_relationships": sorted(set(a_rels) - set(b_rels)),
            "removed_relationships": sorted(set(b_rels) - set(a_rels)),
            "changed_relationships": changed_rels}


# -- plan validation -----------------------------------------------------------

def validate_plan(plan: dict, ctx: Context) -> dict:
    """Every plan file must exist in the current context. Stale refs INVALID."""
    missing, present = [], []
    for path in (plan.get("affected_files") or []):
        # Paths may be repo-relative (context form) or absolute (legacy form).
        rel = path
        try:
            abs_guess = (Path(ctx.root) / path).resolve()
            root = Path(ctx.root).resolve()
            if abs_guess == root or root in abs_guess.parents:
                rel = str(abs_guess.relative_to(root))
        except (OSError, ValueError):
            pass
        if _nid("file", rel) in ctx.nodes or _nid("config", Path(rel).name) in ctx.nodes:
            present.append(path)
        else:
            missing.append(path)
    return {"plan_id": plan.get("plan_id", ""), "valid": not missing,
            "present": sorted(present), "missing": sorted(missing),
            "verdict": "PASS" if not missing else "PLAN INVALID"}


# -- health ------------------------------------------------------------------------------


def health(ctx: Context) -> dict:
    """Lightweight checks over the unified model. PASS / observations / FAIL."""
    issues: list[str] = []
    node_ids = [n["id"] for n in ctx.nodes.values()]
    if len(set(node_ids)) != len(node_ids):
        issues.append("duplicate node ids")
    seen_rel, dup_rel = set(), 0
    for rel in ctx.relationships:
        if rel["id"] in seen_rel:
            dup_rel += 1
        seen_rel.add(rel["id"])
        if rel["source"] not in ctx.nodes or rel["target"] not in ctx.nodes:
            issues.append(f"dangling edge {rel['id']}")
            break
    if dup_rel:
        issues.append(f"{dup_rel} duplicate relationships")
    for rel in ctx.relationships:
        if not rel.get("evidence"):
            issues.append(f"edge without evidence: {rel['id']}")
            break
        if rel.get("confidence") not in (HIGH, MEDIUM):
            issues.append(f"edge with bad confidence: {rel['id']}")
            break
    try:
        _validate_canvas(canvas(ctx))
    except ValueError as exc:
        issues.append(f"canvas invalid: {exc}")
    status = "PASS" if not issues else "FAIL"
    return {"status": status, "issues": issues,
            "counts": {"nodes": len(ctx.nodes),
                       "relationships": len(ctx.relationships)}}


# -- vault projection (Obsidian Markdown + Canvas, via project memory) ---------------

GRAPH_ROOT = "Graphs"
MANAGED_MARKER = "managed_by: ECDAT"


def _managed(path: Path) -> bool:
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:600]
    except OSError:
        return False
    return MANAGED_MARKER in head and "generated: true" in head


def _fm(kind: str, title: str, ctx: Context) -> str:
    return (f"---\nproject: ECDAT\ntype: {kind}\nscan_id: {ctx.scan_id}\n"
            f"commit: {ctx.commit}\nbranch: {ctx.branch}\n"
            f"managed_by: ECDAT\ngenerated: true\nmemory_schema_version: 1\n---\n"
            f"# {title}\n")


def slugish(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")[:60]


def to_vault(ctx: Context, vault: str | Path, report: dict | None = None,
             kinds: tuple[str, ...] = ("system",)) -> dict:
    """Write index, component graph, entity notes, canvases, finding contexts.

    Idempotent per scan scope; never overwrites user notes (collision-safe
    rename + recorded). Returns a manifest with counts and collisions.
    """
    from . import project_memory as pm

    vault_path = Path(vault).expanduser().resolve()
    scope = f"{GRAPH_ROOT}/{ctx.scan_id or 'adhoc'}"
    manifest: dict = {"scope": scope, "notes": [], "canvases": [],
                      "collisions": [], "omitted": {}, "finding_contexts": []}

    def _put(relpath: str, content: str) -> str:
        target = pm.safe_join(vault_path, relpath)
        if target.is_file() and not _managed(target):
            alt = relpath[:-3] + "__ecdat.md"
            manifest["collisions"].append({"kept": relpath, "wrote": alt})
            relpath = alt
            return pm.sync_note(vault_path, relpath, content)
        # Same-scope regeneration of an ECDAT-managed derived artifact:
        # overwrite keeps reruns idempotent; history lives in other scopes.
        return pm.sync_note(vault_path, relpath, content, overwrite=True)

    comp = component_graph(ctx)
    index_lines = [
        _fm("graph-index", f"Codebase graph — {ctx.scan_id or 'adhoc'}", ctx),
        "\nComponent Graph: broad machine connectivity "
        f"({comp['counts']['nodes']} nodes, {comp['counts']['relationships']} rels).\n",
        "\nRelationship Graph: per-finding blast radius (see finding contexts).\n",
        "\nCanvas: curated human overview (NOT a graph dump).\n",
        f"\nSource: {ctx.source} · commit `{ctx.commit}` · branch `{ctx.branch}`.\n",
        "\nTruncation: "
        + (json.dumps(comp["truncation"]) if any(comp["truncation"].values())
           else "NONE — graph is complete") + "\n",
    ]
    entity_paths: dict[str, str] = {}
    file_nodes = [n for n in comp["nodes"] if n["type"] == "FILE"]
    scored = []
    for node in file_nodes:
        links = sum(1 for r in comp["relationships"]
                    if r["source"] == node["id"] or r["target"] == node["id"])
        has_finding = any(r["source"] == node["id"] and
                          r["type"] == "PRODUCES_FINDING"
                          for r in comp["relationships"])
        is_entry = any(r["source"] == node["id"] and r["type"] == "EXPOSES"
                       for r in comp["relationships"])
        if has_finding or is_entry or links >= 3:
            scored.append((0 if has_finding else 1, -links, node))
    scored.sort(key=lambda t: (t[0], t[1], t[2]["id"]))
    chosen = [node for _, _, node in scored[:LIMITS["notes"]]]
    manifest["omitted"]["entity_notes"] = max(0, len(scored) - len(chosen))
    entity_paths = {node["id"]: _entity_note_name(ctx.scan_id, node)
                    for node in chosen}
    for node in chosen:
        note_rel = entity_paths[node["id"]]
        edges = [r for r in comp["relationships"]
                 if r["source"] == node["id"] or r["target"] == node["id"]]
        lines = [_fm("codebase-entity", node["label"], ctx),
                 f"\nPath: `{node['path']}` · language "
                 f"{node['metadata'].get('language', '?')}.\n",
                 "\n## Relationships\n"]
        for edge in sorted(edges, key=lambda e: (e["type"], e["target"]))[:25]:
            other = edge["target"] if edge["source"] == node["id"] else edge["source"]
            other_node = ctx.nodes.get(other, {})
            other_label = other_node.get("label", other)
            other_link = entity_paths.get(other)
            ref = f"[[{other_link}|{other_label}]]" if other_link else f"`{other_label}`"
            lines.append(f"- {edge['type']} → {ref} "
                         f"({edge['confidence']}; {edge['evidence']})\n")
        manifest["notes"].append(note_rel)
        _put(note_rel, "".join(lines))
    for kind in kinds:
        void = canvas(ctx, kind)
        for node in void["nodes"]:
            note = node.pop("note", "")
            label = node["text"].split("\n")[0]
            link = entity_paths.get(next(
                (nid for nid, note_rel in entity_paths.items()
                 if note_rel == note), ""))
            if link:
                node["text"] = (f"[[{link}|{label}]]\n" + "\n".join(
                    node["text"].split("\n")[1:]))
        name = f"{scope}/canvas-{kind}.canvas"
        target = pm.safe_join(vault_path, name, suffix=".canvas")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(void, indent=1), encoding="utf-8")
        manifest["canvases"].append(name)
        index_lines.append(f"\n- [[{name}|{kind} canvas]] "
                           f"({void['metadata']['node_count']} nodes).\n")
    significant = [n for n in ctx.nodes.values()
                   if n["type"] == "CRYPTO_FINDING" and
                   n["metadata"].get("severity") in ("critical", "high")]
    significant += [n for n in ctx.nodes.values()
                    if n["type"] == "CODE_FINDING"][:10]
    capped_contexts = max(0, len(significant) - 25)
    if capped_contexts:
        index_lines.append(
            f"\nFinding contexts capped: 25 of {len(significant)} significant "
            f"findings written (remainder omitted explicitly).\n")
    manifest["notes"].append(f"{scope}/index.md")
    _put(f"{scope}/index.md", "".join(index_lines))
    for node in significant[:25]:
        fid = node["id"].split("#", 1)[1] if "#" in node["id"] else node["id"]
        blast = blast_radius(ctx, fid)
        if blast.get("status") != "KNOWN":
            continue
        rel = f"{scope}/finding-{slugish(fid)}.md"
        sev = (node["metadata"].get("severity")
               or node["metadata"].get("category", ""))
        lines = [_fm("finding-context", node["label"], ctx),
                 f"\nSeverity/category: {sev}\n",
                 f"\nLocation: `{node['path']}`\n", "\n## Blast radius\n"]
        for bucket, entries in blast["affected_surface"].items():
            if entries:
                lines.append(f"\n### {bucket}\n")
                for entry in entries:
                    lines.append(f"- `{entry['path']}` — {entry['reason']} "
                                 f"({entry['relationship']}, {entry['confidence']})\n")
        manifest["finding_contexts"].append(rel)
        _put(rel, "".join(lines))
    manifest["omitted"]["finding_contexts"] = max(
        0, len(significant) - len(manifest["finding_contexts"]))
    return manifest


def prune_snapshots(vault: str | Path, keep: int = 5) -> dict:
    """Remove oldest scan scopes, keeping `keep` newest. Only fully-managed
    scope dirs are removed; anything else is skipped, never touched."""
    vault_path = Path(vault).expanduser().resolve()
    root = vault_path / GRAPH_ROOT
    removed, skipped = [], []
    if not root.is_dir():
        return {"removed": removed, "skipped": skipped}
    scopes = sorted(p for p in root.iterdir()
                    if p.is_dir() and p.name != "current")
    for scope in scopes[:max(0, len(scopes) - keep)]:
        notes = list(scope.rglob("*.md")) + list(scope.rglob("*.canvas"))
        if notes and all(_managed(p) for p in notes if p.suffix == ".md"):
            shutil.rmtree(scope)
            removed.append(scope.name)
        else:
            skipped.append(scope.name)
    return {"removed": removed, "skipped": skipped}
