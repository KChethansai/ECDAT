"""`agent` CLI: init/status/agents/context/memory/plan/run/verify. Every command works or says so."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, adapters, context, orchestration, registry, scan
from .config import CLI_ROOT, resolve_vault_path
from .memory import ObsidianVaultProvider


def _mem(args) -> ObsidianVaultProvider:
    return ObsidianVaultProvider(resolve_vault_path(args.vault))


def cmd_init(args) -> int:
    mem = _mem(args)
    mem.initialize()
    print(f"vault ready: {mem.vault}")
    return 0


def cmd_status(args) -> int:
    mem = _mem(args)
    print(f"agent v{__version__}")
    print(f"vault: {mem.vault} ({'exists' if mem.vault.is_dir() else 'MISSING'})")
    for a in registry.status():
        mark = "ready" if a["available"] else "missing"
        print(f"  [{mark}] {a['name']} ({a['provider']}) -> {a.get('resolved') or a['command']}")
    return 0


def cmd_agents(args) -> int:
    for a in registry.status():
        print(f"{a['name']}: provider={a['provider']} cmd={a['command']} "
              f"available={a['available']} caps={','.join(a.get('capabilities', []))}")
        if args.verbose and a.get("notes"):
            print(f"    {a['notes']}")
    return 0


def cmd_context(args) -> int:
    print(context.build_context(_mem(args), args.task, max_chars=args.max_chars))
    return 0


def cmd_memory(args) -> int:
    mem = _mem(args)
    try:
        if args.op == "get":
            print(mem.kv_get(args.key))
        elif args.op == "set":
            mem.kv_set(args.key, args.value)
            print(f"stored {args.key}")
        elif args.op == "read":
            print(mem.read(args.key))
        elif args.op == "write":
            print(f"wrote {mem.write(args.key, args.value)}")
        elif args.op == "list":
            for n in mem.list(args.key or ""):
                print(n)
        elif args.op == "search":
            for rel, snip in mem.search(args.key):
                print(f"{rel} :: {snip}")
    except (KeyError, FileNotFoundError) as exc:
        print(f"not found: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_plan(args) -> int:
    print(f"plan note: {orchestration.plan(_mem(args), args.goal)}")
    return 0


def cmd_run(args) -> int:
    mem = _mem(args)
    ctx = context.build_context(mem, args.task)
    res = adapters.SubprocessAdapter(args.agent).run(args.task, ctx, args.provider_args)
    if res.get("stdout"):
        print(res["stdout"])
    if res.get("stderr"):
        print(res["stderr"], file=sys.stderr)
    if not res["ok"]:
        print(f"run: {res.get('error')}", file=sys.stderr)
        if res.get("prompt_file"):
            print(f"prepared context kept at: {res['prompt_file']}")
        return 1
    return 0


def cmd_verify(args) -> int:
    del args
    res = orchestration.verify(CLI_ROOT)
    print(res["tail"])
    return 0 if res["ok"] else 1


def cmd_scan(args) -> int:
    try:
        result = scan.scan(_mem(args), args.target, args.data_years, args.migration_years,
                           args.qrqc_years_left)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.summary:
        report = result["report"]
        severity = report["summary"]["bySeverity"]
        priorities = report["riskSummary"]["priorities"]
        print("ECDAT source scan complete")
        print(f"  findings: {report['summary']['real']} real, {report['summary']['mock']} mock")
        print("  severity: " + ", ".join(f"{name}={severity.get(name, 0)}"
                                           for name in ("critical", "high", "medium", "low")))
        print("  priority: " + ", ".join(f"{name}={priorities.get(name, 0)}"
                                           for name in ("P0", "P1", "P2", "P3")))
        print(f"  durable summary: {result['memoryNote']}")
        print("  CBOM-style report: stdout with default JSON output")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent", description="ECDAT provider-neutral dev CLI")
    p.add_argument("--vault", default=None, help="vault path (default: OBSIDIAN_VAULT_PATH or workspace obsidian-vault/)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init").set_defaults(fn=cmd_init)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    ap = sub.add_parser("agents")
    ap.add_argument("--verbose", action="store_true")
    ap.set_defaults(fn=cmd_agents)
    cp = sub.add_parser("context")
    cp.add_argument("task")
    cp.add_argument("--max-chars", type=int, default=4000)
    cp.set_defaults(fn=cmd_context)
    mp = sub.add_parser("memory")
    mp.add_argument("op", choices=["get", "set", "read", "write", "list", "search"])
    mp.add_argument("key", nargs="?", default="")
    mp.add_argument("value", nargs="?", default="")
    mp.set_defaults(fn=cmd_memory)
    pp = sub.add_parser("plan")
    pp.add_argument("goal")
    pp.set_defaults(fn=cmd_plan)
    rp = sub.add_parser("run")
    rp.add_argument("--agent", required=True)
    rp.add_argument("--task", required=True)
    rp.add_argument("provider_args", nargs=argparse.REMAINDER)
    rp.set_defaults(fn=cmd_run)
    sp = sub.add_parser("scan", help="run the real ECDAT source scan pipeline")
    sp.add_argument("target")
    sp.add_argument("--data-years", type=float, default=10.0)
    sp.add_argument("--migration-years", type=float, default=3.0)
    sp.add_argument("--qrqc-years-left", type=float, default=10.0)
    sp.add_argument("--summary", action="store_true", help="print a concise completion summary")
    sp.set_defaults(fn=cmd_scan)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "run" and args.provider_args and args.provider_args[0] == "--":
        args.provider_args = args.provider_args[1:]
    try:
        return args.fn(args)
    except (KeyError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
