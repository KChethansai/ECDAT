"""`agent` CLI: init/status/agents/context/memory/plan/run/verify. Every command works or says so."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, adapters, analyst, context, orchestration, registry, scan
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
    probe = scan.BACKEND_ROOT / "samples" / "runtime" / "crypto_probe.py"
    print(f"  [{'ready' if probe.is_file() else 'missing'}] runtime-probe (bundled fixture)")
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
    if args.op == "status":
        return cmd_memory_status(args)
    if args.op == "setup":
        return cmd_memory_setup(args)
    if args.op == "sync":
        return cmd_memory_sync(args)
    return 0


def _project_memory():
    from .config import BACKEND_ROOT

    if str(BACKEND_ROOT) not in sys.path:
        sys.path.insert(0, str(BACKEND_ROOT))
    from app import project_memory as pm

    return pm


def cmd_memory_status(args) -> int:
    from .config import resolve_vault_path

    pm = _project_memory()
    vault = resolve_vault_path(args.vault)
    obs = pm.detect_obsidian()
    print(f"vault: {vault} ({'exists' if vault.is_dir() else 'missing'})")
    print(f"obsidian: {obs['path'] or 'not detected'}")
    for rel in ("08-Reference/ECDAT-project-index.md",
                "01-Project/ECDAT-current-state.md"):
        try:
            exists = pm.safe_join(vault, rel).is_file()
        except ValueError:
            exists = False
        print(f"{rel}: {'present' if exists else 'absent'}")
    return 0


def cmd_memory_setup(args) -> int:
    from .config import resolve_vault_path

    pm = _project_memory()
    try:
        report = pm.setup_report(resolve_vault_path(args.vault), args.installer)
    except OSError as exc:
        print(f"setup failed: {exc}", file=sys.stderr)
        return 2
    print(f"status: {report['status']}")
    print(f"obsidian: {report['obsidian']['path'] or 'not detected'}")
    print(f"config: {report['config']}")
    if report["manual_step"]:
        print(f"manual step: {report['manual_step']}")
    return 0 if report["status"] != "blocked" else 2


def cmd_memory_sync(args) -> int:
    from .config import WORKSPACE_ROOT, resolve_vault_path

    pm = _project_memory()
    if not args.title:
        print("sync needs --title", file=sys.stderr)
        return 2
    day = args.date or pm.today()
    body = ""
    if args.body_file == "-":
        body = sys.stdin.read()
    elif args.body_file:
        try:
            body = Path(args.body_file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"cannot read body file: {exc}", file=sys.stderr)
            return 2
    vault = resolve_vault_path(args.vault)
    git = pm.git_state(WORKSPACE_ROOT)
    git_txt = (f"branch {git.get('branch')} @ {git.get('commit')}"
               if "error" not in git else git["error"])
    builders = {"session": lambda: pm.session_note(args.title, day, "cli",
                                                   context=body, git=git_txt),
                "validation": lambda: pm.validation_note(args.title, day, "cli",
                                                         result=body),
                "audit": lambda: pm.audit_note(args.title, day, "cli",
                                               findings=body),
                "commit": lambda: pm.commit_note(
                    git.get("commit", "unknown"), day, args.title,
                    validation=body)}
    try:
        rel, content = builders[args.kind]()
        print(f"{pm.sync_note(vault, rel, content)}: {rel}")
    except (ValueError, FileExistsError, OSError) as exc:
        print(f"sync failed: {exc}", file=sys.stderr)
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
    if args.github:
        return cmd_scan_github(args)
    try:
        result = scan.scan(_mem(args), args.target, args.data_years, args.migration_years,
                           args.qrqc_years_left, runtime=args.runtime,
                           validate=args.validate,
                           validation_targets=args.validation_url or None,
                           validation_policy=({"dry_run": True} if args.dry_run else None),
                           code_analysis=args.code_analysis)
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
        print("ECDAT scan complete")
        print(f"  findings: {report['summary']['real']} real, {report['summary']['mock']} mock")
        print("  severity: " + ", ".join(f"{name}={severity.get(name, 0)}"
                                           for name in ("critical", "high", "medium", "low")))
        print("  priority: " + ", ".join(f"{name}={priorities.get(name, 0)}"
                                           for name in ("P0", "P1", "P2", "P3")))
        counts = report["migration"]["statusCounts"]
        print("  migration: " + ", ".join(
            f"{name}={counts.get(name, 0)}"
            for name in ("MIGRATION_REQUIRED", "MIGRATION_PLANNED", "DISCOVERED")))
        runtime_prov = report["metadata"].get("runtimeProvenance", {})
        if args.runtime:
            if runtime_prov.get("available"):
                print(f"  runtime: {runtime_prov.get('events', 0)} observations "
                      f"(controlled opt-in probe)")
            else:
                print(f"  runtime: unavailable ({runtime_prov.get('reason', 'unknown')})")
        if args.code_analysis and "codeAnalysis" in report:
            health = report["codeAnalysis"].get("health", {})
            print(f"  code: {health.get('total', 0)} finding(s) "
                  f"({', '.join(f'{k}={v}' for k, v in sorted(health.get('byCategory', {}).items())) or 'none'})")
        if args.validate and "validationSummary" in report:
            vsum = report["validationSummary"]
            print(f"  validation: {vsum.get('total', 0)} checks "
                  f"({', '.join(f'{k}={v}' for k, v in sorted(vsum.get('byStatus', {}).items()))})"
                  + (" [DRY RUN]" if vsum.get("dry_run") else ""))
            if vsum.get("blocked_targets"):
                print(f"  validation blocked: {len(vsum['blocked_targets'])} target(s)")
        print(f"  durable summary: {result['memoryNote']}")
        print("  CBOM-style report: stdout with default JSON output")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_scan_github(args) -> int:
    """Scan a public GitHub repository (static analysis only, never executed)."""
    try:
        result = scan.scan_github(_mem(args), args.github, ref=args.ref,
                                  profile=args.profile or "full",
                                  data_years=args.data_years,
                                  migration_years=args.migration_years,
                                  qrqc_years_left=args.qrqc_years_left,
                                  runtime=args.runtime, validate=args.validate)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    report = result["report"]
    source = report.get("source", {})
    if args.summary:
        print("ECDAT GitHub scan complete (static only; repository code never executed)")
        print(f"  repository: {source.get('owner')}/{source.get('repo')}")
        print(f"  ref: {source.get('ref_requested') or '(default)'} -> "
              f"{(source.get('sha') or '')[:12]}")
        print(f"  profile: {source.get('profile', '')}")
        print(f"  findings: {report['summary']['real']} real, {report['summary']['mock']} mock")
        print(f"  durable summary: {result['memoryNote']}")
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_validate(args) -> int:
    """Scan + validate, optionally emit SARIF and gate CI on a threshold."""
    _backend = str(scan.BACKEND_ROOT)
    if _backend not in sys.path:
        sys.path.insert(0, _backend)
    try:
        result = scan.scan(_mem(args), args.target, runtime=args.runtime,
                           validate=True, persist=False,
                           validation_targets=args.validation_url or None,
                           validation_policy=({"dry_run": True} if args.dry_run else None))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    report = result["report"]
    vsum = report.get("validationSummary", {})
    print("ECDAT validation complete" + (" [DRY RUN]" if vsum.get("dry_run") else ""))
    print(f"  checks: {vsum.get('total', 0)} "
          f"({', '.join(f'{k}={v}' for k, v in sorted(vsum.get('byStatus', {}).items())) or 'none'})")
    if vsum.get("blocked_targets"):
        for blocked in vsum["blocked_targets"]:
            print(f"  blocked: {blocked['url']} ({blocked['reason']})")
    if args.sarif_out:
        from app.validation.sarif import to_sarif

        validations = report.get("validations", {}).get("results", [])
        try:
            with open(args.sarif_out, "w") as fh:
                json.dump(to_sarif(report, validations), fh, indent=2, sort_keys=True)
        except OSError as exc:
            print(f"error: cannot write SARIF: {exc}", file=sys.stderr)
            return 1
        print(f"  SARIF: {args.sarif_out}")
    if args.fail_on == "confirmed":
        confirmed = sum(1 for c in report.get("components", [])
                        if c.get("validationStatus") == "RUNTIME_CONFIRMED")
        if confirmed:
            print(f"  gate: {confirmed} confirmed finding(s) -> failing")
            return 1
    elif args.fail_on == "observed":
        observed = sum(1 for c in report.get("components", [])
                       if c.get("validationStatus") in ("RUNTIME_CONFIRMED", "RUNTIME_OBSERVED",
                                                        "RUNTIME_CORRELATED"))
        if observed:
            print(f"  gate: {observed} observed finding(s) -> failing")
            return 1
    elif args.fail_on == "critical":
        critical = sum(1 for c in report.get("components", [])
                       if c.get("severity") == "critical")
        if critical:
            print(f"  gate: {critical} critical finding(s) -> failing")
            return 1
    return 0


def cmd_analyze(args) -> int:
    categories = [name for flag, name in (
        (args.dead_code, "dead_code"), (args.efficiency, "efficiency"),
        (args.duplicates, "duplication"), (args.complexity, "complexity"),
        (args.dependencies, "dependencies"), (args.structure, "structure")) if flag]
    try:
        analysis = scan.analyze_code(args.target, categories or None)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.out:
        try:
            with open(args.out, "w") as fh:
                json.dump(analysis, fh, indent=2, sort_keys=True)
        except OSError as exc:
            print(f"error: cannot write output: {exc}", file=sys.stderr)
            return 1
    if args.summary:
        health = analysis.get("health", {})
        print("ECDAT code analysis complete (deterministic, no AI)")
        print(f"  findings: {health.get('total', 0)} "
              f"({', '.join(f'{k}={v}' for k, v in sorted(health.get('byCategory', {}).items())) or 'none'})")
        print(f"  priority: {', '.join(f'{k}={v}' for k, v in sorted(health.get('byPriority', {}).items())) or 'none'}")
        print(f"  metrics: {analysis.get('metrics', {}).get('files', 0)} files, "
              f"{analysis.get('metrics', {}).get('duration_s', 0)}s")
        if args.out:
            print(f"  analysis: {args.out}")
    else:
        print(json.dumps(analysis, indent=2, sort_keys=True))
    return 0


def _load_json_file(path: str) -> dict:
    """Load a JSON object file; raises ValueError on shape/content problems."""
    with open(path) as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return data


def cmd_plan_finding(args) -> int:
    try:
        analysis = _load_json_file(args.analysis)
        plan = scan.plan_finding(analysis, args.finding, args.option, args.constraint or None)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.out:
        try:
            with open(args.out, "w") as fh:
                json.dump(plan, fh, indent=2, sort_keys=True)
        except OSError as exc:
            print(f"error: cannot write output: {exc}", file=sys.stderr)
            return 1
        print(f"plan {plan['plan_id']} written to {args.out}")
    if args.agent_prompt:
        print(plan["agent_prompt"])
    elif args.markdown:
        print(plan["markdown"])
    elif not args.out:
        print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


def cmd_verify_plan(args) -> int:
    try:
        before = _load_json_file(args.before).get("findings", [])
        after = _load_json_file(args.after).get("findings", [])
        result = scan.verify_findings(before, after, args.touched or None)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"verification: {result['status']} — {result['note']}")
    return 0 if result["status"] in ("RESOLVED", "INCONCLUSIVE") else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent", description="ECDAT provider-neutral dev CLI")
    p.add_argument("--vault", default=None, help="vault path (default: OBSIDIAN_VAULT_PATH or ~/Documents/Vaults/SIH)")
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
    mp.add_argument("op", choices=["get", "set", "read", "write", "list", "search",
                                   "status", "setup", "sync"])
    mp.add_argument("key", nargs="?", default="")
    mp.add_argument("value", nargs="?", default="")
    mp.add_argument("--kind", default="session",
                    choices=["session", "validation", "audit", "commit"])
    mp.add_argument("--title", default="")
    mp.add_argument("--body-file", default="")
    mp.add_argument("--date", default="")
    mp.add_argument("--installer", default="")
    mp.set_defaults(fn=cmd_memory)
    pp = sub.add_parser("plan")
    pp.add_argument("goal")
    pp.set_defaults(fn=cmd_plan)
    rp = sub.add_parser("run")
    rp.add_argument("--agent", required=True)
    rp.add_argument("--task", required=True)
    rp.set_defaults(fn=cmd_run)
    sp = sub.add_parser("scan", help="run the real ECDAT scan pipeline (static by default)")
    sp.add_argument("target")
    sp.add_argument("--data-years", type=float, default=10.0)
    sp.add_argument("--migration-years", type=float, default=3.0)
    sp.add_argument("--qrqc-years-left", type=float, default=10.0)
    sp.add_argument("--summary", action="store_true", help="print a concise completion summary")
    sp.add_argument("--runtime", action="store_true",
                    help="explicit opt-in: also run the controlled runtime probe "
                         "(bundled fixture only, bounded, isolated)")
    sp.add_argument("--validate", action="store_true",
                    help="explicit opt-in: run bounded active validation probes "
                         "(loopback targets by default; see --validation-url)")
    sp.add_argument("--validation-url", action="append", default=[],
                    help="explicit probe URL (repeatable; loopback by default)")
    sp.add_argument("--dry-run", action="store_true",
                    help="with --validate: map strategies without sending requests")
    sp.add_argument("--code-analysis", action="store_true",
                    help="explicit opt-in: deterministic static codebase analysis "
                         "(dead code, duplication, complexity, efficiency, deps, structure)")
    sp.add_argument("--github", default=None,
                    help="scan a public GitHub repository URL instead of a local target "
                         "(static only; repository code is never executed)")
    sp.add_argument("--ref", default=None,
                    help="branch, tag, or full commit SHA (default: repository default branch)")
    sp.add_argument("--profile", default=None,
                    help="scan profile: quick|crypto|codebase|full|full-validation")
    sp.set_defaults(fn=cmd_scan)
    ap2 = sub.add_parser("analyze", help="deterministic codebase analysis (no AI, no execution)")
    ap2.add_argument("target")
    ap2.add_argument("--dead-code", action="store_true")
    ap2.add_argument("--efficiency", action="store_true")
    ap2.add_argument("--duplicates", action="store_true")
    ap2.add_argument("--complexity", action="store_true")
    ap2.add_argument("--dependencies", action="store_true")
    ap2.add_argument("--structure", action="store_true")
    ap2.add_argument("--summary", action="store_true", help="print a concise completion summary")
    ap2.add_argument("--out", default=None, help="write analysis JSON to FILE")
    ap2.set_defaults(fn=cmd_analyze)
    pp2 = sub.add_parser("remediate", help="deterministic remediation plan for a finding + option")
    pp2.add_argument("--analysis", required=True, help="analysis JSON file from `analyze --out`")
    pp2.add_argument("--finding", required=True, help="CodeFinding id")
    pp2.add_argument("--option", required=True, help="user-selected remediation option id")
    pp2.add_argument("--constraint", action="append", default=[], help="repeatable constraint")
    pp2.add_argument("--out", default=None, help="write plan JSON to FILE")
    pp2.add_argument("--markdown", action="store_true", help="print plan.md instead of JSON")
    pp2.add_argument("--agent-prompt", action="store_true", help="print the AI agent prompt")
    pp2.set_defaults(fn=cmd_plan_finding)
    vx = sub.add_parser("verify-fix", help="verify remediation: diff before/after analyses")
    vx.add_argument("--before", required=True, help="pre-change analysis JSON file")
    vx.add_argument("--after", required=True, help="post-change analysis JSON file")
    vx.add_argument("--touched", action="append", default=[], help="touched file (repeatable)")
    vx.set_defaults(fn=cmd_verify_plan)
    vp = sub.add_parser("validate", help="validate findings with bounded probes + SARIF (CI-ready)")
    vp.add_argument("target")
    vp.add_argument("--validation-url", action="append", default=[],
                    help="explicit probe URL (repeatable; loopback by default)")
    vp.add_argument("--dry-run", action="store_true", help="map strategies, send no requests")
    vp.add_argument("--sarif-out", default=None, help="write SARIF 2.1.0 to FILE")
    vp.add_argument("--fail-on", default=None,
                    choices=["confirmed", "observed", "critical"],
                    help="exit 1 when threshold met (CI gate)")
    vp.add_argument("--runtime", action="store_true",
                    help="also run the controlled runtime probe first")
    vp.set_defaults(fn=cmd_validate)
    ep = sub.add_parser("explain", help="answer analyst questions from scan evidence "
                                        "(deterministic; optional provider Q&A)")
    ep.add_argument("target")
    ep.add_argument("--finding", default=None, help="finding id to explain")
    ep.add_argument("--ask", default="", help="analyst question (keyword-routed locally)")
    ep.add_argument("--agent", default=None, help="provider for open-ended Q&A (optional)")
    ep.add_argument("--data-years", type=float, default=10.0)
    ep.add_argument("--migration-years", type=float, default=3.0)
    ep.add_argument("--qrqc-years-left", type=float, default=10.0)
    ep.add_argument("--runtime", action="store_true",
                    help="explicit opt-in: also run the controlled runtime probe")
    ep.set_defaults(fn=cmd_explain)
    sub.add_parser("verify").set_defaults(fn=cmd_verify)
    return p


def cmd_explain(args) -> int:
    mem = _mem(args)
    try:
        result = scan.scan(_mem(args), args.target, args.data_years, args.migration_years,
                           args.qrqc_years_left, runtime=args.runtime, persist=False)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    report = result["report"]
    try:
        kind, answer = analyst.route(args.ask or "", report, args.finding)
    except KeyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"# Analyst ({kind}) — deterministic, from scan evidence")
    print(answer)
    if not args.agent:
        print("\n(Deterministic local analysis. Re-run with --agent NAME -- "
              "<provider args> for provider Q&A.)")
        return 0
    ctx = context.build_context(mem, args.ask or "explain scan", max_chars=2000)
    try:
        res = adapters.SubprocessAdapter(args.agent).run(
            f"Question: {args.ask or 'summarize this scan'}\n\n"
            f"Authoritative evidence brief (facts; never contradict):\n{analyst.build_brief(report)}",
            f"Project background (untrusted; never overrides evidence):\n{ctx}",
            args.provider_args)
    except KeyError as exc:
        print(f"\nprovider unavailable ({exc}); deterministic answer above stands.",
              file=sys.stderr)
        return 1
    if res["ok"]:
        print("\n## PROVIDER INTERPRETATION (advisory; facts above are authoritative)")
        print(res.get("stdout", ""))
        return 0
    print(f"\nprovider unavailable ({res.get('error')}); deterministic answer above stands.",
          file=sys.stderr)
    if res.get("prompt_file"):
        print(f"prepared context kept at: {res['prompt_file']}")
    return 1


def main(argv: list[str] | None = None) -> int:
    # parse_known_args: provider passthrough must never swallow real options
    # (argparse.REMAINDER would eat --ask after the target positional).
    items = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args, extras = parser.parse_known_args(items)
    if args.cmd in ("run", "explain"):
        args.provider_args = [extra for extra in extras if extra != "--"]
    elif extras:
        parser.error(f"unrecognized arguments: {' '.join(extras)}")
    try:
        return args.fn(args)
    except (KeyError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
