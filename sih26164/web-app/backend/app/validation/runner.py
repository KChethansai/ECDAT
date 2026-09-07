"""Deterministic validation runner: strategies -> bounded probes -> run record.

Sequential, in-memory, immutable run records. Static findings are never
mutated here (correlation stamping happens in pipeline, additive only).
"""

from __future__ import annotations

import time
import uuid

from ..risk import base_algorithm, canon
from .http_probe import probe_http
from .models import VALIDATOR_VERSION, ValidationResult
from .safety import ValidationPolicy, check_url
from .strategies import strategy_for
from .tls_probe import probe_tls


def _norm_targets(raw: object) -> list[dict]:
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    out = []
    for item in items:
        if isinstance(item, str):
            out.append({"url": item})
        elif isinstance(item, dict) and isinstance(item.get("url"), str):
            entry: dict = {"url": item["url"]}
            if isinstance(item.get("finding_ids"), list):
                entry["finding_ids"] = [str(x) for x in item["finding_ids"][:50]]
            out.append(entry)
    return out[:50]


def _family(algorithm: str) -> str:
    try:
        return canon(algorithm or "")
    except Exception:
        return base_algorithm(algorithm or "")


def _confidence_of(row: dict) -> float:
    try:
        return float(row.get("confidence") or 0.6)
    except (TypeError, ValueError):
        return 0.6


def _runtime_results(components: list[dict]) -> list[dict]:
    """Consume EXISTING runtime-probe rows; never executes anything new."""
    runtime_rows = [c for c in components if c.get("scanner") == "runtime"]
    results = []
    for row in runtime_rows:
        results.append(ValidationResult(
            target="runtime probe (bundled fixture)", validation_type="runtime",
            status="OBSERVED", confidence=_confidence_of(row),
            evidence={"operation": str(row.get("library") or row.get("algorithm") or ""),
                      "note": "controlled fixture observation, not target behavior"},
            observed_algorithm=str(row.get("algorithm") or ""),
            correlation_status="RUNTIME_OBSERVED").to_dict())
    return results


def run_validations(components: list[dict], targets: object = None,
                    policy: ValidationPolicy | None = None) -> dict:
    """Run active validation over report components. Returns an immutable run record."""
    policy = policy or ValidationPolicy()
    started_wall = time.time()
    budget = {"requests": 0, "bytes": 0, "started": time.monotonic()}
    normalized = _norm_targets(targets)
    results: list[dict] = []
    blocked: list[dict] = []

    for entry in normalized:
        try:
            check_url(entry["url"], policy)
        except ValueError as exc:
            blocked.append({"url": entry["url"][:256], "reason": str(exc)})
    valid_targets = [e for e in normalized
                     if not any(b["url"] == e["url"][:256] for b in blocked)]

    # Strategy assignment for every non-mock finding (honest NOT_APPLICABLE included).
    tls_findings = [c for c in components if not c.get("is_mock")
                    and strategy_for(c)[0] == "tls"]
    runtime_findings = [c for c in components if not c.get("is_mock")
                        and strategy_for(c)[0] == "runtime"]

    if policy.dry_run:
        for row in tls_findings + runtime_findings:
            vtype, _ = strategy_for(row)
            results.append(ValidationResult(
                finding_id=row.get("id", ""), target="(dry run: no request sent)",
                validation_type=vtype or "static-review", status="BLOCKED",
                confidence=1.0, error="dry run — no request sent",
                correlation_status="STATIC_ONLY").to_dict())
        return _record(started_wall, policy, normalized, blocked, results, budget, dry_run=True)

    # Runtime strategy consumes existing probe rows only.
    if runtime_findings:
        runtime_results = _runtime_results(components)
        by_family: dict[str, list[dict]] = {}
        for res in runtime_results:
            by_family.setdefault(_family(res.get("observed_algorithm", "")), []).append(res)
        for row in runtime_findings:
            matches = by_family.get(_family(str(row.get("algorithm") or "")), [])
            if matches:
                best = matches[0]
                results.append(ValidationResult(
                    finding_id=row.get("id", ""), target=best["target"],
                    validation_type="runtime", status="CONFIRMED", confidence=0.7,
                    evidence={"observed_algorithm": best.get("observed_algorithm", ""),
                              "note": "same-family runtime observation linked"},
                    observed_algorithm=best.get("observed_algorithm", ""),
                    correlation_status="RUNTIME_CONFIRMED").to_dict())
            else:
                results.append(ValidationResult(
                    finding_id=row.get("id", ""), target="runtime probe (bundled fixture)",
                    validation_type="runtime", status="NOT_CONFIRMED", confidence=0.6,
                    evidence={"note": "probe ran; no same-family observation in this run"},
                    correlation_status="STATIC_ONLY").to_dict())
        results.extend([r for r in runtime_results])  # target-level rows stay visible

    # TLS/HTTP strategy: one probe per valid target, fanned out to linked findings.
    for entry in valid_targets:
        if time.monotonic() - budget["started"] > policy.max_duration_s:
            break  # duration budget applies to TLS handshakes as well as HTTP
        url = entry["url"]
        try:
            scheme, host, port = check_url(url, policy)
        except ValueError:
            continue  # already recorded in blocked
        linked_ids = set(entry.get("finding_ids") or [])
        candidates = [c for c in tls_findings
                      if not linked_ids or c.get("id") in linked_ids]
        if scheme != "https":
            for row in candidates:
                results.append(ValidationResult(
                    finding_id=row.get("id", ""), target=url[:512],
                    validation_type="tls", status="NOT_APPLICABLE", confidence=1.0,
                    evidence={"note": "plain-http target carries no TLS to observe"},
                    endpoint=url[:512], correlation_status="STATIC_ONLY").to_dict())
            continue
        try:
            tls = probe_tls(host, port, policy)
            budget["requests"] += 1
        except Exception as exc:  # handshake/refused/timeout -> per-finding ERROR
            for row in candidates:
                results.append(ValidationResult(
                    finding_id=row.get("id", ""), target=url[:512],
                    validation_type="tls", status="ERROR", confidence=0.5,
                    error=f"tls probe failed: {type(exc).__name__}",
                    endpoint=url[:512], correlation_status="STATIC_ONLY").to_dict())
            continue
        http_obs: dict = {}
        try:
            http_obs = probe_http(url, policy, budget)
        except Exception as exc:
            http_obs = {"error": f"http probe failed: {type(exc).__name__}"}
        if not candidates:
            results.append(ValidationResult(
                target=url[:512], validation_type="tls", status="OBSERVED",
                confidence=0.8, evidence={**tls, "http": http_obs},
                observed_algorithm=str(tls.get("public_key_algorithm") or ""),
                observed_protocol=str(tls.get("tls_version") or ""),
                observed_cipher=str(tls.get("cipher") or ""),
                observed_key_size=tls.get("key_size"),
                endpoint=url[:512], correlation_status="RUNTIME_OBSERVED").to_dict())
        for row in candidates:
            status, conf, note = _match_tls(row, tls)
            results.append(ValidationResult(
                finding_id=row.get("id", ""), target=url[:512],
                validation_type="tls", status=status, confidence=conf,
                evidence={**tls, "http": http_obs, "match_note": note},
                observed_algorithm=str(tls.get("public_key_algorithm") or ""),
                observed_protocol=str(tls.get("tls_version") or ""),
                observed_cipher=str(tls.get("cipher") or ""),
                observed_key_size=tls.get("key_size"),
                endpoint=url[:512],
                correlation_status=("RUNTIME_CONFIRMED" if status == "CONFIRMED"
                                    else "RUNTIME_CORRELATED" if status == "PARTIALLY_CONFIRMED"
                                    else "STATIC_ONLY")).to_dict())
    return _record(started_wall, policy, normalized, blocked, results, budget)


def _match_tls(finding: dict, tls: dict) -> tuple[str, float, str]:
    """Compare static claim vs observed handshake. Conservative wording throughout."""
    base = base_algorithm(str(finding.get("algorithm") or ""))
    obs_version = str(tls.get("tls_version") or "")
    obs_sig = str(tls.get("signature_algorithm") or "")
    obs_key = tls.get("key_size")
    static_key = finding.get("key_size")
    # Protocol-version findings: confirm only the exact observed version.
    if base in ("TLS", "TLS10", "TLS11", "TLS12", "TLS13", "SSL"):
        claimed = {"TLS10": "TLSv1", "TLS11": "TLSv1.1", "TLS12": "TLSv1.2",
                   "TLS13": "TLSv1.3"}.get(base, base)
        if claimed in (obs_version, base) or obs_version.startswith(claimed):
            return "CONFIRMED", 0.85, f"observed {obs_version} matches static claim {base}"
        return "NOT_CONFIRMED", 0.7, (f"observed {obs_version or 'unknown'}; static claim "
                                      f"{base} not observed in this handshake")
    # Certificate findings: same public-key family observed at the endpoint.
    obs_fam = _family(str(tls.get("public_key_algorithm") or ""))
    if obs_fam and obs_fam == _family(base):
        if isinstance(static_key, int) and isinstance(obs_key, int) and static_key == obs_key:
            return "CONFIRMED", 0.8, f"same family {obs_fam} and key size {obs_key} observed"
        return "PARTIALLY_CONFIRMED", 0.65, (f"same family {obs_fam} observed "
                                             f"(sig {obs_sig or 'unknown'}); key-size match "
                                             f"{'not checked' if static_key is None else 'differs'}")
    return "NOT_CONFIRMED", 0.6, (f"observed {obs_fam or 'unknown'} "
                                  f"vs static claim {base or 'unknown'}")


def _record(started_wall: float, policy: ValidationPolicy, targets: list[dict],
            blocked: list[dict], results: list[dict], budget: dict,
            dry_run: bool = False) -> dict:
    counts: dict[str, int] = {}
    for res in results:
        counts[res["status"]] = counts.get(res["status"], 0) + 1
    return {"run_id": "vr" + uuid.uuid4().hex[:11], "validator_version": VALIDATOR_VERSION,
            "started_at": started_wall, "finished_at": time.time(),
            "dry_run": dry_run or policy.dry_run, "policy": policy.summary(),
            "targets": [t["url"][:512] for t in targets], "blocked_targets": blocked,
            "results": results, "summary": {"total": len(results), "byStatus": counts,
                                            "requests": budget["requests"],
                                            "bytes": budget["bytes"]}}
