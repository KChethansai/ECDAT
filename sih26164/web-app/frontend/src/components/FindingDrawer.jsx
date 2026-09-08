import React, { useEffect, useRef } from "react";
import { analystLine, arr, lineLabel, matchesFor, obj, shortPath, skillById, str } from "../lib/report.js";
import { Badge, PriorityBadge, RealBadge, RuntimeBadge, SeverityBadge, StatusBadge, StrengthBadge } from "./Badges.jsx";
import { IconBox, IconCompass, IconDoc, IconEvidence, IconGauge, IconLink, IconLock, IconMigrate, IconX } from "./icons.jsx";
import { triageScopeFor } from "./RepoPanel.jsx";
import TriageControl from "./TriageControl.jsx";

function SecurityContext({ finding, report }) {
  const matches = matchesFor(finding);
  if (matches.length === 0) return null;
  const source = (report?.knowledgeContext?.source) || {};
  return (
    <Sec icon={<IconDoc size={13} />} title={`SECURITY CONTEXT (${matches.length})`}>
      <p>
        Advisory knowledge matched deterministically to this finding's algorithm, scanner, and category. It explains
        relevance — it never changes the evidence, severity, or priority above.
      </p>
      {matches.map((m) => {
        const skill = skillById(report, m.skill);
        if (!skill) return null;
        return (
          <div key={m.skill} style={{ marginTop: 10, paddingTop: 10, borderTop: "1px dashed var(--line)" }}>
            <div className="badge-row">
              <Badge tone={m.strength === "HIGH" ? "cyan" : "muted"} label={`${m.strength} MATCH`} title="Rule depth of the match, not a model score" />
              <b style={{ fontSize: 12.5 }}>{skill.name}</b>
            </div>
            <p style={{ marginBottom: 2 }}>
              <b>Why it applies:</b> {m.why}.
            </p>
            <ul style={{ marginTop: 4 }}>
              {skill.guidance.slice(0, 3).map((g) => (
                <li key={g}>{g}</li>
              ))}
            </ul>
            {(skill.frameworks?.nist_csf?.length > 0 || skill.frameworks?.mitre_attack?.length > 0) && (
              <p className="cell-sub">
                Related: {[...(skill.frameworks?.nist_csf || []), ...(skill.frameworks?.mitre_attack || [])].join(" · ")} (knowledge mapping, not a compliance claim)
              </p>
            )}
          </div>
        );
      })}
      <p className="cell-sub" style={{ marginTop: 8 }}>
        Source: {source.repository || "—"}@{String(source.commit || "").slice(0, 7)} · {source.license || ""} · Evidence confidence and knowledge match are separate; recommendation basis: deterministic + knowledge.
      </p>
    </Sec>
  );
}

function ValidationSection({ finding, report }) {
  const f = obj(finding);
  const all = arr(report?.validations?.results);
  const mine = all.filter((r) => r && r.finding_id === f.id);
  const status = str(f.validationStatus, "STATIC_ONLY");
  if (status === "STATIC_ONLY" && mine.length === 0) return null;
  return (
    <Sec icon={<IconGauge size={13} />} title="ACTIVE VALIDATION">
      <p>
        <b>Status:</b> <span className="mono">{status}</span>
      </p>
      {mine.length === 0 ? (
        <p>No direct validation checks ran for this finding in this report. Family-level runtime observations, if any, are noted under RISK ASSESSMENT.</p>
      ) : (
        <ul>
          {mine.map((r) => (
            <li key={r.validation_id}>
              <span className="mono">{str(r.validation_type, "?")}</span> → <b>{str(r.status, "?")}</b>
              {str(r.observed_protocol) ? <> · protocol <span className="mono">{r.observed_protocol}</span></> : null}
              {str(r.observed_cipher) ? <> · cipher <span className="mono">{r.observed_cipher}</span></> : null}
              {r.observed_key_size ? <> · key <span className="mono">{r.observed_key_size}</span></> : null}
              {str(r.endpoint) ? <> · <code className="evidence">{r.endpoint}</code></> : null}
              {str(r.error) ? <> · <span>{r.error}</span></> : null}
              {str(r.evidence?.match_note) ? <> · <span>{r.evidence.match_note}</span></> : null}
            </li>
          ))}
        </ul>
      )}
      <p>Validation observes and correlates; it never changes the severity or priority above. Absence of confirmation is not proof of safety.</p>
    </Sec>
  );
}

function Sec({ icon, title, children }) {
  return (
    <div className="drawer-sec">
      <h3>
        {icon}
        {title}
      </h3>
      <div className="body">{children}</div>
    </div>
  );
}

export default function FindingDrawer({ finding, byId, report, onClose, onTriageSaved }) {
  const closeRef = useRef(null);
  useEffect(() => {
    if (!finding) return undefined;
    const prev = document.activeElement;
    closeRef.current?.focus();
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
      if (prev && prev.focus) prev.focus();
    };
  }, [finding, onClose]);

  if (!finding) return null;
  const f = obj(finding);
  const related = arr(f.related);
  const supports = arr(obj(f.correlation).supports);
  const runtimeState = f.scanner === "runtime" ? "observed" : supports.length > 0 ? "supported" : "not-observed";

  return (
    <>
      <div className="overlay" onClick={onClose} aria-hidden="true" />
      <div className="drawer" role="dialog" aria-modal="true" aria-label={`Finding ${str(f.algorithm, "")} detail`}>
        <div className="drawer-head">
          <div className="drawer-head-top">
            <div className="badge-row">
              <PriorityBadge value={f.priority} />
              <SeverityBadge value={f.severity} />
              <RealBadge mock={f.is_mock} />
              <StatusBadge value={f.migrationStatus} />
            </div>
            <button ref={closeRef} type="button" className="icon-btn" onClick={onClose} aria-label="Close finding detail">
              <IconX size={15} />
            </button>
          </div>
          <h2>
            <span className="mono">{str(f.algorithm, "Unknown finding")}</span>
          </h2>
          <p className="loc">
            {shortPath(f.file_path)}:{lineLabel(f.line)} · {str(f.usage, "—")} · {str(f.scanner, "?")} scanner
          </p>
        </div>
        <div className="drawer-body">
          <Sec icon={<IconEvidence size={13} />} title="FINDING">
            <p>
              <b>Algorithm:</b> <span className="mono">{str(f.algorithm, "—")}</span> · <b>Category:</b> {str(f.category, "—")}
            </p>
            <p>
              <b>Path:</b> <code className="evidence">{str(f.file_path, "—")}</code>
            </p>
            <p>
              <b>Line:</b> {lineLabel(f.line)} · <b>Usage:</b> {str(f.usage, "—")}
            </p>
          </Sec>

          <Sec icon={<IconLock size={13} />} title="EVIDENCE">
            <code className="evidence evidence-block">{str(f.evidence, "metadata only")}</code>
            <p>Truncated metadata snippet (≤160 chars, secrets redacted server-side). Key material is never emitted.</p>
          </Sec>

          <Sec icon={<IconBox size={13} />} title="CRYPTOGRAPHIC CONTEXT">
            <p>
              <b>Key size:</b> {f.key_size ?? "—"}
              {f.curve ? (
                <>
                  {" "}· <b>Curve:</b> {f.curve}
                </>
              ) : null}
              {f.mode ? (
                <>
                  {" "}· <b>Mode:</b> {f.mode}
                </>
              ) : null}
              {f.protocol_version ? (
                <>
                  {" "}· <b>Protocol:</b> {f.protocol_version}
                </>
              ) : null}
            </p>
            <p>
              {f.library ? (
                <>
                  <b>Library:</b> {str(f.library)} ·{" "}
                </>
              ) : null}
              <b>Confidence:</b> {f.confidence ?? "—"} <StrengthBadge value={f.evidenceStrength} />
            </p>
            {f.signature_algorithm ? (
              <p>
                <b>Signed:</b> {f.signature_algorithm}
              </p>
            ) : null}
            {f.expires_at ? (
              <p>
                <b>Expires:</b> {f.expires_at}
              </p>
            ) : null}
            <p>Strength is an evidence-type rank (HIGH / MEDIUM / LOW), not a probability.</p>
          </Sec>

          <Sec icon={<IconGauge size={13} />} title="RISK ASSESSMENT">
            <p>
              <b>Rationale:</b> {str(f.rationale, "—")}
            </p>
            {arr(f.risk_factors).length > 0 ? (
              <ul>
                {f.risk_factors.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            ) : null}
            <p>
              <b>Runtime relationship:</b>{" "}
              {runtimeState === "observed" ? (
                <RuntimeBadge observed />
              ) : runtimeState === "supported" ? (
                <RuntimeBadge observed count={supports.length} />
              ) : (
                <RuntimeBadge />
              )}
            </p>
            <p>
              {runtimeState === "observed"
                ? "Observed under controlled execution (bundled probe, timeout + isolation)."
                : runtimeState === "supported"
                  ? `Static evidence supported by ${supports.length} runtime observation(s) in this scan.`
                  : "Not runtime-observed in this scan. Absence of runtime observation is not proof of absence."}
            </p>
            {str(obj(f.correlation).note) ? <p>{f.correlation.note}</p> : null}
            <p>{analystLine(f)}</p>
          </Sec>

          <ValidationSection finding={finding} report={report} />

          <Sec icon={<IconDoc size={13} />} title="TRIAGE">
            {str(f.triage?.status, "open") !== "open" ? (
              <p>
                <b>State:</b> {str(f.triage?.status)}{str(f.triage?.reason) ? ` (${str(f.triage?.reason)})` : ""}
              </p>
            ) : null}
            <TriageControl scope={triageScopeFor(report)} fp={str(f.fp)} current={f.triage} onSaved={onTriageSaved} />
          </Sec>

          <SecurityContext finding={finding} report={report} />

          <Sec icon={<IconCompass size={13} />} title="RECOMMENDATION">
            <p>
              <b>Direction:</b> {str(f.recommendation?.recommend, "Review manually")}
            </p>
            {str(f.recommendation?.notes) ? <p>{f.recommendation.notes}</p> : null}
            {str(f.recommendation?.guidance) ? <p>{f.recommendation.guidance}</p> : null}
          </Sec>

          <Sec icon={<IconMigrate size={13} />} title="MIGRATION GUIDANCE">
            <p>
              <b>Status:</b> {str(f.migrationStatus, "—")}
            </p>
            <p>ML-KEM does not automatically drop into every HSM or existing cryptographic architecture — verify provider support first.</p>
          </Sec>

          <Sec icon={<IconLink size={13} />} title={`RELATED EVIDENCE (${related.length})`}>
            {related.length === 0 ? (
              <p>No linked findings in this scan (absence of links is not proof of isolation).</p>
            ) : (
              <ul>
                {related.map((rel) => {
                  const target = byId[rel.id];
                  return (
                    <li key={rel.id}>
                      {target ? (
                        <>
                          <b className="mono">{str(target.algorithm)}</b> · {str(target.scanner)} · {str(target.usage)} ({str(rel.relation)})
                        </>
                      ) : (
                        <>
                          {rel.id} ({str(rel.relation)})
                        </>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </Sec>
        </div>
      </div>
    </>
  );
}
