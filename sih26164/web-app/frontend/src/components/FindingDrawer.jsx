import React, { useEffect, useRef } from "react";
import { analystLine, arr, lineLabel, obj, shortPath, str } from "../lib/report.js";
import { PriorityBadge, RealBadge, RuntimeBadge, SeverityBadge, StatusBadge, StrengthBadge } from "./Badges.jsx";
import { IconBox, IconCompass, IconEvidence, IconGauge, IconLink, IconLock, IconMigrate, IconX } from "./icons.jsx";

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

export default function FindingDrawer({ finding, byId, onClose }) {
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
            <p>
              <code className="evidence">{str(f.evidence, "metadata only")}</code>
            </p>
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
