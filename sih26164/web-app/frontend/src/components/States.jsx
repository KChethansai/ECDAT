import React from "react";
import { IconShield } from "./icons.jsx";

export const SCAN_STAGES = [
  "Preparing scan",
  "Discovering artifacts",
  "Normalizing findings",
  "Assessing risk",
  "Building migration intelligence",
  "Preparing report",
];

export function LoadingStages({ active, runtime }) {
  return (
    <div role="status" aria-live="polite" className="card" style={{ marginTop: 16 }}>
      <p className="eyebrow">SCAN IN PROGRESS</p>
      <ol className="stages">
        {SCAN_STAGES.map((stage, i) => (
          <li key={stage} className={i < active ? "done" : i === active ? "active" : ""} aria-current={i === active ? "step" : undefined}>
            <span className="pip" aria-hidden="true" />
            {stage}
            {i === 0 && runtime ? " (incl. controlled runtime probe)" : ""}
          </li>
        ))}
      </ol>
      <p className="stages-hint">Interface stages only — the backend answers with a single report. Static scans never execute target code.</p>
    </div>
  );
}

export function ErrorState({ message, onRetry }) {
  if (!message) return null;
  return (
    <p role="alert" className="alert alert-error">
      <b>Scan error. </b>
      {message}
      {onRetry ? (
        <>
          {" "}
          <button type="button" className="row-button" onClick={onRetry}>
            Edit target and retry
          </button>
        </>
      ) : null}
    </p>
  );
}

export function EmptyState({ title, body, hint }) {
  return (
    <div className="state-card">
      <span className="art" aria-hidden="true">
        <IconShield size={22} />
      </span>
      <p className="eyebrow">{title}</p>
      <h2>No report yet</h2>
      <p>{body}</p>
      {hint ? <p>{hint}</p> : null}
    </div>
  );
}

export function SectionEmpty({ children }) {
  return <p style={{ color: "var(--muted)", fontSize: 13, margin: "8px 0 0", lineHeight: 1.6 }}>{children}</p>;
}

/** Route-change placeholder: keeps the shell chrome stable behind a shimmer
 *  while a lazy section chunk loads (first visit only — cached chunks render
 *  synchronously and never flash this). */
export function RouteSkeleton() {
  return (
    <div role="status" aria-live="polite" aria-label="Loading section" className="route-skeleton">
      <div className="sk sk-title" />
      <div className="sk sk-sub" />
      <div className="sk sk-card" />
      <div className="sk sk-card short" />
    </div>
  );
}
