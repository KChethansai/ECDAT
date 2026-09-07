import React from "react";

const PRI_TONE = { P0: "red", P1: "orange", P2: "amber", P3: "cyan" };
const SEV_TONE = { critical: "red", high: "orange", medium: "indigo", low: "muted" };
const STRENGTH_TONE = { HIGH: "cyan", MEDIUM: "amber", LOW: "muted" };

export function Badge({ tone = "muted", label, title }) {
  return (
    <span className="badge" data-tone={tone} title={title || label}>
      <span className="sq" aria-hidden="true" />
      {label}
    </span>
  );
}

export function PriorityBadge({ value }) {
  return <Badge tone={PRI_TONE[value] || "muted"} label={value || "P?"} title={`Priority ${value || "unknown"}`} />;
}

export function SeverityBadge({ value }) {
  return <Badge tone={SEV_TONE[value] || "muted"} label={(value || "?").toUpperCase()} title={`Severity ${value || "unknown"}`} />;
}

export function StrengthBadge({ value }) {
  if (!value) return <Badge label="—" title="No evidence strength recorded" />;
  return <Badge tone={STRENGTH_TONE[value] || "muted"} label={value} title={`Evidence strength ${value} (evidence-type rank, not a probability)`} />;
}

export function StatusBadge({ value }) {
  const short = (value || "").replace(/^MIGRATION_/, "") || "—";
  const tone = value === "MIGRATION_REQUIRED" ? "red" : value === "MIGRATION_PLANNED" ? "amber" : value === "DISCOVERED" ? "muted" : "green";
  return <Badge tone={tone} label={short} title={`Migration status ${value || "unknown"}`} />;
}

export function RuntimeBadge({ observed, count }) {
  if (observed) return <Badge tone="green" label={typeof count === "number" ? `OBSERVED ×${count}` : "OBSERVED"} title="Runtime-observed in this scan (controlled probe)" />;
  return <Badge label="NOT OBSERVED" title="Not runtime-observed in this scan — not proof of absence" />;
}

export function ScannerBadge({ value, mock }) {
  if (mock) return <Badge tone="amber" label="MOCK" title="Illustrative placeholder — not discovery" />;
  return <Badge tone="indigo" label={value || "?"} title={`Scanner ${value || "unknown"} (REAL evidence)`} />;
}

export function RealBadge({ mock }) {
  return mock ? (
    <Badge tone="amber" label="MOCK" title="Illustrative placeholder — not discovery" />
  ) : (
    <Badge tone="green" label="REAL" title="Real evidence from a production scanner" />
  );
}
