import React, { useMemo, useState } from "react";
import { activeFilterLabels, filterFindings, findingById, getComponents, scannerSources } from "../lib/selectors.js";
import { useStore } from "../store.jsx";
import FindingsExplorer from "../components/FindingsExplorer.jsx";
import FindingDrawer from "../components/FindingDrawer.jsx";
import { PageHead, RequireReport } from "./_shared.jsx";

const PRESETS = {
  all: {},
  critical: { severity: "critical" },
  high: { severity: "high" },
  open: { triage: "open" },
  suppressed: { triage: "suppressed" },
  quantum: { quantum: true },
  validated: { validated: true },
  migration: { migrationReady: true },
};

const PRESET_LABELS = [
  ["all", "All"],
  ["critical", "Critical"],
  ["high", "High"],
  ["open", "Open"],
  ["suppressed", "Suppressed"],
  ["quantum", "Quantum-relevant"],
  ["validated", "Validated"],
  ["migration", "Migration-ready"],
];

const BASE_FILTERS = { priority: "all", severity: "all", scanner: "all", query: "", triage: "all", quantum: false, validated: false, migrationReady: false };

export default function Findings({ findingId }) {
  const { report, scanId, refreshReport } = useStore();
  const components = useMemo(() => getComponents(report), [report]);
  const [filters, setFilters] = useState(BASE_FILTERS);
  const [preset, setPreset] = useState("all");

  const visible = useMemo(() => filterFindings(components, filters), [components, filters]);
  const labels = useMemo(() => activeFilterLabels(filters), [filters]);
  const selected = findingId ? findingById(report, findingId) : null;
  const byId = useMemo(() => Object.fromEntries(components.map((f) => [f.id, f])), [components]);

  function applyPreset(name) {
    setPreset(name);
    setFilters({ ...BASE_FILTERS, ...(PRESETS[name] || {}) });
  }

  function update(patch) {
    setPreset("custom");
    setFilters((f) => ({ ...f, ...patch }));
  }

  const clear = () => applyPreset("all");

  return (
    <>
      <PageHead eyebrow="SECURITY FINDINGS" title="Findings" sub="Severity → algorithm → location → evidence → recommendation. Select a row for the full analyst workspace." />
      <div className="card" aria-label="Filter presets">
        <div className="badge-row" role="group" aria-label="Filter presets">
          {PRESET_LABELS.map(([name, label]) => (
            <button
              key={name}
              type="button"
              className="btn btn-secondary"
              aria-pressed={preset === name}
              disabled={preset === name}
              onClick={() => applyPreset(name)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      <RequireReport report={report} title="NO FINDINGS">
        <FindingsExplorer
          components={components}
          visible={visible}
          total={components.length}
          filterPriority={filters.priority}
          onPriority={(v) => update({ priority: v })}
          filterSeverity={filters.severity}
          onSeverity={(v) => update({ severity: v })}
          filterScanner={filters.scanner}
          onScanner={(v) => update({ scanner: v })}
          scannerSources={scannerSources(report)}
          query={filters.query}
          onQuery={(v) => update({ query: v })}
          onClear={clear}
          activeFilters={labels}
          onOpen={(f) => { window.location.hash = `#/findings/${encodeURIComponent(f.id)}`; }}
        />
      </RequireReport>
      <FindingDrawer finding={selected} byId={byId} report={report} onClose={() => { window.location.hash = "#/findings"; }} onTriageSaved={refreshReport} />
    </>
  );
}
