import React, { useMemo, useState } from "react";
import { activeFilterLabels, filterFindings, findingById, getComponents, scannerSources } from "../lib/selectors.js";
import { useStore } from "../store.jsx";
import FindingsExplorer from "../components/FindingsExplorer.jsx";
import FindingDrawer from "../components/FindingDrawer.jsx";
import { PageHead, RequireReport } from "./_shared.jsx";

export default function Findings({ findingId }) {
  const { report, scanId, refreshReport } = useStore();
  const components = useMemo(() => getComponents(report), [report]);
  const [priority, setPriority] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [scanner, setScanner] = useState("all");
  const [query, setQuery] = useState("");

  const visible = useMemo(
    () => filterFindings(components, { priority, severity, scanner, query }),
    [components, priority, severity, scanner, query],
  );
  const labels = useMemo(
    () => activeFilterLabels({ priority, severity, scanner, query }),
    [priority, severity, scanner, query],
  );
  const selected = findingId ? findingById(report, findingId) : null;
  const byId = useMemo(() => Object.fromEntries(components.map((f) => [f.id, f])), [components]);

  return (
    <>
      <PageHead eyebrow="SECURITY FINDINGS" title="Findings" sub="Severity → algorithm → location → evidence → recommendation. Select a row for the full analyst workspace." />
      <RequireReport report={report} title="NO FINDINGS">
        <FindingsExplorer
          components={components}
          visible={visible}
          total={components.length}
          filterPriority={priority}
          onPriority={setPriority}
          filterSeverity={severity}
          onSeverity={setSeverity}
          filterScanner={scanner}
          onScanner={setScanner}
          scannerSources={scannerSources(report)}
          query={query}
          onQuery={setQuery}
          onClear={() => { setPriority("all"); setSeverity("all"); setScanner("all"); setQuery(""); }}
          activeFilters={labels}
          onOpen={(f) => { window.location.hash = `#/findings/${encodeURIComponent(f.id)}`; }}
        />
      </RequireReport>
      <FindingDrawer finding={selected} byId={byId} report={report} onClose={() => { window.location.hash = "#/findings"; }} onTriageSaved={refreshReport} />
    </>
  );
}
