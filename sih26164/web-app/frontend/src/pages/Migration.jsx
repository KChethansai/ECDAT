import React from "react";
import { href } from "../lib/router.js";
import { migration } from "../lib/selectors.js";
import { useStore } from "../store.jsx";
import MigrationWorkspace from "../components/MigrationWorkspace.jsx";
import { RecommendationsList, RelationshipsSection } from "../components/RecommendationsPanel.jsx";
import { getComponents } from "../lib/selectors.js";
import { PageHead, RequireReport } from "./_shared.jsx";

export default function Migration() {
  const { report, loading } = useStore();
  const components = getComponents(report);
  const byId = Object.fromEntries(components.map((f) => [f.id, f]));
  return (
    <>
      <PageHead eyebrow="MIGRATION WORKSPACE" title="Migration" sub="Finding → affected surface → options → your choice → plan → verification. The planner never auto-chooses." />
      <RequireReport report={report} loading={loading} title="NO MIGRATION DATA">
        <MigrationWorkspace migration={migration(report)} />
        <RelationshipsSection inventory={report?.intelligence?.inventory} byId={byId} />
        <RecommendationsList components={components} report={report} />
        <p className="section-sub">
          Per-finding remediation options and plan generation live with each code finding on the <a href={href("code")}>Code Intel page</a>.
        </p>
      </RequireReport>
    </>
  );
}
