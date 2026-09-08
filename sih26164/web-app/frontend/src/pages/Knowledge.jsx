import React from "react";
import { getComponents } from "../lib/selectors.js";
import { useStore } from "../store.jsx";
import KnowledgeExplorer from "../components/KnowledgeExplorer.jsx";
import { PageHead, RequireReport } from "./_shared.jsx";

export default function Knowledge() {
  const { report, loading } = useStore();
  return (
    <>
      <PageHead eyebrow="SECURITY KNOWLEDGE" title="Knowledge" sub="Advisory guidance matched deterministically to findings. The engine stays authoritative — knowledge never changes evidence, severity, or priority." />
      <RequireReport report={report} loading={loading} title="NO KNOWLEDGE CONTEXT">
        <KnowledgeExplorer report={report} components={getComponents(report)} />
      </RequireReport>
    </>
  );
}
