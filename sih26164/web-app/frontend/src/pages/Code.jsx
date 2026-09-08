import React from "react";
import { codeAnalysis } from "../lib/selectors.js";
import { useStore } from "../store.jsx";
import CodebaseHealth from "../components/CodebaseHealth.jsx";
import { SectionEmpty } from "../components/States.jsx";
import { PageHead, RequireReport } from "./_shared.jsx";

export default function Code() {
  const { report, loading, refreshReport } = useStore();
  const analysis = codeAnalysis(report);
  return (
    <>
      <PageHead eyebrow="CODE INTELLIGENCE" title="Code Intel" sub="Engineering observations (dead code, duplication, complexity…) — separate from cryptographic severity." />
      <RequireReport report={report} loading={loading} title="NO CODE ANALYSIS">
        {analysis ? (
          <CodebaseHealth analysis={analysis} report={report} onChanged={refreshReport} />
        ) : (
          <div className="card">
            <SectionEmpty>
              This scan did not include code analysis. Re-run from the Scan workspace with “code analysis” ticked — crypto findings are never affected by that option.
            </SectionEmpty>
          </div>
        )}
      </RequireReport>
    </>
  );
}
