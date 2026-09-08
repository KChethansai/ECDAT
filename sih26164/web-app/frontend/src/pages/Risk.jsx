import React from "react";
import { algorithmFamilies, getComponents, quantumExposure } from "../lib/selectors.js";
import { useStore } from "../store.jsx";
import { ExposurePanel, RiskOverview } from "../components/Metrics.jsx";
import { PageHead, RequireReport } from "./_shared.jsx";

export default function Risk() {
  const { report, loading } = useStore();
  const fams = algorithmFamilies(report);
  return (
    <>
      <PageHead eyebrow="RISK & EXPOSURE" title="Risk" sub="Severity, priority, evidence strength, and quantum exposure — all derived from the current report." />
      <RequireReport report={report} loading={loading} title="NO RISK DATA">
        <RiskOverview report={report} components={getComponents(report)} />
        <ExposurePanel report={report} components={getComponents(report)} />
        <div className="section">
          <div className="card">
            <p className="eyebrow">ALGORITHM FAMILIES</p>
            <p className="section-sub">
              {quantumExposure(report)} finding(s) use quantum-vulnerable asymmetric families. Family grouping is a deterministic name canonicalization, not a cryptographic judgment.
            </p>
            <div className="table-wrap">
              <table className="data">
                <caption>Findings grouped by canonical algorithm family</caption>
                <thead>
                  <tr><th scope="col">Family</th><th scope="col">Findings</th><th scope="col">Critical / high</th><th scope="col">Libraries</th></tr>
                </thead>
                <tbody>
                  {fams.map((g) => (
                    <tr key={g.family}>
                      <td><b className="mono">{g.family}</b></td>
                      <td>{g.count}</td>
                      <td>{g.criticalHigh}</td>
                      <td className="cell-sub mono">{g.libraries.join(", ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </RequireReport>
    </>
  );
}
