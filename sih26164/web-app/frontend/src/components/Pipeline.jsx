import React from "react";
import { IconBox, IconCompass, IconEvidence, IconFlag, IconGauge, IconMigrate, IconScan } from "./icons.jsx";

/* DISCOVERY → EVIDENCE → RISK → PRIORITY → RECOMMENDATION → MIGRATION → CBOM.
   Visual state only: active while scanning, completed once a report exists. */
const STAGES = [
  { key: "DISCOVERY", icon: IconScan },
  { key: "EVIDENCE", icon: IconEvidence },
  { key: "RISK", icon: IconGauge },
  { key: "PRIORITY", icon: IconFlag },
  { key: "RECOMMENDATION", icon: IconCompass },
  { key: "MIGRATION", icon: IconMigrate },
  { key: "CBOM", icon: IconBox },
];

export default function Pipeline({ hasReport, loading }) {
  return (
    <ol className="pipeline" aria-label="ECDAT analysis pipeline">
      {STAGES.map((s, i) => {
        const Icon = s.icon;
        const cls = hasReport && !loading ? "done" : loading ? "active" : "";
        return (
          <li key={s.key} className={cls} aria-current={loading && i === 0 ? "step" : undefined}>
            <span className="node">
              <span className="ico">
                <Icon size={13} />
              </span>
              <span className="lbl">{s.key}</span>
            </span>
            {i < STAGES.length - 1 ? <span className="conn" aria-hidden="true" /> : null}
          </li>
        );
      })}
    </ol>
  );
}

