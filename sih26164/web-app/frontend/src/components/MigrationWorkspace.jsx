import React, { useMemo } from "react";
import { arr, obj, str } from "../lib/report.js";
import { PriorityBadge, StatusBadge } from "./Badges.jsx";
import { SectionEmpty } from "./States.jsx";

const BUCKETS = ["Immediate", "Near-term", "Planned", "Monitor"];
const BUCKET_MEANING = {
  Immediate: "P0 / critical — investigate now.",
  "Near-term": "P1 / high — sequence next.",
  Planned: "P2 / medium — schedule.",
  Monitor: "P3 / low — track.",
};

export default function MigrationWorkspace({ migration }) {
  const plan = obj(migration);
  const workItems = arr(plan.workItems);
  const roadmap = obj(plan.roadmap);
  const assumptions = arr(plan.assumptions);
  const byId = useMemo(() => Object.fromEntries(workItems.map((w) => [w.id, w])), [workItems]);

  return (
    <section className="section" aria-label="Migration workspace">
      <div className="section-head">
        <div>
          <p className="eyebrow">MIGRATION WORKSPACE</p>
          <h2 className="section-title">What to migrate first, and why</h2>
          <p className="section-sub">Discovery → risk → decision → migration. Buckets derive from priority/severity only — never calendar dates, costs, or completion claims.</p>
        </div>
      </div>
      {!migration || workItems.length === 0 ? (
        <div className="card">
          <SectionEmpty>
            {migration ? "No migration work items for this report — nothing met the migration heuristics." : "Migration intelligence appears here after a scan."}
          </SectionEmpty>
        </div>
      ) : (
        <>
          <div className="buckets">
            {BUCKETS.map((bucket) => {
              const ids = arr(roadmap[bucket]);
              return (
                <div key={bucket} className="bucket" data-bucket={bucket} aria-label={`${bucket} migration items`}>
                  <h3>
                    {bucket} <span className="badge" data-tone="muted">{ids.length}</span>
                  </h3>
                  <p className="meaning">{BUCKET_MEANING[bucket]}</p>
                  {ids.length === 0 ? (
                    <p className="meaning">Nothing in this bucket for the current report.</p>
                  ) : (
                    ids.map((id, n) => {
                      const item = byId[id];
                      if (!item) return null;
                      return (
                        <article key={id} className="workitem" data-p={str(item.priority, "P3")} style={{ animationDelay: `${Math.min(n, 6) * 40}ms` }}>
                          <div className="badge-row">
                            <PriorityBadge value={item.priority} />
                            <StatusBadge value={item.status} />
                          </div>
                          <p>
                            <strong className="mono">{str(item.family, "?")}</strong> <span style={{ color: "var(--text-muted)" }}>· {str(item.title, "")}</span>
                          </p>
                          <p>{str(item.reason, "—")}</p>
                          <p>
                            <strong>Direction:</strong> {str(item.direction, "Review manually")}
                          </p>
                          {str(item.directionNotes) ? <p>{item.directionNotes}</p> : null}
                          <p className="flags">
                            Artifacts: {item.artifactCount ?? arr(item.artifacts).length}
                            {item.hsmInvolved ? " · involves HSM (config evidence)" : ""}
                            {item.cloudInvolved ? " · involves cloud (config evidence)" : ""}
                            {item.runtimeObserved ? " · runtime-observed" : ""}
                          </p>
                          {arr(item.unknowns).length > 0 ? <p className="flags">Unknowns: {item.unknowns.join("; ")}</p> : null}
                          {str(item.validation) ? <p className="flags">Validation: {item.validation}</p> : null}
                        </article>
                      );
                    })
                  )}
                </div>
              );
            })}
          </div>
          {assumptions.length > 0 ? <p className="assumptions">Assumptions: {assumptions.join(" · ")}</p> : null}
        </>
      )}
    </section>
  );
}
