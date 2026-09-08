import React from "react";
import { href } from "../lib/router.js";
import { EmptyState } from "../components/States.jsx";

export function PageHead({ eyebrow, title, sub }) {
  return (
    <div className="page-head">
      <p className="eyebrow">{eyebrow}</p>
      <h1 className="page-title">{title}</h1>
      {sub ? <p className="section-sub">{sub}</p> : null}
    </div>
  );
}

export function RequireReport({ report, loading, title, children }) {
  if (report) return <>{children}</>;
  return (
    <EmptyState
      title={title || "NO REPORT"}
      body={
        <>
          This view needs a scan report. <a href={href("scan")}>Run a scan</a>{" "}
          {loading ? "or wait for the running scan to finish" : "to populate it"}.
        </>
      }
      hint="Reports live in backend memory; restarting the API clears them."
    />
  );
}
