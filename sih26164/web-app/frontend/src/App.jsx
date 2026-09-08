import React from "react";
import { useHashRoute } from "./hooks.js";
import { AppProvider, useStore } from "./store.jsx";
import Shell from "./components/Shell.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Scan from "./pages/Scan.jsx";
import Findings from "./pages/Findings.jsx";
import Inventory from "./pages/Inventory.jsx";
import Risk from "./pages/Risk.jsx";
import Migration from "./pages/Migration.jsx";
import Code from "./pages/Code.jsx";
import Validation from "./pages/Validation.jsx";
import History from "./pages/History.jsx";
import Knowledge from "./pages/Knowledge.jsx";
import Reports from "./pages/Reports.jsx";
import Settings from "./pages/Settings.jsx";
import { href } from "./lib/router.js";

function NotFound() {
  return (
    <div className="card">
      <p className="eyebrow">NOT FOUND</p>
      <h1 className="page-title">Unknown section</h1>
      <p className="section-sub">
        That route does not exist. <a href={href("dashboard")}>Back to Dashboard</a>.
      </p>
    </div>
  );
}

function RouteView({ route }) {
  const { scanId } = useStore();
  switch (route.name) {
    case "dashboard":
      return <Dashboard />;
    case "scan":
      return <Scan />;
    case "findings":
      // Remount per report so filters and drawer selection reset on replacement.
      return <Findings key={scanId} findingId={route.param} />;
    case "inventory":
      return <Inventory />;
    case "risk":
      return <Risk />;
    case "migration":
      return <Migration />;
    case "code":
      return <Code key={scanId} />;
    case "validation":
      return <Validation key={scanId} />;
    case "history":
      return <History />;
    case "knowledge":
      return <Knowledge />;
    case "reports":
      return <Reports />;
    case "settings":
      return <Settings />;
    default:
      return <NotFound />;
  }
}

function Chrome() {
  const [route] = useHashRoute();
  const { error, downloadReport, hasReport } = useStore();
  return (
    <Shell route={route} error={error} onExport={downloadReport} canExport={hasReport}>
      <RouteView route={route} />
    </Shell>
  );
}

export default function App() {
  return (
    <AppProvider>
      <Chrome />
    </AppProvider>
  );
}
