import React, { Suspense } from "react";
import { useHashRoute } from "./hooks.js";
import { AppProvider, useStore } from "./store.jsx";
import Shell from "./components/Shell.jsx";
import { RouteSkeleton } from "./components/States.jsx";
import { href } from "./lib/router.js";

// Lazy per-route splits: the shell (nav, health, topbar) renders instantly while
// the section chunk loads behind a skeleton — no blank flash on navigation.
const Dashboard = React.lazy(() => import("./pages/Dashboard.jsx"));
const Scan = React.lazy(() => import("./pages/Scan.jsx"));
const Findings = React.lazy(() => import("./pages/Findings.jsx"));
const Inventory = React.lazy(() => import("./pages/Inventory.jsx"));
const Risk = React.lazy(() => import("./pages/Risk.jsx"));
const Migration = React.lazy(() => import("./pages/Migration.jsx"));
const Code = React.lazy(() => import("./pages/Code.jsx"));
const Validation = React.lazy(() => import("./pages/Validation.jsx"));
const History = React.lazy(() => import("./pages/History.jsx"));
const Knowledge = React.lazy(() => import("./pages/Knowledge.jsx"));
const Reports = React.lazy(() => import("./pages/Reports.jsx"));
const Settings = React.lazy(() => import("./pages/Settings.jsx"));

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

/** Catches lazy-chunk load failures (stale deploy, offline split) so a broken
 *  section shows a retry instead of hanging on the skeleton forever. */
class RouteErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { failed: false };
  }
  static getDerivedStateFromError() {
    return { failed: true };
  }
  componentDidUpdate(prevProps) {
    if (prevProps.resetKey !== this.props.resetKey && this.state.failed) {
      this.setState({ failed: false });
    }
  }
  render() {
    if (this.state.failed) {
      return (
        <div className="card" role="alert">
          <p className="eyebrow">SECTION FAILED TO LOAD</p>
          <p className="section-sub">
            This section did not load (stale assets or network blip).{" "}
            <button type="button" className="row-button" onClick={() => window.location.reload()}>
              Reload the app
            </button>
            .
          </p>
        </div>
      );
    }
    return this.props.children;
  }
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
      <RouteErrorBoundary resetKey={route.name}>
        <Suspense key={route.name} fallback={<RouteSkeleton />}>
          <RouteView route={route} />
        </Suspense>
      </RouteErrorBoundary>
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
