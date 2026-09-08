import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/* Dev proxy: every backend route the UI calls (keep in sync with src/lib/api.js
   and backend/app/main.py). Keys are path prefixes, so each entry also covers
   its subpaths — e.g. "/reports" forwards /reports/{id} and /reports/{id}/sarif,
   "/plans" forwards /plans, /plans/{pid} and /plans/verify. Full coverage:
   /health, /scans, /reports/*, /scan-history, /scan-delta, /triage,
   /validations/*, /code-analysis/*, /plans*. Backend routes stay root-level
   (no /api prefix) because backend/tests assert those exact paths. */
const API_PATHS = ["/health", "/scans", "/reports", "/scan-history", "/scan-delta",
  "/triage", "/validations", "/code-analysis", "/plans"];

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: Object.fromEntries(
      API_PATHS.map((p) => [p, "http://localhost:8000"]),
    ),
  },
});
