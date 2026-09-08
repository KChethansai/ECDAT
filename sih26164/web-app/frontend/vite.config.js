import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/* Dev proxy: every backend route the UI calls (keep in sync with lib/api.js). */
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
