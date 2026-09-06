import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/health": "http://localhost:8000", "/scans": "http://localhost:8000", "/reports": "http://localhost:8000" } },
});
