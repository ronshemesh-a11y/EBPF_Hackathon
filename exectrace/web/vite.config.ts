import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// Build the SPA into the Go server package so it can be embedded with
// go:embed and shipped inside the single `server` binary.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: resolve(__dirname, "../internal/server/dist"),
    emptyOutDir: true,
  },
  server: {
    // `npm run dev` proxies API/ws to the running Go server on :8080.
    proxy: {
      "/api": "http://localhost:8080",
      "/ws": { target: "ws://localhost:8080", ws: true },
    },
  },
});
