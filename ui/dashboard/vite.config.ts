import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The dashboard is served by Go at /scout/ui/ and embedded from ../dist.
export default defineConfig({
  base: "/scout/ui/",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    assetsInlineLimit: 0, // keep fonts as files so they cache
  },
  server: {
    proxy: {
      "/scout/api": "http://localhost:9090",
      "/scout/ws": { target: "ws://localhost:9090", ws: true },
    },
  },
});
