import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const rootDir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    dedupe: ["react", "react-dom"],
    alias: {
      "@grdr/tokens/tokens.css": resolve(rootDir, "packages/tokens/src/tokens.css"),
      "@grdr/i18n": resolve(rootDir, "packages/i18n/src/index.ts"),
      "@grdr/api": resolve(rootDir, "packages/api/src/index.ts"),
      "@grdr/ui": resolve(rootDir, "packages/ui/src/index.ts"),
      "@grdr/kit": resolve(rootDir, "packages/kit/src/index.ts"),
      "@grdr/console": resolve(rootDir, "apps/console/src/App.tsx"),
      "@grdr/operator": resolve(rootDir, "apps/operator/src/OperatorApp.tsx"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./tests/test-setup.ts",
    include: ["tests/**/*.test.tsx"],
  },
});
