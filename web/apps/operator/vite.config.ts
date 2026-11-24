import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const appDir = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(appDir, "../..");

export default defineConfig({
  root: appDir,
  plugins: [react()],
  resolve: {
    alias: {
      "@grdr/tokens/tokens.css": resolve(webRoot, "packages/tokens/src/tokens.css"),
      "@grdr/i18n": resolve(webRoot, "packages/i18n/src/index.ts"),
      "@grdr/api": resolve(webRoot, "packages/api/src/index.ts"),
      "@grdr/ui": resolve(webRoot, "packages/ui/src/index.ts"),
      "@grdr/kit": resolve(webRoot, "packages/kit/src/index.ts"),
    },
  },
  server: {
    port: 5174,
    proxy: {
      "/grdr.": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
      },
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: resolve(webRoot, "dist-operator"),
    emptyOutDir: true,
  },
});
