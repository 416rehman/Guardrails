// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

const pkgDir = dirname(fileURLToPath(import.meta.url));
const webDir = resolve(pkgDir, "../..");

export default defineConfig({
  root: pkgDir,
  plugins: [react()],
  resolve: {
    dedupe: ["react", "react-dom"],
    alias: {
      "@grdr/tokens/tokens.css": resolve(webDir, "packages/tokens/src/tokens.css"),
      "@grdr/tokens": resolve(webDir, "packages/tokens/src/index.ts"),
      "@grdr/i18n": resolve(webDir, "packages/i18n/src/index.ts"),
      "@grdr/ui": resolve(webDir, "packages/ui/src/index.ts"),
      "@grdr/kit": resolve(webDir, "packages/kit/src/index.ts"),
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/__tests__/**/*.test.tsx"],
  },
});
