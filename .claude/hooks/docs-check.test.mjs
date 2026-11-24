// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Unit tests for design-doc alignment and banned-stack checks in .claude/hooks/docs-check.mjs.
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  checkPrBodyAlignment,
  checkWebStack,
  evaluateEngineeringPayload,
  isWebPackageJsonPath,
} from "./docs-check.mjs";

test("isWebPackageJsonPath matches workspace manifests and excludes node_modules", () => {
  assert.equal(isWebPackageJsonPath("web/package.json"), true);
  assert.equal(isWebPackageJsonPath("web/apps/console/package.json"), true);
  assert.equal(isWebPackageJsonPath("web/packages/ui/package.json"), true);
  assert.equal(isWebPackageJsonPath("web/node_modules/next/package.json"), false);
  assert.equal(isWebPackageJsonPath("web/apps/console/node_modules/express/package.json"), false);
  assert.equal(isWebPackageJsonPath("web/apps/console/src/App.tsx"), false);
  assert.equal(isWebPackageJsonPath("package.json"), false);
});

test("checkWebStack rejects unapproved frameworks, SSR tools, and Node DB ORMs", () => {
  const banned = [
    ["next", "^15.0.0"],
    ["nuxt", "^3.16.0"],
    ["express", "^4.21.0"],
    ["fastify", "^5.0.0"],
    ["koa", "^2.15.0"],
    ["@nestjs/core", "^11.0.0"],
    ["mongodb", "^6.0.0"],
    ["mongoose", "^8.0.0"],
    ["prisma", "^6.0.0"],
    ["drizzle-orm", "^0.41.0"],
    ["astro", "^5.0.0"],
    ["@remix-run/react", "^2.16.0"],
    ["svelte", "^5.0.0"],
    ["vue", "^3.5.0"],
  ];

  for (const [pkg, version] of banned) {
    const manifest = JSON.stringify({
      name: "@grdr/console",
      dependencies: {
        react: "^19.1.0",
        [pkg]: version,
      },
    });
    const found = checkWebStack("web/apps/console/package.json", manifest);
    assert.ok(
      found.some((msg) => msg.includes(`"${pkg}"`) && msg.includes("D-33/D-42")),
      `expected ${pkg} to be rejected, got: ${found.join("\n")}`,
    );
  }
});

test("checkWebStack catches banned packages in devDependencies and partial edit_file snippets", () => {
  const devManifest = JSON.stringify({
    name: "grdr-web-workspace",
    devDependencies: {
      vite: "^6.3.0",
      prisma: "^6.0.0",
    },
  });
  const devFound = checkWebStack("web/package.json", devManifest);
  assert.equal(devFound.length, 1);
  assert.match(devFound[0], /"prisma"/);

  const partialSnippet = '    "react-dom": "^19.1.0",\n    "next": "^15.0.0"\n';
  const snippetDeny = evaluateEngineeringPayload(
    {
      toolCall: {
        name: "edit_file",
        args: {
          Path: "/repo/web/apps/console/package.json",
          Replacement: partialSnippet,
        },
      },
      cwd: "/repo",
    },
    "/repo",
  );
  assert.equal(snippetDeny.length, 1);
  assert.match(snippetDeny[0], /"next"/);
});

test("checkWebStack allows approved Vite, React 19, Astryx, TanStack, and visualization packages", () => {
  const validManifest = JSON.stringify({
    name: "@grdr/console",
    dependencies: {
      "@astryxdesign/core": "0.7.17",
      "@grdr/ui": "workspace:*",
      "@tanstack/react-router": "^1.120.0",
      "@ui-sdk/react": "0.1.0-beta.16",
      "@xyflow/react": "^13.0.3",
      codemirror: "^6.0.1",
      echarts: "6.1.0",
      "openapi-fetch": "^0.13.0",
      react: "^19.1.0",
      "react-dom": "^19.1.0",
    },
    devDependencies: {
      vite: "^6.3.0",
      vitest: "^4.1.12",
    },
  });
  assert.deepEqual(checkWebStack("web/apps/console/package.json", validManifest), []);
});

test("checkPrBodyAlignment requires both an issue link and a design doc or decision/principle ID", () => {
  const missingBoth = checkPrBodyAlignment("Implements a feature.");
  assert.equal(missingBoth.length, 2);

  const missingDesign = checkPrBodyAlignment("Closes #50\n\nImplements guard.");
  assert.equal(missingDesign.length, 1);
  assert.match(missingDesign[0], /governing docs\/design\//);

  const missingIssue = checkPrBodyAlignment("Implements guard per D-42.");
  assert.equal(missingIssue.length, 1);
  assert.match(missingIssue[0], /accompanying GitHub issue/);

  assert.deepEqual(checkPrBodyAlignment("Closes #50\n\nAligned with D-42 and P14."), []);
  assert.deepEqual(checkPrBodyAlignment("Fixes #50\n\nSee docs/design/27-web-console-ux.md."), []);
  assert.deepEqual(checkPrBodyAlignment("Resolves #50\n\nFollows P17."), []);
});
