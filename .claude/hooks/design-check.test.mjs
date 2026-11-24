// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
import assert from "node:assert/strict";
import { test } from "node:test";
import { checkDesignContent, evaluateDesignToolPayload } from "./design-check.mjs";

test("rejects raw hex color outside token owners", () => {
  const findings = checkDesignContent(
    "web/apps/console/src/styles.css",
    ".panel { color: #ff00aa; }",
  );
  assert.ok(findings.some((f) => f.includes("raw #hex colors")));
});

test("allows raw hex color inside web/packages/tokens and desktop theme.rs", () => {
  assert.deepEqual(
    checkDesignContent("web/packages/tokens/src/tokens.css", ":root { --bg-canvas: #FFFFFF; }"),
    [],
  );
  assert.deepEqual(
    checkDesignContent(
      "desktop/grdr-desktop/src/theme.rs",
      "const CANVAS_LIGHT: &str = \"#FFFFFF\";",
    ),
    [],
  );
});

test("rejects indigo/violet defaults, emojis, left border stripes, CDNs, and buzzwords", () => {
  const sample = `
    .card { border-inline-start: 3px solid var(--tone-allow); box-shadow: 0 0 20px rgba(139,92,246,0.5); }
    const title = "World-class posture monitor";
    const cdn = "https://fonts.googleapis.com/css2?family=Inter";
    const icon = "🚀";
  `;
  const findings = checkDesignContent("web/apps/console/src/pages/HomePage.tsx", sample);
  assert.ok(findings.length >= 4, findings.join("\n"));
});

test("rejects direct @astryxdesign or @ui-sdk import outside web/packages/ui", () => {
  const findings = checkDesignContent(
    "web/packages/kit/src/ModeControl.tsx",
    'import { SegmentedControl } from "@ui-sdk/react/segmented-control";',
  );
  assert.ok(findings.some((f) => f.includes("ARCH-101..104")));
  assert.deepEqual(
    checkDesignContent(
      "web/packages/ui/src/primitives.tsx",
      'import { SegmentedControl } from "@ui-sdk/react/segmented-control";',
    ),
    [],
  );
});

test("evaluates both Antigravity and Claude Code write payloads", () => {
  const agyDeny = evaluateDesignToolPayload(
    {
      toolCall: {
        name: "write_file",
        args: {
          Path: "D:/repo/web/apps/console/src/Foo.tsx",
          Content: "export const x = 'Built for seamless posture tracking';",
        },
      },
    },
    "D:/repo",
  );
  assert.ok(agyDeny.length >= 2);

  const claudeDeny = evaluateDesignToolPayload(
    {
      tool_name: "Edit",
      tool_input: {
        file_path: "D:/repo/web/apps/console/src/Foo.css",
        new_string: ".box { border-left: 4px solid red; font-family: 'Space Grotesk'; }",
      },
    },
    "D:/repo",
  );
  assert.ok(claudeDeny.length >= 2);
});
