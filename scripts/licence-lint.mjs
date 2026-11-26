// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Enforces SPDX headers and licence rules per security/supply-chain/licence-headers.toml,
// licences.toml, brand.toml, and the fixture + glob-cases suite.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { closeSync, fstatSync, openSync, readdirSync, readFileSync } from "node:fs";
import { posix, resolve } from "node:path";

import { compileGlob } from "./glob-match.mjs";
import { parseSimpleToml } from "./toml-parse.mjs";

const ROOT = resolve(import.meta.dirname, "..");
const SPDX_ID_KEY = ["SPDX", "License", "Identifier"].join("-");
const GPL_FAMILY_RE = /\b(?:LGPL|AGPL|GPL)-[A-Za-z0-9.-]+/;
const SPDX_DECL_RE = new RegExp(`(?:^|//|#|/\\*|\\*|<!--|--)\\s*${SPDX_ID_KEY}\\s*:`, "i");
const SPDX_GPL_LINE_RE = new RegExp(`${SPDX_ID_KEY}\\s*:[^\\n]*\\b(?:LGPL|AGPL|GPL)-[A-Za-z0-9.-]+`, "i");
const CARGO_GPL_RE = /^\s*license\s*=\s*"[^"]*\b(?:LGPL|AGPL|GPL)-[A-Za-z0-9.-]+/m;
const JSON_GPL_RE = /^\s*"license"\s*:\s*"[^"]*\b(?:LGPL|AGPL|GPL)-[A-Za-z0-9.-]+/m;
const NEGATIVE_DENY_FIXTURE_PREFIX = "security/supply-chain/fixtures/deny/";

// Untouched pre-existing Wave-0C baseline files lacking SPDX headers (primarily UI files outside
// this non-UI PR's visual-audit scope and pinned CI helper scripts). Any new file OR any modified
// file on the branch MUST carry the full two-line SPDX header.
const LEGACY_MISSING_HEADER_BASELINE = new Set([
  ".github/actions/pins/read_pins.py",
  ".github/actions/pins/test_read_pins.py",
  ".github/actions/tree-paths/check_tree.py",
  ".github/actions/tree-paths/pin_rules.py",
  ".github/actions/tree-paths/pinned_toolchain.py",
  ".github/actions/tree-paths/test_check_tree.py",
  ".github/actions/tree-paths/test_pinned_toolchain.py",
  ".github/actions/tree-paths/test_trust_core_touched.py",
  ".github/actions/tree-paths/tree_fixtures.py",
  ".github/actions/tree-paths/trust_core_touched.py",
  ".github/actions/tree-paths/workflow_reader.py",
  "crates/grdr-interface-gen/src/emit_rust.rs",
  "crates/grdr-interface-gen/src/emit_web.rs",
  "crates/grdr-interface-gen/src/lib.rs",
  "crates/grdr-interface-gen/src/loader.rs",
  "crates/grdr-interface-gen/src/main.rs",
  "crates/grdr-interface-gen/src/model.rs",
  "crates/grdr-messages/src/generated.rs",
  "crates/grdr-messages/src/lib.rs",
  "crates/grdr-strings/src/generated.rs",
  "crates/grdr-strings/src/lib.rs",
  "crates/grdr-ui-model/src/demo.rs",
  "crates/grdr-ui-model/src/lib.rs",
  "crates/grdr-ui-model/src/reduce.rs",
  "deploy/qa/run-airgap-s31.sh",
  "deploy/qa/run-slice0-e2e.sh",
  "desktop/grdr-desktop/src/icons.rs",
  "desktop/grdr-desktop/src/kit.rs",
  "desktop/grdr-desktop/src/kit_widgets.rs",
  "desktop/grdr-desktop/src/main.rs",
  "desktop/grdr-desktop/src/screens/activity.rs",
  "desktop/grdr-desktop/src/screens/first_run.rs",
  "desktop/grdr-desktop/src/screens/home.rs",
  "desktop/grdr-desktop/src/screens/mod.rs",
  "desktop/grdr-desktop/src/screens/privacy.rs",
  "desktop/grdr-desktop/src/screens/rules.rs",
  "desktop/grdr-desktop/src/screens/settings.rs",
  "desktop/grdr-desktop/src/screens/why_card.rs",
  "desktop/grdr-desktop/src/theme.rs",
  "desktop/grdr-desktop/src/viz.rs",
  "programs/grdr-approve/src/main.rs",
  "programs/grdr-tray/src/main.rs",
  "web/apps/console/src/App.tsx",
  "web/apps/console/src/ConsoleContext.tsx",
  "web/apps/console/src/ConsoleShell.tsx",
  "web/apps/console/src/components/Breadcrumbs.tsx",
  "web/apps/console/src/components/CommandPaletteDialog.tsx",
  "web/apps/console/src/components/PagerBar.tsx",
  "web/apps/console/src/components/SidebarNav.tsx",
  "web/apps/console/src/components/navigation.ts",
  "web/apps/console/src/components/useConsoleStream.ts",
  "web/apps/console/src/components/useServerPage.ts",
  "web/apps/console/src/consoleState.ts",
  "web/apps/console/src/main.tsx",
  "web/apps/console/src/pages/BrowserPoliciesSection.tsx",
  "web/apps/console/src/pages/CompliancePage.tsx",
  "web/apps/console/src/pages/ConnectMdmAndIntegrations.tsx",
  "web/apps/console/src/pages/ConnectSection.tsx",
  "web/apps/console/src/pages/CoveragePage.tsx",
  "web/apps/console/src/pages/FindingsSection.tsx",
  "web/apps/console/src/pages/FirstRunPage.tsx",
  "web/apps/console/src/pages/HomePage.tsx",
  "web/apps/console/src/pages/InventoryAgentsSection.tsx",
  "web/apps/console/src/pages/InventoryEndpointsSection.tsx",
  "web/apps/console/src/pages/InventoryMcpAndSkills.tsx",
  "web/apps/console/src/pages/InventoryPage.tsx",
  "web/apps/console/src/pages/InventorySkillsSection.tsx",
  "web/apps/console/src/pages/KillSwitchControls.tsx",
  "web/apps/console/src/pages/ProtectPage.tsx",
  "web/apps/console/src/pages/ProtectRuleViews.tsx",
  "web/apps/console/src/pages/ProviderWorkbenchPage.tsx",
  "web/apps/console/src/pages/RespondPage.tsx",
  "web/apps/console/src/pages/RespondSections.tsx",
  "web/apps/console/src/pages/ReviewQueuePage.tsx",
  "web/apps/console/src/pages/SessionInspectorViews.tsx",
  "web/apps/console/src/pages/SessionListPane.tsx",
  "web/apps/console/src/pages/SessionsPage.tsx",
  "web/apps/console/src/pages/SettingsPrivacyPage.tsx",
  "web/apps/console/src/pages/TesterPage.tsx",
  "web/apps/console/src/pages/TraceWaterfall.tsx",
  "web/apps/console/src/pages/UserDetailSection.tsx",
  "web/apps/console/src/pages/UsersPage.tsx",
  "web/apps/console/src/queries.ts",
  "web/apps/console/src/router.tsx",
  "web/apps/console/src/searchSchema.ts",
  "web/apps/console/vite.config.ts",
  "web/apps/operator/src/OperatorApp.tsx",
  "web/apps/operator/src/OperatorBackupsView.tsx",
  "web/apps/operator/src/OperatorUpgradesView.tsx",
  "web/apps/operator/src/OperatorViews.tsx",
  "web/apps/operator/src/main.tsx",
  "web/apps/operator/src/queries.ts",
  "web/apps/operator/src/router.tsx",
  "web/apps/operator/vite.config.ts",
  "web/assets.d.ts",
  "web/e2e/global-setup.ts",
  "web/e2e/helpers.ts",
  "web/e2e/inventory-and-sessions-pagination.spec.ts",
  "web/e2e/overview-and-navigation.spec.ts",
  "web/e2e/protect-policy-and-tester.spec.ts",
  "web/e2e/respond-killswitch-and-approvals.spec.ts",
  "web/e2e/surfaces-and-operator.spec.ts",
  "web/packages/api/src/client-surfaces.ts",
  "web/packages/api/src/client.ts",
  "web/packages/api/src/connect.ts",
  "web/packages/api/src/index.ts",
  "web/packages/api/src/normalize-ops.ts",
  "web/packages/api/src/normalize-surfaces.ts",
  "web/packages/api/src/normalize.ts",
  "web/packages/api/src/types-connect.ts",
  "web/packages/api/src/types-surfaces.ts",
  "web/packages/api/src/types.ts",
  "web/packages/i18n/src/generated.ts",
  "web/packages/i18n/src/index.ts",
  "web/packages/i18n/src/present.ts",
  "web/packages/kit/src/ApprovalCard.tsx",
  "web/packages/kit/src/DeviceAssuranceDrawer.tsx",
  "web/packages/kit/src/EntityLink.tsx",
  "web/packages/kit/src/InsightTile.tsx",
  "web/packages/kit/src/ModeControl.tsx",
  "web/packages/kit/src/Quoted.tsx",
  "web/packages/kit/src/VerdictBadge.tsx",
  "web/packages/kit/src/ViewStateFrame.tsx",
  "web/packages/kit/src/WhyCardDrawer.tsx",
  "web/packages/kit/src/index.ts",
  "web/packages/tokens/src/index.ts",
  "web/packages/ui/src/assets.d.ts",
  "web/packages/ui/src/brand-icons.tsx",
  "web/packages/ui/src/charts.tsx",
  "web/packages/ui/src/components.tsx",
  "web/packages/ui/src/fleet-hex-map.tsx",
  "web/packages/ui/src/flow-graph.tsx",
  "web/packages/ui/src/index.ts",
  "web/packages/ui/src/primitives.tsx",
  "web/packages/ui/src/theme.tsx",
  "web/playwright.config.ts",
  "web/tests/console.test.tsx",
  "web/tests/surfaces.test.tsx",
  "web/tests/test-setup.ts",
  "web/vite.config.ts",
]);

function compileMatchers(patterns) {
  return (patterns || []).map((pat) => ({ pat, re: compileGlob(pat) }));
}

function matchesAny(compiled, relPath) {
  return compiled.some(({ re }) => re.test(relPath));
}

export function loadLicenceConfig(root = ROOT) {
  const hdrCfg = parseSimpleToml(
    readFileSync(resolve(root, "security/supply-chain/licence-headers.toml"), "utf8"),
  );
  const licCfg = parseSimpleToml(
    readFileSync(resolve(root, "security/supply-chain/licences.toml"), "utf8"),
  );
  const brandCfg = parseSimpleToml(
    readFileSync(resolve(root, hdrCfg.copyright.file), "utf8"),
  );
  const [holderSection, holderKey] = hdrCfg.copyright.key.split(".");
  const copyrightHolder = brandCfg[holderSection][holderKey];

  const allowedIdentifiers = new Set();
  for (const cls of licCfg.class || []) {
    for (const lic of cls.licences || []) {
      allowedIdentifiers.add(lic);
    }
  }
  const gplAllowedPrefixes = licCfg.banned?.gpl_allowed_under || ["bpf/"];

  return {
    copyrightHolder,
    defaultExpression: hdrCfg.default_expression || "Apache-2.0",
    shebangFirst: Boolean(hdrCfg.shebang_first),
    shebangPrefixes: hdrCfg.shebang_prefixes || ["#!/", "#! "],
    exemptMatchers: compileMatchers(hdrCfg.exempt),
    gplExemptMatchers: compileMatchers(hdrCfg.gpl_exempt),
    comments: Object.fromEntries(
      Object.entries(hdrCfg.comment || {}).map(([k, v]) => [k.toLowerCase(), v]),
    ),
    pathRules: (hdrCfg.path || []).map((entry) => ({
      glob: entry.glob,
      re: compileGlob(entry.glob),
      expression: entry.expression,
    })),
    allowedIdentifiers,
    gplAllowedPrefixes,
  };
}

export function classifyPath(relPath, cfg) {
  const norm = relPath.replace(/\\/g, "/");
  const base = posix.basename(norm);
  const dotIdx = base.lastIndexOf(".");
  const ext = dotIdx > 0 ? base.slice(dotIdx + 1).toLowerCase() : "";
  const commentPrefix = cfg.comments[ext] || null;
  const gplAllowed = cfg.gplAllowedPrefixes.some((p) => norm.startsWith(p));
  const gpl = matchesAny(cfg.gplExemptMatchers, norm)
    ? "skipped"
    : gplAllowed
      ? "allowed"
      : "refused";

  if (!commentPrefix) {
    return { header: "none", commentPrefix: null, expression: null, gpl };
  }
  if (matchesAny(cfg.exemptMatchers, norm)) {
    return { header: "exempt", commentPrefix, expression: null, gpl };
  }
  let expression = cfg.defaultExpression;
  for (const rule of cfg.pathRules) {
    if (rule.re.test(norm)) {
      expression = rule.expression;
    }
  }
  return { header: "required", commentPrefix, expression, gpl };
}

function splitLinesWithLfCheck(text) {
  const lines = [];
  let start = 0;
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === "\n") {
      lines.push({ text: text.slice(start, i), endedWithLf: true });
      start = i + 1;
    }
  }
  if (start < text.length) {
    lines.push({ text: text.slice(start), endedWithLf: false });
  }
  return lines;
}

function extractIdentifiers(expression) {
  return expression
    .split(/\s+(?:AND|OR|WITH)\s+/)
    .map((tok) => tok.trim().replace(/^\(+|\)+$/g, ""))
    .filter(Boolean);
}

function hasDisallowedGplDeclaration(relPath, text) {
  if (SPDX_GPL_LINE_RE.test(text)) return true;
  const base = posix.basename(relPath.replace(/\\/g, "/"));
  if (base === "Cargo.toml" && CARGO_GPL_RE.test(text)) return true;
  if (base === "package.json" && JSON_GPL_RE.test(text)) return true;
  if (base === "pyproject.toml" && CARGO_GPL_RE.test(text)) return true;
  return false;
}

export function checkFileBuffer(relPath, buf, cfg) {
  const normRel = relPath.replace(/\\/g, "/");
  if (normRel.startsWith(NEGATIVE_DENY_FIXTURE_PREFIX)) return null;
  const cls = classifyPath(relPath, cfg);
  if (cls.gpl === "refused") {
    const rawUtf8 = buf.toString("utf8");
    if (hasDisallowedGplDeclaration(relPath, rawUtf8)) {
      return `${relPath}: disallowed GPL/LGPL/AGPL identifier outside [${cfg.gplAllowedPrefixes.join(", ")}]`;
    }
  }
  if (cls.header !== "required") return null;

  if (buf.length >= 3 && buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) {
    return `${relPath}: UTF-8 BOM is forbidden`;
  }
  const text = buf.toString("utf8");
  const lines = splitLinesWithLfCheck(text);

  let hdrIdx = 0;
  if (
    cfg.shebangFirst &&
    lines.length > 0 &&
    cfg.shebangPrefixes.some((p) => lines[0].text.startsWith(p))
  ) {
    if (!lines[0].endedWithLf || lines[0].text.includes("\r")) {
      return `${relPath}: shebang line contains CR or lacks LF`;
    }
    hdrIdx = 1;
  }

  const lineId = lines[hdrIdx];
  const lineHolder = lines[hdrIdx + 1];
  const expectedId = `${cls.commentPrefix} ${SPDX_ID_KEY}: ${cls.expression}`;
  const expectedHolder = `${cls.commentPrefix} SPDX-FileCopyrightText: ${cfg.copyrightHolder}`;

  if (!lineId || !lineId.endedWithLf || lineId.text.includes("\r") || lineId.text !== expectedId) {
    return `${relPath}: expected line ${hdrIdx + 1} to be exactly \`${expectedId}\\n\``;
  }
  if (
    !lineHolder ||
    !lineHolder.endedWithLf ||
    lineHolder.text.includes("\r") ||
    lineHolder.text !== expectedHolder
  ) {
    return `${relPath}: expected line ${hdrIdx + 2} to be exactly \`${expectedHolder}\\n\``;
  }

  for (const ident of extractIdentifiers(cls.expression)) {
    if (!cfg.allowedIdentifiers.has(ident)) {
      return `${relPath}: licence identifier ${ident} is not on the allow-list`;
    }
  }
  if (cls.gpl === "refused" && GPL_FAMILY_RE.test(cls.expression)) {
    return `${relPath}: disallowed GPL/LGPL/AGPL expression ${cls.expression}`;
  }

  for (let i = hdrIdx + 1; i < lines.length; i += 1) {
    if (SPDX_DECL_RE.test(lines[i].text.trimStart())) {
      return `${relPath}: duplicate ${SPDX_ID_KEY} on line ${i + 1}`;
    }
  }
  return null;
}

export function runFixturesAndGlobCases(cfg, root = ROOT) {
  const globCasesCfg = parseSimpleToml(
    readFileSync(resolve(root, "security/supply-chain/fixtures/licence-lint/glob-cases.toml"), "utf8"),
  );
  for (const c of globCasesCfg.case || []) {
    const got = classifyPath(c.path, cfg);
    assert.equal(got.header, c.header, `glob-case header mismatch for ${c.path}`);
    assert.equal(got.gpl, c.gpl, `glob-case gpl mismatch for ${c.path}`);
    if (c.expression) {
      assert.equal(got.expression, c.expression, `glob-case expression mismatch for ${c.path}`);
    }
  }

  const fixRoot = resolve(root, "security/supply-chain/fixtures/licence-lint");
  let fixtureCount = 0;
  for (const dirEntry of readdirSync(fixRoot, { withFileTypes: true })) {
    if (!dirEntry.isDirectory()) continue;
    const dirPath = resolve(fixRoot, dirEntry.name);
    for (const fileEntry of readdirSync(dirPath, { withFileTypes: true })) {
      const buf = readRegularFileSafe(resolve(dirPath, fileEntry.name));
      if (!buf) continue;
      fixtureCount += 1;
      const err = checkFileBuffer(`fixtures/${dirEntry.name}/${fileEntry.name}`, buf, cfg);
      const expectPass = dirEntry.name.startsWith("good-");
      if (expectPass) {
        assert.equal(err, null, `expected passing fixture ${dirEntry.name}/${fileEntry.name} failed: ${err}`);
      } else {
        assert.notEqual(err, null, `expected failing fixture ${dirEntry.name}/${fileEntry.name} unexpectedly passed`);
      }
    }
  }
  return { globCases: (globCasesCfg.case || []).length, fixtures: fixtureCount };
}

function collectChangedFiles(root) {
  const changed = new Set();
  const baseSha = process.env.BASE?.trim();
  const headSha = process.env.HEAD?.trim();

  if (baseSha && headSha) {
    const prDiff = execFileSync("git", ["diff", "--name-only", `${baseSha}...${headSha}`], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    for (const line of prDiff.split(/\r?\n/)) {
      const trimmed = line.trim().replace(/\\/g, "/");
      if (trimmed) changed.add(trimmed);
    }
  } else {
    let resolvedMainDiff = false;
    try {
      const out = execFileSync("git", ["diff", "--name-only", "origin/main...HEAD"], {
        cwd: root,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
      for (const line of out.split(/\r?\n/)) {
        const trimmed = line.trim().replace(/\\/g, "/");
        if (trimmed) changed.add(trimmed);
      }
      resolvedMainDiff = true;
    } catch (error) {
      if (process.env.CI === "true") {
        throw new Error(
          `licence-lint fail-closed: unable to compute diff against origin/main in CI (${error.message})`,
        );
      }
    }
    if (!resolvedMainDiff && process.argv.includes("--strict-base")) {
      throw new Error("licence-lint fail-closed: --strict-base requested without resolvable origin/main");
    }
  }

  for (const args of [["diff", "--name-only", "--cached"], ["diff", "--name-only"]]) {
    const out = execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    for (const line of out.split(/\r?\n/)) {
      const trimmed = line.trim().replace(/\\/g, "/");
      if (trimmed) changed.add(trimmed);
    }
  }
  return changed;
}

function readRegularFileSafe(absPath) {
  let fd;
  try {
    fd = openSync(absPath, "r");
  } catch {
    return null;
  }
  try {
    if (!fstatSync(fd).isFile()) return null;
    return readFileSync(fd);
  } finally {
    closeSync(fd);
  }
}

function main() {
  const cfg = loadLicenceConfig(ROOT);
  const { globCases, fixtures } = runFixturesAndGlobCases(cfg, ROOT);
  const changedFiles = collectChangedFiles(ROOT);

  const tracked = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" })
    .trim()
    .split(/\r?\n/)
    .filter(Boolean);
  const untrackedNew = execFileSync("git", ["ls-files", "--others", "--exclude-standard"], {
    cwd: ROOT,
    encoding: "utf8",
  })
    .trim()
    .split(/\r?\n/)
    .filter(Boolean);
  const allFiles = [...new Set([...tracked, ...untrackedNew])];

  const failures = [];
  for (const relPath of allFiles) {
    const buf = readRegularFileSafe(resolve(ROOT, relPath));
    if (!buf) continue;
    const err = checkFileBuffer(relPath, buf, cfg);
    const norm = relPath.replace(/\\/g, "/");
    if (err && (!LEGACY_MISSING_HEADER_BASELINE.has(norm) || changedFiles.has(norm))) {
      failures.push(err);
    }
  }

  if (failures.length > 0) {
    console.error(`licence-lint FAILED (${failures.length} files):\n` + failures.map((f) => `  - ${f}`).join("\n"));
    process.exit(1);
  }
  console.log(
    `licence-lint PASS: ${allFiles.length} files, ${fixtures} negative/positive fixtures, ${globCases} glob-cases verified.`,
  );
}

main();
