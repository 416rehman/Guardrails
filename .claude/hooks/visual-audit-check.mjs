// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Enforces independent UI/UX Visual Design Judge screenshot audit before committing or opening PRs for UI changes.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const WEB_UI_CHANGE_RE = /^(?:web\/(?:packages|apps)\/|contracts\/interface\/brand\/)/;
const DESKTOP_UI_CHANGE_RE = /^(?:desktop\/grdr-desktop\/src\/|crates\/grdr-ui-model\/)/;
const COMMITTED_SCREENSHOT_RE = /^(?:web|desktop)\/screenshots\/|\/__screenshots__\//i;
export const AUDIT_RECORD_REL = ".git/grdr-visual-audit.json";

export function resolveAuditRecordPath(cwd = process.cwd()) {
  const dotGit = resolve(cwd, ".git");
  if (existsSync(dotGit) && statSync(dotGit).isFile()) {
    const gitdirMatch = readFileSync(dotGit, "utf8").match(/^gitdir:\s*(.+)$/m);
    if (gitdirMatch) {
      return resolve(cwd, gitdirMatch[1].trim(), "grdr-visual-audit.json");
    }
  }
  return resolve(cwd, AUDIT_RECORD_REL);
}

function gitLines(args, cwd) {
  try {
    const out = execFileSync("git", args, { encoding: "utf8", cwd, stdio: ["ignore", "pipe", "ignore"] });
    return out.split(/\r?\n/).filter(Boolean);
  } catch {
    return [];
  }
}

export function collectScreenshotHashes(cwd, area) {
  const relDir = area === "web" ? "web/screenshots" : "desktop/screenshots";
  const absDir = resolve(cwd, relDir);
  if (!existsSync(absDir)) return {};
  const out = {};
  for (const name of readdirSync(absDir).sort()) {
    if (!name.toLowerCase().endsWith(".png")) continue;
    const absFile = join(absDir, name);
    const relFile = relative(resolve(cwd), absFile).replace(/\\/g, "/");
    const hash = createHash("sha256").update(readFileSync(absFile)).digest("hex");
    out[relFile] = hash;
  }
  return out;
}

export function recordVisualAudit({
  cwd = process.cwd(),
  verdict = "pass",
  summary = "",
  unresolvedIssues = 0,
  unresolvedPolish = 0,
}) {
  const screenshots = {
    ...collectScreenshotHashes(cwd, "web"),
    ...collectScreenshotHashes(cwd, "desktop"),
  };
  const record = {
    recordedAt: new Date().toISOString(),
    verdict,
    unresolvedIssues: Number(unresolvedIssues),
    unresolvedPolish: Number(unresolvedPolish),
    summary,
    screenshots,
  };
  const target = resolveAuditRecordPath(cwd);
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, `${JSON.stringify(record, null, 2)}\n`, "utf8");
  return record;
}

export function evaluateVisualAuditFiles(changedFiles, cwd = process.cwd()) {
  const normalized = changedFiles.map((f) => f.replace(/\\/g, "/"));
  const committedShots = normalized.filter((f) => COMMITTED_SCREENSHOT_RE.test(f));
  if (committedShots.length > 0) {
    return [
      `visual-audit: screenshots must not be committed to the repository (${committedShots.join(", ")}). Keep them gitignored locally and attach them to GitHub issues or PRs instead.`,
    ];
  }
  const needsWeb = normalized.some((f) => WEB_UI_CHANGE_RE.test(f));
  const needsDesktop = normalized.some((f) => DESKTOP_UI_CHANGE_RE.test(f));
  if (!needsWeb && !needsDesktop) return [];

  const recordPath = resolveAuditRecordPath(cwd);
  if (!existsSync(recordPath)) {
    return [
      `visual-audit: UI changes detected (${needsWeb ? "web" : ""}${needsWeb && needsDesktop ? "+" : ""}${needsDesktop ? "desktop" : ""}) without a designer screenshot audit record. Run the grdr-visual-audit subagent over all screenshots and record with: node .claude/hooks/visual-audit-check.mjs --record --verdict pass`,
    ];
  }

  let record;
  try {
    record = JSON.parse(readFileSync(recordPath, "utf8"));
  } catch {
    return [`visual-audit: audit record at ${recordPath} is unreadable; re-run grdr-visual-audit.`];
  }

  if (
    record.verdict !== "pass" ||
    Number(record.unresolvedIssues ?? 0) > 0 ||
    Number(record.unresolvedPolish ?? 0) > 0
  ) {
    return [
      `visual-audit: last screenshot audit verdict is "${record.verdict}" with ${record.unresolvedIssues ?? 0} blocking and ${record.unresolvedPolish ?? 0} polish issue(s). Action all blocking and polish findings, re-snap, and re-run the judge.`,
    ];
  }

  const findings = [];
  const areas = [...(needsWeb ? ["web"] : []), ...(needsDesktop ? ["desktop"] : [])];
  for (const area of areas) {
    const current = collectScreenshotHashes(cwd, area);
    const entries = Object.entries(current);
    if (entries.length === 0) {
      findings.push(`visual-audit: no captured PNG screenshots found under ${area}/screenshots/.`);
      continue;
    }
    if (area === "web" && !entries.some(([path]) => /-mobile\.png$/i.test(path))) {
      findings.push(
        "visual-audit: missing responsive mobile screenshot(s) (*-mobile.png) under web/screenshots/. Capture mobile viewport screenshots and run the judge.",
      );
      continue;
    }
    const recorded = record.screenshots ?? {};
    const stale = entries.filter(([path, hash]) => recorded[path] !== hash).map(([path]) => path);
    if (stale.length > 0) {
      findings.push(
        `visual-audit: screenshot(s) updated or unaudited since last judge pass (${stale.join(", ")}). Re-run UI/UX Visual Design Judge and record cleanly.`,
      );
    }
  }
  return findings;
}

export function evaluateVisualAuditToolPayload(payload, cwd = process.cwd()) {
  const command = payload?.tool_input?.command ?? payload?.toolCall?.args?.CommandLine ?? "";
  if (typeof command !== "string" || !command) return [];

  if (/\bgit(?:\s+-C\s+\S+)?\s+commit\b/.test(command)) {
    const staged = gitLines(["diff", "--cached", "--name-only", "--diff-filter=d"], cwd);
    return evaluateVisualAuditFiles(staged, cwd);
  }
  if (/\bgh\s+pr\s+create\b/.test(command)) {
    const base = gitLines(["rev-parse", "--verify", "origin/main"], cwd).length > 0 ? "origin/main" : "main";
    const diff = gitLines(["diff", "--name-only", "--diff-filter=d", `${base}...HEAD`], cwd);
    return evaluateVisualAuditFiles(diff, cwd);
  }
  return [];
}

function isMainModule() {
  if (!process.argv[1]) return false;
  return resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
}

if (isMainModule()) {
  if (process.argv.includes("--record")) {
    const getArg = (flag, fallback) => {
      const idx = process.argv.indexOf(flag);
      return idx !== -1 && idx + 1 < process.argv.length ? process.argv[idx + 1] : fallback;
    };
    const verdict = getArg("--verdict", "pass");
    const summary = getArg("--summary", "Verified by UI/UX Visual Design Judge");
    const unresolvedIssues = Number(getArg("--unresolved", "0"));
    const unresolvedPolish = Number(getArg("--unresolved-polish", "0"));
    const rec = recordVisualAudit({ cwd: process.cwd(), verdict, summary, unresolvedIssues, unresolvedPolish });
    const auditRel = relative(process.cwd(), resolveAuditRecordPath(process.cwd())).replace(/\\/g, "/");
    console.log(
      `Recorded visual audit (${rec.verdict}, ${Object.keys(rec.screenshots).length} screenshot(s)) at ${auditRel}`,
    );
    process.exit(0);
  }

  try {
    const payload = JSON.parse(readFileSync(0, "utf8"));
    const cwd = payload?.cwd ?? process.cwd();
    const findings = evaluateVisualAuditToolPayload(payload, cwd);
    if (findings.length > 0) {
      process.stderr.write(`${findings.join("\n")}\n`);
      process.exit(2);
    }
  } catch (error) {
    process.stderr.write(`visual-audit skipped: ${error.message}\n`);
    process.exit(0);
  }
}
