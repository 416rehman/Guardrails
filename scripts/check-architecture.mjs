// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Enforces 5-layer workspace architecture, ARCH-006 sole crypto crate, error code registry,
// unsafe register consistency, trust-core privileged boundary, and P11 plans-lint.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { parseSimpleToml } from "./toml-parse.mjs";

const ROOT = resolve(import.meta.dirname, "..");

const UI_DECISION_TAG_ALLOWLIST = new Map([
  ["GRDR-DEC-ALLOW", new Set(["programs/grdr-server/src/store/surfaces_why.rs"])],
  ["GRDR-DEC-DEFER", new Set(["programs/grdr-server/src/store/surfaces_why.rs"])],
  [
    "GRDR-DEC-DENY",
    new Set([
      "crates/grdr-messages/src/lib.rs",
      "crates/grdr-ui-model/src/demo.rs",
      "desktop/grdr-desktop/src/screens/why_card.rs",
      "programs/grdr-server/src/store/surfaces_why.rs",
    ]),
  ],
  ["GRDR-DEC-MODIFY", new Set(["programs/grdr-server/src/store/surfaces_why.rs"])],
  [
    "GRDR-DEC-STEPUP",
    new Set([
      "crates/grdr-messages/src/lib.rs",
      "programs/grdr-server/src/store/surfaces_why.rs",
    ]),
  ],
  ["GRDR-UPDATER-NNNN", new Set(["programs/grdr-updater/src/error.rs"])],
]);

const ALLOWED_PLAN_BOOL_KEYS = new Set(["shown_by_default"]);
const FORBIDDEN_PLAN_KEY_PREFIXES = ["enable_", "disable_", "feature_", "allow_", "has_", "use_", "unlock_"];
const PRIVILEGED_FORBIDDEN_PARSERS = new Set([
  "cedar-policy",
  "yara-x",
  "rsigma",
  "rsigma-parser",
  "rsigma-eval",
  "grdr-llm-proto",
  "grdr-mcp-proto",
]);

function buildLayerIndex(archCfg) {
  const pkgToLayer = new Map();
  for (const [layerKey, names] of Object.entries(archCfg.layers || {})) {
    for (const name of names) {
      if (pkgToLayer.has(name)) {
        throw new Error(`Duplicate crate ${name} in architecture.toml [layers]`);
      }
      pkgToLayer.set(name, layerKey === "tool" ? "tool" : Number.parseInt(layerKey, 10));
    }
  }
  const sameLayer = new Map();
  for (const [pkg, allowed] of Object.entries(archCfg.same_layer_edges || {})) {
    sameLayer.set(pkg, new Set(allowed));
  }
  return { pkgToLayer, sameLayer };
}

export function validateArchitectureGraph(packages, archCfg, trustCoreText) {
  const errors = [];
  const { pkgToLayer, sameLayer } = buildLayerIndex(archCfg);
  const pkgNames = new Set(packages.map((p) => p.name));
  for (const declared of pkgToLayer.keys()) {
    if (!pkgNames.has(declared)) {
      errors.push(`ARCH-CFG-0001: architecture.toml lists unknown package ${declared}`);
    }
  }

  const soleCrypto = archCfg.crypto_boundary?.sole_crypto_crate || "grdr-crypto";
  const restrictedCrypto = new Set(archCfg.crypto_boundary?.restricted_crates || ["sha2"]);
  const trustCoreLines = trustCoreText
    .split(/\r?\n/)
    .map((l) => l.trim().toLowerCase())
    .filter((l) => l && !l.startsWith("#"));

  for (const pkg of packages) {
    const metaLayer = pkg.metadata?.grdr?.layer;
    const expectedLayer = pkgToLayer.get(pkg.name);
    if (expectedLayer === undefined) {
      errors.push(`ARCH-001: workspace package ${pkg.name} is missing from contracts/architecture.toml [layers]`);
      continue;
    }
    if (metaLayer !== expectedLayer) {
      errors.push(
        `ARCH-001: ${pkg.name} [package.metadata.grdr].layer=${String(metaLayer)} disagrees with architecture.toml (${String(expectedLayer)})`,
      );
    }

    const normalDeps = (pkg.dependencies || []).filter((d) => !d.kind || d.kind === "normal");
    for (const dep of pkg.dependencies || []) {
      if (restrictedCrypto.has(dep.name) && pkg.name !== soleCrypto) {
        errors.push(
          `ARCH-006: ${pkg.name} directly depends on cryptography crate ${dep.name} (${dep.kind || "normal"}); only ${soleCrypto} may link cryptography`,
        );
      }
    }

    for (const dep of normalDeps) {
      const depLayer = pkgToLayer.get(dep.name);
      if (depLayer === undefined) continue;
      if (expectedLayer !== "tool" && depLayer === "tool") {
        errors.push(`ARCH-001: non-tool crate ${pkg.name} (layer ${expectedLayer}) depends normally on tool crate ${dep.name}`);
        continue;
      }
      if (expectedLayer === "tool") continue;

      if (depLayer > expectedLayer) {
        errors.push(`ARCH-001: ${pkg.name} (layer ${expectedLayer}) depends upward on ${dep.name} (layer ${depLayer})`);
      } else if (depLayer === expectedLayer) {
        const allowed = sameLayer.get(pkg.name);
        if (!allowed || !allowed.has(dep.name)) {
          const code = expectedLayer === 3 ? "ARCH-002" : "ARCH-001";
          errors.push(`${code}: unlisted same-layer dependency ${pkg.name} -> ${dep.name} at layer ${expectedLayer}`);
        }
      }
    }

    if (pkg.metadata?.grdr?.privilege === "privileged") {
      const dirRoot = expectedLayer === 4 ? "programs" : "crates";
      const expectedPrefix = `${dirRoot}/${pkg.name.toLowerCase()}/**`;
      if (!trustCoreLines.includes(expectedPrefix)) {
        errors.push(`ARCH-004: privileged package ${pkg.name} is not covered by ${expectedPrefix} in security/trust-core.paths`);
      }
      for (const dep of normalDeps) {
        if (PRIVILEGED_FORBIDDEN_PARSERS.has(dep.name)) {
          errors.push(`ARCH-004: privileged package ${pkg.name} directly links disallowed parser ${dep.name}`);
        }
      }
    }
  }
  return errors;
}

export function validatePlansConfig(plansCfg) {
  const errors = [];
  const plans = plansCfg.plans || {};
  const planEntries = Object.entries(plans);
  if (planEntries.length === 0) {
    errors.push("P11-PLANS-0001: contracts/plans.toml defines no [plans.*] tables");
    return errors;
  }
  for (const [planName, cfg] of planEntries) {
    if (!cfg || typeof cfg !== "object") {
      errors.push(`P11-PLANS-0002: [plans.${planName}] must be a table`);
      continue;
    }
    for (const [key, val] of Object.entries(cfg)) {
      if (FORBIDDEN_PLAN_KEY_PREFIXES.some((prefix) => key.startsWith(prefix))) {
        errors.push(`P11-PLANS-0003: [plans.${planName}] contains forbidden feature-toggle key ${key}`);
      }
      if (typeof val === "boolean" && !ALLOWED_PLAN_BOOL_KEYS.has(key)) {
        errors.push(`P11-PLANS-0004: [plans.${planName}] contains disallowed boolean flag ${key}=${val}`);
      }
    }
    if (Object.hasOwn(cfg, "audit_retention_days") && cfg.audit_retention_days !== 0) {
      errors.push(`P11-PLANS-0005: [plans.${planName}].audit_retention_days must be 0 (audit logs are never truncated)`);
    }
  }
  return errors;
}

export function validateErrorCodes(sourceEntries, registryCfg) {
  const errors = [];
  const registryCodes = registryCfg.codes || {};
  const known = new Map();

  for (const [code, meta] of Object.entries(registryCodes)) {
    if (!/^GRDR-[A-Z0-9]+-\d{4}$/.test(code)) {
      errors.push(`ARCH-017: invalid error code format in registry.toml: ${code}`);
    }
    const owners = new Set([meta.owner, ...(Array.isArray(meta.shared_with) ? meta.shared_with : [])].filter(Boolean));
    known.set(code, owners);
  }

  for (const entry of sourceEntries) {
    const lines = entry.content.split(/\r?\n/);
    for (let idx = 0; idx < lines.length; idx += 1) {
      const line = lines[idx];
      if (line.includes("#[cfg(test)]")) break;

      for (const m of line.matchAll(/\bGRDR-[A-Z0-9]+-\d{4}\b/g)) {
        const code = m[0];
        if (!known.has(code)) {
          errors.push(`ARCH-017: unregistered code ${code} in ${entry.file}:${idx + 1}`);
        } else if (entry.pkg && !known.get(code).has(entry.pkg)) {
          errors.push(
            `ARCH-017: code ${code} used in ${entry.pkg} (${entry.file}:${idx + 1}) without registration in owner/shared_with`,
          );
        }
      }

      for (const m of line.matchAll(/\bGRDR-[A-Z0-9]+-[A-Z]{2,}\b/g)) {
        const tag = m[0];
        const allowedFiles = UI_DECISION_TAG_ALLOWLIST.get(tag);
        if (!allowedFiles || !allowedFiles.has(entry.file)) {
          errors.push(`ARCH-017: non-numeric status/error code ${tag} forbidden in ${entry.file}:${idx + 1}`);
        }
      }
    }
  }
  return errors;
}

function findEnclosingUnsafeSymbols(content) {
  const lines = content.split(/\r?\n/);
  let currentImpl = null;
  let implStartDepth = -1;
  let currentFn = null;
  let fnStartDepth = -1;
  let braceDepth = 0;
  let pendingNoMangleLine = null;
  const occurrences = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (line.includes("#[cfg(test)]")) break;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#![forbid(unsafe_code)]") || trimmed.startsWith("#![allow(unsafe_code")) {
      continue;
    }

    const stripped = trimmed.replace(/"(?:\\.|[^"\\])*"/g, '""');
    const implMatch = stripped.match(/^(?:pub(?:\([^)]*\))?\s+)?impl(?:<[^>]*>)?\s+(?:[A-Za-z0-9_:<>]+\s+for\s+)?([A-Za-z0-9_]+)/);
    if (implMatch && stripped.includes("{")) {
      currentImpl = implMatch[1];
      implStartDepth = braceDepth;
    }

    if (/^#\[\s*unsafe\s*\(/.test(stripped)) {
      pendingNoMangleLine = i + 1;
    }

    const fnMatch = stripped.match(/\bfn\s+([A-Za-z0-9_]+)\s*(?:<|\()/);
    if (fnMatch) {
      currentFn = fnMatch[1];
      fnStartDepth = braceDepth;
      if (pendingNoMangleLine !== null) {
        const sym = currentImpl ? `${currentImpl}::${currentFn}` : currentFn;
        occurrences.push({ line: pendingNoMangleLine, symbol: sym, fnName: currentFn });
        pendingNoMangleLine = null;
      }
    }

    if (/\bunsafe\s*(\{|fn\b|extern\b|impl\b)/.test(stripped)) {
      const sym = currentImpl && currentFn ? `${currentImpl}::${currentFn}` : currentFn || "<top-level>";
      occurrences.push({ line: i + 1, symbol: sym, fnName: currentFn || "<top-level>" });
    }

    for (const ch of stripped) {
      if (ch === "{") braceDepth += 1;
      else if (ch === "}") {
        braceDepth = Math.max(0, braceDepth - 1);
        if (currentFn && braceDepth <= fnStartDepth) {
          currentFn = null;
          fnStartDepth = -1;
        }
        if (currentImpl && braceDepth <= implStartDepth) {
          currentImpl = null;
          implStartDepth = -1;
        }
      }
    }
  }
  return occurrences;
}

export function validateSurfacesAndUnsafe(packages, surfacesCfg, unsafeCfg, sourceEntries) {
  const errors = [];
  const surfaceCrates = surfacesCfg.crates || {};
  for (const pkg of packages) {
    if (pkg.metadata?.grdr?.surface === "public" && !Object.hasOwn(surfaceCrates, pkg.name)) {
      errors.push(`ARCH-007: public crate ${pkg.name} is missing from contracts/surfaces.toml`);
    }
  }

  const registered = (unsafeCfg.entry || []).map((e) => ({ ...e, matched: false }));
  for (const entry of sourceEntries) {
    for (const hit of findEnclosingUnsafeSymbols(entry.content)) {
      const match = registered.find(
        (r) => r.file === entry.file && (r.symbol === hit.symbol || r.symbol === hit.fnName),
      );
      if (!match) {
        errors.push(
          `SD-01: unregistered unsafe item in ${hit.symbol} at ${entry.file}:${hit.line}; document it in security/unsafe-register.toml`,
        );
      } else {
        match.matched = true;
      }
    }
  }

  for (const entry of registered) {
    if (!entry.matched) {
      errors.push(`SD-01: stale unsafe-register.toml entry ${entry.file}::${entry.symbol} not found in non-test source`);
    }
  }
  return errors;
}

export function checkDesktopCryptoDeps(desktopPkg, restrictedCrypto) {
  const errors = [];
  for (const dep of desktopPkg?.dependencies || []) {
    if (restrictedCrypto.has(dep.name)) {
      errors.push(`ARCH-006: grdr-desktop cannot directly depend on cryptography crate ${dep.name}`);
    }
  }
  return errors;
}

function runNegativeSelfTests(archCfg, registryCfg) {
  const brokenUpward = validateArchitectureGraph(
    [
      { name: "grdr-core", metadata: { grdr: { layer: 1, privilege: "none" } }, dependencies: [{ name: "grdr-blob", kind: null }] },
      { name: "grdr-blob", metadata: { grdr: { layer: 3, privilege: "none" } }, dependencies: [] },
    ],
    archCfg,
    "",
  );
  assert.ok(brokenUpward.some((e) => e.includes("ARCH-001")), "self-test must reject upward layer edge");

  const brokenSameLayer = validateArchitectureGraph(
    [
      { name: "grdr-agents", metadata: { grdr: { layer: 3, privilege: "none" } }, dependencies: [{ name: "grdr-blob", kind: null }] },
      { name: "grdr-blob", metadata: { grdr: { layer: 3, privilege: "none" } }, dependencies: [] },
    ],
    archCfg,
    "",
  );
  assert.ok(brokenSameLayer.some((e) => e.includes("ARCH-002")), "self-test must reject unlisted L3->L3 edge");

  const brokenPrivL3 = validateArchitectureGraph(
    [{ name: "grdr-export", metadata: { grdr: { layer: 3, privilege: "privileged" } }, dependencies: [] }],
    archCfg,
    "",
  );
  assert.ok(brokenPrivL3.some((e) => e.includes("ARCH-004")), "self-test must reject privileged L3 crate outside trust-core");

  const brokenCrypto = validateArchitectureGraph(
    [{ name: "grdr-agents", metadata: { grdr: { layer: 3, privilege: "none" } }, dependencies: [{ name: "sha2", kind: null }] }],
    archCfg,
    "",
  );
  assert.ok(brokenCrypto.some((e) => e.includes("ARCH-006")), "self-test must reject sha2 outside grdr-crypto");

  const brokenDesktopCrypto = checkDesktopCryptoDeps(
    { name: "grdr-desktop", dependencies: [{ name: "ed25519-dalek" }] },
    new Set(archCfg.crypto_boundary.restricted_crates),
  );
  assert.ok(brokenDesktopCrypto.some((e) => e.includes("ARCH-006")), "self-test must reject all restricted crypto crates in desktop");

  const brokenUnsafe = validateSurfacesAndUnsafe(
    [],
    { crates: {} },
    { entry: [{ file: "crates/grdr-ipc-os/src/windows_pipe.rs", symbol: "stale_nonexistent" }] },
    [{ file: "crates/grdr-fastpath-ffi/src/lib.rs", pkg: "grdr-fastpath-ffi", content: "unsafe fn rogue() {}" }],
  );
  assert.ok(brokenUnsafe.some((e) => e.includes("rogue")), "self-test must inspect grdr-fastpath-ffi unsafe");
  assert.ok(brokenUnsafe.some((e) => e.includes("stale_nonexistent")), "self-test must reject stale unsafe-register entries");

  const brokenCodes = validateErrorCodes(
    [{ file: "crates/grdr-broker/src/lib.rs", pkg: "grdr-broker", content: 'let c = "GRDR-DEC-STEPUP"; let u = "GRDR-FAKE-9999";' }],
    registryCfg,
  );
  assert.ok(brokenCodes.some((e) => e.includes("GRDR-DEC-STEPUP")), "self-test must reject non-numeric GRDR-DEC-STEPUP");
  assert.ok(brokenCodes.some((e) => e.includes("GRDR-FAKE-9999")), "self-test must reject unregistered error code");

  const brokenPlans = validatePlansConfig({
    plans: { pro: { enable_sso: true, audit_retention_days: 30 } },
  });
  assert.ok(brokenPlans.some((e) => e.includes("P11-PLANS-0003")), "self-test must reject plan feature toggle");
  assert.ok(brokenPlans.some((e) => e.includes("P11-PLANS-0005")), "self-test must reject audit truncation");
}

function loadRepoSources() {
  const files = execFileSync("git", ["ls-files", "crates/", "programs/", "desktop/"], {
    cwd: ROOT,
    encoding: "utf8",
  })
    .trim()
    .split(/\r?\n/)
    .filter((f) => f && f.endsWith(".rs") && !f.includes("/tests/"));
  return files.map((file) => {
    const parts = file.split("/");
    return { file, pkg: parts[1], content: readFileSync(resolve(ROOT, file), "utf8") };
  });
}

function main() {
  const archCfg = parseSimpleToml(readFileSync(resolve(ROOT, "contracts/architecture.toml"), "utf8"));
  const plansCfg = parseSimpleToml(readFileSync(resolve(ROOT, "contracts/plans.toml"), "utf8"));
  const surfacesCfg = parseSimpleToml(readFileSync(resolve(ROOT, "contracts/surfaces.toml"), "utf8"));
  const registryCfg = parseSimpleToml(readFileSync(resolve(ROOT, "contracts/codes/registry.toml"), "utf8"));
  const unsafeCfg = parseSimpleToml(readFileSync(resolve(ROOT, "security/unsafe-register.toml"), "utf8"));
  const trustCoreText = readFileSync(resolve(ROOT, "security/trust-core.paths"), "utf8");

  runNegativeSelfTests(archCfg, registryCfg);
  if (process.argv.includes("--self-test")) {
    console.log("check-architecture self-tests: OK (11 assertions)");
    return;
  }

  const meta = JSON.parse(
    execFileSync("cargo", ["metadata", "--locked", "--no-deps", "--format-version", "1"], {
      cwd: ROOT,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    }),
  );
  const wsSet = new Set(meta.workspace_members);
  const wsPackages = meta.packages.filter((p) => wsSet.has(p.id));
  const sources = loadRepoSources();

  const errors = [
    ...validateArchitectureGraph(wsPackages, archCfg, trustCoreText),
    ...validatePlansConfig(plansCfg),
    ...validateErrorCodes(sources, registryCfg),
    ...validateSurfacesAndUnsafe(wsPackages, surfacesCfg, unsafeCfg, sources),
  ];

  const desktopToml = resolve(ROOT, "desktop/grdr-desktop/Cargo.toml");
  if (existsSync(desktopToml)) {
    const desktopMeta = JSON.parse(
      execFileSync(
        "cargo",
        ["metadata", "--manifest-path", desktopToml, "--locked", "--no-deps", "--format-version", "1"],
        { cwd: ROOT, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 },
      ),
    );
    const deskPkg = desktopMeta.packages.find((p) => p.name === "grdr-desktop");
    const restrictedCrypto = new Set(archCfg.crypto_boundary?.restricted_crates || ["sha2"]);
    errors.push(...checkDesktopCryptoDeps(deskPkg, restrictedCrypto));
  }

  if (errors.length > 0) {
    console.error("check-architecture FAILED:\n" + errors.map((e) => `  - ${e}`).join("\n"));
    process.exit(1);
  }
  console.log(
    `check-architecture PASS: ${wsPackages.length} workspace packages, ${Object.keys(registryCfg.codes || {}).length} registered codes, ${Object.keys(plansCfg.plans || {}).length} plans verified.`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}
