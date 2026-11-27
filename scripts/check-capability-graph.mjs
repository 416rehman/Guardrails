// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Validates docs/plan/capability-graph.json against schema, DAG acyclicity, preconditions, and repo paths.

import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parseSimpleToml } from "./toml-parse.mjs";

const ROOT = resolve(import.meta.dirname, "..");
const EXPECTED_SCHEMA = "grdr.plan.capability-graph.v1";
const VALID_STATUSES = ["complete", "partial", "stub", "missing", "broken", "external_blocked"];
const VALID_STATUS_SET = new Set(VALID_STATUSES);
const VALID_P14_SET = new Set(["pass", "partial", "fail", "na", "untested"]);
const REQUIRED_TEXT_FIELDS = ["slice", "domain", "kind", "title"];
const REQUIRED_OBJECT_TEXT_PROPS = [["axiomatic", ["fr", "dp", "pv"]], ["friction_lens", ["first_time_user", "operator", "extender"]]];
const LINE_SUFFIX_RE = /:(?:L?\d+(?:-L?\d+)?(?:\s*,\s*L?\d+(?:-L?\d+)?)*|lines?\s+[\d,\-\s]+)$/i;
const EM_DASH = "\u2014";
const [DFS_UNVISITED, DFS_VISITING, DFS_DONE] = [0, 1, 2];

const own = (obj, key) => (Object.hasOwn(obj, key) ? obj[key] : undefined);
const realpath = realpathSync.native ?? realpathSync;

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function containsEmDash(root) {
  const seen = new Set();
  const stack = [root];
  while (stack.length > 0) {
    const item = stack.pop();
    if (typeof item === "string") { if (item.includes(EM_DASH)) return true; continue; }
    if (!item || typeof item !== "object" || seen.has(item)) continue;
    seen.add(item);
    if (Array.isArray(item)) { for (let i = 0; i < item.length; i += 1) stack.push(item[i]); continue; }
    for (const key of Object.keys(item)) {
      if (key.includes(EM_DASH)) return true;
      stack.push(Object.getOwnPropertyDescriptor(item, key)?.value);
    }
  }
  return false;
}

function normalizeForCompare(targetPath) {
  let out = targetPath;
  if (targetPath.toUpperCase().startsWith("\\\\?\\UNC\\")) out = `\\\\${targetPath.slice(8)}`;
  else if (targetPath.startsWith("\\\\?\\")) out = targetPath.slice(4);
  const clean = out.replace(/\\/g, "/");
  return process.platform === "win32" ? clean.toLowerCase() : clean;
}

function isInsideRoot(realRoot, targetPath) {
  const rel = posix.relative(normalizeForCompare(realRoot), normalizeForCompare(targetPath));
  return Boolean(rel) && rel !== ".." && !rel.startsWith("../") && !posix.isAbsolute(rel) && !/^[a-z]:/i.test(rel);
}

function resolveRealRepoRoot(repoRoot, errors) {
  if (repoRoot === null) return null;
  const target = repoRoot === undefined ? ROOT : repoRoot;
  if (typeof target !== "string" || !target.trim()) { errors.push("CAPGRAPH-09: repoRoot must be a non-empty directory path"); return null; }
  try {
    const real = realpath(target);
    if (lstatSync(real).isDirectory()) return real;
    errors.push(`CAPGRAPH-09: repoRoot is not a directory (${target})`);
  } catch (error) { errors.push(`CAPGRAPH-09: unreadable repoRoot (${error.message})`); }
  return null;
}

function extractConcreteSourcePath(ref) {
  const noteIdx = ref.search(/\s+\(/);
  const base = noteIdx === -1 ? ref.trim() : ref.slice(0, noteIdx).trim();
  return base.replace(/\([^)]*\)\s*$/, "").replace(/#.*$/, "").replace(LINE_SUFFIX_RE, "").trim();
}

function hasUnsafePathShape(pathText) {
  return !pathText || pathText === "." || pathText.includes("\0") || pathText.includes("\\") || pathText.includes("*") || pathText.includes("?") || pathText.startsWith("/") || /^[A-Za-z]:/.test(pathText) || pathText.split("/").includes("..");
}

function resolveContainedPath(realRoot, relPath, label, rawRef, errors) {
  const candidate = resolve(realRoot, relPath);
  if (!isInsideRoot(realRoot, candidate)) { errors.push(`CAPGRAPH-09: ${label} source_ref escapes repoRoot "${rawRef}"`); return; }
  try {
    if (!isInsideRoot(realRoot, realpath(candidate))) errors.push(`CAPGRAPH-09: ${label} source_ref symlink escapes repoRoot "${relPath}"`);
  } catch (error) {
    let linkStat = null;
    try { linkStat = lstatSync(candidate); } catch {}
    if (error?.code === "ELOOP") errors.push(`CAPGRAPH-09: ${label} source_ref has symlink loop "${relPath}"`);
    else if (linkStat?.isSymbolicLink()) errors.push(`CAPGRAPH-09: ${label} source_ref is a dangling symlink "${relPath}"`);
    else errors.push(`CAPGRAPH-09: ${label} references missing path "${relPath}"`);
  }
}

function checkSourceRefs(node, label, realRoot, errors) {
  const refs = own(node, "source_refs");
  if (refs === undefined) return;
  if (!Array.isArray(refs)) { errors.push(`CAPGRAPH-09: ${label} "source_refs" must be an array`); return; }
  for (const rawRef of refs) {
    if (typeof rawRef !== "string" || !rawRef.length || rawRef.trim() !== rawRef) {
      errors.push(`CAPGRAPH-09: ${label} contains empty, untrimmed, or non-string source_ref`);
      continue;
    }
    const clean = hasUnsafePathShape(rawRef) ? "" : extractConcreteSourcePath(rawRef);
    if (hasUnsafePathShape(clean)) { errors.push(`CAPGRAPH-09: ${label} has unsafe source_ref path "${rawRef}"`); continue; }
    if (own(node, "status") === "missing" || !realRoot) continue;
    resolveContainedPath(realRoot, clean, label, rawRef, errors);
  }
}

function validateNodeShape(node, idx, nodeMap, validPreSet, realRoot, errors) {
  if (!isPlainObject(node)) { errors.push(`CAPGRAPH-03: nodes[${idx}] must be an object`); return; }
  const idVal = own(node, "id");
  const hasId = typeof idVal === "string" && idVal.length > 0 && idVal.trim() === idVal;
  const label = hasId ? `node "${idVal}"` : `nodes[${idx}]`;
  if (!hasId) errors.push(`CAPGRAPH-03: nodes[${idx}] missing non-empty trimmed string "id"`);
  else if (nodeMap.has(idVal)) errors.push(`CAPGRAPH-03: duplicate node id "${idVal}"`);
  else nodeMap.set(idVal, node);

  for (const key of REQUIRED_TEXT_FIELDS) {
    const val = own(node, key);
    if (typeof val !== "string" || !val.trim()) errors.push(`CAPGRAPH-04: ${label} missing non-empty "${key}"`);
  }
  const statusVal = own(node, "status");
  const p14Val = own(node, "p14_dynamic_check");
  if (typeof statusVal !== "string" || !VALID_STATUS_SET.has(statusVal)) errors.push(`CAPGRAPH-05: ${label} has invalid status "${String(statusVal)}"`);
  if (typeof p14Val !== "string" || !VALID_P14_SET.has(p14Val)) errors.push(`CAPGRAPH-05: ${label} has invalid p14_dynamic_check "${String(p14Val)}"`);

  for (const [fieldName, keys] of REQUIRED_OBJECT_TEXT_PROPS) {
    const obj = own(node, fieldName);
    if (!isPlainObject(obj)) { errors.push(`CAPGRAPH-04: ${label} "${fieldName}" must be an object`); continue; }
    for (const key of keys) {
      const val = own(obj, key);
      if (typeof val !== "string" || !val.trim()) errors.push(`CAPGRAPH-04: ${label} missing non-empty "${fieldName}.${key}"`);
    }
  }
  const extIds = own(node, "external_precondition_ids");
  if (!Array.isArray(extIds)) errors.push(`CAPGRAPH-08: ${label} "external_precondition_ids" must be an array`);
  else {
    for (const preId of extIds) if (typeof preId !== "string" || !validPreSet.has(preId)) errors.push(`CAPGRAPH-08: ${label} references unknown external_precondition_id "${String(preId)}"`);
    if (statusVal === "external_blocked" && extIds.length === 0) errors.push(`CAPGRAPH-08: ${label} has status="external_blocked" with empty external_precondition_ids`);
  }
  checkSourceRefs(node, label, realRoot, errors);
}

function validateNodeEdges(node, nodeMap, errors) {
  const parentId = own(node, "parent_id");
  if (parentId !== null && (typeof parentId !== "string" || !parentId.trim() || !nodeMap.has(parentId))) errors.push(`CAPGRAPH-06: node "${node.id}" references missing parent_id "${String(parentId)}"`);
  const deps = own(node, "dependencies");
  if (!Array.isArray(deps)) { errors.push(`CAPGRAPH-06: node "${node.id}" "dependencies" must be an array`); return; }
  for (const dep of deps) if (typeof dep !== "string" || !nodeMap.has(dep)) errors.push(`CAPGRAPH-06: node "${node.id}" references missing dependency "${String(dep)}"`);
}

function detectCycles(nodeMap, getNeighbors, edgeLabel, errors) {
  const color = new Map();
  for (const startId of nodeMap.keys()) {
    if ((color.get(startId) ?? DFS_UNVISITED) !== DFS_UNVISITED) continue;
    const stack = [{ id: startId, neighbors: getNeighbors(nodeMap.get(startId)), idx: 0 }];
    color.set(startId, DFS_VISITING);
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      if (frame.idx >= frame.neighbors.length) { color.set(frame.id, DFS_DONE); stack.pop(); continue; }
      const nextId = frame.neighbors[frame.idx++];
      if (!nodeMap.has(nextId)) continue;
      const nextColor = color.get(nextId) ?? DFS_UNVISITED;
      if (nextColor === DFS_VISITING) {
        const startIdx = stack.findIndex((entry) => entry.id === nextId);
        errors.push(`CAPGRAPH-07: ${edgeLabel} cycle detected: ${[...stack.slice(startIdx).map((e) => e.id), nextId].join(" -> ")}`);
      } else if (nextColor === DFS_UNVISITED) { color.set(nextId, DFS_VISITING); stack.push({ id: nextId, neighbors: getNeighbors(nodeMap.get(nextId)), idx: 0 }); }
    }
  }
}

function computeSummary(nodes) {
  const counts = new Map(VALID_STATUSES.map((s) => [s, 0]));
  for (const node of nodes) {
    const status = isPlainObject(node) ? own(node, "status") : undefined;
    if (typeof status === "string" && VALID_STATUS_SET.has(status)) counts.set(status, (counts.get(status) ?? 0) + 1);
  }
  const buildableTotal = nodes.length - (counts.get("external_blocked") ?? 0);
  const complete = counts.get("complete") ?? 0;
  const pct = buildableTotal > 0 ? Math.round((complete * 1000) / buildableTotal) / 10 : 0;
  return { total_nodes: nodes.length, status_counts: Object.fromEntries(counts.entries()), buildable_total: buildableTotal, buildable_complete: complete, buildable_completion_pct: pct };
}

function checkSummaryParity(declared, computed, errors) {
  if (!isPlainObject(declared)) { errors.push('CAPGRAPH-12: capability graph missing object "summary"'); return; }
  for (const field of ["total_nodes", "buildable_total", "buildable_complete", "buildable_completion_pct"]) {
    const val = own(declared, field);
    if (val !== computed[field]) errors.push(`CAPGRAPH-12: summary.${field}=${String(val)} disagrees with computed ${computed[field]}`);
  }
  const statusCounts = own(declared, "status_counts");
  if (!isPlainObject(statusCounts)) { errors.push("CAPGRAPH-12: summary.status_counts must be an object"); return; }
  for (const status of VALID_STATUSES) {
    const actual = own(statusCounts, status);
    if (actual !== computed.status_counts[status]) errors.push(`CAPGRAPH-12: summary.status_counts.${status}=${String(actual)} disagrees with computed ${computed.status_counts[status]}`);
  }
  for (const extraKey of Object.keys(statusCounts)) if (!VALID_STATUS_SET.has(extraKey)) errors.push(`CAPGRAPH-12: summary.status_counts contains unknown status "${extraKey}"`);
}

function validateEnumArray(graph, fieldName, expectedSet, errors) {
  const list = own(graph, fieldName);
  if (list === undefined) return;
  if (!Array.isArray(list)) { errors.push(`CAPGRAPH-01: "${fieldName}" must be an array`); return; }
  const seen = new Set();
  for (const val of list) {
    if (typeof val !== "string" || !expectedSet.has(val)) errors.push(`CAPGRAPH-01: "${fieldName}" contains unexpected entry "${String(val)}"`);
    else if (seen.has(val)) errors.push(`CAPGRAPH-01: "${fieldName}" contains duplicate entry "${val}"`);
    else seen.add(val);
  }
  for (const expected of expectedSet) if (!seen.has(expected)) errors.push(`CAPGRAPH-01: "${fieldName}" missing expected entry "${expected}"`);
}

export function parsePreconditionIds(tomlText, options = {}) {
  const { allowEmpty = false } = isPlainObject(options) ? options : {};
  if (typeof tomlText !== "string") throw new TypeError("CAPGRAPH-08: preconditions TOML text must be a string");
  const parsed = parseSimpleToml(tomlText);
  if (Object.hasOwn(parsed, "precondition") && !Array.isArray(parsed.precondition)) throw new Error("CAPGRAPH-08: preconditions [precondition] must be an array of tables");
  const ids = new Set();
  for (const entry of parsed.precondition ?? []) {
    const id = isPlainObject(entry) ? own(entry, "id") : undefined;
    if (typeof id !== "string" || !id.trim()) throw new Error("CAPGRAPH-08: [[precondition]] entry missing non-empty id");
    if (id !== id.trim()) throw new Error(`CAPGRAPH-08: precondition id "${id}" must not have surrounding whitespace`);
    if (ids.has(id)) throw new Error(`CAPGRAPH-08: duplicate precondition id "${id}"`);
    ids.add(id);
  }
  if (!allowEmpty && ids.size === 0) throw new Error("CAPGRAPH-08: preconditions registry produced zero precondition IDs");
  return ids;
}

export function validateCapabilityGraph(graph, options = {}) {
  const { repoRoot, validPreconditionIds, rawText } = isPlainObject(options) ? options : {};
  const errors = [];
  let hasEmDashError = false;
  if (rawText !== undefined) {
    if (typeof rawText !== "string") errors.push("CAPGRAPH-11: rawText must be a string");
    else if (rawText.includes(EM_DASH)) { errors.push("CAPGRAPH-11: capability graph text contains forbidden Unicode em dash (\\u2014)"); hasEmDashError = true; }
  }
  if (!isPlainObject(graph)) { errors.push("CAPGRAPH-01: capability graph root must be a JSON object"); return { errors, summary: null }; }
  if (!hasEmDashError && containsEmDash(graph)) errors.push("CAPGRAPH-11: capability graph contains forbidden Unicode em dash (\\u2014)");
  if (own(graph, "schema") !== EXPECTED_SCHEMA) errors.push(`CAPGRAPH-01: expected schema "${EXPECTED_SCHEMA}", got "${String(own(graph, "schema"))}"`);
  const nodes = own(graph, "nodes");
  if (!Array.isArray(nodes) || nodes.length === 0) { errors.push('CAPGRAPH-02: capability graph "nodes" must be a non-empty array'); return { errors, summary: null }; }
  const validPreSet = new Set();
  if (validPreconditionIds instanceof Set || Array.isArray(validPreconditionIds)) {
    for (const preId of validPreconditionIds) {
      if (typeof preId !== "string" || !preId.trim() || preId.trim() !== preId) errors.push(`CAPGRAPH-08: validPreconditionIds contains invalid precondition ID "${String(preId)}"`);
      else validPreSet.add(preId);
    }
  } else if (validPreconditionIds !== undefined) errors.push("CAPGRAPH-08: validPreconditionIds must be a Set or Array of precondition IDs");

  validateEnumArray(graph, "valid_statuses", VALID_STATUS_SET, errors);
  validateEnumArray(graph, "valid_p14_checks", VALID_P14_SET, errors);
  validateEnumArray(graph, "valid_external_preconditions", validPreSet, errors);

  const realRoot = resolveRealRepoRoot(repoRoot, errors);
  const nodeMap = new Map();
  for (let i = 0; i < nodes.length; i += 1) validateNodeShape(nodes[i], i, nodeMap, validPreSet, realRoot, errors);
  for (const node of nodeMap.values()) validateNodeEdges(node, nodeMap, errors);

  const parentNeighbors = (node) => { const p = own(node, "parent_id"); return typeof p === "string" && nodeMap.has(p) ? [p] : []; };
  const depNeighbors = (node) => { const d = own(node, "dependencies"); return Array.isArray(d) ? d.filter((x) => typeof x === "string") : []; };
  detectCycles(nodeMap, parentNeighbors, "parent_id", errors);
  detectCycles(nodeMap, depNeighbors, "dependencies", errors);
  detectCycles(nodeMap, (node) => [...parentNeighbors(node), ...depNeighbors(node)], "combined", errors);

  const summary = computeSummary(nodes);
  checkSummaryParity(own(graph, "summary"), summary, errors);
  return { errors, summary };
}

function isMainModule() {
  if (!process.argv[1]) return false;
  const norm = (p) => { let out = resolve(p); try { out = realpath(p); } catch {} return normalizeForCompare(out); };
  return norm(process.argv[1]) === norm(fileURLToPath(import.meta.url));
}

function main() {
  let rawText, graph, validPreconditionIds;
  try {
    rawText = readFileSync(resolve(ROOT, "docs/plan/capability-graph.json"), "utf8");
    graph = JSON.parse(rawText);
    validPreconditionIds = parsePreconditionIds(readFileSync(resolve(ROOT, "docs/plan/preconditions.toml"), "utf8"));
  } catch (error) { console.error(`check-capability-graph FAILED: ${error.message}`); process.exit(1); }
  const { errors, summary } = validateCapabilityGraph(graph, { repoRoot: ROOT, validPreconditionIds, rawText });
  if (errors.length > 0) { console.error(`check-capability-graph FAILED (${errors.length} error(s)):\n` + errors.map((e) => `  - ${e}`).join("\n")); process.exit(1); }
  const counts = VALID_STATUSES.map((s) => `${s}=${summary.status_counts[s]}`).join(", ");
  console.log(`check-capability-graph PASS: ${summary.total_nodes} nodes (${counts}); buildable ${summary.buildable_complete}/${summary.buildable_total} (${summary.buildable_completion_pct}%).`);
}

if (isMainModule()) main();
