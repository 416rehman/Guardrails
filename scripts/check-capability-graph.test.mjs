// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Unit tests for scripts/check-capability-graph.mjs covering live repo graph and adversarial negative cases.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { parsePreconditionIds, validateCapabilityGraph } from "./check-capability-graph.mjs";

const REPO_ROOT = resolve(import.meta.dirname, "..");

function makeNode(overrides = {}) {
  return {
    id: "N1",
    slice: "A",
    domain: "core",
    parent_id: null,
    kind: "capability",
    title: "Sample capability",
    status: "complete",
    external_precondition_ids: [],
    source_refs: [],
    dependencies: [],
    axiomatic: { fr: "Provide deterministic validation.", dp: "Pure validation module.", pv: "Automated unit tests." },
    p14_dynamic_check: "pass",
    friction_lens: { first_time_user: "Clear diagnostics.", operator: "Predictable defaults.", extender: "Schema-driven checks." },
    ...overrides,
  };
}

function makeGraph(nodes, summaryOverrides = {}) {
  const counts = { complete: 0, partial: 0, stub: 0, missing: 0, broken: 0, external_blocked: 0 };
  for (const node of nodes) {
    if (Object.hasOwn(counts, node.status)) counts[node.status] += 1;
  }
  const buildableTotal = nodes.length - counts.external_blocked;
  const buildableComplete = counts.complete;
  const pct = buildableTotal > 0 ? Math.round((buildableComplete * 1000) / buildableTotal) / 10 : 0;
  return {
    schema: "grdr.plan.capability-graph.v1",
    summary: {
      total_nodes: nodes.length,
      status_counts: counts,
      buildable_total: buildableTotal,
      buildable_complete: buildableComplete,
      buildable_completion_pct: pct,
      ...summaryOverrides,
    },
    nodes,
  };
}

function withTempDir(prefix, fn) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function trySymlink(target, linkPath, type) {
  try {
    symlinkSync(target, linkPath, type);
    return true;
  } catch (err) {
    if (process.platform === "win32" && type === "dir") {
      try {
        symlinkSync(target, linkPath, "junction");
        return true;
      } catch {
        return false;
      }
    }
    if (err?.code === "EPERM" || err?.code === "EACCES") return false;
    throw err;
  }
}

test("live docs/plan/capability-graph.json validates cleanly against repo and preconditions.toml", () => {
  const rawText = readFileSync(resolve(REPO_ROOT, "docs/plan/capability-graph.json"), "utf8");
  const graph = JSON.parse(rawText);
  const validPreconditionIds = parsePreconditionIds(readFileSync(resolve(REPO_ROOT, "docs/plan/preconditions.toml"), "utf8"));
  assert.ok(validPreconditionIds.has("pre-apple-dev"));
  assert.ok(validPreconditionIds.has("pre-foundation-transfer"));
  const { errors, summary } = validateCapabilityGraph(graph, { repoRoot: REPO_ROOT, validPreconditionIds, rawText });
  assert.deepEqual(errors, []);
  assert.equal(summary.total_nodes, graph.summary.total_nodes);
  assert.equal(summary.buildable_total, graph.summary.buildable_total);
  assert.equal(summary.buildable_complete, graph.summary.buildable_complete);
  assert.equal(summary.buildable_completion_pct, graph.summary.buildable_completion_pct);
});

test("CLI entrypoint exits 0 on live repository graph", () => {
  const stdout = execFileSync(process.execPath, [resolve(REPO_ROOT, "scripts/check-capability-graph.mjs")], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  });
  assert.match(stdout, /check-capability-graph PASS:/);
});

test("accepts diamond DAG, root ..foo file, dotdirs, concrete packs, comma/L line suffixes, and missing-status refs", () => {
  withTempDir("capgraph-valid-", (tmpRoot) => {
    mkdirSync(join(tmpRoot, "crates/grdr-sample/src"), { recursive: true });
    mkdirSync(join(tmpRoot, ".github/workflows"), { recursive: true });
    mkdirSync(join(tmpRoot, "packs/core/lists"), { recursive: true });
    writeFileSync(join(tmpRoot, "crates/grdr-sample/src/lib.rs"), "// ok\n", "utf8");
    writeFileSync(join(tmpRoot, ".github/workflows/ci.yml"), "name: ci\n", "utf8");
    writeFileSync(join(tmpRoot, "packs/core/lists/default.yaml"), "rules: []\n", "utf8");
    writeFileSync(join(tmpRoot, "..foo"), "dotdot prefix file\n", "utf8");
    writeFileSync(join(tmpRoot, "README.md"), "# readme\n", "utf8");

    const nodes = [
      makeNode({
        id: "ROOT",
        status: "complete",
        source_refs: [
          "README.md",
          "..foo",
          ".github/workflows/ci.yml:L1-L20",
          "crates/grdr-sample/src/lib.rs:21-26,78-83",
          "crates/grdr-sample/src/lib.rs:14,17,413",
          "crates/grdr-sample/src/lib.rs#L12",
          "crates/grdr-sample/src/lib.rs (lines 1-2)",
          "packs/core/lists/default.yaml",
        ],
      }),
      makeNode({ id: "LEFT", parent_id: "ROOT", status: "partial", dependencies: ["ROOT"] }),
      makeNode({ id: "RIGHT", parent_id: "ROOT", status: "partial", dependencies: ["ROOT"] }),
      makeNode({ id: "LEAF", parent_id: "ROOT", status: "missing", source_refs: ["crates/does-not-exist/lib.rs", "llms.txt"], dependencies: ["LEFT", "RIGHT"] }),
      makeNode({ id: "EXT", status: "external_blocked", external_precondition_ids: ["pre-ext"] }),
    ];
    const graph = makeGraph(nodes);
    const { errors } = validateCapabilityGraph(graph, { repoRoot: tmpRoot, validPreconditionIds: new Set(["pre-ext"]), rawText: JSON.stringify(graph) });
    assert.deepEqual(errors, []);
    if (process.platform === "win32") {
      const extPrefixed = validateCapabilityGraph(graph, { repoRoot: `\\\\?\\${tmpRoot}`, validPreconditionIds: new Set(["pre-ext"]) });
      assert.deepEqual(extPrefixed.errors, []);
    }
  });
});

test("rejects non-object graph/node, invalid schema, empty nodes, and drifted top-level enum lists", () => {
  assert.ok(validateCapabilityGraph(null, { repoRoot: null }).errors.some((e) => e.includes("CAPGRAPH-01")));
  assert.ok(validateCapabilityGraph([makeNode()], { repoRoot: null }).errors.some((e) => e.includes("CAPGRAPH-01")));
  assert.ok(validateCapabilityGraph(new Date(), { repoRoot: null }).errors.some((e) => e.includes("CAPGRAPH-01")));

  const inheritedGraph = Object.create({ schema: "grdr.plan.capability-graph.v1", nodes: [makeNode()], summary: makeGraph([makeNode()]).summary });
  assert.ok(validateCapabilityGraph(inheritedGraph, { repoRoot: null }).errors.some((e) => e.includes("CAPGRAPH-01")));

  const badNodeProto = makeGraph([makeNode()]);
  badNodeProto.nodes.push(Object.create(makeNode({ id: "PROTO_NODE" })));
  assert.ok(validateCapabilityGraph(badNodeProto, { repoRoot: null }).errors.some((e) => e.includes("nodes[1] must be an object")));

  const drifted = makeGraph([makeNode()]);
  drifted.valid_statuses = ["complete", "bogus"];
  drifted.valid_p14_checks = ["pass", "pass"];
  drifted.valid_external_preconditions = ["pre-extra"];
  const { errors } = validateCapabilityGraph(drifted, { repoRoot: null, validPreconditionIds: new Set(["pre-real"]) });
  assert.ok(errors.some((e) => e.includes('"valid_statuses" contains unexpected entry "bogus"')));
  assert.ok(errors.some((e) => e.includes('"valid_p14_checks" contains duplicate entry "pass"')));
  assert.ok(errors.some((e) => e.includes('"valid_external_preconditions" missing expected entry "pre-real"')));

  const emptyNodes = { schema: "grdr.plan.capability-graph.v1", summary: {}, nodes: [] };
  assert.ok(validateCapabilityGraph(emptyNodes, { repoRoot: null }).errors.some((e) => e.includes("CAPGRAPH-02")));
});

test("rejects duplicate IDs, empty/padded IDs, invalid enums, missing props, and non-array edge/ref fields", () => {
  const dupGraph = makeGraph([makeNode({ id: "DUP" }), makeNode({ id: "DUP" }), makeNode({ id: "  " }), makeNode({ id: " PADDED " })]);
  const dupErrs = validateCapabilityGraph(dupGraph, { repoRoot: null }).errors;
  assert.ok(dupErrs.some((e) => e.includes('duplicate node id "DUP"')));
  assert.ok(dupErrs.some((e) => e.includes('nodes[2] missing non-empty trimmed string "id"')));
  assert.ok(dupErrs.some((e) => e.includes('nodes[3] missing non-empty trimmed string "id"')));

  const badTypes = makeGraph([
    makeNode({
      id: "BAD",
      status: "shipped",
      p14_dynamic_check: "maybe",
      title: "",
      axiomatic: true,
      friction_lens: { first_time_user: "", operator: "ok", extender: "ok" },
      dependencies: "not-array",
      external_precondition_ids: "not-array",
      source_refs: "not-array",
    }),
    makeNode({ id: "ARR_AX", axiomatic: ["P14"], parent_id: "MISSING_P", dependencies: ["MISSING_D"] }),
  ]);
  const { errors } = validateCapabilityGraph(badTypes, { repoRoot: null });
  for (const needle of [
    'invalid status "shipped"',
    'invalid p14_dynamic_check "maybe"',
    'missing non-empty "title"',
    'node "BAD" "axiomatic" must be an object',
    'node "ARR_AX" "axiomatic" must be an object',
    'missing non-empty "friction_lens.first_time_user"',
    '"dependencies" must be an array',
    '"external_precondition_ids" must be an array',
    '"source_refs" must be an array',
    'missing parent_id "MISSING_P"',
    'missing dependency "MISSING_D"',
  ]) {
    assert.ok(errors.some((e) => e.includes(needle)), `expected error matching: ${needle}`);
  }
});

test("rejects self-loops, parent_id cycles, dependency cycles, and combined parent+dep cycles", () => {
  const selfLoops = makeGraph([
    makeNode({ id: "S_PARENT", parent_id: "S_PARENT" }),
    makeNode({ id: "S_DEP", dependencies: ["S_DEP"] }),
  ]);
  const selfErrs = validateCapabilityGraph(selfLoops, { repoRoot: null }).errors;
  assert.ok(selfErrs.some((e) => e.includes("parent_id cycle detected: S_PARENT -> S_PARENT")));
  assert.ok(selfErrs.some((e) => e.includes("dependencies cycle detected: S_DEP -> S_DEP")));

  const cycles = makeGraph([
    makeNode({ id: "P1", parent_id: "P2" }),
    makeNode({ id: "P2", parent_id: "P1" }),
    makeNode({ id: "D1", dependencies: ["D2"] }),
    makeNode({ id: "D2", dependencies: ["D3"] }),
    makeNode({ id: "D3", dependencies: ["D1"] }),
  ]);
  const cycleErrs = validateCapabilityGraph(cycles, { repoRoot: null }).errors;
  assert.ok(cycleErrs.some((e) => e.includes("parent_id cycle detected")));
  assert.ok(cycleErrs.some((e) => e.includes("dependencies cycle detected")));

  const combined = makeGraph([makeNode({ id: "C1", parent_id: "C2" }), makeNode({ id: "C2", dependencies: ["C1"] })]);
  const combinedErrs = validateCapabilityGraph(combined, { repoRoot: null }).errors;
  assert.ok(!combinedErrs.some((e) => e.includes("parent_id cycle detected")));
  assert.ok(!combinedErrs.some((e) => e.includes("dependencies cycle detected")));
  assert.ok(combinedErrs.some((e) => e.includes("combined cycle detected")));
});

test("rejects bad preconditions and invalid parsePreconditionIds inputs", () => {
  const graph = makeGraph([
    makeNode({ id: "UNK", status: "partial", external_precondition_ids: ["pre-missing"] }),
    makeNode({ id: "EMPTY_BLK", status: "external_blocked", external_precondition_ids: [] }),
  ]);
  const { errors } = validateCapabilityGraph(graph, { repoRoot: null, validPreconditionIds: new Set(["pre-real"]) });
  assert.ok(errors.some((e) => e.includes('unknown external_precondition_id "pre-missing"')));
  assert.ok(errors.some((e) => e.includes('status="external_blocked" with empty external_precondition_ids')));

  const badPreIds = validateCapabilityGraph(makeGraph([makeNode()]), {
    repoRoot: null,
    validPreconditionIds: ["pre-real", " pre-padded ", "", 42],
  }).errors;
  assert.ok(badPreIds.some((e) => e.includes('invalid precondition ID " pre-padded "')));
  assert.ok(badPreIds.some((e) => e.includes('invalid precondition ID ""')));
  assert.ok(badPreIds.some((e) => e.includes('invalid precondition ID "42"')));

  assert.throws(() => parsePreconditionIds(null));
  assert.throws(() => parsePreconditionIds(123));
  assert.throws(() => parsePreconditionIds(""));
  assert.throws(() => parsePreconditionIds("# comment only\n"));
  assert.throws(() => parsePreconditionIds('[precondition]\nid = "single-table"\n'));
  assert.throws(() => parsePreconditionIds('[[precondition]]\nid = " pre-padded "\n'));
  assert.throws(() => parsePreconditionIds('[[precondition]]\nid = "dup"\n[[precondition]]\nid = "dup"\n'));
  assert.throws(() => parsePreconditionIds('[[precondition]]\narea = "missing id"\n'));
  assert.equal(parsePreconditionIds("", { allowEmpty: true }).size, 0);
});

test("rejects traversal, drive paths, NUL bytes, missing root/dotdir paths, and invalid repoRoot", () => {
  withTempDir("capgraph-paths-", (tmpRoot) => {
    mkdirSync(join(tmpRoot, "crates"), { recursive: true });
    const filePath = join(tmpRoot, "crates/file.txt");
    writeFileSync(filePath, "hi\n", "utf8");

    for (const badRoot of ["", join(tmpRoot, "missing-dir"), filePath]) {
      const { errors } = validateCapabilityGraph(makeGraph([makeNode()]), { repoRoot: badRoot });
      assert.ok(errors.some((e) => e.includes("CAPGRAPH-09:")), `expected repoRoot error for ${String(badRoot)}`);
    }

    const unsafeRefs = [
      "../etc/passwd",
      "./crates/../../outside",
      "crates\\..\\..\\outside",
      "/etc/passwd",
      "C:/Windows/System32",
      "crates/a\0b.rs",
      "crates/a.rs#\0note",
      "crates/a.rs (\0note)",
      "crates/foo/.. (note)",
      "  crates/file.txt  ",
      "*nonexistent*",
      "nonexistent*",
      "crates*",
      "*/nonexistent",
      "packs/*/no_such_dir/*.yaml",
      "crates/foo?.rs",
      123,
    ];
    const missNode = makeNode({ id: "MISS", status: "missing", source_refs: unsafeRefs });
    assert.equal(validateCapabilityGraph(makeGraph([missNode]), { repoRoot: null }).errors.length, unsafeRefs.length);

    const activeNode = makeNode({
      id: "ACT",
      status: "partial",
      source_refs: [...unsafeRefs, ".github/nonexistent.yml", "llms.txt"],
    });
    const activeErrs = validateCapabilityGraph(makeGraph([activeNode]), { repoRoot: tmpRoot }).errors;
    assert.equal(activeErrs.length, unsafeRefs.length + 2);
    assert.ok(activeErrs.every((e) => e.includes("CAPGRAPH-09:")));
    assert.ok(activeErrs.some((e) => e.includes('references missing path ".github/nonexistent.yml"')));
    assert.ok(activeErrs.some((e) => e.includes('references missing path "llms.txt"')));
  });
});

test("rejects escaping, self-root, and dangling symlinks under repoRoot", () => {
  withTempDir("capgraph-sym-", (outerDir) => {
    const repoRoot = join(outerDir, "repo");
    const outsideFile = join(outerDir, "secret.txt");
    const outsideDir = join(outerDir, "outside-dir");
    const danglingTarget = join(outerDir, "dangling-target");
    mkdirSync(join(repoRoot, "crates"), { recursive: true });
    mkdirSync(outsideDir, { recursive: true });
    mkdirSync(danglingTarget, { recursive: true });
    writeFileSync(outsideFile, "secret\n", "utf8");

    const refs = [];
    const expectedNeedles = [];
    if (trySymlink(outsideDir, join(repoRoot, "crates/escape-dir"), "dir")) {
      refs.push("crates/escape-dir");
      expectedNeedles.push("symlink escapes repoRoot");
    }
    if (trySymlink(repoRoot, join(repoRoot, "crates/self-root"), "dir")) {
      refs.push("crates/self-root");
      expectedNeedles.push("symlink escapes repoRoot");
    }
    if (trySymlink(outsideFile, join(repoRoot, "crates/escape-file.txt"), "file")) {
      refs.push("crates/escape-file.txt");
      expectedNeedles.push("symlink escapes repoRoot");
    }
    if (trySymlink(danglingTarget, join(repoRoot, "crates/dangling"), "dir")) {
      rmSync(danglingTarget, { recursive: true, force: true });
      refs.push("crates/dangling");
      expectedNeedles.push("dangling symlink");
    }
    assert.ok(refs.length >= 3, "expected junction/symlink creation to exercise escaping, self-root, and dangling checks");

    const { errors } = validateCapabilityGraph(makeGraph([makeNode({ id: "SYM", status: "partial", source_refs: refs })]), { repoRoot });
    for (const needle of expectedNeedles) {
      assert.ok(errors.some((e) => e.includes(needle)), `expected symlink check error containing: ${needle}`);
    }
  });
});

test("protects against __proto__ keys, prototype pollution, and em dashes", () => {
  const protoNode = makeNode({ id: "__proto__", parent_id: null, dependencies: ["__proto__"] });
  const protoGraph = makeGraph([protoNode]);
  const protoErrs = validateCapabilityGraph(protoGraph, { repoRoot: null }).errors;
  assert.ok(protoErrs.some((e) => e.includes("dependencies cycle detected: __proto__ -> __proto__")));

  const badSummaryJson = JSON.parse('{"schema":"grdr.plan.capability-graph.v1","summary":{"total_nodes":1,"buildable_total":1,"buildable_complete":1,"buildable_completion_pct":100,"status_counts":{"complete":1,"partial":0,"stub":0,"missing":0,"broken":0,"external_blocked":0,"__proto__":1}},"nodes":[]}');
  badSummaryJson.nodes = [makeNode()];
  assert.ok(validateCapabilityGraph(badSummaryJson, { repoRoot: null }).errors.some((e) => e.includes('unknown status "__proto__"')));

  const protoDashGraph = JSON.parse('{"schema":"grdr.plan.capability-graph.v1","__proto__":{"note":"bad \\u2014 dash"}}');
  protoDashGraph.nodes = [makeNode()];
  protoDashGraph.summary = makeGraph([makeNode()]).summary;
  assert.ok(validateCapabilityGraph(protoDashGraph, { repoRoot: null }).errors.some((e) => e.includes("em dash")));

  const titleDash = makeGraph([makeNode({ title: "Bad \u2014 em dash" })]);
  assert.ok(validateCapabilityGraph(titleDash, { repoRoot: null, rawText: JSON.stringify(titleDash).replace("\\u2014", "\u2014") }).errors.some((e) => e.includes("em dash")));
  assert.ok(validateCapabilityGraph(titleDash, { repoRoot: null }).errors.some((e) => e.includes("em dash")));
});

test("handles deep 5,500-node DAG and nested objects without stack overflow", () => {
  const count = 5500;
  const nodes = [];
  for (let i = 0; i < count; i += 1) {
    nodes.push(makeNode({
      id: `N_${i}`,
      parent_id: i > 0 ? `N_${i - 1}` : null,
      dependencies: i > 0 ? [`N_${i - 1}`] : [],
      status: "complete",
    }));
  }
  let nested = "clean";
  for (let i = 0; i < count; i += 1) nested = { child: nested };
  const graph = makeGraph(nodes);
  graph.deep_meta = nested;
  const { errors, summary } = validateCapabilityGraph(graph, { repoRoot: null });
  assert.deepEqual(errors, []);
  assert.equal(summary.total_nodes, count);
});

test("rejects stale summary totals, percentages, and status_counts", () => {
  const staleTotal = makeGraph([makeNode()], { total_nodes: 99 });
  assert.ok(validateCapabilityGraph(staleTotal, { repoRoot: null }).errors.some((e) => e.includes("summary.total_nodes=99")));

  const stalePct = makeGraph([makeNode({ status: "partial" })], { buildable_completion_pct: 50 });
  assert.ok(validateCapabilityGraph(stalePct, { repoRoot: null }).errors.some((e) => e.includes("buildable_completion_pct=50")));

  const staleStatus = makeGraph([makeNode({ status: "complete" })]);
  staleStatus.summary.status_counts.complete = 0;
  staleStatus.summary.status_counts.extra_bad = 1;
  const { errors } = validateCapabilityGraph(staleStatus, { repoRoot: null });
  assert.ok(errors.some((e) => e.includes("summary.status_counts.complete=0")));
  assert.ok(errors.some((e) => e.includes('unknown status "extra_bad"')));
});
