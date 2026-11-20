// AC-1 of #1550: every refusal of R5, produced by grant.mjs against fixture issues, and the hook
// and grant.mjs agreeing on the main checkout from the main checkout and from a worktree.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { GRANT_2, ISSUE_2, git, hookInput, makeRepository, runGrant, runHook } from "./fixture.mjs";

let repo;
let issues;
const label = (name) => ({ name });
const lowTier = (writeSet, extra = {}) => ({
  state: "OPEN",
  labels: [label("tier:low"), label("agent:impl-rust")],
  body: `### Kind\nfeature\n\n### Write set\n${writeSet.join("\n")}\n\n### Spec\nx\n`,
  ...extra,
});
const FIXTURE_ISSUES = {
  2: ISSUE_2,
  11: lowTier(["crates/x/**"], { state: "CLOSED" }),
  12: lowTier(["crates/x/**"], { labels: [label("agent:impl-rust"), label("agent:impl-web")] }),
  13: { state: "OPEN", labels: [label("agent:impl-rust")], body: "### Spec\nnothing to write\n" },
  14: lowTier(["/crates/x/**"]),
  15: lowTier(["crates/../architecture.toml"]),
  16: lowTier(["!crates/x/**"]),
  17: lowTier(["spec/*.md"]),
  18: lowTier(["crates/grdr-core/**", "Cargo.lock"]),
};

before(() => {
  repo = makeRepository();
  issues = join(repo.base, "issues");
  mkdirSync(issues);
  for (const [n, issue] of Object.entries(FIXTURE_ISSUES)) writeFileSync(join(issues, `${n}.json`), JSON.stringify(issue));
});
after(() => repo.remove());

const grantFile = (n) => join(repo.main, ".claude", "grants", `${n}.json`);
const grantsListing = () => readdirSync(join(repo.main, ".claude", "grants")).sort();

describe("grant.mjs refusals", () => {
  test("print 2 gives the grant of #2 and writes nothing", () => {
    const listed = grantsListing();
    const result = runGrant(repo.roots.w2, repo.roots.w2, issues, "print", "2");
    assert.equal(result.status, 0, result.line);
    assert.deepEqual(JSON.parse(result.stdout), GRANT_2);
    assert.deepEqual(grantsListing(), listed);
  });
  test("an issue that is closed, has two agent labels or no write set is refused with 0007", () => {
    for (const n of ["11", "12", "13"]) {
      assert.equal(runGrant(repo.main, repo.main, issues, "open", n).code, "GRDR-KIT-0007", n);
      assert.equal(existsSync(grantFile(n)), false);
    }
  });
  test("an absolute, parent or negated write-set line is refused with 0007", () => {
    for (const n of ["14", "15", "16"]) assert.equal(runGrant(repo.main, repo.main, issues, "print", n).code, "GRDR-KIT-0007", n);
  });
  test("a write-set line that is never grantable is refused with 0006", () => {
    const result = runGrant(repo.main, repo.main, issues, "open", "17");
    assert.equal(result.code, "GRDR-KIT-0006");
    assert.match(result.line, /spec\/\*\.md/);
  });
  test("open and close from a worktree's copy are refused with 0009", () => {
    assert.equal(runGrant(repo.roots.w2, repo.roots.w2, issues, "open", "18").code, "GRDR-KIT-0009");
    assert.equal(runGrant(repo.roots.w2, repo.main, issues, "close", "2").code, "GRDR-KIT-0009");
    assert.equal(existsSync(grantFile(2)), true);
  });
  test("a high-tier issue is refused with 0010 until the precondition path is on main", () => {
    const grant2 = grantFile(2);
    const saved = readFileSync(grant2, "utf8");
    const refused = runGrant(repo.main, repo.main, issues, "open", "2");
    assert.equal(refused.code, "GRDR-KIT-0010");
    assert.match(refused.line, /\.github\/workflows\/write-set\.yml/);
    assert.equal(readFileSync(grant2, "utf8"), saved);
    mkdirSync(join(repo.main, ".github", "workflows"), { recursive: true });
    writeFileSync(join(repo.main, ".github", "workflows", "write-set.yml"), "");
    assert.equal(runGrant(repo.main, repo.main, issues, "open", "2").status, 0);
    assert.deepEqual(JSON.parse(readFileSync(grant2, "utf8")), GRANT_2);
  });
  test("a failing gh or a bad argument is refused with 0008", () => {
    assert.equal(runGrant(repo.main, repo.main, issues, "open", "19").code, "GRDR-KIT-0008");
    assert.equal(runGrant(repo.main, repo.main, issues, "grant", "18").code, "GRDR-KIT-0008");
    assert.equal(runGrant(repo.main, repo.main, issues, "open", "x").code, "GRDR-KIT-0008");
    assert.equal(existsSync(grantFile(19)), false);
  });
});

describe("one main checkout for grant.mjs and the hook", () => {
  test("open from a worktree's cwd writes under the main checkout, the hook reads it from either, close removes it", () => {
    const w18 = join(repo.base, "w18");
    git(repo.main, "worktree", "add", "-q", "-b", "issue/18", w18);
    assert.equal(runGrant(repo.main, repo.roots.w2, issues, "open", "18").status, 0);
    assert.equal(existsSync(grantFile(18)), true);
    const caller = { agentId: "a1", agentType: "impl-rust" };
    for (const projectDir of [repo.main, w18]) {
      const inside = runHook(projectDir, hookInput(w18, "Write", { file_path: join(w18, "crates", "grdr-core", "src", "lib.rs") }, caller));
      const outside = runHook(projectDir, hookInput(w18, "Write", { file_path: join(w18, "README.md") }, caller));
      assert.deepEqual([inside.code, outside.code], [null, "GRDR-KIT-0003"], projectDir);
    }
    assert.equal(runGrant(repo.main, w18, issues, "close", "18").status, 0);
    assert.equal(existsSync(grantFile(18)), false);
  });
});
