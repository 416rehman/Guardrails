// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Tests for branch-check.mjs: node --test .claude/hooks/branch-check.test.mjs
// Each fixture's `expect` and `expect_fork_links` are written by hand from the owner rule on #1875
// and the rulings on it, never from the script. `closing_issues` is what GitHub's
// closingIssuesReferences reports for that pull request; `fail-adv-*`, `pass-adv-*` and
// `unreadable-adv-*` are the eval-adversarial cases of round 1 in that shape.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkState, closingPageArgs, findings, forkLinks, liveState, loadRules, openPullsArgs, printable, truncatedForks, unseenOwn } from "./branch-findings.mjs";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const SCRIPT = join(HERE, "branch-check.mjs");
const FIXTURES = join(HERE, "fixtures", "branch-check");
const RULES_TEXT = readFileSync(join(HERE, "branch-rules.json"), "utf8");
const FIXTURE_NAMES = readdirSync(FIXTURES);
const STATE_FIXTURES = FIXTURE_NAMES.filter((name) => /^(pass|fail)-.+\.json$/.test(name));
const UNREADABLE_FIXTURES = FIXTURE_NAMES.filter((name) => name.startsWith("unreadable"));
const SUMMARY = /^branch-check: example\/repo: \d+ branches, \d+ open pull requests, fork links: (\d+), findings: (\d+)\.$/;
const LINK_REFUSED = new Set(["EPERM", "EACCES", "ENOTSUP", "ENOSYS"]);
const PULL = { number: 1, head: "issue/1", head_repo: "example/repo", author: { login: "example-dev", type: "User" }, body: null, closing_issues: [], closing_total: 0 };
const STATE = { repo: "example/repo", default_branch: "main", branches: ["main", "issue/1"], pulls: [PULL] };

function run(script, ...args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
}

function lastLine(stdout) {
  return stdout.split(/\r?\n/).filter(Boolean).at(-1) ?? "";
}

function kindsAndSubjects(list) {
  return list.map(({ kind, subject }) => `${kind} ${subject}`).sort();
}

function pullsAndIssues(list) {
  return list.map(({ pull, issue }) => `#${pull} #${issue}`).sort();
}

function rulesWith(change) {
  const raw = JSON.parse(RULES_TEXT);
  change(raw);
  return JSON.stringify(raw);
}

function linkOrSkip(t, target, path, type) {
  try {
    symlinkSync(target, path, type);
    return true;
  } catch (error) {
    if (!LINK_REFUSED.has(error.code)) throw error;
    t.skip(`this system refuses to create a ${type} link (${error.code})`);
    return false;
  }
}

test("the fixture set seeds failures, clean states and states it cannot read", () => {
  assert.ok(STATE_FIXTURES.filter((name) => name.startsWith("fail-")).length >= 4);
  assert.ok(STATE_FIXTURES.filter((name) => name.startsWith("pass-")).length >= 2);
  assert.ok(UNREADABLE_FIXTURES.length >= 3);
});

for (const name of STATE_FIXTURES) {
  const fixture = JSON.parse(readFileSync(join(FIXTURES, name), "utf8"));
  const seededFailure = name.startsWith("fail-");
  const expectedForkLinks = fixture.expect_fork_links ?? [];

  test(`${name}: findings and fork links match the hand-written expectation`, () => {
    const state = checkState(fixture);
    const rules = loadRules(RULES_TEXT);
    assert.deepEqual(kindsAndSubjects(findings(state, rules)), kindsAndSubjects(fixture.expect));
    assert.deepEqual(pullsAndIssues(forkLinks(state, rules)), pullsAndIssues(expectedForkLinks));
    assert.equal(fixture.expect.length > 0, seededFailure);
  });

  test(`${name}: the command exits ${seededFailure ? 1 : 0} and ends with the summary line`, () => {
    const result = run(SCRIPT, "--state", join(FIXTURES, name));
    assert.equal(result.status, seededFailure ? 1 : 0, result.stderr);
    const printed = result.stdout.split(/\r?\n/);
    for (const { subject } of fixture.expect) {
      const shown = subject.startsWith("#") ? subject : printable(subject);
      assert.ok(printed.some((line) => line.startsWith(`finding: ${shown}: `)), subject);
    }
    assert.equal(printed.filter((line) => line.startsWith("finding: ")).length, fixture.expect.length);
    const summary = SUMMARY.exec(lastLine(result.stdout));
    assert.ok(summary, `last line: ${lastLine(result.stdout)}`);
    assert.equal(Number(summary[1]), expectedForkLinks.length);
    assert.equal(Number(summary[2]), fixture.expect.length);
    const truncated = printed.filter((line) => /^info: fork pull request #\d+ closes more issues than one page lists/.test(line));
    assert.deepEqual(truncated.map((line) => Number(/#(\d+)/.exec(line)?.[1])), fixture.expect_truncated_forks ?? []);
    const unseen = printed.filter((line) => /^info: pull request #\d+ counts \d+ closing references the token cannot see/.test(line));
    assert.deepEqual(unseen.map((line) => Number(/#(\d+)/.exec(line)?.[1])), fixture.expect_unseen ?? []);
  });
}

for (const name of UNREADABLE_FIXTURES) {
  test(`${name}: the command exits 2 and prints no summary line`, () => {
    const result = run(SCRIPT, "--state", join(FIXTURES, name));
    assert.equal(result.status, 2);
    assert.match(result.stderr, /^branch-check could not look: /);
    assert.equal(result.stdout, "");
  });
}

test("the entry runs through a directory link (junction on Windows)", (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "branch-check-"));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const linked = join(scratch, "hooks");
  if (!linkOrSkip(t, HERE, linked, "junction")) return;
  const result = run(join(linked, "branch-check.mjs"), "--state", join(linked, "fixtures", "branch-check", "fail-bad-name.json"));
  assert.equal(result.status, 1, result.stderr);
  assert.match(lastLine(result.stdout), /findings: 6\.$/);
});

test("the entry runs through a file link", (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "branch-check-"));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const linked = join(scratch, "branch-check.mjs");
  if (!linkOrSkip(t, SCRIPT, linked, "file")) return;
  const result = run(linked, "--state", join(FIXTURES, "fail-bad-name.json"));
  assert.equal(result.status, 1, result.stderr);
  assert.match(lastLine(result.stdout), /findings: 6\.$/);
});

test("the first --state wins when it is given twice", () => {
  const result = run(SCRIPT, "--state", join(FIXTURES, "fail-adv-a25-state-flag-twice.json"), "--state", join(FIXTURES, "pass-default-branch-only.json"));
  assert.equal(result.status, 1, result.stderr);
  assert.match(lastLine(result.stdout), /findings: 1\.$/);
});

// A stand-in for `gh`: answers the four reads by their arguments, in GitHub's shapes after --jq,
// and records each closing-references page asked for.
function fakeGh({ ownTotal, forkTotal = 0, pageSize, alwaysMore = false }) {
  const asked = [];
  const issuesFrom = (start, count) => Array.from({ length: count }, (_, k) => ({ number: start + k, repo: "example/repo" }));
  const first = (number, head_repo, total) => ({
    number, head: number === 1 ? "issue/1" : "patch-1", head_repo, author: PULL.author, body: null,
    closing_issues: issuesFrom(number * 1000, Math.min(total, pageSize)), closing_total: total,
    closing_cursor: total > pageSize ? `c${number}-1` : null, closing_more: total > pageSize,
  });
  const gh = (args) => {
    const query = args.find((arg) => arg.startsWith("query=")) ?? "";
    if (args[1] === "repos/{owner}/{repo}") return JSON.stringify({ full_name: "example/repo", default_branch: "main" });
    if (args[1] === "repos/{owner}/{repo}/branches") return "main\nissue/1\n";
    if (query.includes("pullRequests(")) {
      return [first(1, "example/repo", ownTotal), first(2, "contributor/repo", forkTotal)].map((p) => JSON.stringify(p)).join("\n");
    }
    const number = Number(args[args.indexOf("-F") + 1]?.replace("number=", ""));
    const after = args.find((arg) => arg.startsWith("after="))?.slice(6) ?? "";
    asked.push({ number, after });
    const page = Number(after.split("-")[1]);
    const start = number * 1000 + page * pageSize;
    const count = Math.max(0, Math.min(pageSize, ownTotal - page * pageSize));
    const more = alwaysMore || (page + 1) * pageSize < ownTotal;
    return JSON.stringify({ issues: issuesFrom(start, alwaysMore ? pageSize : count), cursor: `c${number}-${page + 1}`, more });
  };
  return { gh, asked };
}

test("live: an own pull request's closing references are read page by page until complete", () => {
  const rules = loadRules(RULES_TEXT);
  const { gh, asked } = fakeGh({ ownTotal: 2 * rules.pageSize + 50, pageSize: rules.pageSize });
  const state = checkState(liveState(rules, gh));
  const own = state.pulls.find((pull) => pull.number === 1);
  assert.equal(own?.closing_issues.length, 2 * rules.pageSize + 50);
  assert.equal(new Set(own?.closing_issues.map((issue) => issue.number)).size, 2 * rules.pageSize + 50);
  assert.deepEqual(asked, [{ number: 1, after: "c1-1" }, { number: 1, after: "c1-2" }]);
  assert.deepEqual(findings(state, rules), []);
});

test("live: an own pull request over closing_pages_limit could not be looked at", () => {
  const rules = loadRules(rulesWith((raw) => (raw.closing_pages_limit = 3)));
  const { gh, asked } = fakeGh({ ownTotal: 10 * rules.pageSize, pageSize: rules.pageSize, alwaysMore: true });
  assert.throws(() => liveState(rules, gh), /#1 closes more issues than 3 pages list/);
  assert.equal(asked.length, 2);
});

test("live: a fork pull request keeps one page and becomes an info line", () => {
  const rules = loadRules(RULES_TEXT);
  const { gh, asked } = fakeGh({ ownTotal: 1, forkTotal: rules.pageSize + 1, pageSize: rules.pageSize });
  const state = checkState(liveState(rules, gh));
  assert.deepEqual(asked, []);
  assert.deepEqual(truncatedForks(state), [2]);
});

test("the closing-references page query passes owner, name and cursor as strings", () => {
  const args = closingPageArgs("123", "true", 7, 100, "Y3Vyc29y");
  const field = (flag, value) => args.some((arg, i) => arg === flag && args[i + 1] === value);
  assert.ok(field("-f", "owner=123") && field("-f", "name=true") && field("-f", "after=Y3Vyc29y"), args.join(" "));
  assert.ok(field("-F", "number=7") && field("-F", "pageSize=100"), args.join(" "));
  assert.ok(!args.includes("--paginate"));
});

test("a flood of fork links prints at most the limit of info lines, one count, then the summary", (t) => {
  const scratch = mkdtempSync(join(tmpdir(), "branch-check-"));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const forks = 10;
  const refsEach = 6058;
  const body = Array.from({ length: refsEach }, (_, k) => `Refs #${k + 1}`).join("\n");
  const flood = Array.from({ length: forks }, (_, k) => ({ ...PULL, number: 100 + k, head: `patch-${k}`, head_repo: "outsider/repo", body }));
  const file = join(scratch, "flood.json");
  writeFileSync(file, JSON.stringify({ ...STATE, pulls: [PULL, ...flood] }));
  const limit = JSON.parse(RULES_TEXT).fork_info_line_limit;
  const result = run(SCRIPT, "--state", file);
  assert.equal(result.status, 0, result.stderr);
  const printed = result.stdout.split(/\r?\n/).filter(Boolean);
  assert.equal(printed.length, limit + 2);
  assert.equal(printed.at(-2), `info: ${forks * refsEach - limit} more fork lines not shown.`);
  const summary = SUMMARY.exec(printed.at(-1) ?? "");
  assert.ok(summary, printed.at(-1));
  assert.equal(Number(summary[1]), forks * refsEach);
  assert.equal(Number(summary[2]), 0);
});

test("branch names are always quoted, with anything outside printable ASCII escaped", () => {
  assert.equal(printable("issue/30"), '"issue/30"');
  assert.equal(printable("info"), '"info"');
  assert.equal(printable('a"b\\c'), '"a\\u{22}b\\u{5c}c"');
  assert.equal(printable("issue/30\n"), '"issue/30\\u{a}"');
  assert.equal(printable("issue/30\u200b"), '"issue/30\\u{200b}"');
  assert.equal(printable("d\u0435pendabot/x"), '"d\\u{435}pendabot/x"');
  assert.equal(printable("\u001b[2Jissue/1"), '"\\u{1b}[2Jissue/1"');
});

test("every finding names the fix and where it is written", () => {
  const fixture = JSON.parse(readFileSync(join(FIXTURES, "fail-replaced-pull-request-left-open.json"), "utf8"));
  for (const finding of findings(checkState(fixture), loadRules(RULES_TEXT))) {
    assert.match(finding.message, /grdr-work-issue, "Branches and pull requests"/);
  }
});

test("Dependabot's prefix and release-please's one branch, each with its bot author, are the only exemptions", () => {
  assert.deepEqual(loadRules(RULES_TEXT).exemptions, [
    { match: "prefix", value: "dependabot/", authors: [{ login: "dependabot", type: "Bot" }] },
    { match: "name", value: "release-please--branches--main", authors: [{ login: "github-actions", type: "Bot" }] },
  ]);
});

test("the open pull request query passes owner and name as strings", () => {
  const args = openPullsArgs("123", "true", 100);
  const field = (flag, value) => args.some((arg, i) => arg === flag && args[i + 1] === value);
  assert.ok(field("-f", "owner=123"), args.join(" "));
  assert.ok(field("-f", "name=true"), args.join(" "));
  assert.ok(field("-F", "pageSize=100"), args.join(" "));
  assert.ok(!args.some((arg, i) => arg === "-F" && /^(owner|name)=/.test(args[i + 1] ?? "")));
});

test("an exemption names exactly one of prefix and name, and authors with login and type", () => {
  const bot = { login: "a", type: "Bot" };
  const entries = [
    { authors: [bot] },
    { prefix: "a/", name: "b", authors: [bot] },
    { name: "", authors: [bot] },
    { prefix: "a/" },
    { prefix: "a/", authors: [] },
    { prefix: "a/", authors: ["a[bot]"] },
    { prefix: "a/", authors: [{ login: "a" }] },
  ];
  for (const entry of entries) {
    assert.throws(() => loadRules(rulesWith((raw) => (raw.exempt_from_name = [entry]))), /exempt_from_name/);
  }
});

test("unreadable state exits 2, not 0, and prints no summary line", () => {
  const result = run(SCRIPT, "--state", join(FIXTURES, "unreadable.txt"));
  assert.equal(result.status, 2);
  assert.match(result.stderr, /^branch-check could not look: /);
  assert.equal(result.stdout, "");
});

test("--state with no file exits 2", () => {
  assert.equal(run(SCRIPT, "--state").status, 2);
});

test("a state of the wrong shape could not be looked at", () => {
  assert.ok(checkState(STATE));
  assert.ok(checkState({ ...STATE, pulls: [{ ...PULL, author: null, head_repo: null }] }));
  const wrong = [
    { ...STATE, pulls: undefined },
    { ...STATE, repo: undefined },
    { ...STATE, pulls: [{ ...PULL, number: "1" }] },
    { ...STATE, pulls: [{ ...PULL, author: undefined }] },
    { ...STATE, pulls: [{ ...PULL, author: "example-dev" }] },
    { ...STATE, pulls: [{ ...PULL, author: { login: "example-dev" } }] },
    { ...STATE, pulls: [{ ...PULL, closing_issues: undefined }] },
    { ...STATE, pulls: [{ ...PULL, closing_issues: [30] }] },
    { ...STATE, pulls: [{ ...PULL, closing_total: undefined }] },
    { ...STATE, pulls: [{ ...PULL, closing_total: -1 }] },
    { ...STATE, pulls: [{ ...PULL, closing_issues: [{ number: 2, repo: "example/repo" }], closing_total: 0 }] },
  ];
  for (const state of wrong) assert.throws(() => checkState(state), /documented shape/);
});

test("a short closing list is information: references the token cannot see on ours, one page on forks", () => {
  const short = { closing_issues: [{ number: 2, repo: "example/repo" }], closing_total: 150 };
  const own = checkState({ ...STATE, pulls: [{ ...PULL, ...short }] });
  assert.deepEqual(unseenOwn(own), [{ pull: 1, unseen: 149 }]);
  assert.deepEqual(truncatedForks(own), []);
  const unreadable = { closing_issues: [], closing_total: 1 };
  assert.deepEqual(unseenOwn(checkState({ ...STATE, pulls: [{ ...PULL, ...unreadable }] })), [{ pull: 1, unseen: 1 }]);
  const forks = [
    { ...PULL, number: 2, head_repo: "contributor/repo", ...short },
    { ...PULL, number: 3, head_repo: null, ...short },
    { ...PULL, number: 4, head_repo: "contributor/repo", ...unreadable },
  ];
  const state = checkState({ ...STATE, pulls: [PULL, ...forks] });
  assert.deepEqual(truncatedForks(state), [2, 3, 4]);
  assert.deepEqual(unseenOwn(state), []);
});

test("messages name the work branch from the work_branch_form data", () => {
  const rules = loadRules(rulesWith((raw) => Object.assign(raw, { work_branch: "^work-([1-9][0-9]*)$", work_branch_form: "work-<n>" })));
  const second = { ...PULL, number: 2, head: "wip", closing_issues: [{ number: 1, repo: "example/repo" }], closing_total: 1 };
  const state = { ...STATE, branches: ["main", "work-1", "wip"], pulls: [{ ...PULL, head: "work-1" }, second] };
  const messages = findings(state, rules).map((finding) => finding.message);
  assert.ok(messages.some((message) => message.startsWith('"wip": not named work-<n>,') && message.includes("Move its commits to work-<n>")), messages.join("\n"));
  assert.ok(messages.some((message) => message.includes("Keep the one on work-1 ")), messages.join("\n"));
  assert.ok(messages.every((message) => !message.includes("issue/")), messages.join("\n"));
});

test("a branch list without the default branch is incomplete", () => {
  assert.throws(() => checkState({ ...STATE, branches: ["issue/1"] }), /lacks the default branch/);
});

test("a closing reference to another repository is not a link", () => {
  const other = { ...PULL, number: 2, head: "issue/2", closing_issues: [{ number: 1, repo: "other/repo" }] };
  const state = { ...STATE, branches: ["main", "issue/1", "issue/2"], pulls: [PULL, other] };
  assert.deepEqual(findings(state, loadRules(RULES_TEXT)), []);
  const same = { ...other, closing_issues: [{ number: 1, repo: "example/repo" }] };
  assert.deepEqual(kindsAndSubjects(findings({ ...state, pulls: [PULL, same] }, loadRules(RULES_TEXT))), ["second-pull-request #1"]);
});

test("rules missing a value, or with the wrong capture groups, are refused", () => {
  for (const key of ["work_branch", "reference_line"]) {
    assert.throws(() => loadRules(rulesWith((raw) => delete raw[key])), new RegExp(`no ${key}`));
  }
  for (const key of ["exempt_from_name", "graphql_page_size", "closing_pages_limit", "fork_info_line_limit", "gh_output_limit_bytes"]) {
    assert.throws(() => loadRules(rulesWith((raw) => delete raw[key])), new RegExp(key));
  }
  assert.throws(() => loadRules(rulesWith((raw) => (raw.reference_line = "^refs #[0-9]+$"))), /exactly one capture group/);
  assert.throws(() => loadRules(rulesWith((raw) => delete raw.work_branch_form)), /work_branch_form/);
  assert.throws(() => loadRules(rulesWith((raw) => (raw.work_branch_form = "issue/n"))), /work_branch_form/);
  assert.throws(() => loadRules(rulesWith((raw) => (raw.work_branch_form = "work/<n>"))), /work_branch_form/);
});
