// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Tests for ci-stop.mjs: node --test .claude/hooks/ci-stop.test.mjs
// Each fixture records GitHub's answers to the exact gh commands of grdr-build's CI stop condition,
// keyed by the start of the command, and the verdict the session's rulings on #1875 call for.
// `never_asked` lists answers that are there as a trap: reading them would be the defect.
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { judge, loadCiRules, main } from "./ci-judge.mjs";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const FIXTURES = join(HERE, "fixtures", "ci-stop");
const EXIT_FOR = { green: 0, red: 1, "could not judge": 2 };
const RULES_TEXT = readFileSync(join(HERE, "ci-rules.json"), "utf8");
const RULES = loadCiRules(RULES_TEXT);

function rulesTextFor(fixture) {
  return JSON.stringify({ ...JSON.parse(RULES_TEXT), ...fixture.rules });
}

// An answer that is a list is returned one item per call, its last item from then on.
function fakeGh(answers) {
  const asked = [];
  const calls = new Map();
  const gh = (args) => {
    const command = args.join(" ");
    asked.push(command);
    const match = answers.filter(([key]) => command.startsWith(key)).sort(([a], [b]) => b.length - a.length)[0];
    if (!match) throw new Error(`unexpected gh call: gh ${command}`);
    const [key, answer] = match;
    if (!Array.isArray(answer)) return answer;
    const call = calls.get(key) ?? 0;
    calls.set(key, call + 1);
    return answer[Math.min(call, answer.length - 1)];
  };
  return { gh, asked };
}

function fakeSleep() {
  const slept = [];
  return { sleep: (seconds) => slept.push(seconds), slept };
}

function verdictOf(gh, sleep = fakeSleep().sleep, rules = RULES) {
  try {
    return judge(gh, rules, sleep).verdict;
  } catch (error) {
    if (/^unexpected gh call/.test(error.message)) throw error;
    return "could not judge";
  }
}

function quietly(run) {
  const write = process.stdout.write;
  const writeError = process.stderr.write;
  const printed = [];
  process.stdout.write = (text) => printed.push(String(text)) > 0;
  process.stderr.write = (text) => printed.push(String(text)) > 0;
  try {
    return { status: run(), printed: printed.join("") };
  } finally {
    process.stdout.write = write;
    process.stderr.write = writeError;
  }
}

const FIXTURE_NAMES = readdirSync(FIXTURES).filter((name) => name.endsWith(".json"));

test("the fixtures cover green, a workflow that fails to start, and a pull request that renames its jobs", () => {
  for (const name of ["green.json", "verify-fails-to-start.json", "renamed-jobs-pull-request.json"]) assert.ok(FIXTURE_NAMES.includes(name), name);
});

for (const name of FIXTURE_NAMES) {
  const fixture = JSON.parse(readFileSync(join(FIXTURES, name), "utf8"));

  test(`${name}: reads ${fixture.expect}`, () => {
    const { gh, asked } = fakeGh(fixture.answers);
    const { sleep, slept } = fakeSleep();
    assert.equal(verdictOf(gh, sleep, loadCiRules(rulesTextFor(fixture))), fixture.expect);
    for (const trap of fixture.never_asked ?? []) assert.ok(!asked.some((command) => command.startsWith(trap)), `asked: ${trap}`);
    const polls = asked.filter((command) => / --json status,conclusion$/.test(command)).length;
    if (fixture.expect_polls !== undefined) assert.equal(polls, fixture.expect_polls);
    assert.equal(slept.length, polls);
    assert.ok(slept.every((seconds) => seconds === RULES.pollIntervalSeconds));
  });

  test(`${name}: main exits ${EXIT_FOR[fixture.expect]} and, when it judged, ends with the summary`, () => {
    const { gh } = fakeGh(fixture.answers);
    const { status, printed } = quietly(() => main(gh, fakeSleep().sleep, rulesTextFor(fixture)));
    assert.equal(status, EXIT_FOR[fixture.expect], printed);
    if (fixture.expect === "could not judge") assert.match(printed, /^ci-stop could not judge: /);
    else assert.match(printed.trim().split(/\r?\n/).at(-1) ?? "", new RegExp(`^ci-stop: ${fixture.expect}: required workflows .+\\.$`));
  });
}

test("a gh failure could not be judged, never green", () => {
  const gh = () => {
    throw new Error("HTTP 401");
  };
  const { status, printed } = quietly(() => main(gh, fakeSleep().sleep));
  assert.equal(status, 2);
  assert.match(printed, /^ci-stop could not judge: gh failed: HTTP 401/);
});

test("no workflow providing a required check could not be judged", () => {
  const answers = [
    ["api repos/{owner}/{repo}/rules/branches/main", "cargo-deny\n"],
    ["workflow list", "415167653\n"],
    ["run list --workflow 415167653 --branch main --event push --limit 1", '[{"databaseId":20,"conclusion":"success","status":"completed"}]'],
    ["run view 20 --json jobs", "Secrets (gitleaks)\n"],
  ];
  assert.equal(verdictOf(fakeGh(answers).gh), "could not judge");
});

test("a required run still running after poll_limit polls reads red", () => {
  const fixture = JSON.parse(readFileSync(join(FIXTURES, "verify-never-finishes.json"), "utf8"));
  const { gh, asked } = fakeGh(fixture.answers);
  assert.equal(verdictOf(gh), "red");
  assert.equal(asked.filter((command) => / --json status,conclusion$/.test(command)).length, RULES.pollLimit);
});

test("every conclusion other than success reads red", () => {
  for (const conclusion of ["failure", "cancelled", "timed_out", "action_required", "neutral", "skipped", "stale", ""]) {
    const answers = [
      ["api repos/{owner}/{repo}/rules/branches/main", "cargo-deny\n"],
      ["workflow list", "415167656\n"],
      ["run list --workflow 415167656 --branch main --event push --limit 1", JSON.stringify([{ databaseId: 16, conclusion, status: "completed" }])],
      ["run view 16 --json jobs", "cargo-deny\n"],
    ];
    assert.equal(verdictOf(fakeGh(answers).gh), "red", conclusion);
  }
});

test("the list reads are capped from ci-rules.json and use the cap they read", () => {
  const { gh, asked } = fakeGh(JSON.parse(readFileSync(join(FIXTURES, "green.json"), "utf8")).answers);
  verdictOf(gh);
  assert.ok(asked.includes(`workflow list --limit ${RULES.workflowListLimit} --json id --jq .[].id`), asked.join("\n"));
  assert.ok(asked.some((command) => command.startsWith("api repos/{owner}/{repo}/rules/branches/main --paginate --jq ")), asked.join("\n"));
});

test("ci-rules.json needs every bound as a positive integer", () => {
  const raw = JSON.parse(RULES_TEXT);
  for (const key of Object.keys(raw)) {
    for (const value of [undefined, 0, -1, 1.5, "1"]) {
      assert.throws(() => loadCiRules(JSON.stringify({ ...raw, [key]: value })), /ci-rules.json/, `${key}=${value}`);
    }
  }
  assert.throws(() => loadCiRules("not JSON"), /ci-rules.json is not JSON/);
});
