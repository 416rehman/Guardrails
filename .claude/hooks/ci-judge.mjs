// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// The CI stop condition of skill grdr-build: is CI on `main` red? It judges each required
// workflow by its latest push run on `main`, never by the newest runs of any kind, and reads job
// names only from runs of merged code, so a pull request that renames its jobs cannot make a red
// `main` read green. Exit 0 green, 1 red, 2 could not judge; the last line of stdout is the summary
// only when it judged.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const RULES_FILE = fileURLToPath(new URL("./ci-rules.json", import.meta.url));
const EXIT = { green: 0, red: 1, couldNotJudge: 2 };
const REQUIRED_CHECKS = '.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context';
const PUSH_ON_MAIN = ["--branch", "main", "--event", "push"];

class CouldNotJudge extends Error {}

function lines(text) {
  return text.split(/\r?\n/).filter(Boolean);
}

function positiveInteger(raw, key) {
  const value = raw?.[key];
  if (!Number.isSafeInteger(value) || value <= 0) throw new CouldNotJudge(`ci-rules.json ${key} needs a positive integer`);
  return value;
}

export function loadCiRules(text) {
  let raw;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new CouldNotJudge("ci-rules.json is not JSON");
  }
  return {
    pollIntervalSeconds: positiveInteger(raw, "poll_interval_seconds"),
    pollLimit: positiveInteger(raw, "poll_limit"),
    workflowListLimit: positiveInteger(raw, "workflow_list_limit"),
    requiredCheckLimit: positiveInteger(raw, "required_check_limit"),
  };
}

// A list as long as its cap may have been cut short, so it cannot be judged from.
function belowCap(list, cap, what) {
  if (list.length >= cap) throw new CouldNotJudge(`${what} reached its cap of ${cap}, so it may be incomplete`);
  return list;
}

function firstRun(text) {
  let runs;
  try {
    runs = JSON.parse(text);
  } catch {
    throw new CouldNotJudge("gh run list printed no JSON list");
  }
  if (!Array.isArray(runs)) throw new CouldNotJudge("gh run list did not return a list");
  return runs[0];
}

function jobNames(gh, runId) {
  return lines(gh(["run", "view", String(runId), "--json", "jobs", "--jq", ".jobs[].name"]));
}

// Polls rather than `gh run watch`, whose output over a long run outgrows any fixed buffer. A run
// still unfinished after the last poll keeps a conclusion that is not success, so it reads red.
function finished(gh, run, rules, sleep) {
  let current = run;
  for (let poll = 0; current.status !== "completed"; poll += 1) {
    if (poll >= rules.pollLimit) return { ...current, conclusion: `still ${current.status} after ${rules.pollLimit} polls` };
    sleep(rules.pollIntervalSeconds);
    current = { ...current, ...JSON.parse(gh(["run", "view", String(run.databaseId), "--json", "status,conclusion"])) };
  }
  return current;
}

// Job names come from the latest push run on `main`. A run that never started has none, so they
// come from the last successful push run on `main` instead; with no such run there is no merged
// code to say which checks the workflow provides, and it counts as red.
function judgeWorkflow(gh, id, required, rules, sleep) {
  const latest = firstRun(gh(["run", "list", "--workflow", id, ...PUSH_ON_MAIN, "--limit", "1", "--json", "databaseId,conclusion,status"]));
  if (!latest) return { id, verdict: "not judged" };
  const run = finished(gh, latest, rules, sleep);
  const jobs = run.conclusion === "startup_failure" ? [] : jobNames(gh, run.databaseId);
  if (jobs.length > 0) {
    if (!jobs.some((job) => required.includes(job))) return { id, verdict: "not required" };
    return { id, verdict: run.conclusion === "success" ? "green" : "red", conclusion: run.conclusion };
  }
  const merged = firstRun(gh(["run", "list", "--workflow", id, ...PUSH_ON_MAIN, "--status", "success", "--limit", "1", "--json", "databaseId"]));
  if (!merged) return { id, verdict: "red", conclusion: `${run.conclusion}, no successful push run on main` };
  if (!jobNames(gh, merged.databaseId).some((job) => required.includes(job))) return { id, verdict: "not required" };
  return { id, verdict: "red", conclusion: run.conclusion };
}

export function judge(gh, rules, sleep) {
  const ruleset = lines(gh(["api", "repos/{owner}/{repo}/rules/branches/main", "--paginate", "--jq", REQUIRED_CHECKS]));
  const required = belowCap(ruleset, rules.requiredCheckLimit, "the required check list");
  if (required.length === 0) throw new CouldNotJudge("the ruleset of main lists no required checks");
  const listed = lines(gh(["workflow", "list", "--limit", String(rules.workflowListLimit), "--json", "id", "--jq", ".[].id"]));
  const workflows = belowCap(listed, rules.workflowListLimit, "the workflow list").map((id) => judgeWorkflow(gh, id, required, rules, sleep));
  const red = workflows.filter((workflow) => workflow.verdict === "red");
  if (red.length > 0) return { verdict: "red", workflows: red };
  const green = workflows.filter((workflow) => workflow.verdict === "green");
  if (green.length === 0) throw new CouldNotJudge("no workflow's latest push run on main provides a required check");
  return { verdict: "green", workflows: green };
}

function sleepSeconds(seconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, seconds * 1000);
}

function runGh(args) {
  return execFileSync("gh", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

export function main(gh = runGh, sleep = sleepSeconds, rulesText = undefined) {
  try {
    const rules = loadCiRules(rulesText ?? readFileSync(RULES_FILE, "utf8"));
    const result = judge(gh, rules, sleep);
    const named = result.workflows.map((workflow) => `${workflow.id}=${workflow.conclusion ?? "success"}`).join(", ");
    process.stdout.write(`ci-stop: ${result.verdict}: required workflows ${named}.\n`);
    return result.verdict === "red" ? EXIT.red : EXIT.green;
  } catch (error) {
    const reason = error instanceof CouldNotJudge ? error.message : `gh failed: ${error.message}`;
    process.stderr.write(`ci-stop could not judge: ${reason}\n`);
    return EXIT.couldNotJudge;
  }
}
