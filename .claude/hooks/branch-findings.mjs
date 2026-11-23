// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// Streamlined repository branch hygiene checks:
// - Branches (other than main and exempt bots) follow feat/<slug>, fix/<slug>, chore/<slug>, docs/<slug>, refactor/<slug>, or issue/<n>-<slug>.
// - Pushed branches should have an open pull request.
// Exit 0 with no findings, 1 with findings, 2 when state is unreadable.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const RULES_FILE = fileURLToPath(new URL("./branch-rules.json", import.meta.url));
const EXIT = { clean: 0, findings: 1, couldNotLook: 2 };
const OPEN_PULLS_QUERY = `query($owner: String!, $name: String!, $pageSize: Int!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: $pageSize, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number headRefName title body
        headRepository { nameWithOwner }
        author { login __typename }
      }
    }
  }
}`;
const OPEN_PULL_FIELDS = `.data.repository.pullRequests.nodes[] | {
  number, head: .headRefName, title, head_repo: .headRepository.nameWithOwner, body,
  author: (if .author then {login: .author.login, type: .author.__typename} else null end)
}`;

export function slugifyTitle(title, maxLen = 60) {
  const raw = String(title ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (raw.length <= maxLen) return raw;
  return raw.slice(0, maxLen).replace(/-+$/g, "");
}

function isAuthor(author) {
  return typeof author?.login === "string" && author.login !== "" && typeof author.type === "string" && author.type !== "";
}

function isExemption(entry) {
  const given = ["prefix", "name"].filter((key) => typeof entry?.[key] === "string" && entry[key]);
  if (given.length !== 1 || ("prefix" in entry && "name" in entry)) return false;
  return Array.isArray(entry.authors) && entry.authors.length > 0 && entry.authors.every(isAuthor);
}

function positiveInteger(raw, key) {
  const value = raw?.[key];
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`branch-rules.json ${key} needs a positive integer`);
  return value;
}

export function loadRules(text) {
  const raw = JSON.parse(text);
  const exempt = raw?.exempt_from_name;
  if (!Array.isArray(exempt) || !exempt.every(isExemption)) {
    throw new Error("branch-rules.json exempt_from_name needs a list of entries, each with either a prefix or a name, and its authors");
  }
  const source = raw?.work_branch;
  if (typeof source !== "string" || !source) {
    throw new Error("branch-rules.json has no work_branch pattern");
  }
  const form = raw?.work_branch_form;
  if (typeof form !== "string" || !form) {
    throw new Error("branch-rules.json needs work_branch_form");
  }
  return {
    workBranch: new RegExp(source),
    workBranchForm: form,
    exemptions: exempt.map(({ prefix, name, authors }) => ({
      ...(prefix === undefined ? { match: "name", value: name } : { match: "prefix", value: prefix }),
      authors: authors.map(({ login, type }) => ({ login, type })),
    })),
    pageSize: positiveInteger(raw, "graphql_page_size"),
    forkInfoLineLimit: positiveInteger(raw, "fork_info_line_limit"),
    outputLimitBytes: positiveInteger(raw, "gh_output_limit_bytes"),
  };
}

function isPull(pull) {
  return (
    Number.isSafeInteger(pull?.number) &&
    typeof pull.head === "string" &&
    (pull.title === undefined || pull.title === null || typeof pull.title === "string") &&
    (pull.head_repo === null || typeof pull.head_repo === "string") &&
    (pull.author === null || isAuthor(pull.author)) &&
    (pull.body === null || typeof pull.body === "string")
  );
}

function isOwnPull(pull, state) {
  return pull.head_repo === state.repo;
}

export function checkState(state) {
  const shaped =
    typeof state?.repo === "string" &&
    typeof state.default_branch === "string" &&
    Array.isArray(state.branches) &&
    state.branches.every((branch) => typeof branch === "string") &&
    Array.isArray(state.pulls) &&
    state.pulls.every(isPull);
  if (!shaped) throw new Error("the state needs repo, default_branch, branches and pulls in the documented shape");
  if (!state.branches.includes(state.default_branch)) {
    throw new Error(`the branch list lacks the default branch ${state.default_branch}, so it is not the whole list`);
  }
  return state;
}

function lines(text) {
  return text.split(/\r?\n/).filter(Boolean);
}

export function openPullsArgs(owner, name, pageSize) {
  const variables = ["-f", `owner=${owner}`, "-f", `name=${name}`, "-F", `pageSize=${pageSize}`];
  return ["api", "graphql", "--paginate", "-f", `query=${OPEN_PULLS_QUERY}`, ...variables, "--jq", OPEN_PULL_FIELDS];
}

function runGh(rules) {
  return (args) => execFileSync("gh", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: rules.outputLimitBytes });
}

export function liveState(rules, gh = runGh(rules)) {
  const repository = JSON.parse(gh(["api", "repos/{owner}/{repo}", "--jq", "{full_name, default_branch}"]));
  const [owner, name, ...rest] = String(repository.full_name).split("/");
  if (!owner || !name || rest.length) throw new Error(`GitHub named the repository ${repository.full_name}, not owner/name`);
  const branches = lines(gh(["api", "repos/{owner}/{repo}/branches", "--paginate", "--jq", ".[].name"]));
  const pulls = lines(gh(openPullsArgs(owner, name, rules.pageSize))).map((line) => JSON.parse(line));
  return { repo: repository.full_name, default_branch: repository.default_branch, branches, pulls };
}

function stateFrom(argv, rules) {
  const at = argv.indexOf("--state");
  if (at === -1) return checkState(liveState(rules));
  const file = argv[at + 1];
  if (!file) throw new Error("--state needs a file");
  return checkState(JSON.parse(readFileSync(file, "utf8")));
}

export function isValidWorkBranch(branch, rules) {
  return rules.workBranch.test(branch);
}

function isByAuthor(pull, authors) {
  return authors.some((author) => author.login === pull.author?.login && author.type === pull.author?.type);
}

export function coversBranch(exemption, branch) {
  return exemption.match === "prefix" ? branch.startsWith(exemption.value) : branch === exemption.value;
}

function isExempt(branch, pulls, rules) {
  return rules.exemptions.some(
    (exemption) => coversBranch(exemption, branch) && pulls.every((pull) => isByAuthor(pull, exemption.authors)),
  );
}

export function printable(name) {
  const escaped = [...name].map((char) => (/^[\x20-\x7e]$/.test(char) && char !== '"' && char !== "\\" ? char : `\\u{${char.codePointAt(0)?.toString(16)}}`));
  return `"${escaped.join("")}"`;
}

function pullNumbers(pulls) {
  return pulls.map((pull) => `#${pull.number}`).join(", ");
}

export function findings(state, rules) {
  const pullsByHead = new Map();
  for (const pull of state.pulls.filter((candidate) => isOwnPull(candidate, state))) {
    pullsByHead.set(pull.head, [...(pullsByHead.get(pull.head) ?? []), pull]);
  }
  const found = [];
  for (const branch of state.branches.filter((name) => name !== state.default_branch)) {
    const pulls = pullsByHead.get(branch) ?? [];
    if (pulls.length > 1) {
      found.push({
        kind: "second-pull-request",
        subject: branch,
        message: `${printable(branch)}: head of multiple open pull requests (${pullNumbers(pulls)}).`,
      });
    }
    if (pulls.length === 0) {
      found.push({
        kind: "no-pull-request",
        subject: branch,
        message: `${printable(branch)}: no open pull request. Open a PR or delete the stale branch.`,
      });
    }
    if (!isValidWorkBranch(branch, rules) && !isExempt(branch, pulls, rules)) {
      found.push({
        kind: "bad-name",
        subject: branch,
        message: `${printable(branch)}: branch name should follow ${rules.workBranchForm}.`,
      });
    }
  }
  return found;
}

export function main(argv) {
  try {
    const rules = loadRules(readFileSync(RULES_FILE, "utf8"));
    const state = stateFrom(argv, rules);
    const found = findings(state, rules);
    for (const finding of found) process.stdout.write(`finding: ${finding.message}\n`);
    process.stdout.write(
      `branch-check: ${state.repo}: ${state.branches.length} branches, ${state.pulls.length} open pull requests, findings: ${found.length}.\n`,
    );
    return found.length ? EXIT.findings : EXIT.clean;
  } catch (error) {
    process.stderr.write(`branch-check could not look: ${error.message}\n`);
    return EXIT.couldNotLook;
  }
}
