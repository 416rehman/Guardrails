// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// The checks behind branch-check.mjs: the owner rule of #1875, one issue, one branch `issue/<n>`,
// one pull request, against the remote branches and open pull requests of GH_REPO or a JSON state.
// Exit 0 with no findings, 1 with findings, 2 when it could not look, which never counts as clean;
// the last line of stdout is the summary line only when it looked.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const RULES_FILE = fileURLToPath(new URL("./branch-rules.json", import.meta.url));
const EXIT = { clean: 0, findings: 1, couldNotLook: 2 };
const FIX_SECTION = 'skill grdr-work-issue, "Branches and pull requests"';
const OPEN_PULLS_QUERY = `query($owner: String!, $name: String!, $pageSize: Int!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: $pageSize, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number headRefName body
        headRepository { nameWithOwner }
        author { login __typename }
        closingIssuesReferences(first: $pageSize) {
          totalCount pageInfo { hasNextPage endCursor } nodes { number repository { nameWithOwner } }
        }
      }
    }
  }
}`;
const OPEN_PULL_FIELDS = `.data.repository.pullRequests.nodes[] | {
  number, head: .headRefName, head_repo: .headRepository.nameWithOwner, body,
  author: (if .author then {login: .author.login, type: .author.__typename} else null end),
  closing_issues: [.closingIssuesReferences.nodes[] | {number, repo: .repository.nameWithOwner}],
  closing_total: .closingIssuesReferences.totalCount,
  closing_cursor: .closingIssuesReferences.pageInfo.endCursor,
  closing_more: .closingIssuesReferences.pageInfo.hasNextPage
}`;
const CLOSING_PAGE_QUERY = `query($owner: String!, $name: String!, $number: Int!, $pageSize: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      closingIssuesReferences(first: $pageSize, after: $after) {
        pageInfo { hasNextPage endCursor } nodes { number repository { nameWithOwner } }
      }
    }
  }
}`;
const CLOSING_PAGE_FIELDS = `.data.repository.pullRequest.closingIssuesReferences | {
  issues: [.nodes[] | {number, repo: .repository.nameWithOwner}], cursor: .pageInfo.endCursor, more: .pageInfo.hasNextPage
}`;

function captureGroups(source) {
  return (new RegExp(`(?:${source})|`).exec("")?.length ?? 1) - 1;
}

function issuePattern(raw, key, flags) {
  const source = raw?.[key];
  if (typeof source !== "string" || !source) throw new Error(`branch-rules.json has no ${key} pattern`);
  if (captureGroups(source) !== 1) throw new Error(`branch-rules.json ${key} needs exactly one capture group, the issue number`);
  return new RegExp(source, flags);
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

// The form people read, `issue/<n>`, must name the same branches as the work_branch pattern.
function workBranchForm(raw, workBranch) {
  const form = raw?.work_branch_form;
  const sample = typeof form === "string" && form.split("<n>").length === 2 ? form.replace("<n>", "1") : undefined;
  if (sample === undefined || workBranch.exec(sample)?.[1] !== "1") {
    throw new Error("branch-rules.json work_branch_form needs one <n> and must match work_branch when <n> is a number");
  }
  return form;
}

export function loadRules(text) {
  const raw = JSON.parse(text);
  const exempt = raw?.exempt_from_name;
  if (!Array.isArray(exempt) || !exempt.every(isExemption)) {
    throw new Error("branch-rules.json exempt_from_name needs a list of entries, each with either a prefix or a name, and its authors");
  }
  const workBranch = issuePattern(raw, "work_branch", "");
  return {
    workBranch,
    workBranchForm: workBranchForm(raw, workBranch),
    referenceLine: issuePattern(raw, "reference_line", "gim"),
    exemptions: exempt.map(({ prefix, name, authors }) => ({
      ...(prefix === undefined ? { match: "name", value: name } : { match: "prefix", value: prefix }),
      authors: authors.map(({ login, type }) => ({ login, type })),
    })),
    pageSize: positiveInteger(raw, "graphql_page_size"),
    closingPagesLimit: positiveInteger(raw, "closing_pages_limit"),
    forkInfoLineLimit: positiveInteger(raw, "fork_info_line_limit"),
    outputLimitBytes: positiveInteger(raw, "gh_output_limit_bytes"),
  };
}

function isClosingIssue(issue) {
  return Number.isSafeInteger(issue?.number) && typeof issue.repo === "string";
}

function isPull(pull) {
  return (
    Number.isSafeInteger(pull?.number) &&
    typeof pull.head === "string" &&
    (pull.head_repo === null || typeof pull.head_repo === "string") &&
    (pull.author === null || isAuthor(pull.author)) &&
    (pull.body === null || typeof pull.body === "string") &&
    Array.isArray(pull.closing_issues) &&
    pull.closing_issues.every(isClosingIssue) &&
    Number.isSafeInteger(pull.closing_total) &&
    pull.closing_total >= pull.closing_issues.length
  );
}

function isTruncated(pull) {
  return pull.closing_total > pull.closing_issues.length;
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

// After complete paging, GitHub's count can still exceed the list: it counts references in
// repositories the token cannot read. Those are never issues of this repository, so they cannot
// hide a link, and an account with write access to its own repository must not be able to make
// the check stop by adding them.
export function unseenOwn(state) {
  return state.pulls
    .filter((pull) => isOwnPull(pull, state) && isTruncated(pull))
    .map((pull) => ({ pull: pull.number, unseen: pull.closing_total - pull.closing_issues.length }));
}

// A fork pull request with an incomplete list stays information: any account can open one.
export function truncatedForks(state) {
  return state.pulls.filter((pull) => !isOwnPull(pull, state) && isTruncated(pull)).map((pull) => pull.number);
}

function lines(text) {
  return text.split(/\r?\n/).filter(Boolean);
}

// `-f` keeps owner and name as strings; `-F` would turn a repository named `true` or `123` into a
// boolean or a number.
export function openPullsArgs(owner, name, pageSize) {
  const variables = ["-f", `owner=${owner}`, "-f", `name=${name}`, "-F", `pageSize=${pageSize}`];
  return ["api", "graphql", "--paginate", "-f", `query=${OPEN_PULLS_QUERY}`, ...variables, "--jq", OPEN_PULL_FIELDS];
}

export function closingPageArgs(owner, name, number, pageSize, after) {
  const variables = ["-f", `owner=${owner}`, "-f", `name=${name}`, "-F", `number=${number}`, "-F", `pageSize=${pageSize}`, "-f", `after=${after}`];
  return ["api", "graphql", "-f", `query=${CLOSING_PAGE_QUERY}`, ...variables, "--jq", CLOSING_PAGE_FIELDS];
}

// Our own pull requests are read to the end, at most closing_pages_limit pages; a fork keeps its
// first page, since its links are information only.
function withAllClosingIssues(pull, repository, rules, gh) {
  const [owner, name] = repository.split("/");
  let issues = pull.closing_issues;
  let cursor = pull.closing_cursor;
  let more = pull.closing_more === true;
  for (let pages = 1; more; pages += 1) {
    if (pages >= rules.closingPagesLimit) {
      throw new Error(`pull request #${pull.number} closes more issues than ${rules.closingPagesLimit} pages list`);
    }
    const page = JSON.parse(gh(closingPageArgs(owner, name, pull.number, rules.pageSize, cursor)));
    if (!Array.isArray(page?.issues)) throw new Error(`GitHub returned no closing references page for pull request #${pull.number}`);
    issues = [...issues, ...page.issues];
    cursor = page.cursor;
    more = page.more === true;
  }
  return { ...pull, closing_issues: issues };
}

function runGh(rules) {
  return (args) => execFileSync("gh", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: rules.outputLimitBytes });
}

export function liveState(rules, gh = runGh(rules)) {
  const repository = JSON.parse(gh(["api", "repos/{owner}/{repo}", "--jq", "{full_name, default_branch}"]));
  const [owner, name, ...rest] = String(repository.full_name).split("/");
  if (!owner || !name || rest.length) throw new Error(`GitHub named the repository ${repository.full_name}, not owner/name`);
  const branches = lines(gh(["api", "repos/{owner}/{repo}/branches", "--paginate", "--jq", ".[].name"]));
  const firstPages = lines(gh(openPullsArgs(owner, name, rules.pageSize))).map((line) => JSON.parse(line));
  const pulls = firstPages.map((pull) =>
    pull.head_repo === repository.full_name ? withAllClosingIssues(pull, repository.full_name, rules, gh) : pull,
  );
  return { repo: repository.full_name, default_branch: repository.default_branch, branches, pulls };
}

function stateFrom(argv, rules) {
  const at = argv.indexOf("--state");
  if (at === -1) return checkState(liveState(rules));
  const file = argv[at + 1];
  if (!file) throw new Error("--state needs a file");
  return checkState(JSON.parse(readFileSync(file, "utf8")));
}

// Links are GitHub's own closing references (every keyword form, owner/repo#n, issue URLs and the
// Development sidebar) for issues of this repository, the head issue/<n>, and a line `Refs #n`.
// A pull request by an exempt bot on its entry's own branch links through its head only:
// release-please renders commit footers such as `Closes #n` into its changelog, and closing its
// pull request would only make release-please open it again.
function linkedIssues(pull, state, rules) {
  const issues = new Set();
  const head = pull.head_repo === state.repo ? rules.workBranch.exec(pull.head) : null;
  if (head) issues.add(head[1]);
  if (isExemptBotPull(pull, rules)) return issues;
  for (const issue of pull.closing_issues) if (issue.repo === state.repo) issues.add(String(issue.number));
  const body = (pull.body ?? "").replace(/\r\n?/g, "\n");
  for (const match of body.matchAll(rules.referenceLine)) issues.add(match[1]);
  return issues;
}

function isByAuthor(pull, authors) {
  return authors.some((author) => author.login === pull.author?.login && author.type === pull.author?.type);
}

function coversBranch(exemption, branch) {
  return exemption.match === "prefix" ? branch.startsWith(exemption.value) : branch === exemption.value;
}

// Only on the exempt entry's own branch: the same bot on any other branch links normally.
function isExemptBotPull(pull, rules) {
  return rules.exemptions.some((exemption) => coversBranch(exemption, pull.head) && isByAuthor(pull, exemption.authors));
}

function isExempt(branch, pulls, rules) {
  return rules.exemptions.some(
    (exemption) => coversBranch(exemption, branch) && pulls.every((pull) => isByAuthor(pull, exemption.authors)),
  );
}

// Branch names reach a terminal: always quoted, with anything outside printable ASCII escaped, so a
// control character cannot rewrite the output, a homoglyph is visible and a branch named `info`
// cannot pass for an info line.
export function printable(name) {
  const escaped = [...name].map((char) => (/^[\x20-\x7e]$/.test(char) && char !== '"' && char !== "\\" ? char : `\\u{${char.codePointAt(0)?.toString(16)}}`));
  return `"${escaped.join("")}"`;
}

function pullNumbers(pulls) {
  return pulls.map((pull) => `#${pull.number}`).join(", ");
}

function branchFindings(state, rules) {
  const pullsByHead = new Map();
  for (const pull of state.pulls.filter((candidate) => isOwnPull(candidate, state))) {
    pullsByHead.set(pull.head, [...(pullsByHead.get(pull.head) ?? []), pull]);
  }
  const found = [];
  for (const branch of state.branches.filter((name) => name !== state.default_branch)) {
    const pulls = pullsByHead.get(branch) ?? [];
    const isWorkBranch = rules.workBranch.test(branch);
    if (pulls.length > 1 && !isWorkBranch) {
      found.push({
        kind: "second-pull-request",
        subject: branch,
        message: `${printable(branch)}: head of open pull requests ${pullNumbers(pulls)}. Keep one and close each other one with a comment naming it (${FIX_SECTION}).`,
      });
    }
    if (pulls.length === 0) {
      found.push({
        kind: "no-pull-request",
        subject: branch,
        message: `${printable(branch)}: no open pull request. Open its draft pull request, or, when its issue is closed, record its last commit on the issue and delete the branch (${FIX_SECTION}).`,
      });
    }
    if (!isWorkBranch && !isExempt(branch, pulls, rules)) {
      found.push({
        kind: "bad-name",
        subject: branch,
        message: `${printable(branch)}: not named ${rules.workBranchForm}, and no exemption covers it with its pull request author. Move its commits to ${rules.workBranchForm} of its issue, replace its pull request and delete the branch (${FIX_SECTION}).`,
      });
    }
  }
  return found;
}

function pullFindings(state, rules) {
  const pullsByIssue = new Map();
  for (const pull of state.pulls.filter((candidate) => isOwnPull(candidate, state))) {
    for (const issue of linkedIssues(pull, state, rules)) {
      pullsByIssue.set(issue, [...(pullsByIssue.get(issue) ?? []), pull]);
    }
  }
  return [...pullsByIssue]
    .filter(([, pulls]) => pulls.length > 1)
    .map(([issue, pulls]) => ({
      kind: "second-pull-request",
      subject: `#${issue}`,
      message: `#${issue}: linked from open pull requests ${pullNumbers(pulls)}. Keep the one on ${rules.workBranchForm.replace("<n>", issue)} and close each other one with a comment naming it (${FIX_SECTION}).`,
    }));
}

export function findings(state, rules) {
  return [...branchFindings(state, rules), ...pullFindings(state, rules)];
}

// Links from fork pull requests are information only: any account can open one, so they must not
// be able to raise a finding or stop grdr-build.
export function forkLinks(state, rules) {
  return state.pulls
    .filter((pull) => !isOwnPull(pull, state))
    .flatMap((pull) => [...linkedIssues(pull, state, rules)].map((issue) => ({ pull: pull.number, issue })));
}

// At most the rules' limit of fork lines, then one count, so a flood from forks cannot push the
// summary line out of a reader's view.
function infoLines(state, links, rules) {
  const unseen = unseenOwn(state).map(
    ({ pull, unseen: count }) => `info: pull request #${pull} counts ${count} closing references the token cannot see; only those listed are read.`,
  );
  const fork = [
    ...truncatedForks(state).map((pull) => `info: fork pull request #${pull} closes more issues than one page lists; only those listed are read.`),
    ...links.map((link) => `info: fork pull request #${link.pull} links #${link.issue}; fork links raise no finding.`),
  ];
  const hidden = fork.length - rules.forkInfoLineLimit;
  const shown = hidden > 0 ? [...fork.slice(0, rules.forkInfoLineLimit), `info: ${hidden} more fork lines not shown.`] : fork;
  return [...unseen, ...shown];
}

export function main(argv) {
  try {
    const rules = loadRules(readFileSync(RULES_FILE, "utf8"));
    const state = stateFrom(argv, rules);
    const found = findings(state, rules);
    const links = forkLinks(state, rules);
    for (const finding of found) process.stdout.write(`finding: ${finding.message}\n`);
    for (const line of infoLines(state, links, rules)) process.stdout.write(`${line}\n`);
    process.stdout.write(
      `branch-check: ${state.repo}: ${state.branches.length} branches, ${state.pulls.length} open pull requests, fork links: ${links.length}, findings: ${found.length}.\n`,
    );
    return found.length ? EXIT.findings : EXIT.clean;
  } catch (error) {
    process.stderr.write(`branch-check could not look: ${error.message}\n`);
    return EXIT.couldNotLook;
  }
}
