// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
// The checks behind branch-check.mjs: one issue, one branch `issue/<n>-<slug>`, one pull request,
// issue name in branch and PR, and every non-exempt PR targeting an issue.
// Exit 0 with no findings, 1 with findings, 2 when it could not look, which never counts as clean;
// the last line of stdout is the summary line only when it looked.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const RULES_FILE = fileURLToPath(new URL("./branch-rules.json", import.meta.url));
const EXIT = { clean: 0, findings: 1, couldNotLook: 2 };
const FIX_SECTION = 'skill grdr-work-issue, "Branches and pull requests"';
const CLOSING_KEYWORD = /\b(?:close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved):?\s+#([1-9][0-9]*)\b/gi;
const OPEN_PULLS_QUERY = `query($owner: String!, $name: String!, $pageSize: Int!, $endCursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequests(states: OPEN, first: $pageSize, after: $endCursor) {
      pageInfo { hasNextPage endCursor }
      nodes {
        number headRefName title body
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
  number, head: .headRefName, title, head_repo: .headRepository.nameWithOwner, body,
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

export function slugifyIssueTitle(title, maxLen = 60) {
  const raw = String(title ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (raw.length <= maxLen) return raw;
  return raw.slice(0, maxLen).replace(/-+$/g, "");
}

function captureGroups(source) {
  return (new RegExp(`(?:${source})|`).exec("")?.length ?? 1) - 1;
}

function patternWithGroups(raw, key, expectedGroups, flags) {
  const source = raw?.[key];
  if (typeof source !== "string" || !source) throw new Error(`branch-rules.json has no ${key} pattern`);
  const count = captureGroups(source);
  const valid = Array.isArray(expectedGroups) ? expectedGroups.includes(count) : count === expectedGroups;
  if (!valid) {
    const label = expectedGroups === 1 ? "one capture group" : `${Array.isArray(expectedGroups) ? expectedGroups.join(" or ") : expectedGroups} capture groups`;
    throw new Error(`branch-rules.json ${key} needs exactly ${label}`);
  }
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

function parseWorkBranchForm(raw) {
  const form = raw?.work_branch_form;
  if (typeof form !== "string" || form.split("<n>").length !== 2) {
    throw new Error("branch-rules.json work_branch_form needs one <n> and must match work_branch when <n> is a number");
  }
  const hasSlug = form.includes("<slug>");
  if (hasSlug && form.split("<slug>").length !== 2) {
    throw new Error("branch-rules.json work_branch_form may contain at most one <slug>");
  }
  return { form, hasSlug };
}

function workBranchForm(form, hasSlug, workBranch) {
  const sample = hasSlug
    ? form.replace("<n>", "1").replace("<slug>", "sample-issue")
    : form.replace("<n>", "1");
  const match = workBranch.exec(sample);
  if (match?.[1] !== "1" || (hasSlug && match?.[2] !== "sample-issue")) {
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
  const { form, hasSlug } = parseWorkBranchForm(raw);
  const workBranch = patternWithGroups(raw, "work_branch", hasSlug ? 2 : 1, "");
  const minSlugLength = raw?.min_slug_length === undefined ? 3 : positiveInteger(raw, "min_slug_length");
  const maxSlugLength = raw?.max_slug_length === undefined ? 60 : positiveInteger(raw, "max_slug_length");
  if (maxSlugLength < minSlugLength) {
    throw new Error("branch-rules.json max_slug_length must be >= min_slug_length");
  }
  const issueHeaderLine = raw?.issue_header_line
    ? patternWithGroups(raw, "issue_header_line", 2, "gim")
    : /^[ \t]*Issue:[ \t]+#([1-9][0-9]*)[ \t]+(.+?)[ \t]*$/gim;
  const legacyList = raw?.legacy_pre_slug_branches ?? [];
  if (!Array.isArray(legacyList) || !legacyList.every((b) => typeof b === "string" && /^issue\/[1-9][0-9]*$/.test(b))) {
    throw new Error("branch-rules.json legacy_pre_slug_branches needs a list of issue/<n> strings");
  }
  return {
    workBranch,
    workBranchForm: workBranchForm(form, hasSlug, workBranch),
    minSlugLength,
    maxSlugLength,
    referenceLine: patternWithGroups(raw, "reference_line", 1, "gim"),
    issueHeaderLine,
    legacyPreSlugBranches: new Set(legacyList),
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
    (pull.title === undefined || pull.title === null || typeof pull.title === "string") &&
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

export function unseenOwn(state) {
  return state.pulls
    .filter((pull) => isOwnPull(pull, state) && isTruncated(pull))
    .map((pull) => ({ pull: pull.number, unseen: pull.closing_total - pull.closing_issues.length }));
}

export function truncatedForks(state) {
  return state.pulls.filter((pull) => !isOwnPull(pull, state) && isTruncated(pull)).map((pull) => pull.number);
}

function lines(text) {
  return text.split(/\r?\n/).filter(Boolean);
}

export function openPullsArgs(owner, name, pageSize) {
  const variables = ["-f", `owner=${owner}`, "-f", `name=${name}`, "-F", `pageSize=${pageSize}`];
  return ["api", "graphql", "--paginate", "-f", `query=${OPEN_PULLS_QUERY}`, ...variables, "--jq", OPEN_PULL_FIELDS];
}

export function closingPageArgs(owner, name, number, pageSize, after) {
  const variables = ["-f", `owner=${owner}`, "-f", `name=${name}`, "-F", `number=${number}`, "-F", `pageSize=${pageSize}`, "-f", `after=${after}`];
  return ["api", "graphql", "-f", `query=${CLOSING_PAGE_QUERY}`, ...variables, "--jq", CLOSING_PAGE_FIELDS];
}

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

export function isValidWorkBranch(branch, rules) {
  const match = rules.workBranch.exec(branch);
  if (!match) return false;
  if (match[2] !== undefined) {
    return match[2].length >= rules.minSlugLength && match[2].length <= rules.maxSlugLength;
  }
  return true;
}

function isLegacyBranch(branch, rules) {
  return rules.legacyPreSlugBranches.has(branch);
}

function explicitBodyIssues(bodyText, rules) {
  const issues = new Set();
  for (const match of bodyText.matchAll(rules.referenceLine)) issues.add(match[1]);
  for (const match of bodyText.matchAll(rules.issueHeaderLine)) issues.add(match[1]);
  return issues;
}

function linkedIssues(pull, state, rules) {
  const issues = new Set();
  const head = pull.head_repo === state.repo ? rules.workBranch.exec(pull.head) : null;
  if (head && isValidWorkBranch(pull.head, rules)) issues.add(head[1]);
  if (isExemptBotPull(pull, rules)) return issues;
  for (const issue of pull.closing_issues) if (issue.repo === state.repo) issues.add(String(issue.number));
  const body = (pull.body ?? "").replace(/\r\n?/g, "\n");
  for (const num of explicitBodyIssues(body, rules)) issues.add(num);
  return issues;
}

function hasExplicitTargetIssue(pull, state, rules) {
  if (pull.closing_issues.some((issue) => issue.repo === state.repo)) return true;
  const body = (pull.body ?? "").replace(/\r\n?/g, "\n");
  if (explicitBodyIssues(body, rules).size > 0) return true;
  CLOSING_KEYWORD.lastIndex = 0;
  return CLOSING_KEYWORD.test(body);
}

export function hasIssueNameInPull(title, body, issueNumber, slug) {
  const normBody = String(body ?? "").replace(/\r\n?/g, "\n");
  const headerRe = new RegExp(`^[ \\t]*Issue:[ \\t]+#${issueNumber}[ \\t]+(.+?)[ \\t]*$`, "im");
  const header = headerRe.exec(normBody);
  if (header && header[1].trim().length >= 3) return true;
  const normTitle = String(title ?? "").toLowerCase();
  if (!normTitle) return false;
  if (!slug) return normTitle.includes(`#${issueNumber}`);
  const words = slug.split("-").filter((w) => w.length >= 3);
  const needed = words.length > 0 ? words : slug.split("-").filter(Boolean);
  if (needed.length === 0) return false;
  const hits = needed.filter((w) => normTitle.includes(w)).length;
  return hits >= Math.min(2, needed.length);
}

function isByAuthor(pull, authors) {
  return authors.some((author) => author.login === pull.author?.login && author.type === pull.author?.type);
}

export function coversBranch(exemption, branch) {
  return exemption.match === "prefix" ? branch.startsWith(exemption.value) : branch === exemption.value;
}

function isExemptBotPull(pull, rules) {
  return rules.exemptions.some((exemption) => coversBranch(exemption, pull.head) && isByAuthor(pull, exemption.authors));
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

function branchFindings(state, rules) {
  const pullsByHead = new Map();
  for (const pull of state.pulls.filter((candidate) => isOwnPull(candidate, state))) {
    pullsByHead.set(pull.head, [...(pullsByHead.get(pull.head) ?? []), pull]);
  }
  const found = [];
  for (const branch of state.branches.filter((name) => name !== state.default_branch)) {
    const pulls = pullsByHead.get(branch) ?? [];
    const isWorkBranch = isValidWorkBranch(branch, rules);
    const isLegacy = isLegacyBranch(branch, rules);
    if (pulls.length > 1 && !isWorkBranch && !isLegacy) {
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
    if (!isWorkBranch && !isLegacy && !isExempt(branch, pulls, rules)) {
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
  const found = [];
  for (const pull of state.pulls.filter((candidate) => isOwnPull(candidate, state))) {
    const issues = linkedIssues(pull, state, rules);
    for (const issue of issues) {
      pullsByIssue.set(issue, [...(pullsByIssue.get(issue) ?? []), pull]);
    }
    if (isExemptBotPull(pull, rules)) continue;
    const label = `PR #${pull.number}`;
    if (issues.size === 0 || !hasExplicitTargetIssue(pull, state, rules)) {
      found.push({
        kind: "no-target-issue",
        subject: label,
        message: `${printable(label)}: pull request targets no issue. Add 'Refs #<n>' or 'Closes #<n>' and 'Issue: #<n> <title>' (${FIX_SECTION}).`,
      });
      continue;
    }
    if (!isLegacyBranch(pull.head, rules) && isValidWorkBranch(pull.head, rules)) {
      const headMatch = rules.workBranch.exec(pull.head);
      const matchesIssue = Boolean(headMatch && issues.has(headMatch[1]));
      const hasName = matchesIssue && hasIssueNameInPull(pull.title, pull.body, headMatch[1], headMatch[2]);
      if (!matchesIssue || !hasName) {
        found.push({
          kind: "missing-issue-name",
          subject: label,
          message: `${printable(label)}: pull request and branch must include the issue name (branch ${rules.workBranchForm} and PR title or 'Issue: #<n> <title>') (${FIX_SECTION}).`,
        });
      }
    }
  }
  for (const [issue, pulls] of pullsByIssue) {
    if (pulls.length > 1) {
      found.push({
        kind: "second-pull-request",
        subject: `#${issue}`,
        message: `#${issue}: linked from open pull requests ${pullNumbers(pulls)}. Keep the one on ${rules.workBranchForm.replace("<n>", issue)} and close each other one with a comment naming it (${FIX_SECTION}).`,
      });
    }
  }
  return found;
}

export function findings(state, rules) {
  return [...branchFindings(state, rules), ...pullFindings(state, rules)];
}

export function forkLinks(state, rules) {
  return state.pulls
    .filter((pull) => !isOwnPull(pull, state))
    .flatMap((pull) => [...linkedIssues(pull, state, rules)].map((issue) => ({ pull: pull.number, issue })));
}

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
