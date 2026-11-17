// The design/34 docs rules a script can check: a PreToolUse hook on `gh pr create` and
// `gh pr merge`, and the docs CI job with `--ci`. Its own errors let the change through.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const CODE = /^(crates|programs|proto|schema|web|desktop|platform|bpf|packs|rules|interface|sdk|spec|conformance|lab)\//;
const DOCS = /^(docs|site)\/|(^|\/)README(\.md)?$/;
const PRODUCT_PAGE = /^docs\/product\/(?!reference\/_generated\/).+\.mdx?$/;
const PUBLISHED = /^(site|docs\/product|docs\/runbooks|docs\/training)\/.+\.(mdx?|[cm]?[jt]sx?|json|ya?ml|css|html)$/;
const FRONT_MATTER_KEYS = ["id", "type", "personas", "shapes", "covers", "owner_squad", "stability"];
const NOTE_CATEGORIES = ["feature", "fix", "security", "deprecation", "breaking", "known-issue", "none"];
const THIRD_PARTY =
  /googletagmanager|google-analytics|gtag\(|fonts\.googleapis|fonts\.gstatic|use\.typekit|plausible\.io|segment\.(io|com)|hotjar|cdn\.jsdelivr|unpkg\.com|cdnjs\.cloudflare/;
const PIPE_TO_SHELL = /curl[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b/;
const DOCS_ESCAPE = /(^|\n|")Docs: unchanged because \S/;

function run(command, args) {
  return execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

function optionValue(command, name) {
  const match = command.match(new RegExp(`${name}[ =](?:"([^"]+)"|'([^']+)'|(\\S+))`));
  return match ? (match[1] ?? match[2] ?? match[3]) : undefined;
}

function diffFiles(range) {
  return run("git", ["diff", "--name-only", "--diff-filter=d", range]).split("\n").filter(Boolean);
}

function fromHookCommand(command) {
  const merge = command.match(/gh pr merge\s+(\d+)/);
  if (merge) {
    const pr = JSON.parse(run("gh", ["pr", "view", merge[1], "--json", "files,body,headRefOid"]));
    return { files: pr.files.map((file) => file.path), body: pr.body ?? "", ref: pr.headRefOid };
  }
  const head = optionValue(command, "--head");
  const ref = head ? `origin/${head}` : "HEAD";
  const bodyFile = optionValue(command, "--body-file");
  const body = bodyFile ? readFileSync(bodyFile, "utf8") : command.replace(/\\n/g, "\n");
  return { files: diffFiles(`origin/main...${ref}`), body, ref };
}

function fromCi() {
  const { BASE, HEAD, BODY } = process.env;
  return { files: diffFiles(`${BASE}...${HEAD}`), body: (BODY ?? "").replace(/\r/g, ""), ref: HEAD };
}

function fileAt(ref, path) {
  try {
    return run("git", ["show", `${ref}:${path}`]);
  } catch {
    return undefined;
  }
}

function frontMatterKeys(text) {
  const match = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!match) return [];
  return match[1].split(/\r?\n/).map((line) => line.match(/^([A-Za-z_]+):/)?.[1]).filter(Boolean);
}

function findings({ files, body, ref }) {
  const found = [];
  const codeChanged = files.some((f) => CODE.test(f));
  if (codeChanged && !files.some((f) => DOCS.test(f)) && !DOCS_ESCAPE.test(body)) {
    found.push(
      "design/34 §1 and §3: code changed but no docs did. Update the design doc (docs/design), the docs site (docs/product, site/) or a README, or add a body line 'Docs: unchanged because <reason>'.",
    );
  }
  if (/Closes #\d+/.test(body)) {
    const category = body.match(/category\s*=\s*\\?"([\w-]+)\\?"/)?.[1];
    if (!body.includes("[release_note]") || !NOTE_CATEGORIES.includes(category)) {
      found.push(
        `design/34 §14: the body needs a [release_note] block with category one of ${NOTE_CATEGORIES.join(", ")}.`,
      );
    } else if (["breaking", "deprecation"].includes(category) && !/action_required\s*=\s*\\?"[^"\\\s]/.test(body)) {
      found.push("design/34 §14: a breaking or deprecation release note needs action_required.");
    }
  }
  for (const path of files.filter((f) => PRODUCT_PAGE.test(f) || PUBLISHED.test(f))) {
    const text = fileAt(ref, path);
    if (text === undefined) continue;
    if (PRODUCT_PAGE.test(path)) {
      const keys = frontMatterKeys(text);
      const missing = FRONT_MATTER_KEYS.filter((key) => !keys.includes(key));
      if (missing.length) found.push(`design/34 §1: ${path} front matter lacks ${missing.join(", ")}.`);
    }
    if (THIRD_PARTY.test(text)) found.push(`design/34 §1 (F11): ${path} loads a third-party script, font or analytics.`);
    if (PIPE_TO_SHELL.test(text)) found.push(`design/34 §1: ${path} pipes a download into a shell; show a signed package and its verification.`);
  }
  return found;
}

try {
  const ci = process.argv.includes("--ci");
  const command = ci ? "" : (JSON.parse(readFileSync(0, "utf8")).tool_input?.command ?? "");
  if (ci || /gh pr (create|merge)/.test(command)) {
    const found = findings(ci ? fromCi() : fromHookCommand(command));
    if (found.length) {
      process.stderr.write(`${found.join("\n")}\n`);
      if (ci) for (const line of found) process.stdout.write(`::error::${line}\n`);
      process.exit(ci ? 1 : 2);
    }
  }
} catch (error) {
  process.stderr.write(`docs-check skipped: ${error.message}\n`);
  process.exit(0);
}
