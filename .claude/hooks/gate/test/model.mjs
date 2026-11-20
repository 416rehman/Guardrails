// The reference model of R2 and R3 of #1550, written from the spec and independent of gate/*.mjs:
// it never parses a command or matches a glob. Cases are generated as structure (a root, a path
// relative to it, the segments of a command), rendered to the text the hook reads, and decided
// here from the structure and the hand-written labels below.

const D63 = "d63";
const ANY = "any";
const D63_AGENTS = ["lead-agent-kit", "chief-architect"];

// Path relative to a checkout root -> what R7 makes of it. `gate` is the class of the gate-list
// entries matching it (the narrower one where two match), `names` that a shell word naming it
// names a gate-list path (itself or by holding an entry's literal prefix), `grants` and `tool`
// the grants directory and the grant tool.
const gate = (cls) => ({ gate: cls, names: true });
const holds = { names: true };
const plain = {};
export const LABELS = new Map(
  Object.entries({
    "": holds,
    ".claude": holds,
    web: holds,
    "web/packages": holds,
    ".claude/agents/impl-rust.md": gate(D63),
    ".claude/skills": gate(D63),
    ".claude/skills/grdr-verify/SKILL.md": gate(D63),
    ".claude/skills/x/AGENTS.md": gate(D63),
    ".claude/hooks": gate(D63),
    ".claude/hooks/gate-paths.mjs": gate(D63),
    ".claude/hooks/grant.mjs": { ...gate(D63), tool: true },
    ".claude/gate-paths.json": gate(D63),
    ".claude/risk-tiers.toml": gate(D63),
    ".claude/owners.toml": gate(D63),
    "CLAUDE.md": gate(D63),
    "AGENTS.md": gate(D63),
    ".github": gate(D63),
    ".github/workflows/verify.yml": gate(D63),
    "architecture.toml": gate(D63),
    "Cargo.toml": gate(D63),
    "rust-toolchain.toml": gate(D63),
    ".cargo/config.toml": gate(D63),
    "deny.toml": gate(D63),
    "clippy.toml": gate(D63),
    "crates/grdr-core/clippy.toml": gate(D63),
    "rustfmt.toml": gate(D63),
    "pnpm-workspace.yaml": gate(D63),
    "supply-chain/licences.toml": gate(D63),
    "security/trust-core.paths": gate(D63),
    "audits/a01.md": gate(D63),
    "web/packages/ui/exceptions.toml": gate(D63),
    "surfaces.toml": gate(D63),
    "support.toml": gate(D63),
    "REVIEW.md": gate(D63),
    "crates/grdr-core/REVIEW.md": gate(D63),
    "crates/grdr-core/AGENTS.md": gate(ANY),
    "docs/AGENTS.md": gate(ANY),
    "limits.toml": gate(ANY),
    "dist.toml": gate(ANY),
    "brand/brand.toml": gate(ANY),
    "third_party/x/LICENSE": gate(ANY),
    "Cargo.lock": gate(ANY),
    "pnpm-lock.yaml": gate(ANY),
    ".claude/grants": { grants: true },
    ".claude/grants/2.json": { grants: true },
    ".claude/grants/9.json": { grants: true },
    ".claude/settings.json": plain,
    ".claude/settings.local.json": plain,
    ".claude/.claude/hooks/grant.mjs": plain,
    "crates/grdr-core/src/lib.rs": plain,
    "crates/grdr-core/Cargo.toml": plain,
    "crates/grdr-proto/build.rs": plain,
    "programs/grdr/src/main.rs": plain,
    "docs/design/00-decisions.md": plain,
    "README.md": plain,
    "target/proposed.md": plain,
    "web/packages/ui/src/a.ts": plain,
    "LICENSE": plain,
    "spec/x.qnt": plain,
    crates: plain,
    "crates/x": plain,
    docs: plain,
    hooks: plain,
    skills: plain,
    "agents/impl-rust.md": plain,
    "grants/2.json": plain,
    "settings.local.json": plain,
  }),
);

// Words a command uses after `cd .claude`: each is labelled both from the root and from `.claude`.
const DOT_CLAUDE_WORDS = ["", "hooks", "skills", "agents/impl-rust.md", "grants/2.json", "settings.local.json"];
const ROOT_WORDS = [...LABELS.keys()].filter((rel) => !rel.startsWith(".claude/.claude"));
const FILE_TOOLS = ["Edit", "Write", "MultiEdit", "NotebookEdit"];
const MODES = ["default", "plan", "acceptEdits", "auto", "dontAsk", "bypassPermissions"];
const AGENT_TYPES = ["lead-agent-kit", "impl-rust", "chief-architect", "eval-diff"];
const PREFIXED = [["git", "status"], ["git", "diff"], ["git", "log"], ["git", "add"], ["rg", "foo"], ["cargo", "test"], ["node", "--test"], ["gh", "issue", "view", "5"]];
const UNPREFIXED = [["rm", "-rf"], ["cat"], ["mkdir", "-p"], ["echo", "hi"], ["cp", "x"]];
const DEPTH_NAMES = ["AGENTS.md", "clippy.toml", "REVIEW.md"];
const SEPARATORS = [" && ", " || ", " ; ", " | ", "\n", " & "];
const REDIRECTS = [" > ", " >> ", " 2> ", " &> ", " >| "];

export function rng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = (random, list) => list[Math.floor(random() * list.length)];

export function writeSetPredicate(lines) {
  const covers = (line, rel) => (line.endsWith("/**") ? rel === line.slice(0, -3) || rel.startsWith(line.slice(0, -2)) : rel === line);
  return (rel) => covers("target/**", rel) || lines.some((line) => covers(line, rel));
}

// `world.grants` maps a worktree to "invalid" or to the `agent` and `inWriteSet` of its grant.
export function generateCase(random, world) {
  const callerRoot = pick(random, ["main", "w2", "w2", "w3", "w4", "w5", "w5", "wd"]);
  const subagent = callerRoot !== "main" || random() < 0.3;
  const agentType = subagent ? pick(random, AGENT_TYPES) : random() < 0.5 ? "lead-agent-kit" : undefined;
  const caller = { root: callerRoot, subagent, agentType };
  const base = {
    session_id: "s",
    transcript_path: `${world.roots.main}/t.jsonl`,
    cwd: render(world, world.roots[callerRoot], random),
    permission_mode: pick(random, MODES),
    hook_event_name: "PreToolUse",
    tool_use_id: "toolu_1",
    ...(subagent ? { agent_id: "a1" } : {}),
    ...(agentType ? { agent_type: agentType } : {}),
  };
  if (random() < 0.5) {
    const tool = pick(random, FILE_TOOLS);
    const root = pick(random, ["main", "w2", "w3", "w4", "w5", "wd", "outside", callerRoot, callerRoot]);
    const rel = pick(random, [...LABELS.keys()].filter((key) => key !== ""));
    const dir = root === "outside" ? world.outside : world.roots[root];
    const field = tool === "NotebookEdit" ? "notebook_path" : "file_path";
    const input = { ...base, tool_name: tool, tool_input: { [field]: render(world, `${dir}/${rel}`, random) } };
    return { input, expected: modelFile(world, caller, root, rel) };
  }
  const dialect = random() < 0.25 ? "PowerShell" : "Bash";
  const { text, segments } = generateCommand(random, world, callerRoot, dialect);
  const input = { ...base, tool_name: dialect, tool_input: { command: text } };
  return { input, expected: modelShell(world, caller, segments) };
}

function modelFile(world, caller, root, rel) {
  if (root === "outside") return null;
  const label = LABELS.get(rel);
  if (label.grants) return "GRDR-KIT-0005";
  if (caller.subagent && root !== caller.root) return "GRDR-KIT-0002";
  const grant = world.grants[caller.root];
  if (grant === "invalid" && root === caller.root) return "GRDR-KIT-0007";
  const matching = caller.subagent && grant !== undefined && grant !== "invalid" && grant.agent === caller.agentType;
  if (!matching) return label.gate ? "GRDR-KIT-0001" : null;
  if (!grant.inWriteSet(rel)) return "GRDR-KIT-0003";
  if (label.gate === D63 && !D63_AGENTS.includes(grant.agent)) return "GRDR-KIT-0006";
  return null;
}

function generateCommand(random, world, callerRoot, dialect) {
  const segments = [];
  let dotClaude = false;
  const count = 1 + Math.floor(random() * 3);
  for (let i = 0; i < count; i += 1) {
    const roll = random();
    if (roll < 0.2) {
      const toDotClaude = !dotClaude && random() < 0.6;
      const other = pick(random, ["main", "w2", "w3", "w5"]);
      segments.push({ kind: "cd", target: toDotClaude ? { rel: ".claude" } : { root: other, rel: "" }, words: [] });
      dotClaude ||= toDotClaude;
      continue;
    }
    const wordList = dotClaude ? DOT_CLAUDE_WORDS : ROOT_WORDS;
    const pathWord = () => (random() < 0.25 ? { root: pick(random, ["main", "w2", "w3", "w5", "outside"]), rel: pick(random, ROOT_WORDS) } : { rel: pick(random, wordList) });
    if (roll < 0.3) segments.push({ kind: "grant", words: [{ rel: ".claude/hooks/grant.mjs" }] });
    else if (roll < 0.4) segments.push({ kind: "tee", words: [], target: pathWord() });
    else {
      const prefixed = random() < 0.4;
      const words = Array.from({ length: Math.floor(random() * 3) }, () => ({ ...pathWord(), option: random() < 0.15 }));
      segments.push({ kind: prefixed ? "prefixed" : "plain", head: pick(random, prefixed ? PREFIXED : UNPREFIXED), words, redirect: random() < 0.25 ? pathWord() : null });
    }
  }
  const text = segments
    .map((segment, i) => {
      const separator = i === 0 ? "" : segment.kind === "tee" ? " | " : pick(random, SEPARATORS);
      return separator + renderSegment(random, world, dialect, segment);
    })
    .join("");
  return { text, segments };
}

function renderSegment(random, world, dialect, segment) {
  const word = (w, optionForm) => renderWord(random, world, dialect, w, optionForm);
  if (segment.kind === "cd") return `${pick(random, dialect === "PowerShell" ? ["cd", "Set-Location", "pushd"] : ["cd", "pushd"])} ${word(segment.target, false)}`;
  if (segment.kind === "grant") return `node ${segment.words[0].rel} open 9`;
  if (segment.kind === "tee") return `tee ${random() < 0.3 ? "-a " : ""}${word(segment.target, false)}`;
  const words = segment.words.map((w) => word(w, w.option));
  const redirect = segment.redirect ? `${pick(random, REDIRECTS)}${word(segment.redirect, false)}` : "";
  return [...segment.head, ...words].join(" ") + redirect;
}

function renderWord(random, world, dialect, w, optionForm) {
  const raw = rawWord(world, w);
  const text = world.windows ? flipCase(random, dialect === "PowerShell" && random() < 0.5 ? raw.replaceAll("/", "\\") : raw) : raw;
  const quoted = pick(random, [text, text, `'${text}'`, `"${text}"`]);
  return optionForm ? `--out=${quoted}` : quoted;
}

// R3 also reads `--out=<value>` as a path relative to the base, which only the entries that
// match at any depth can name: a last segment AGENTS.md, clippy.toml or REVIEW.md after a `/`.
function optionWordLabel(world, w) {
  const segments = `--out=${rawWord(world, w)}`.split("/");
  return segments.length > 1 && DEPTH_NAMES.includes(segments.at(-1)) ? holds : plain;
}

function rawWord(world, w) {
  return w.root === undefined ? w.rel || "." : `${w.root === "outside" ? world.outside : world.roots[w.root]}${w.rel ? `/${w.rel}` : ""}`;
}

function modelShell(world, caller, segments) {
  let bases = [{ root: caller.root, prefix: "" }];
  const analysed = [];
  for (const segment of segments) {
    const valueLabels = (w) => (w.root !== undefined ? [labelAt(w.root, w.rel)] : bases.map((b) => labelAt(b.root, join(b.prefix, w.rel))));
    const labelsOf = (w) => (w.option ? [...valueLabels(w), optionWordLabel(world, w)] : valueLabels(w));
    const targets = segment.kind === "tee" ? [segment.target] : segment.redirect ? [segment.redirect] : [];
    const words = segment.kind === "cd" ? [segment.target] : segment.words;
    analysed.push({ checked: segment.kind === "plain" || segment.kind === "tee", words: words.flatMap(labelsOf), writes: targets.flatMap(labelsOf) });
    if (segment.kind === "cd") {
      const t = segment.target;
      bases = t.root !== undefined ? [...bases, { root: t.root, prefix: "" }] : [...bases, ...bases.map((b) => ({ root: b.root, prefix: join(b.prefix, t.rel) }))];
    }
  }
  const all = analysed.flatMap((s) => [...s.words, ...s.writes]);
  if (caller.subagent && all.some((label) => label.grants || label.tool)) return "GRDR-KIT-0005";
  if (analysed.some((s) => s.writes.some((label) => label.names))) return "GRDR-KIT-0004";
  if (analysed.some((s) => s.checked && s.words.some((label) => label.names))) return "GRDR-KIT-0004";
  return null;
}

function labelAt(root, rel) {
  if (root === "outside") return plain;
  const label = LABELS.get(rel);
  if (label === undefined) throw new Error(`model has no label for ${rel}`);
  return label;
}

function join(prefix, rel) {
  return [prefix, rel].filter((part) => part !== "").join("/");
}

function render(world, path, random) {
  return world.windows ? flipCase(random, path.replaceAll("/", random() < 0.5 ? "\\" : "/")) : path;
}

function flipCase(random, text) {
  return [...text].map((ch) => (random() < 0.2 ? (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()) : ch)).join("");
}
