// AC-1 and AC-3 of #1550: the hook run as a subprocess on the decision table R1 to R4.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { git, hookInput, makeRepository, runHook } from "./fixture.mjs";

let repo;
before(() => {
  repo = makeRepository();
});
after(() => repo.remove());

const LEAD = { agentId: "a1", agentType: "lead-agent-kit" };
const IMPL = { agentId: "a2", agentType: "impl-rust" };
const MAIN = {};
const write = (root, rel) => ({ file_path: join(root, rel), content: "x" });

function decision(cwdRoot, tool, toolInput, caller) {
  return runHook(repo.main, hookInput(repo.roots[cwdRoot], tool, toolInput, caller));
}

function fileCode(cwdRoot, caller, targetRoot, rel, tool = "Write") {
  const target = targetRoot === "outside" ? repo.outside : repo.roots[targetRoot];
  const field = tool === "NotebookEdit" ? "notebook_path" : "file_path";
  return decision(cwdRoot, tool, { [field]: join(target, rel) }, caller).code;
}

function shellCode(cwdRoot, caller, command, tool = "Bash") {
  return decision(cwdRoot, tool, { command }, caller).code;
}

describe("issue-2: R2 and R3 applied to the write set of #2", () => {
  test("lead-agent-kit on issue/2 writes architecture.toml and a crate AGENTS.md with no decision", () => {
    assert.equal(fileCode("w2", LEAD, "w2", "architecture.toml"), null);
    assert.equal(fileCode("w2", LEAD, "w2", "crates/grdr-core/AGENTS.md"), null);
  });
  test("impl-rust on issue/2 writing architecture.toml is refused with 0001", () => {
    assert.equal(fileCode("w2", IMPL, "w2", "architecture.toml"), "GRDR-KIT-0001");
  });
  test("lead-agent-kit on issue/2 writing limits.toml is refused with 0003", () => {
    assert.equal(fileCode("w2", LEAD, "w2", "limits.toml"), "GRDR-KIT-0003");
  });
  test("lead-agent-kit on issue/2 redirecting into architecture.toml is refused with 0004", () => {
    assert.equal(shellCode("w2", LEAD, "echo x > architecture.toml"), "GRDR-KIT-0004");
  });
  test("any subagent running grant.mjs open 9 is refused with 0005", () => {
    for (const [root, caller] of [["w2", LEAD], ["w3", IMPL], ["main", { agentId: "a3", agentType: "eval-diff" }]]) {
      assert.equal(shellCode(root, caller, "node .claude/hooks/grant.mjs open 9"), "GRDR-KIT-0005");
    }
  });
  test("the main session writing architecture.toml is refused with 0001", () => {
    assert.equal(fileCode("main", MAIN, "main", "architecture.toml"), "GRDR-KIT-0001");
    assert.equal(fileCode("main", MAIN, "w2", "architecture.toml"), "GRDR-KIT-0001");
  });
  test("lead-agent-kit on issue/3 writing architecture.toml is refused with 0001", () => {
    assert.equal(fileCode("w3", LEAD, "w3", "architecture.toml"), "GRDR-KIT-0001");
  });
  test("the main session running grant.mjs open 2 gets no decision", () => {
    assert.equal(shellCode("main", MAIN, "node .claude/hooks/grant.mjs open 2"), null);
  });
});

describe("R2, file tools", () => {
  test("a: the grants directory is refused with 0005 for every session", () => {
    assert.equal(fileCode("main", MAIN, "main", ".claude/grants/2.json"), "GRDR-KIT-0005");
    assert.equal(fileCode("w2", LEAD, "w2", ".claude/grants/7.json"), "GRDR-KIT-0005");
  });
  test("b: a write outside the repository gets no decision, a granted implementer's included", () => {
    assert.equal(fileCode("w2", LEAD, "outside", "notes.md"), null);
    assert.equal(fileCode("main", MAIN, "outside", "architecture.toml"), null);
  });
  test("c: a subagent writing another checkout is refused with 0002", () => {
    assert.equal(fileCode("w2", LEAD, "main", "README.md"), "GRDR-KIT-0002");
    assert.equal(fileCode("w2", LEAD, "w3", "architecture.toml"), "GRDR-KIT-0002");
    assert.equal(fileCode("main", IMPL, "w3", "README.md"), "GRDR-KIT-0002");
  });
  test("d: an invalid grant refuses every write in its worktree with 0007", () => {
    assert.equal(fileCode("w4", LEAD, "w4", "README.md"), "GRDR-KIT-0007");
  });
  test("e: a matching grant allows its write set and target/, and refuses the rest", () => {
    assert.equal(fileCode("w2", LEAD, "w2", "target/proposed.md"), null);
    assert.equal(fileCode("w2", LEAD, "w2", "README.md"), "GRDR-KIT-0003");
    assert.equal(fileCode("w5", IMPL, "w5", "Cargo.lock"), null);
    assert.equal(fileCode("w5", IMPL, "w5", "architecture.toml"), "GRDR-KIT-0006");
    assert.equal(fileCode("w5", IMPL, "w5", "crates/grdr-core/clippy.toml"), "GRDR-KIT-0006");
  });
  test("f: without a matching grant every gate-list path is refused with 0001", () => {
    assert.equal(fileCode("wd", LEAD, "wd", ".github/workflows/verify.yml"), "GRDR-KIT-0001");
    assert.equal(fileCode("main", { agentType: "lead-agent-kit" }, "main", "architecture.toml"), "GRDR-KIT-0001");
    assert.equal(fileCode("main", { agentType: "lead-agent-kit" }, "w2", "architecture.toml"), "GRDR-KIT-0001");
    assert.equal(fileCode("main", MAIN, "main", ".claude/skills/x/AGENTS.md"), "GRDR-KIT-0001");
    assert.equal(fileCode("main", MAIN, "main", "README.md"), null);
  });
  test("every file tool is checked, NotebookEdit by notebook_path", () => {
    for (const tool of ["Edit", "Write", "MultiEdit", "NotebookEdit"]) {
      assert.equal(fileCode("w3", IMPL, "w3", "architecture.toml", tool), "GRDR-KIT-0001", tool);
    }
  });
  test("an input with agent_type and no agent_id is decided as the main session", () => {
    assert.equal(fileCode("w2", { agentType: "lead-agent-kit" }, "w2", "architecture.toml"), "GRDR-KIT-0001");
    assert.equal(fileCode("w2", { agentType: "lead-agent-kit" }, "main", "README.md"), null);
  });
  test("each decision is the same under bypassPermissions as under default", () => {
    const cases = [
      ["w2", LEAD, "w2", "architecture.toml"],
      ["w2", IMPL, "w2", "architecture.toml"],
      ["w2", LEAD, "w2", "limits.toml"],
      ["w2", LEAD, "main", "README.md"],
      ["main", MAIN, "main", "architecture.toml"],
    ];
    for (const [cwd, caller, root, rel] of cases) {
      const codes = ["default", "bypassPermissions"].map((mode) => fileCode(cwd, { ...caller, mode }, root, rel));
      assert.equal(codes[0], codes[1], `${rel} from ${cwd}`);
    }
    const shell = ["default", "bypassPermissions"].map((mode) => shellCode("w2", { ...LEAD, mode }, "rm -rf .github"));
    assert.deepEqual(shell, ["GRDR-KIT-0004", "GRDR-KIT-0004"]);
  });
});

describe("R3, shell tools", () => {
  test("a: a subagent naming the grant tool or the grants directory is refused with 0005", () => {
    assert.equal(shellCode("w2", LEAD, "cat .claude/grants/2.json"), "GRDR-KIT-0005");
    assert.equal(shellCode("w2", LEAD, `rm ${join(repo.main, ".claude", "grants", "2.json").replaceAll("\\", "/")}`), "GRDR-KIT-0005");
    assert.equal(shellCode("main", MAIN, "cat .claude/grants/2.json"), null);
  });
  test("b: a redirection or tee into a gate-list path is refused with 0004, prefix or not", () => {
    assert.equal(shellCode("w2", LEAD, "git log > .github/x.yml"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "git diff | tee -a AGENTS.md"), "GRDR-KIT-0004");
    assert.equal(shellCode("main", MAIN, "cargo metadata 2> Cargo.lock"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "echo x &> limits.toml"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "echo x > target/out.txt 2>&1"), null);
  });
  test("c: a segment naming a gate-list path without a shell prefix is refused with 0004", () => {
    assert.equal(shellCode("w2", LEAD, "rm -rf .claude"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "rm -rf ."), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "cd .claude && rm -rf hooks"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "rm -rf $(echo .github)"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "(cd crates; cat ../Cargo.toml)"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "cp x --target-directory=.cargo"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "rm -rf .cl*"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "rm -rf .git*"), null);
    assert.equal(shellCode("w2", LEAD, "cd /nonexistent; rm -rf .github"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "Remove-Item -Recurse .github", "PowerShell"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, "Set-Location .claude; Remove-Item hooks", "PowerShell"), "GRDR-KIT-0004");
    assert.equal(shellCode("w2", LEAD, `Remove-Item "${join(repo.roots.w2, "deny.toml")}"`, "PowerShell"), "GRDR-KIT-0004");
  });
  test("c: commands that name no gate-list path, or start with a shell prefix, get no decision", () => {
    assert.equal(shellCode("w2", LEAD, "mkdir crates/x"), null);
    assert.equal(shellCode("w2", LEAD, `cd ${repo.roots.w2} && git status`), null);
    assert.equal(shellCode("w2", LEAD, "git add architecture.toml && git commit -m 'feat: x'"), null);
    assert.equal(shellCode("w2", LEAD, "rg architecture .github"), null);
    assert.equal(shellCode("w2", LEAD, 'node --test ".claude/hooks/**/*.test.mjs"'), null);
    assert.equal(shellCode("main", MAIN, 'gh issue comment 5 --body "see architecture.toml"'), null);
    assert.equal(shellCode("w2", LEAD, "node .claude/hooks/grant.mjs.bak open 2"), "GRDR-KIT-0004");
  });
});

describe("R1 and R4: output shape and failing closed", () => {
  test("a denial is the PreToolUse JSON of the hooks reference and no decision is empty output", () => {
    const denied = runHook(repo.main, hookInput(repo.main, "Write", write(repo.main, "deny.toml")));
    assert.equal(denied.status, 0);
    assert.deepEqual(Object.keys(denied.output).sort(), ["hookEventName", "permissionDecision", "permissionDecisionReason"]);
    assert.equal(denied.output.hookEventName, "PreToolUse");
    assert.equal(denied.output.permissionDecision, "deny");
    assert.match(denied.reason, /^GRDR-KIT-0001: deny\.toml /);
    const none = runHook(repo.main, hookInput(repo.main, "Write", write(repo.main, "README.md")));
    assert.deepEqual([none.status, none.code], [0, null]);
  });
  test("CLAUDE_PROJECT_DIR unset denies file and shell calls with 0008", () => {
    for (const [tool, toolInput] of [["Write", write(repo.main, "README.md")], ["Bash", { command: "git status" }]]) {
      const result = runHook(repo.main, hookInput(repo.main, tool, toolInput), { CLAUDE_PROJECT_DIR: undefined });
      assert.equal(result.code, "GRDR-KIT-0008");
      assert.match(result.reason, /CLAUDE_PROJECT_DIR/);
    }
  });
  test("a missing or invalid gate list denies with 0008 naming the file", () => {
    const bare = mkdtempSync(join(tmpdir(), "grdr-gate-bare-"));
    try {
      git(bare, "init", "-q");
      const missing = runHook(bare, hookInput(bare, "Bash", { command: "ls" }));
      assert.equal(missing.code, "GRDR-KIT-0008");
      assert.match(missing.reason, /gate-paths\.json/);
      mkdirSync(join(bare, ".claude"));
      writeFileSync(join(bare, ".claude", "gate-paths.json"), '{"schema": "grdr.kit.gate-paths.v1"}');
      const invalid = runHook(bare, hookInput(bare, "Write", write(bare, "README.md")));
      assert.equal(invalid.code, "GRDR-KIT-0008");
      assert.match(invalid.reason, /gate-paths\.json: entries/);
    } finally {
      rmSync(bare, { recursive: true, force: true });
    }
  });
  test("git failing in the project directory, bad JSON or a missing cwd denies with 0008", () => {
    const notGit = runHook(repo.outside, hookInput(repo.main, "Write", write(repo.main, "README.md")));
    assert.equal(notGit.code, "GRDR-KIT-0008");
    assert.match(notGit.reason, /git -C .* worktree list/);
    assert.equal(runHook(repo.main, "not json").code, "GRDR-KIT-0008");
    const noCwd = hookInput(repo.main, "Bash", { command: "ls" });
    delete noCwd.cwd;
    assert.equal(runHook(repo.main, noCwd).code, "GRDR-KIT-0008");
    const noPath = runHook(repo.main, hookInput(repo.main, "Edit", { old_string: "a", new_string: "b" }));
    assert.equal(noPath.code, "GRDR-KIT-0008");
  });
});
