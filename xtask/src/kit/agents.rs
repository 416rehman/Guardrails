//! `.claude/agents/<name>.md` from a roster entry: front matter, then `.agents/templates/common.md`
//! (team/02 section 1.3), then the role's body (team/02 section 1.1).
//! No definition sets `isolation: worktree`: that field isolates a subagent, and every writer runs
//! as the main thread of a `claude --agent` session that the dispatcher already starts in its own
//! git worktree under `.agent/worktrees/`.

use std::fmt::Write as _;

use anyhow::{Result, bail};

use super::research;
use crate::config::Kit;
use crate::config::models::FABLE;
use crate::config::roster::Agent;
use crate::repo::Repo;

pub const AGENTS_OUTPUT_DIR: &str = ".claude/agents";
pub const COMMON_BLOCK: &str = "templates/common.md";
/// Front-matter fields Claude Code reads on a subagent; it silently ignores any other.
pub const ALLOWED_FIELDS: &[&str] = &[
    "name",
    "description",
    "tools",
    "disallowedTools",
    "model",
    "effort",
    "permissionMode",
    "maxTurns",
    "skills",
    "hooks",
    "color",
    "isolation",
    "background",
];
/// team/02 section 1.1: never set on any agent.
pub const FORBIDDEN_FIELDS: &[&str] = &["memory", "mcpServers"];
const PERMISSION_MODE: &str = "dontAsk";

pub fn output_path(name: &str) -> String {
    format!("{AGENTS_OUTPUT_DIR}/{name}.md")
}

pub fn render(repo: &Repo, kit: &Kit, name: &str, agent: &Agent) -> Result<String> {
    let Some(model) = kit.models.id(&agent.model) else {
        bail!(
            "agent `{name}`: model `{}` is not bound in .agents/models.toml",
            agent.model
        );
    };
    if agent.model == FABLE
        && !kit
            .models
            .rules
            .fable_agents
            .iter()
            .any(|allowed| allowed == name)
    {
        bail!(
            "agent `{name}` is bound to fable; only {:?} may be",
            kit.models.rules.fable_agents
        );
    }
    let description = agent.description.trim();
    if description.is_empty() || description.contains('\n') {
        bail!("agent `{name}`: description must be one non-empty line");
    }
    if agent.tools.is_empty() {
        bail!("agent `{name}`: tools is empty");
    }
    let lists = research::tool_lists(kit, name, agent)?;
    for word in lists
        .tools
        .iter()
        .chain(&lists.disallowed)
        .chain(&agent.skills)
    {
        if word.is_empty() || word.contains([',', '\n', '"', '\'', '#']) {
            bail!("agent `{name}`: `{word}` cannot be written into front matter");
        }
    }
    let common = repo.read(&format!("{}/{COMMON_BLOCK}", crate::config::AGENTS_DIR))?;
    let body = repo.read(&format!("{}/{}", crate::config::AGENTS_DIR, agent.body))?;
    let mut out = String::from("---\n");
    let _ = writeln!(out, "name: {name}");
    let _ = writeln!(out, "description: {}", serde_json::to_string(description)?);
    let _ = writeln!(out, "model: {model}");
    let _ = writeln!(out, "effort: {}", agent.effort.as_str());
    let _ = writeln!(out, "tools: {}", lists.tools.join(", "));
    if !lists.disallowed.is_empty() {
        let _ = writeln!(out, "disallowedTools: {}", lists.disallowed.join(", "));
    }
    let _ = writeln!(out, "permissionMode: {PERMISSION_MODE}");
    let _ = writeln!(out, "maxTurns: {}", agent.max_turns);
    if !agent.skills.is_empty() {
        out.push_str("skills:\n");
        for skill in &agent.skills {
            let _ = writeln!(out, "  - {skill}");
        }
    }
    out.push_str("---\n\n");
    out.push_str(common.trim());
    out.push_str("\n\n");
    out.push_str(body.trim());
    out.push('\n');
    Ok(out)
}
