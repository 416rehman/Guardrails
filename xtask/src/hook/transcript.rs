//! The transcript JSONL Claude Code writes: the model of the last assistant message, which guard
//! hooks need because only SessionStart carries a `model` field, and the tool calls a session or
//! subagent made.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde_json::Value;

use crate::config::limits::TranscriptLimits;

#[derive(Debug, Clone, PartialEq)]
pub struct ToolUse {
    pub name: String,
    pub input: Value,
}

/// The entries in the last `bytes` of the file, in file order; a partial first line is dropped.
pub fn tail(path: &Path, bytes: u64) -> Result<Vec<Value>> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let length = file.metadata()?.len();
    let start = length.saturating_sub(bytes);
    file.seek(SeekFrom::Start(start))?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let mut lines = text.lines();
    if start > 0 {
        lines.next();
    }
    Ok(lines
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect())
}

/// The model of the last assistant message; synthetic messages (`<synthetic>`) are skipped. The
/// tail read is widened once when it holds no assistant message.
pub fn last_model(path: &Path, limits: &TranscriptLimits) -> Result<Option<String>> {
    for bytes in [limits.model_tail_bytes, limits.widened_tail_bytes] {
        let entries = tail(path, bytes)?;
        let found = entries.iter().rev().find_map(assistant_model);
        if found.is_some() {
            return Ok(found);
        }
        let whole = std::fs::metadata(path)
            .map(|m| m.len() <= bytes)
            .unwrap_or(true);
        if whole {
            break;
        }
    }
    Ok(None)
}

/// The model of the last assistant message written after byte `from`, if there is one.
pub fn last_model_since(path: &Path, from: u64) -> Result<Option<String>> {
    let length = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    if length <= from {
        return Ok(None);
    }
    let entries = tail(path, length - from)?;
    Ok(entries.iter().rev().find_map(assistant_model))
}

pub fn tool_uses(entries: &[Value]) -> Vec<ToolUse> {
    entries
        .iter()
        .filter(|entry| entry.get("type").and_then(Value::as_str) == Some("assistant"))
        .filter_map(|entry| entry.pointer("/message/content").and_then(Value::as_array))
        .flatten()
        .filter(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
        .map(|block| ToolUse {
            name: block
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            input: block.get("input").cloned().unwrap_or(Value::Null),
        })
        .collect()
}

/// The commands of every Bash and PowerShell call.
pub fn shell_commands(uses: &[ToolUse]) -> Vec<String> {
    uses.iter()
        .filter(|tool| matches!(tool.name.as_str(), "Bash" | "PowerShell"))
        .filter_map(|tool| tool.input.get("command").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

/// The file paths of every file-tool call.
pub fn edited_paths(uses: &[ToolUse]) -> Vec<String> {
    uses.iter()
        .filter(|tool| {
            matches!(
                tool.name.as_str(),
                "Edit" | "Write" | "MultiEdit" | "NotebookEdit"
            )
        })
        .filter_map(|tool| {
            tool.input
                .get("file_path")
                .or_else(|| tool.input.get("notebook_path"))
                .and_then(Value::as_str)
        })
        .map(str::to_owned)
        .collect()
}

/// A subagent's own transcript, `<session>/subagents/agent-<id>.jsonl` beside the main one.
pub fn subagent_transcript(main: &Path, agent_id: &str) -> Option<PathBuf> {
    let stem = main.file_stem()?;
    let dir = main.parent()?.join(stem).join("subagents");
    let bare = agent_id.strip_prefix("agent-").unwrap_or(agent_id);
    [format!("agent-{bare}.jsonl"), format!("{agent_id}.jsonl")]
        .into_iter()
        .map(|name| dir.join(name))
        .find(|path| path.is_file())
}

fn assistant_model(entry: &Value) -> Option<String> {
    if entry.get("type").and_then(Value::as_str) != Some("assistant") {
        return None;
    }
    let model = entry.pointer("/message/model").and_then(Value::as_str)?;
    (!model.is_empty() && !model.starts_with('<')).then(|| model.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_model_and_tool_uses() {
        let dir = std::env::temp_dir().join(format!("xtask-transcript-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.jsonl");
        let lines = [
            r#"{"type":"user","message":{"content":"hi"}}"#,
            r#"{"type":"assistant","message":{"model":"claude-opus-5-5","content":[{"type":"tool_use","name":"Bash","input":{"command":"cargo test -p xtask"}}]}}"#,
            r#"{"type":"assistant","message":{"model":"<synthetic>","content":[]}}"#,
            "not json",
        ];
        std::fs::write(&path, lines.join("\n")).unwrap();
        assert_eq!(
            last_model(
                &path,
                &crate::config::limits::Limits::built_with()
                    .unwrap()
                    .hook
                    .transcript
            )
            .unwrap()
            .as_deref(),
            Some("claude-opus-5-5")
        );
        let uses = tool_uses(&tail(&path, 1 << 20).unwrap());
        assert_eq!(shell_commands(&uses), vec!["cargo test -p xtask"]);
        let sub = dir.join("s").join("subagents");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("agent-x1.jsonl"), "").unwrap();
        assert!(subagent_transcript(&path, "x1").is_some());
        assert!(subagent_transcript(&path, "agent-x1").is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
