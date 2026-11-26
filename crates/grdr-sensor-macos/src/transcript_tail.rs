// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::MacOsSensorError;

const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_SKIPPED_OVERSIZE_BYTES: usize = 1_048_576;
const MAX_SEEN_TOOL_USE_IDS: usize = 4_096;
#[cfg(windows)]
const WIN_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
#[cfg(windows)]
const WIN_FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptToolUseEntry {
    pub tool_use_id: String,
    pub session_id: String,
    pub tool_name: String,
    pub target: String,
    pub observed_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TranscriptCanaryOutcome {
    MatchedPreHook {
        entry: TranscriptToolUseEntry,
    },
    CanaryMissed {
        reason: &'static str,
        entry: TranscriptToolUseEntry,
    },
}

#[derive(Debug, Clone)]
pub struct TranscriptTailer {
    path: PathBuf,
    byte_offset: u64,
    pre_hook_ids: BTreeSet<String>,
    fifo_order: VecDeque<String>,
}

impl TranscriptTailer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            byte_offset: 0,
            pre_hook_ids: BTreeSet::new(),
            fifo_order: VecDeque::new(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn byte_offset(&self) -> u64 {
        self.byte_offset
    }

    pub fn record_pre_hook(&mut self, tool_use_id: impl Into<String>) {
        let id = tool_use_id.into();
        if id.is_empty() {
            return;
        }
        if self.pre_hook_ids.insert(id.clone()) {
            if self.fifo_order.len() >= MAX_SEEN_TOOL_USE_IDS
                && let Some(oldest) = self.fifo_order.pop_front()
            {
                self.pre_hook_ids.remove(&oldest);
            }
            self.fifo_order.push_back(id);
        }
    }

    pub fn poll_reconciled(
        &mut self,
        max_lines: usize,
    ) -> Result<Vec<TranscriptCanaryOutcome>, MacOsSensorError> {
        if max_lines == 0 {
            return Ok(Vec::new());
        }
        let lstat = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(MacOsSensorError::Source(format!(
                    "failed inspecting transcript `{}`: {e}",
                    self.path.display()
                )));
            }
        };
        if lstat.file_type().is_symlink() || !lstat.file_type().is_file() {
            return Err(MacOsSensorError::Source(format!(
                "refusing symlink or non-regular transcript `{}`",
                self.path.display()
            )));
        }
        #[cfg(windows)]
        if (lstat.file_attributes() & WIN_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(MacOsSensorError::Source(format!(
                "refusing reparse point transcript `{}`",
                self.path.display()
            )));
        }
        let mut opts = OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        opts.custom_flags(libc::O_NOFOLLOW);
        #[cfg(windows)]
        opts.custom_flags(WIN_FILE_FLAG_OPEN_REPARSE_POINT);
        let file = opts.open(&self.path).map_err(|e| {
            MacOsSensorError::Source(format!(
                "failed opening transcript `{}`: {e}",
                self.path.display()
            ))
        })?;
        let fstat = file
            .metadata()
            .map_err(|e| MacOsSensorError::Source(format!("transcript metadata failed: {e}")))?;
        #[cfg(windows)]
        if (fstat.file_attributes() & WIN_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(MacOsSensorError::Source(format!(
                "refusing opened reparse transcript `{}`",
                self.path.display()
            )));
        }
        if !fstat.file_type().is_file() {
            return Err(MacOsSensorError::Source(format!(
                "refusing non-regular opened transcript `{}`",
                self.path.display()
            )));
        }
        let file_len = fstat.len();

        if file_len < self.byte_offset {
            self.byte_offset = 0;
        }

        let mut reader = BufReader::new(file);
        reader
            .seek(SeekFrom::Start(self.byte_offset))
            .map_err(|e| MacOsSensorError::Source(format!("transcript seek failed: {e}")))?;

        let mut outcomes = Vec::new();
        let mut line_buf = Vec::with_capacity(512);
        let max_read = u64::try_from(MAX_LINE_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
        while outcomes.len() < max_lines {
            line_buf.clear();
            let read_bytes = (&mut reader)
                .take(max_read)
                .read_until(b'\n', &mut line_buf)
                .map_err(|e| MacOsSensorError::Source(format!("transcript read failed: {e}")))?;
            if read_bytes == 0 {
                break;
            }
            if !line_buf.ends_with(b"\n") {
                if line_buf.len() <= MAX_LINE_BYTES {
                    break;
                }
                let drained = drain_oversize_line(&mut reader, &mut self.byte_offset, read_bytes)?;
                if !drained {
                    break;
                }
                continue;
            }
            self.byte_offset = self
                .byte_offset
                .saturating_add(u64::try_from(read_bytes).unwrap_or(u64::MAX));
            if line_buf.len() > MAX_LINE_BYTES {
                continue;
            }
            let Ok(line) = std::str::from_utf8(&line_buf) else {
                continue;
            };
            if let Some(entry) = parse_transcript_line(line.trim()) {
                let matched = self.pre_hook_ids.contains(&entry.tool_use_id);
                if matched {
                    outcomes.push(TranscriptCanaryOutcome::MatchedPreHook { entry });
                } else {
                    outcomes.push(TranscriptCanaryOutcome::CanaryMissed {
                        reason: "canary-missed",
                        entry,
                    });
                }
            }
        }
        Ok(outcomes)
    }
}

fn drain_oversize_line(
    reader: &mut BufReader<File>,
    byte_offset: &mut u64,
    initial_bytes: usize,
) -> Result<bool, MacOsSensorError> {
    let mut skipped = initial_bytes;
    let mut scratch = [0u8; 4_096];
    while skipped <= MAX_SKIPPED_OVERSIZE_BYTES {
        let n = reader
            .read(&mut scratch)
            .map_err(|e| MacOsSensorError::Source(format!("transcript drain failed: {e}")))?;
        if n == 0 {
            return Ok(false);
        }
        let chunk = scratch.get(..n).unwrap_or_default();
        if let Some(nl) = chunk.iter().position(|&b| b == b'\n') {
            let line_end = nl.saturating_add(1);
            let rewind = i64::try_from(n.saturating_sub(line_end)).unwrap_or(0);
            if rewind > 0 {
                reader
                    .seek_relative(0_i64.saturating_sub(rewind))
                    .map_err(|e| {
                        MacOsSensorError::Source(format!("transcript seek failed: {e}"))
                    })?;
            }
            let total_advance = skipped.saturating_add(line_end);
            *byte_offset = byte_offset.saturating_add(u64::try_from(total_advance).unwrap_or(0));
            return Ok(true);
        }
        skipped = skipped.saturating_add(n);
    }
    Err(MacOsSensorError::Source(format!(
        "transcript single line exceeded {MAX_SKIPPED_OVERSIZE_BYTES} byte hard cap"
    )))
}

fn parse_transcript_line(raw: &str) -> Option<TranscriptToolUseEntry> {
    if raw.is_empty() {
        return None;
    }
    let val: serde_json::Value = serde_json::from_str(raw).ok()?;
    let kind = val.get("type")?.as_str()?;
    if kind != "tool_use" {
        return None;
    }
    let tool_use_id = val
        .get("id")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("tool_use_id").and_then(|v| v.as_str()))?
        .to_string();
    let session_id = val
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let tool_name = val
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let target = val
        .get("input")
        .and_then(|obj| obj.get("command").or_else(|| obj.get("path")))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let observed_at = val
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Timestamp>().ok())
        .unwrap_or(Timestamp::UNIX_EPOCH);

    Some(TranscriptToolUseEntry {
        tool_use_id,
        session_id,
        tool_name,
        target,
        observed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn detects_canary_missed_when_tool_use_lacks_pre_hook_and_handles_truncation() {
        let dir = std::env::temp_dir().join(format!("grdr-transcript-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("session.jsonl");
        {
            let mut f = File::create(&path).expect("create jsonl");
            writeln!(
                f,
                "{{\"type\":\"tool_use\",\"id\":\"tu-seen\",\"session_id\":\"s1\",\"name\":\"Bash\",\"input\":{{\"command\":\"ls\"}}}}"
            )
            .expect("write seen line");
            writeln!(
                f,
                "{{\"type\":\"tool_use\",\"id\":\"tu-unhooked\",\"session_id\":\"s1\",\"name\":\"Bash\",\"input\":{{\"command\":\"curl evil\"}}}}"
            )
            .expect("write missed line");
        }

        let mut tailer = TranscriptTailer::new(&path);
        tailer.record_pre_hook("tu-seen");
        let batch = tailer.poll_reconciled(10).expect("poll lines");
        assert_eq!(batch.len(), 2);
        assert!(matches!(
            batch.first(),
            Some(TranscriptCanaryOutcome::MatchedPreHook { entry }) if entry.tool_use_id == "tu-seen"
        ));
        assert!(matches!(
            batch.get(1),
            Some(TranscriptCanaryOutcome::CanaryMissed { reason, entry })
                if *reason == "canary-missed" && entry.tool_use_id == "tu-unhooked"
        ));

        File::create(&path)
            .and_then(|mut f| {
                writeln!(
                    f,
                    "{{\"type\":\"tool_use\",\"id\":\"tu-after-rotate\",\"session_id\":\"s1\",\"name\":\"Read\",\"input\":{{\"path\":\"/etc/hosts\"}}}}"
                )
            })
            .expect("truncate and write shorter line");
        let after_rotate = tailer.poll_reconciled(10).expect("poll rotated");
        assert_eq!(after_rotate.len(), 1);
        assert!(matches!(
            after_rotate.first(),
            Some(TranscriptCanaryOutcome::CanaryMissed { reason, .. }) if *reason == "canary-missed"
        ));

        let oversize_path = dir.join("oversize.jsonl");
        {
            let mut f = File::create(&oversize_path).expect("create oversize jsonl");
            let big = "a".repeat(MAX_LINE_BYTES + 128);
            writeln!(f, "{big}").expect("write oversize line");
            writeln!(
                f,
                "{{\"type\":\"tool_use\",\"id\":\"tu-after-big\",\"session_id\":\"s1\",\"name\":\"Read\",\"input\":{{\"path\":\"/etc/passwd\"}}}}"
            )
            .expect("write trailing valid line");
        }
        let mut big_tailer = TranscriptTailer::new(&oversize_path);
        let after_big = big_tailer
            .poll_reconciled(10)
            .expect("skip bounded oversize");
        assert_eq!(after_big.len(), 1);
        assert!(matches!(
            after_big.first(),
            Some(TranscriptCanaryOutcome::CanaryMissed { entry, .. }) if entry.tool_use_id == "tu-after-big"
        ));

        #[cfg(unix)]
        {
            let link_path = dir.join("link.jsonl");
            std::os::unix::fs::symlink(&path, &link_path).expect("create unix symlink");
            let mut link_tailer = TranscriptTailer::new(&link_path);
            assert!(link_tailer.poll_reconciled(10).is_err());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
