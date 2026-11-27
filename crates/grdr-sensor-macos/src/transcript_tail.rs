// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::MacOsSensorError;
use crate::brand::MacOsLimitsSnapshot;

const MAX_SEEN_TOOL_USE_IDS: usize = 4_096;
const MAX_OVERSIZE_SKIP_CHUNKS: usize = 32;
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

pub trait TranscriptDeltaParser {
    fn parse_raw_delta(
        &mut self,
        path_hint: &str,
        raw_bytes: &[u8],
    ) -> Result<Vec<TranscriptToolUseEntry>, MacOsSensorError>;
}

#[derive(Debug)]
pub struct TranscriptFdHandoff {
    file: File,
    start_offset: u64,
    file_len: u64,
    max_bytes: usize,
    truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptRawDelta {
    pub raw_bytes: Vec<u8>,
    pub new_offset: u64,
    pub truncated: bool,
    pub skipped_oversize_lines: u32,
}

#[derive(Debug, Clone)]
pub struct TranscriptTailer {
    path: PathBuf,
    byte_offset: u64,
    max_chunk_bytes: usize,
    skip_cap_bytes: usize,
    pre_hook_ids: BTreeSet<String>,
    fifo_order: VecDeque<String>,
}

impl TranscriptFdHandoff {
    pub const fn start_offset(&self) -> u64 {
        self.start_offset
    }

    pub const fn file_len(&self) -> u64 {
        self.file_len
    }

    pub const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub const fn was_truncated(&self) -> bool {
        self.truncated
    }

    pub const fn as_file(&self) -> &File {
        &self.file
    }

    pub fn into_file(self) -> File {
        self.file
    }
}

#[cfg(unix)]
impl AsRawFd for TranscriptFdHandoff {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl TranscriptTailer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let (max_chunk_bytes, skip_cap_bytes) = match MacOsLimitsSnapshot::try_embedded() {
            Ok(limits) => (
                limits.transcript_chunk_max_bytes.max(1),
                limits.transcript_skip_cap_bytes.max(1),
            ),
            Err(_) => (65_536, 1_048_576),
        };
        Self {
            path: path.into(),
            byte_offset: 0,
            max_chunk_bytes,
            skip_cap_bytes,
            pre_hook_ids: BTreeSet::new(),
            fifo_order: VecDeque::new(),
        }
    }

    pub fn with_chunk_cap(mut self, max_chunk_bytes: usize) -> Self {
        self.max_chunk_bytes = max_chunk_bytes.max(1);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn byte_offset(&self) -> u64 {
        self.byte_offset
    }

    pub fn advance_offset(&mut self, new_offset: u64) {
        self.byte_offset = new_offset;
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

    pub fn open_fd_handoff(&mut self) -> Result<Option<TranscriptFdHandoff>, MacOsSensorError> {
        let Some(file) = open_verified_regular_transcript(&self.path)? else {
            return Ok(None);
        };
        let fstat = file
            .metadata()
            .map_err(|e| MacOsSensorError::Source(format!("transcript metadata failed: {e}")))?;
        let file_len = fstat.len();
        let mut truncated = false;
        if file_len < self.byte_offset {
            self.byte_offset = 0;
            truncated = true;
        }
        Ok(Some(TranscriptFdHandoff {
            file,
            start_offset: self.byte_offset,
            file_len,
            max_bytes: self.max_chunk_bytes,
            truncated,
        }))
    }

    pub fn read_raw_delta(
        &mut self,
        max_bytes: usize,
    ) -> Result<Option<TranscriptRawDelta>, MacOsSensorError> {
        if max_bytes == 0 {
            return Ok(None);
        }
        let Some(handoff) = self.open_fd_handoff()? else {
            return Ok(None);
        };
        let cap = max_bytes.min(self.max_chunk_bytes).max(1);
        let truncated = handoff.was_truncated();
        let mut reader = BufReader::new(handoff.into_file());
        reader
            .seek(SeekFrom::Start(self.byte_offset))
            .map_err(|e| MacOsSensorError::Source(format!("transcript seek failed: {e}")))?;

        let mut skipped_oversize_lines: u32 = 0;
        for _ in 0..MAX_OVERSIZE_SKIP_CHUNKS {
            let take_limit = u64::try_from(cap.saturating_add(1)).unwrap_or(u64::MAX);
            let mut buf = Vec::with_capacity(cap.min(8_192));
            let n = (&mut reader)
                .take(take_limit)
                .read_to_end(&mut buf)
                .map_err(|e| MacOsSensorError::Source(format!("transcript read failed: {e}")))?;
            if n == 0 {
                return Ok(None);
            }
            if let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') {
                let consumed = last_nl.saturating_add(1);
                buf.truncate(consumed);
                self.byte_offset = self
                    .byte_offset
                    .saturating_add(u64::try_from(consumed).unwrap_or(u64::MAX));
                return Ok(Some(TranscriptRawDelta {
                    raw_bytes: buf,
                    new_offset: self.byte_offset,
                    truncated,
                    skipped_oversize_lines,
                }));
            }
            if n <= cap {
                return Ok(None);
            }
            let drained =
                drain_oversize_line(&mut reader, &mut self.byte_offset, n, self.skip_cap_bytes)?;
            if !drained {
                return Ok(None);
            }
            skipped_oversize_lines = skipped_oversize_lines.saturating_add(1);
        }

        Err(MacOsSensorError::Source(
            "transcript exceeded consecutive oversize line skip limit".into(),
        ))
    }

    pub fn poll_reconciled_with<P: TranscriptDeltaParser + ?Sized>(
        &mut self,
        parser: &mut P,
        max_bytes: usize,
    ) -> Result<Vec<TranscriptCanaryOutcome>, MacOsSensorError> {
        let Some(delta) = self.read_raw_delta(max_bytes)? else {
            return Ok(Vec::new());
        };
        let path_hint = self.path.display().to_string();
        let entries = parser.parse_raw_delta(&path_hint, &delta.raw_bytes)?;
        Ok(self.reconcile_entries(entries))
    }

    pub fn reconcile_entries(
        &self,
        entries: Vec<TranscriptToolUseEntry>,
    ) -> Vec<TranscriptCanaryOutcome> {
        entries
            .into_iter()
            .map(|entry| {
                if self.pre_hook_ids.contains(&entry.tool_use_id) {
                    TranscriptCanaryOutcome::MatchedPreHook { entry }
                } else {
                    TranscriptCanaryOutcome::CanaryMissed {
                        reason: "canary-missed",
                        entry,
                    }
                }
            })
            .collect()
    }
}

fn open_verified_regular_transcript(path: &Path) -> Result<Option<File>, MacOsSensorError> {
    let lstat = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(MacOsSensorError::Source(format!(
                "failed inspecting transcript `{}`: {e}",
                path.display()
            )));
        }
    };
    if lstat.file_type().is_symlink() || !lstat.file_type().is_file() {
        return Err(MacOsSensorError::Source(format!(
            "refusing symlink or non-regular transcript `{}`",
            path.display()
        )));
    }
    #[cfg(windows)]
    if (lstat.file_attributes() & WIN_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(MacOsSensorError::Source(format!(
            "refusing reparse point transcript `{}`",
            path.display()
        )));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    #[cfg(windows)]
    opts.custom_flags(WIN_FILE_FLAG_OPEN_REPARSE_POINT);
    let file = opts.open(path).map_err(|e| {
        MacOsSensorError::Source(format!(
            "failed opening transcript `{}`: {e}",
            path.display()
        ))
    })?;
    let fstat = file
        .metadata()
        .map_err(|e| MacOsSensorError::Source(format!("transcript metadata failed: {e}")))?;
    #[cfg(windows)]
    if (fstat.file_attributes() & WIN_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(MacOsSensorError::Source(format!(
            "refusing opened reparse transcript `{}`",
            path.display()
        )));
    }
    if !fstat.file_type().is_file() {
        return Err(MacOsSensorError::Source(format!(
            "refusing non-regular opened transcript `{}`",
            path.display()
        )));
    }
    Ok(Some(file))
}

fn drain_oversize_line(
    reader: &mut BufReader<File>,
    byte_offset: &mut u64,
    initial_bytes: usize,
    skip_cap_bytes: usize,
) -> Result<bool, MacOsSensorError> {
    let mut skipped = initial_bytes;
    let mut scratch = [0u8; 4_096];
    while skipped <= skip_cap_bytes {
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
        "transcript single line exceeded {skip_cap_bytes} byte hard cap"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct UnprivilegedEngineMockParser;

    impl TranscriptDeltaParser for UnprivilegedEngineMockParser {
        fn parse_raw_delta(
            &mut self,
            _path_hint: &str,
            raw_bytes: &[u8],
        ) -> Result<Vec<TranscriptToolUseEntry>, MacOsSensorError> {
            let text = std::str::from_utf8(raw_bytes)
                .map_err(|e| MacOsSensorError::Source(e.to_string()))?;
            let mut out = Vec::new();
            for line in text.lines() {
                if let Some((id, cmd)) = line.split_once('|') {
                    out.push(TranscriptToolUseEntry {
                        tool_use_id: id.trim().to_string(),
                        session_id: "s1".to_string(),
                        tool_name: "Bash".to_string(),
                        target: cmd.trim().to_string(),
                        observed_at: Timestamp::UNIX_EPOCH,
                    });
                }
            }
            Ok(out)
        }
    }

    #[test]
    fn hands_off_bounded_fd_and_reconciles_via_unprivileged_parser_port() {
        let dir = std::env::temp_dir().join(format!("grdr-transcript-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        let path = dir.join("session.jsonl");
        {
            let mut f = File::create(&path).expect("create transcript");
            writeln!(f, "tu-seen|ls").expect("write seen line");
            writeln!(f, "tu-unhooked|curl evil").expect("write missed line");
        }

        let mut parser = UnprivilegedEngineMockParser;
        let mut tailer = TranscriptTailer::new(&path);
        tailer.record_pre_hook("tu-seen");

        let handoff = tailer
            .open_fd_handoff()
            .expect("open handoff")
            .expect("some handoff");
        assert_eq!(handoff.start_offset(), 0);
        assert!(handoff.file_len() > 0);
        assert!(!handoff.was_truncated());
        drop(handoff);

        let batch = tailer
            .poll_reconciled_with(&mut parser, 65_536)
            .expect("poll reconciled");
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
            .and_then(|mut f| writeln!(f, "tu-after-rotate|/etc/hosts"))
            .expect("truncate and write shorter line");
        let after_rotate = tailer
            .poll_reconciled_with(&mut parser, 65_536)
            .expect("poll rotated");
        assert_eq!(after_rotate.len(), 1);
        assert!(matches!(
            after_rotate.first(),
            Some(TranscriptCanaryOutcome::CanaryMissed { reason, .. }) if *reason == "canary-missed"
        ));

        let oversize_path = dir.join("oversize.jsonl");
        {
            let mut f = File::create(&oversize_path).expect("create oversize log");
            let big = "a".repeat(66_000);
            writeln!(f, "{big}").expect("write oversize line");
            writeln!(f, "tu-after-big|/etc/passwd").expect("write trailing valid line");
        }
        let mut big_tailer = TranscriptTailer::new(&oversize_path).with_chunk_cap(4_096);
        let after_big = big_tailer
            .poll_reconciled_with(&mut parser, 4_096)
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
            assert!(link_tailer.open_fd_handoff().is_err());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
