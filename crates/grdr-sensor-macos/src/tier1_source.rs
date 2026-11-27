// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use grdr_model::ActionClass;
use jiff::Timestamp;

use crate::brand::MacOsLimitsSnapshot;
use crate::catalogue::HarnessCatalogue;
use crate::es_tree::{EsAuditToken, EsEventPayload, ProcessTreeKey};
use crate::macos_probes::{
    FseventsDirectoryWatch, MacOsProcessIdentity, enumerate_macos_processes,
};
use crate::transcript_tail::{TranscriptCanaryOutcome, TranscriptDeltaParser, TranscriptTailer};
use crate::{MacOsEventSource, MacOsRawEvent, MacOsSensorError};

const MAX_PENDING_HANDOFF_PATHS: usize = 256;

pub trait ProcessDiscoveryProbe: Send {
    fn list_processes(&mut self) -> Result<Vec<MacOsProcessIdentity>, MacOsSensorError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LiveProcessProbe;

#[derive(Debug, Clone)]
pub struct MacOsTier1Config {
    pub home_dir: Option<PathBuf>,
    pub workspace_root: Option<PathBuf>,
    pub watch_roots: Vec<PathBuf>,
    pub transcript_paths: Vec<PathBuf>,
    pub max_transcript_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrackedAgentRoot {
    key: ProcessTreeKey,
    harness_id: String,
}

pub struct MacOsTier1EventSource<P = LiveProcessProbe> {
    probe: P,
    catalogue: HarnessCatalogue,
    home_dir: Option<PathBuf>,
    workspace_root: Option<PathBuf>,
    watch: FseventsDirectoryWatch,
    tailers: Vec<TranscriptTailer>,
    parser: Option<Box<dyn TranscriptDeltaParser + Send>>,
    tracked_roots: BTreeMap<u32, TrackedAgentRoot>,
    pending_handoffs: VecDeque<PathBuf>,
    seq_counter: u64,
    max_transcript_bytes: usize,
}

impl ProcessDiscoveryProbe for LiveProcessProbe {
    fn list_processes(&mut self) -> Result<Vec<MacOsProcessIdentity>, MacOsSensorError> {
        enumerate_macos_processes()
    }
}

impl MacOsTier1Config {
    pub fn from_catalogue(
        catalogue: &HarnessCatalogue,
        home_dir: Option<&Path>,
        workspace_root: Option<&Path>,
    ) -> Result<Self, MacOsSensorError> {
        let limits = MacOsLimitsSnapshot::try_embedded()?;
        Ok(Self {
            home_dir: home_dir.map(Path::to_path_buf),
            workspace_root: workspace_root.map(Path::to_path_buf),
            watch_roots: catalogue.resolve_watch_roots(home_dir, workspace_root),
            transcript_paths: Vec::new(),
            max_transcript_bytes: limits.transcript_chunk_max_bytes,
        })
    }

    pub fn host_default() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let cwd = std::env::current_dir().ok();
        let catalogue = HarnessCatalogue::embedded();
        Self::from_catalogue(catalogue, home.as_deref(), cwd.as_deref()).unwrap_or_else(|_| Self {
            home_dir: home.clone(),
            workspace_root: cwd.clone(),
            watch_roots: catalogue.resolve_watch_roots(home.as_deref(), cwd.as_deref()),
            transcript_paths: Vec::new(),
            max_transcript_bytes: 65_536,
        })
    }
}

impl Default for MacOsTier1EventSource<LiveProcessProbe> {
    fn default() -> Self {
        Self::new(
            LiveProcessProbe,
            HarnessCatalogue::embedded().clone(),
            MacOsTier1Config::host_default(),
        )
    }
}

impl MacOsTier1EventSource<LiveProcessProbe> {
    pub fn live() -> Self {
        Self::default()
    }
}

impl<P: ProcessDiscoveryProbe> MacOsTier1EventSource<P> {
    pub fn new(probe: P, catalogue: HarnessCatalogue, config: MacOsTier1Config) -> Self {
        let tailers = config
            .transcript_paths
            .into_iter()
            .map(TranscriptTailer::new)
            .collect();
        Self {
            probe,
            catalogue,
            home_dir: config.home_dir,
            workspace_root: config.workspace_root,
            watch: FseventsDirectoryWatch::new(config.watch_roots),
            tailers,
            parser: None,
            tracked_roots: BTreeMap::new(),
            pending_handoffs: VecDeque::new(),
            seq_counter: 1,
            max_transcript_bytes: config.max_transcript_bytes.max(1),
        }
    }

    pub fn with_transcript_parser(mut self, parser: Box<dyn TranscriptDeltaParser + Send>) -> Self {
        self.parser = Some(parser);
        self
    }

    pub fn add_transcript_path(&mut self, path: PathBuf) {
        if !self.tailers.iter().any(|t| t.path() == path) {
            self.tailers.push(TranscriptTailer::new(path));
        }
    }

    pub fn record_pre_hook(&mut self, tool_use_id: &str) {
        for tailer in &mut self.tailers {
            tailer.record_pre_hook(tool_use_id);
        }
    }

    pub fn drain_ready_transcript_handoffs(&mut self) -> Vec<PathBuf> {
        self.pending_handoffs.drain(..).collect()
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.seq_counter;
        self.seq_counter = self.seq_counter.saturating_add(1);
        seq
    }

    fn push_pending_handoff(&mut self, path: PathBuf) {
        if self.pending_handoffs.iter().any(|p| p == &path) {
            return;
        }
        if self.pending_handoffs.len() >= MAX_PENDING_HANDOFF_PATHS {
            self.pending_handoffs.pop_front();
        }
        self.pending_handoffs.push_back(path);
    }
}

impl<P: ProcessDiscoveryProbe> MacOsEventSource for MacOsTier1EventSource<P> {
    fn source_name(&self) -> &str {
        "macos-tier1-live"
    }

    fn poll_raw_events(
        &mut self,
        max_events: usize,
    ) -> Result<Vec<MacOsRawEvent>, MacOsSensorError> {
        if max_events == 0 {
            return Ok(Vec::new());
        }
        let now = Timestamp::now();
        let mut events = Vec::new();

        let live_procs = self.probe.list_processes()?;
        let mut live_pids = BTreeSet::new();
        for proc_id in &live_procs {
            live_pids.insert(proc_id.key.pid);
            if events.len() >= max_events {
                continue;
            }
            let Some(matched) = self.catalogue.match_process(
                &proc_id.executable_path,
                &proc_id.argv,
                proc_id.signing_id.as_deref(),
                proc_id.team_id.as_deref(),
            ) else {
                continue;
            };
            let matched_id = matched.id.clone();
            let existing = self.tracked_roots.get(&proc_id.key.pid);
            let same_instance = existing.is_some_and(|e| e.key == proc_id.key);
            if same_instance {
                continue;
            }
            let seq = self.next_seq();
            let session_id = format!("tier1-{matched_id}-{}", proc_id.key.pid);
            self.tracked_roots.insert(
                proc_id.key.pid,
                TrackedAgentRoot {
                    key: proc_id.key,
                    harness_id: matched_id.clone(),
                },
            );
            events.push(MacOsRawEvent::EsEvent {
                payload: EsEventPayload::RegisterAgentRoot {
                    root: EsAuditToken {
                        key: proc_id.key,
                        uid: proc_id.uid,
                        team_id: proc_id.team_id.clone(),
                    },
                    session_id,
                },
                seq_num: seq,
                agent_name: matched_id,
                target: proc_id.executable_path.clone(),
                timestamp: now,
            });
        }

        let exited: Vec<(u32, TrackedAgentRoot)> = self
            .tracked_roots
            .iter()
            .filter(|(pid, _)| !live_pids.contains(pid))
            .map(|(pid, root)| (*pid, root.clone()))
            .collect();
        for (pid, root) in exited {
            if events.len() >= max_events {
                break;
            }
            self.tracked_roots.remove(&pid);
            let seq = self.next_seq();
            events.push(MacOsRawEvent::EsEvent {
                payload: EsEventPayload::NotifyExit { key: root.key },
                seq_num: seq,
                agent_name: root.harness_id,
                target: format!("pid:{pid}"),
                timestamp: now,
            });
        }

        if events.len() < max_events {
            let changed_paths = self.watch.poll_changed_paths()?;
            for path in changed_paths {
                if events.len() >= max_events {
                    break;
                }
                if self.tailers.iter().any(|t| t.path() == path) {
                    continue;
                }
                let agent_name = self
                    .catalogue
                    .infer_agent_for_watch_path(
                        &path,
                        self.home_dir.as_deref(),
                        self.workspace_root.as_deref(),
                    )
                    .unwrap_or("undetermined")
                    .to_string();
                events.push(MacOsRawEvent::FseventsConfigWatch {
                    session_id: "tier1-fsevents".to_string(),
                    agent_name,
                    target: path.display().to_string(),
                    timestamp: now,
                });
            }
        }

        if events.len() < max_events {
            let max_chunk = self.max_transcript_bytes;
            let mut handoffs_ready = Vec::new();
            for tailer in &mut self.tailers {
                if events.len() >= max_events {
                    break;
                }
                if let Some(parser) = self.parser.as_deref_mut() {
                    let outcomes = tailer.poll_reconciled_with(parser, max_chunk)?;
                    for outcome in outcomes {
                        if events.len() >= max_events {
                            break;
                        }
                        if let TranscriptCanaryOutcome::CanaryMissed { entry, .. } = outcome {
                            events.push(MacOsRawEvent::TranscriptClaim {
                                session_id: entry.session_id,
                                agent_name: "transcript-tail".to_string(),
                                action_class: ActionClass::Exec,
                                target: entry.target,
                                timestamp: entry.observed_at,
                            });
                        }
                    }
                } else if let Some(handoff) = tailer.open_fd_handoff()?
                    && handoff.file_len() > handoff.start_offset()
                {
                    handoffs_ready.push(tailer.path().to_path_buf());
                }
            }
            for p in handoffs_ready {
                self.push_pending_handoff(p);
            }
        }

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::ActionClass;
    use std::io::Write;

    struct ScriptedProcessProbe {
        batches: VecDeque<Vec<MacOsProcessIdentity>>,
    }

    impl ProcessDiscoveryProbe for ScriptedProcessProbe {
        fn list_processes(&mut self) -> Result<Vec<MacOsProcessIdentity>, MacOsSensorError> {
            Ok(self.batches.pop_front().unwrap_or_default())
        }
    }

    struct LineMockParser;

    impl TranscriptDeltaParser for LineMockParser {
        fn parse_raw_delta(
            &mut self,
            _path_hint: &str,
            raw_bytes: &[u8],
        ) -> Result<Vec<crate::TranscriptToolUseEntry>, MacOsSensorError> {
            let text = std::str::from_utf8(raw_bytes)
                .map_err(|e| MacOsSensorError::Source(e.to_string()))?;
            let mut out = Vec::new();
            for line in text.lines() {
                if let Some((id, target)) = line.split_once('|') {
                    out.push(crate::TranscriptToolUseEntry {
                        tool_use_id: id.to_string(),
                        session_id: "sess-tier1".to_string(),
                        tool_name: "Bash".to_string(),
                        target: target.to_string(),
                        observed_at: Timestamp::UNIX_EPOCH,
                    });
                }
            }
            Ok(out)
        }
    }

    #[test]
    fn discovers_processes_watches_config_and_tails_transcripts_without_json() {
        let dir = std::env::temp_dir().join(format!("grdr-tier1-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg_dir = dir.join(".claude");
        std::fs::create_dir_all(&cfg_dir).expect("create cfg dir");
        let cfg_file = cfg_dir.join("settings.json");
        std::fs::write(&cfg_file, b"{}").expect("write cfg");

        let transcript = dir.join("transcript.log");
        {
            let mut f = std::fs::File::create(&transcript).expect("create transcript");
            writeln!(f, "tu-1|echo hi").expect("write line");
        }

        let probe = ScriptedProcessProbe {
            batches: VecDeque::from([
                vec![MacOsProcessIdentity {
                    key: ProcessTreeKey {
                        pid: 4242,
                        pidversion: 7,
                    },
                    parent_pid: 1,
                    uid: 501,
                    executable_path: "/opt/homebrew/bin/claude".to_string(),
                    team_id: Some("TEAM123456".to_string()),
                    signing_id: Some("com.anthropic.claude-code".to_string()),
                    cdhash: Some("deadbeef".to_string()),
                    argv: vec!["claude".to_string()],
                    adhoc_signed: false,
                }],
                vec![],
            ]),
        };
        let cfg = MacOsTier1Config {
            home_dir: Some(dir.clone()),
            workspace_root: None,
            watch_roots: vec![cfg_dir],
            transcript_paths: vec![transcript],
            max_transcript_bytes: 8_192,
        };
        let mut src = MacOsTier1EventSource::new(probe, HarnessCatalogue::embedded().clone(), cfg)
            .with_transcript_parser(Box::new(LineMockParser));

        let batch1 = src.poll_raw_events(16).expect("first poll");
        assert!(batch1.iter().any(|ev| matches!(
            ev,
            MacOsRawEvent::EsEvent {
                payload: EsEventPayload::RegisterAgentRoot { .. },
                agent_name,
                ..
            } if agent_name == "claude-code"
        )));
        assert!(batch1.iter().any(|ev| matches!(
            ev,
            MacOsRawEvent::FseventsConfigWatch {
                agent_name,
                ..
            } if agent_name == "claude-code"
        )));
        assert!(batch1.iter().any(|ev| matches!(
            ev,
            MacOsRawEvent::TranscriptClaim {
                action_class: ActionClass::Exec,
                target,
                ..
            } if target == "echo hi"
        )));

        let batch2 = src.poll_raw_events(16).expect("second poll");
        assert!(batch2.iter().any(|ev| matches!(
            ev,
            MacOsRawEvent::EsEvent {
                payload: EsEventPayload::NotifyExit {
                    key: ProcessTreeKey {
                        pid: 4242,
                        pidversion: 7
                    }
                },
                ..
            }
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
