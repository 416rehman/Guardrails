// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{BTreeSet, VecDeque};
#[cfg(windows)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use std::time::Instant;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::WindowsSensorError;
#[cfg(windows)]
use crate::etw::EtwProviderKind;
use crate::etw::{
    EtwLossMetrics, EtwSessionDescriptor, EtwSource, RawEtwRecord, default_etw_session_descriptor,
};

#[cfg(windows)]
pub(crate) const ETW_CHANNEL_CAP: usize = 2_048;
const UNIX_EPOCH_100NS_OFFSET: i64 = 116_444_736_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwSessionState {
    NotStarted,
    Running,
    DegradedUnprivilegedW0,
    Stopped,
    Faulted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveEtwSessionStatus {
    pub session_name: String,
    pub session_state: EtwSessionState,
    pub enabled_providers: usize,
    pub failed_providers: usize,
    pub detail: String,
}

#[derive(Debug)]
pub(crate) struct EtwSharedQueue {
    pub(crate) queue: Mutex<VecDeque<RawEtwRecord>>,
    #[cfg(windows)]
    pub(crate) providers: Vec<(ParsedGuid, EtwProviderKind)>,
    #[cfg(windows)]
    pub(crate) session_id: String,
    pub(crate) agent_pids: Mutex<BTreeSet<u32>>,
    #[cfg(windows)]
    pub(crate) event_count: AtomicU64,
}

#[derive(Debug)]
pub struct LiveWindowsEtwSource {
    descriptor: EtwSessionDescriptor,
    session_state: EtwSessionState,
    shared: Arc<EtwSharedQueue>,
    last_rate_per_sec: u64,
    #[cfg(windows)]
    last_query_at: Option<Instant>,
    #[cfg(windows)]
    last_event_count: u64,
    #[cfg(windows)]
    platform_handle: Option<crate::win_etw_sys::WinEtwHandle>,
}

impl LiveWindowsEtwSource {
    pub fn new(descriptor: EtwSessionDescriptor) -> Self {
        #[cfg(windows)]
        let mut providers = Vec::with_capacity(descriptor.providers.len());
        #[cfg(windows)]
        for spec in &descriptor.providers {
            if let Ok(parsed) = parse_guid_str(&spec.provider_guid) {
                providers.push((parsed, spec.kind));
            }
        }
        let shared = Arc::new(EtwSharedQueue {
            queue: Mutex::new(VecDeque::new()),
            #[cfg(windows)]
            providers,
            #[cfg(windows)]
            session_id: descriptor.session_name.clone(),
            agent_pids: Mutex::new(BTreeSet::new()),
            #[cfg(windows)]
            event_count: AtomicU64::new(0),
        });
        Self {
            descriptor,
            session_state: EtwSessionState::NotStarted,
            shared,
            last_rate_per_sec: 0,
            #[cfg(windows)]
            last_query_at: None,
            #[cfg(windows)]
            last_event_count: 0,
            #[cfg(windows)]
            platform_handle: None,
        }
    }

    pub fn with_default_descriptor() -> Self {
        Self::new(default_etw_session_descriptor())
    }

    pub const fn session_state(&self) -> EtwSessionState {
        self.session_state
    }

    pub fn descriptor(&self) -> &EtwSessionDescriptor {
        &self.descriptor
    }

    pub fn track_agent_pid(&self, pid: u32) {
        if let Ok(mut guard) = self.shared.agent_pids.lock() {
            guard.insert(pid);
        }
    }

    pub fn start_session(&mut self) -> Result<LiveEtwSessionStatus, WindowsSensorError> {
        self.stop_session();
        #[cfg(windows)]
        {
            match crate::win_etw_sys::start_win_etw_session(
                &self.descriptor.session_name,
                &self.descriptor.providers,
                Arc::clone(&self.shared),
            ) {
                Ok((maybe_handle, status)) => {
                    self.platform_handle = maybe_handle;
                    self.session_state = status.session_state;
                    self.last_query_at = Some(Instant::now());
                    self.last_event_count = self.shared.event_count.load(Ordering::Relaxed);
                    Ok(status)
                }
                Err(err) => {
                    self.session_state = EtwSessionState::Faulted;
                    Err(err)
                }
            }
        }
        #[cfg(not(windows))]
        {
            self.session_state = EtwSessionState::DegradedUnprivilegedW0;
            Ok(LiveEtwSessionStatus {
                session_name: self.descriptor.session_name.clone(),
                session_state: EtwSessionState::DegradedUnprivilegedW0,
                enabled_providers: 0,
                failed_providers: 0,
                detail: "ETW live session unavailable on non-Windows host; using W0 fallback"
                    .to_string(),
            })
        }
    }

    pub fn query_loss_metrics(&mut self) -> Result<EtwLossMetrics, WindowsSensorError> {
        #[cfg(windows)]
        {
            if let Some(handle) = &self.platform_handle {
                let now = Instant::now();
                let total_events = self.shared.event_count.load(Ordering::Relaxed);
                let delta = total_events.saturating_sub(self.last_event_count);
                let elapsed_secs = self
                    .last_query_at
                    .map(|prev| now.saturating_duration_since(prev).as_secs().max(1))
                    .unwrap_or(1);
                let current_rate = delta.checked_div(elapsed_secs).unwrap_or(0);
                let metrics = crate::win_etw_sys::query_win_etw_loss(
                    handle,
                    &self.descriptor.session_name,
                    self.last_rate_per_sec,
                    current_rate,
                )?;
                self.last_rate_per_sec = metrics.current_rate_per_sec;
                self.last_query_at = Some(now);
                self.last_event_count = total_events;
                return Ok(metrics);
            }
        }
        Ok(EtwLossMetrics {
            events_lost: 0,
            buffers_lost: 0,
            prior_rate_per_sec: self.last_rate_per_sec,
            current_rate_per_sec: 0,
        })
    }

    pub fn stop_session(&mut self) {
        #[cfg(windows)]
        if let Some(handle) = self.platform_handle.take() {
            crate::win_etw_sys::stop_win_etw_session(handle, &self.descriptor.session_name);
        }
        if self.session_state == EtwSessionState::Running {
            self.session_state = EtwSessionState::Stopped;
        }
    }
}

impl Drop for LiveWindowsEtwSource {
    fn drop(&mut self) {
        self.stop_session();
    }
}

impl EtwSource for LiveWindowsEtwSource {
    fn session_name(&self) -> &str {
        &self.descriptor.session_name
    }

    fn poll_records(
        &mut self,
        max_records: usize,
    ) -> Result<Vec<RawEtwRecord>, WindowsSensorError> {
        if max_records == 0 {
            return Ok(Vec::new());
        }
        let mut guard =
            self.shared.queue.lock().map_err(|_| {
                WindowsSensorError::Etw("ETW shared queue lock poisoned".to_string())
            })?;
        let drain_count = max_records.min(guard.len());
        Ok(guard.drain(..drain_count).collect())
    }
}

pub fn filetime_to_timestamp(ft_100ns: i64) -> Timestamp {
    let unix_100ns = ft_100ns.saturating_sub(UNIX_EPOCH_100NS_OFFSET);
    let nanos = i128::from(unix_100ns).saturating_mul(100);
    Timestamp::from_nanosecond(nanos).unwrap_or(Timestamp::UNIX_EPOCH)
}

pub fn parse_guid_str(raw: &str) -> Result<ParsedGuid, WindowsSensorError> {
    let trimmed = raw.trim().trim_start_matches('{').trim_end_matches('}');
    let mut parts = trimmed.split('-');
    let p1 = parts
        .next()
        .ok_or_else(|| WindowsSensorError::Etw(format!("invalid GUID `{raw}`")))?;
    let p2 = parts
        .next()
        .ok_or_else(|| WindowsSensorError::Etw(format!("invalid GUID `{raw}`")))?;
    let p3 = parts
        .next()
        .ok_or_else(|| WindowsSensorError::Etw(format!("invalid GUID `{raw}`")))?;
    let p4 = parts
        .next()
        .ok_or_else(|| WindowsSensorError::Etw(format!("invalid GUID `{raw}`")))?;
    let p5 = parts
        .next()
        .ok_or_else(|| WindowsSensorError::Etw(format!("invalid GUID `{raw}`")))?;
    if parts.next().is_some()
        || p1.len() != 8
        || p2.len() != 4
        || p3.len() != 4
        || p4.len() != 4
        || p5.len() != 12
    {
        return Err(WindowsSensorError::Etw(format!("malformed GUID `{raw}`")));
    }
    let data1 = u32::from_str_radix(p1, 16)
        .map_err(|_| WindowsSensorError::Etw(format!("invalid GUID data1 `{p1}`")))?;
    let data2 = u16::from_str_radix(p2, 16)
        .map_err(|_| WindowsSensorError::Etw(format!("invalid GUID data2 `{p2}`")))?;
    let data3 = u16::from_str_radix(p3, 16)
        .map_err(|_| WindowsSensorError::Etw(format!("invalid GUID data3 `{p3}`")))?;
    let mut tail = String::with_capacity(16);
    tail.push_str(p4);
    tail.push_str(p5);
    let mut data4 = [0u8; 8];
    for (idx, byte_slot) in data4.iter_mut().enumerate() {
        let start = idx.saturating_mul(2);
        let pair = tail
            .get(start..start.saturating_add(2))
            .ok_or_else(|| WindowsSensorError::Etw("GUID tail slice out of range".into()))?;
        *byte_slot = u8::from_str_radix(pair, 16)
            .map_err(|_| WindowsSensorError::Etw(format!("invalid GUID hex byte `{pair}`")))?;
    }
    Ok(ParsedGuid {
        data1,
        data2,
        data3,
        data4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_default_etw_provider_guids() {
        let desc = default_etw_session_descriptor();
        for spec in &desc.providers {
            let parsed = parse_guid_str(&spec.provider_guid).expect("valid provider GUID");
            assert_ne!(parsed.data1, 0);
        }
        assert!(parse_guid_str("not-a-guid").is_err());
        assert!(parse_guid_str("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e71").is_err());
    }

    #[test]
    fn converts_win32_filetime_to_unix_timestamp() {
        let ts = filetime_to_timestamp(UNIX_EPOCH_100NS_OFFSET.saturating_add(10_000_000));
        assert_eq!(ts.as_second(), 1);
    }

    #[test]
    fn live_source_start_handles_privileges_or_fallback_cleanly() {
        let mut src = LiveWindowsEtwSource::with_default_descriptor();
        let status = src.start_session().expect("start or clean W0 fallback");
        assert!(matches!(
            status.session_state,
            EtwSessionState::Running | EtwSessionState::DegradedUnprivilegedW0
        ));
        src.track_agent_pid(std::process::id());
        let loss = src.query_loss_metrics().expect("loss metrics query");
        assert_eq!(loss.prior_rate_per_sec, 0);
        let polled = src.poll_records(8).expect("non-blocking poll");
        assert!(polled.len() <= 8);
        src.stop_session();
    }
}
