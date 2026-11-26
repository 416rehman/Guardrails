// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::sync::Arc;
use std::sync::atomic::Ordering;

use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW,
};

use crate::WindowsSensorError;
use crate::etw::{EtwLossMetrics, RawEtwRecord};
use crate::win_etw::{
    ETW_CHANNEL_CAP, EtwSessionState, EtwSharedQueue, LiveEtwSessionStatus, ParsedGuid,
    filetime_to_timestamp, parse_guid_str,
};

const WIN32_ERROR_ACCESS_DENIED: u32 = 5;
const WIN32_ERROR_ALREADY_EXISTS: u32 = 183;
const ETW_BUFFER_SIZE_KB: u32 = 64;
const ETW_MIN_BUFFERS: u32 = 4;
const ETW_MAX_BUFFERS: u32 = 64;
const ETW_FLUSH_TIMER_SECS: u32 = 1;

#[derive(Debug)]
pub(crate) struct WinEtwHandle {
    session_name: String,
    trace_handle: u64,
    consumer_handle: u64,
    reader_thread: Option<std::thread::JoinHandle<()>>,
    _shared: Arc<EtwSharedQueue>,
}

struct EtwPropertiesBuf {
    words: Vec<u64>,
}

impl Drop for WinEtwHandle {
    fn drop(&mut self) {
        self.shutdown_internal();
    }
}

impl WinEtwHandle {
    fn shutdown_internal(&mut self) {
        if self.consumer_handle != u64::MAX {
            #[allow(
                unsafe_code,
                reason = "Close ETW consumer handle to stop ProcessTrace."
            )]
            // SAFETY: consumer_handle came from OpenTraceW and is closed once.
            unsafe {
                let _ = CloseTrace(PROCESSTRACE_HANDLE {
                    Value: self.consumer_handle,
                });
            }
            self.consumer_handle = u64::MAX;
        }
        if self.trace_handle != 0 {
            stop_trace_handle(self.trace_handle, &self.session_name);
            self.trace_handle = 0;
        }
        if let Some(join) = self.reader_thread.take() {
            let _ = join.join();
        }
    }
}

impl EtwPropertiesBuf {
    fn allocate(wide_name: &[u16], configure_realtime: bool) -> Result<Self, WindowsSensorError> {
        let header_bytes = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_bytes = wide_name
            .len()
            .checked_mul(2)
            .ok_or_else(|| WindowsSensorError::Etw("ETW logger name length overflow".into()))?;
        let total_bytes = header_bytes
            .checked_add(name_bytes)
            .ok_or_else(|| WindowsSensorError::Etw("ETW properties buffer overflow".into()))?;
        let size_bytes = u32::try_from(total_bytes)
            .map_err(|_| WindowsSensorError::Etw("ETW properties size exceeds u32".into()))?;
        let mut words = vec![0u64; total_bytes.div_ceil(8)];
        let props_ptr = words.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        let logger_offset = u32::try_from(header_bytes).unwrap_or(120);

        #[allow(
            unsafe_code,
            reason = "Initialize aligned EVENT_TRACE_PROPERTIES header in owned Vec<u64> buffer."
        )]
        // SAFETY: words is 8-byte aligned and sized for EVENT_TRACE_PROPERTIES + trailing logger name.
        unsafe {
            let p = &mut *props_ptr;
            p.Wnode.BufferSize = size_bytes;
            p.LoggerNameOffset = logger_offset;
            if configure_realtime {
                p.Wnode.Guid = to_win_guid(session_guid());
                p.Wnode.ClientContext = 1;
                p.Wnode.Flags = 0x0002_0000;
                p.BufferSize = ETW_BUFFER_SIZE_KB;
                p.MinimumBuffers = ETW_MIN_BUFFERS;
                p.MaximumBuffers = ETW_MAX_BUFFERS;
                p.FlushTimer = ETW_FLUSH_TIMER_SECS;
                p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            }
        }
        Ok(Self { words })
    }

    fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.words.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }
}

pub(crate) fn start_win_etw_session(
    session_name: &str,
    provider_specs: &[crate::etw::EtwProviderSpec],
    shared: Arc<EtwSharedQueue>,
) -> Result<(Option<WinEtwHandle>, LiveEtwSessionStatus), WindowsSensorError> {
    let mut wide_name = encode_utf16_nul(session_name)?;
    let mut props = EtwPropertiesBuf::allocate(&wide_name, true)?;
    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };

    #[allow(unsafe_code, reason = "Create real-time Win32 ETW trace session.")]
    // SAFETY: props is aligned and zero-initialized with trailing capacity for wide_name.
    let mut status = unsafe { StartTraceW(&mut handle, wide_name.as_ptr(), props.as_mut_ptr()) };

    if status == WIN32_ERROR_ALREADY_EXISTS {
        let mut stop_props = EtwPropertiesBuf::allocate(&wide_name, false)?;
        #[allow(
            unsafe_code,
            reason = "Stop stale ETW trace session before recreating."
        )]
        // SAFETY: stop_props holds an initialized EVENT_TRACE_PROPERTIES buffer.
        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                wide_name.as_ptr(),
                stop_props.as_mut_ptr(),
                EVENT_TRACE_CONTROL_STOP,
            );
            status = StartTraceW(&mut handle, wide_name.as_ptr(), props.as_mut_ptr());
        }
    }

    if status == WIN32_ERROR_ACCESS_DENIED {
        return Ok((
            None,
            LiveEtwSessionStatus {
                session_name: session_name.to_string(),
                session_state: EtwSessionState::DegradedUnprivilegedW0,
                enabled_providers: 0,
                failed_providers: 0,
                detail: "StartTraceW denied; using unprivileged W0 observation fallback"
                    .to_string(),
            },
        ));
    }

    if status != 0 {
        return Err(WindowsSensorError::Etw(format!(
            "StartTraceW failed for `{session_name}` with win32={status}"
        )));
    }

    let mut parsed_providers = Vec::with_capacity(provider_specs.len());
    for spec in provider_specs {
        parsed_providers.push(parse_guid_str(&spec.provider_guid)?);
    }
    let (enabled, failed) = enable_etw_providers(handle.Value, &parsed_providers);
    let context_ptr = Arc::as_ptr(&shared) as *mut core::ffi::c_void;

    #[allow(unsafe_code, reason = "Open real-time ETW trace consumer handle.")]
    // SAFETY: wide_name is NUL-terminated for OpenTraceW and shared stays alive while reader_thread runs.
    let consumer = unsafe {
        let mut logfile: EVENT_TRACE_LOGFILEW = std::mem::zeroed();
        logfile.LoggerName = wide_name.as_mut_ptr();
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(etw_event_record_callback);
        logfile.Context = context_ptr;
        OpenTraceW(&mut logfile)
    };

    if consumer.Value == u64::MAX {
        stop_trace_handle(handle.Value, session_name);
        return Err(WindowsSensorError::Etw(
            "OpenTraceW returned invalid handle".to_string(),
        ));
    }

    let consumer_val = consumer.Value;
    let thread_shared = Arc::clone(&shared);
    let join = std::thread::Builder::new()
        .name("grdr-etw-consumer".to_string())
        .spawn(move || {
            let _keep_alive = thread_shared;
            let handles = [PROCESSTRACE_HANDLE {
                Value: consumer_val,
            }];
            #[allow(
                unsafe_code,
                reason = "Drain ETW records on dedicated consumer thread."
            )]
            // SAFETY: handles[0] stays open until CloseTrace runs in stop_win_etw_session.
            unsafe {
                let _ = ProcessTrace(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null());
            }
        })
        .map_err(|e| {
            #[allow(unsafe_code, reason = "Close consumer handle on spawn failure.")]
            // SAFETY: consumer_val is a valid handle returned by OpenTraceW.
            unsafe {
                let _ = CloseTrace(PROCESSTRACE_HANDLE {
                    Value: consumer_val,
                });
            }
            stop_trace_handle(handle.Value, session_name);
            WindowsSensorError::Etw(format!("ETW thread spawn failed: {e}"))
        })?;

    Ok((
        Some(WinEtwHandle {
            session_name: session_name.to_string(),
            trace_handle: handle.Value,
            consumer_handle: consumer_val,
            reader_thread: Some(join),
            _shared: shared,
        }),
        LiveEtwSessionStatus {
            session_name: session_name.to_string(),
            session_state: EtwSessionState::Running,
            enabled_providers: enabled,
            failed_providers: failed,
            detail: format!("ETW trace active ({enabled} providers enabled)"),
        },
    ))
}

pub(crate) fn query_win_etw_loss(
    handle: &WinEtwHandle,
    session_name: &str,
    prior_rate_per_sec: u64,
    current_rate_per_sec: u64,
) -> Result<EtwLossMetrics, WindowsSensorError> {
    let wide_name = encode_utf16_nul(session_name)?;
    let mut props = EtwPropertiesBuf::allocate(&wide_name, false)?;

    #[allow(unsafe_code, reason = "Query ETW EventsLost and BuffersLost counters.")]
    // SAFETY: props is sized and aligned for ControlTraceW query output on active trace_handle.
    let rc = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE {
                Value: handle.trace_handle,
            },
            std::ptr::null(),
            props.as_mut_ptr(),
            EVENT_TRACE_CONTROL_QUERY,
        )
    };
    if rc != 0 {
        return Err(WindowsSensorError::Etw(format!(
            "ControlTraceW query failed with win32={rc}"
        )));
    }

    #[allow(unsafe_code, reason = "Read EventsLost and buffer loss counts.")]
    // SAFETY: ControlTraceW succeeded so EVENT_TRACE_PROPERTIES counters are valid.
    let (events_lost, buffers_lost) = unsafe {
        let p = &*props.as_mut_ptr();
        (
            u64::from(p.EventsLost),
            u64::from(p.LogBuffersLost).saturating_add(u64::from(p.RealTimeBuffersLost)),
        )
    };
    Ok(EtwLossMetrics {
        events_lost,
        buffers_lost,
        prior_rate_per_sec,
        current_rate_per_sec,
    })
}

pub(crate) fn stop_win_etw_session(mut handle: WinEtwHandle, _session_name: &str) {
    handle.shutdown_internal();
}

fn stop_trace_handle(trace_handle: u64, session_name: &str) {
    if let Ok(wide_name) = encode_utf16_nul(session_name)
        && let Ok(mut props) = EtwPropertiesBuf::allocate(&wide_name, false)
    {
        #[allow(unsafe_code, reason = "Stop real-time ETW trace session.")]
        // SAFETY: props is aligned and sized for ControlTraceW stop request.
        unsafe {
            let _ = ControlTraceW(
                CONTROLTRACE_HANDLE {
                    Value: trace_handle,
                },
                std::ptr::null(),
                props.as_mut_ptr(),
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }
}

fn enable_etw_providers(trace_handle: u64, guids: &[ParsedGuid]) -> (usize, usize) {
    let params = ENABLE_TRACE_PARAMETERS {
        Version: 2,
        EnableProperty: 0,
        ControlFlags: 0,
        SourceId: to_win_guid(session_guid()),
        EnableFilterDesc: std::ptr::null_mut(),
        FilterDescCount: 0,
    };
    let mut enabled = 0usize;
    let mut failed = 0usize;
    for guid in guids {
        let win_guid = to_win_guid(*guid);
        #[allow(unsafe_code, reason = "Enable ETW provider on active trace session.")]
        // SAFETY: trace_handle is valid and win_guid/params point to initialized stack structs.
        let rc = unsafe {
            EnableTraceEx2(
                CONTROLTRACE_HANDLE {
                    Value: trace_handle,
                },
                &win_guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                4,
                u64::MAX,
                0,
                0,
                &params,
            )
        };
        if rc == 0 {
            enabled = enabled.saturating_add(1);
        } else {
            failed = failed.saturating_add(1);
        }
    }
    (enabled, failed)
}

#[allow(
    unsafe_code,
    reason = "Win32 ProcessTrace event callback bridges EVENT_RECORD headers into RawEtwRecord inside catch_unwind."
)]
// SAFETY: Checks null pointers before reading EVENT_RECORD or UserContext and catches panics across ABI.
unsafe extern "system" fn etw_event_record_callback(event_record: *mut EVENT_RECORD) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if event_record.is_null() {
            return;
        }
        // SAFETY: Verified non-null EVENT_RECORD pointer from ProcessTrace.
        let rec = unsafe { &*event_record };
        if rec.UserContext.is_null() {
            return;
        }
        // SAFETY: UserContext points to EtwSharedQueue kept alive by thread_shared Arc in ProcessTrace thread.
        let shared = unsafe { &*(rec.UserContext as *const EtwSharedQueue) };
        let prov = from_win_guid(rec.EventHeader.ProviderId);
        let Some(kind) = shared
            .providers
            .iter()
            .find(|(g, _)| *g == prov)
            .map(|(_, k)| *k)
        else {
            return;
        };
        let pid = rec.EventHeader.ProcessId;
        let event_id = rec.EventHeader.EventDescriptor.Id;
        shared.event_count.fetch_add(1, Ordering::Relaxed);
        let (_start_us, image_opt) = crate::win_process::query_process_identity_fields(pid);
        let in_agent_lineage = shared
            .agent_pids
            .lock()
            .map(|g| g.contains(&pid))
            .unwrap_or(false);
        if let Ok(mut guard) = shared.queue.lock() {
            if guard.len() >= ETW_CHANNEL_CAP {
                guard.pop_front();
            }
            guard.push_back(RawEtwRecord {
                provider: kind,
                event_id,
                kernel_header_pid: pid,
                claimed_pid: pid,
                parent_pid: 0,
                process_image: image_opt.unwrap_or_default(),
                in_agent_lineage,
                target: format!("etw://{kind:?}/{event_id}"),
                session_id: shared.session_id.clone(),
                agent_name: String::new(),
                timestamp: filetime_to_timestamp(rec.EventHeader.TimeStamp),
            });
        }
    }));
}

fn encode_utf16_nul(value: &str) -> Result<Vec<u16>, WindowsSensorError> {
    if value.trim().is_empty() || value.chars().any(|c| c == '\0') {
        return Err(WindowsSensorError::Etw(
            "ETW session name must be non-empty and NUL-free".to_string(),
        ));
    }
    let mut out: Vec<u16> = value.encode_utf16().collect();
    out.push(0);
    Ok(out)
}

const fn session_guid() -> ParsedGuid {
    ParsedGuid {
        data1: 0x6772_6472,
        data2: 0x5730,
        data3: 0x4554,
        data4: *b"GRDR_ETW",
    }
}

const fn to_win_guid(g: ParsedGuid) -> windows_sys::core::GUID {
    windows_sys::core::GUID {
        data1: g.data1,
        data2: g.data2,
        data3: g.data3,
        data4: g.data4,
    }
}

const fn from_win_guid(g: windows_sys::core::GUID) -> ParsedGuid {
    ParsedGuid {
        data1: g.data1,
        data2: g.data2,
        data3: g.data3,
        data4: g.data4,
    }
}
