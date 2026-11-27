// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::{BTreeSet, VecDeque};
use std::ffi::{CStr, CString, c_char, c_void};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;

use crate::seatbelt::canonicalize_macos_path;

const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const K_CF_RUN_LOOP_ENTRY: usize = 1 << 0;
const K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW: u64 = 0xFFFF_FFFF_FFFF_FFFF;
const K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER: u32 = 0x0000_0002;
const K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS: u32 = 0x0000_0010;
const FSEVENTS_LATENCY_SECS: f64 = 0.05;
const MAX_QUEUED_EVENTS: usize = 8_192;
const MAX_CALLBACK_BATCH: usize = 4_096;

type FSEventStreamCallback = unsafe extern "C" fn(
    stream_ref: *const c_void,
    client_call_back_info: *mut c_void,
    num_events: usize,
    event_paths: *mut c_void,
    event_flags: *const u32,
    event_ids: *const u64,
);

type CFRunLoopObserverCallBack = unsafe extern "C" fn(*const c_void, usize, *mut c_void);

#[repr(C)]
struct FSEventStreamContext {
    version: isize,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<unsafe extern "C" fn(*const c_void)>,
    copy_description: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
}

#[repr(C)]
struct CFRunLoopObserverContext {
    version: isize,
    info: *mut c_void,
    retain: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
    release: Option<unsafe extern "C" fn(*const c_void)>,
    copy_description: Option<unsafe extern "C" fn(*const c_void) -> *const c_void>,
}

struct SendRunLoop(*const c_void);

struct EntrySignalState {
    ready_tx: Mutex<Option<mpsc::Sender<Option<SendRunLoop>>>>,
    run_loop: *const c_void,
}

#[derive(Debug, Default)]
struct FseventsQueue {
    target_prefixes: Vec<PathBuf>,
    paths: VecDeque<PathBuf>,
    dropped_events: u64,
}

#[derive(Debug)]
pub(crate) struct DarwinFseventsStream {
    queue: Arc<Mutex<FseventsQueue>>,
    run_loop: Option<SendRunLoop>,
    worker: Option<JoinHandle<()>>,
}

#[link(name = "CoreFoundation", kind = "framework")]
#[allow(
    unsafe_code,
    reason = "Apple CoreFoundation bindings for FSEvents run loop and kCFRunLoopEntry observer."
)]
// SAFETY: Standard Apple CoreFoundation C ABI declarations matching CFBase/CFString/CFArray/CFRunLoop.
unsafe extern "C" {
    static kCFRunLoopDefaultMode: *const c_void;
    static kCFTypeArrayCallBacks: u8;
    fn CFRetain(cf: *const c_void) -> *const c_void;
    fn CFRelease(cf: *const c_void);
    fn CFStringCreateWithCString(
        alloc: *const c_void,
        c_str: *const c_char,
        encoding: u32,
    ) -> *const c_void;
    fn CFArrayCreateMutable(
        alloc: *const c_void,
        capacity: isize,
        call_backs: *const c_void,
    ) -> *mut c_void;
    fn CFArrayAppendValue(the_array: *mut c_void, value: *const c_void);
    fn CFRunLoopGetCurrent() -> *const c_void;
    fn CFRunLoopObserverCreate(
        allocator: *const c_void,
        activities: usize,
        repeats: u8,
        order: isize,
        callout: CFRunLoopObserverCallBack,
        context: *mut CFRunLoopObserverContext,
    ) -> *const c_void;
    fn CFRunLoopAddObserver(rl: *const c_void, observer: *const c_void, mode: *const c_void);
    fn CFRunLoopRemoveObserver(rl: *const c_void, observer: *const c_void, mode: *const c_void);
    fn CFRunLoopRun();
    fn CFRunLoopStop(rl: *const c_void);
}

#[link(name = "CoreServices", kind = "framework")]
#[allow(unsafe_code, reason = "Apple CoreServices FSEvents C API bindings.")]
// SAFETY: Standard Apple CoreServices FSEvents declarations matching <CoreServices/CoreServices.h>.
unsafe extern "C" {
    fn FSEventStreamCreate(
        allocator: *const c_void,
        callback: FSEventStreamCallback,
        context: *mut FSEventStreamContext,
        paths_to_watch: *const c_void,
        since_when: u64,
        latency: f64,
        flags: u32,
    ) -> *const c_void;
    fn FSEventStreamScheduleWithRunLoop(
        stream_ref: *const c_void,
        run_loop: *const c_void,
        run_loop_mode: *const c_void,
    );
    fn FSEventStreamStart(stream_ref: *const c_void) -> u8;
    fn FSEventStreamStop(stream_ref: *const c_void);
    fn FSEventStreamInvalidate(stream_ref: *const c_void);
    fn FSEventStreamRelease(stream_ref: *const c_void);
}

#[allow(
    unsafe_code,
    reason = "Apple CoreFoundation documents CFRunLoopStop and CFRetain/CFRelease as thread-safe."
)]
// SAFETY: SendRunLoop wraps a retained CFRunLoopRef stopped cross-thread via thread-safe CFRunLoopStop.
unsafe impl Send for SendRunLoop {}

#[allow(
    unsafe_code,
    reason = "EntrySignalState runs on CoreFoundation worker and Drop sync channel."
)]
// SAFETY: EntrySignalState wraps Send Sender and a retained CFRunLoopRef stopped only after loop entry.
unsafe impl Send for EntrySignalState {}

#[allow(
    unsafe_code,
    reason = "Mutex guards shared ready_tx access across observer and worker setup."
)]
// SAFETY: Inner Sender is guarded by Mutex; run_loop pointer is immutable CFRunLoopRef.
unsafe impl Sync for EntrySignalState {}

impl std::fmt::Debug for SendRunLoop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SendRunLoop(..)")
    }
}

impl DarwinFseventsStream {
    pub(crate) fn start(roots: &[PathBuf]) -> Option<Self> {
        let (watch_ancestors, target_prefixes) = resolve_watch_ancestors(roots);
        if watch_ancestors.is_empty() {
            return None;
        }
        let queue = Arc::new(Mutex::new(FseventsQueue {
            target_prefixes,
            paths: VecDeque::new(),
            dropped_events: 0,
        }));
        let worker_queue = Arc::clone(&queue);
        let (tx, rx) = mpsc::channel::<Option<SendRunLoop>>();

        let handle = std::thread::Builder::new()
            .name("grdr-fsevents".to_string())
            .spawn(move || run_fsevents_loop(watch_ancestors, worker_queue, tx))
            .ok()?;

        match rx.recv() {
            Ok(Some(rl)) => Some(Self {
                queue,
                run_loop: Some(rl),
                worker: Some(handle),
            }),
            _ => {
                let _ = handle.join();
                None
            }
        }
    }

    pub(crate) fn drain_paths(&self) -> Vec<PathBuf> {
        let Ok(mut guard) = self.queue.lock() else {
            return Vec::new();
        };
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        while let Some(path) = guard.paths.pop_front() {
            if seen.insert(path.clone()) {
                out.push(path);
            }
        }
        out
    }
}

impl Drop for DarwinFseventsStream {
    fn drop(&mut self) {
        if let Some(rl) = self.run_loop.take()
            && !rl.0.is_null()
        {
            #[allow(
                unsafe_code,
                reason = "Stop FSEvents worker CFRunLoop and release retained CFRunLoopRef."
            )]
            // SAFETY: rl.0 was emitted by kCFRunLoopEntry inside CFRunLoopRun and retained for Drop.
            let () = unsafe {
                CFRunLoopStop(rl.0);
                CFRelease(rl.0);
            };
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn resolve_watch_ancestors(roots: &[PathBuf]) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut ancestors = BTreeSet::new();
    let mut targets = Vec::new();
    for raw_root in roots {
        let canon = PathBuf::from(canonicalize_macos_path(&raw_root.to_string_lossy()));
        targets.push(canon.clone());
        for anc in canon.ancestors() {
            if anc.components().count() < 3 {
                break;
            }
            if let Ok(meta) = std::fs::symlink_metadata(anc)
                && !meta.file_type().is_symlink()
                && meta.file_type().is_dir()
            {
                ancestors.insert(anc.to_path_buf());
                break;
            }
        }
    }
    (ancestors.into_iter().collect(), targets)
}

fn run_fsevents_loop(
    roots: Vec<PathBuf>,
    queue: Arc<Mutex<FseventsQueue>>,
    ready_tx: mpsc::Sender<Option<SendRunLoop>>,
) {
    let c_strings: Vec<CString> = roots
        .iter()
        .filter_map(|r| CString::new(r.to_string_lossy().as_bytes()).ok())
        .collect();
    if c_strings.is_empty() {
        let _ = ready_tx.send(None);
        return;
    }

    let info_raw = Arc::into_raw(Arc::clone(&queue)).cast::<c_void>();
    let mut ctx = FSEventStreamContext {
        version: 0,
        info: info_raw,
        retain: Some(arc_retain::<Mutex<FseventsQueue>>),
        release: Some(arc_release::<Mutex<FseventsQueue>>),
        copy_description: None,
    };

    #[allow(
        unsafe_code,
        reason = "Create CoreServices FSEventStream over ancestor directories and attach kCFRunLoopEntry observer."
    )]
    // SAFETY: CFArray, stream, observer, and run-loop refs stay scoped cleanly and release symmetrically on all exit paths.
    unsafe {
        let cf_paths = build_cf_path_array(&c_strings);
        if cf_paths.is_null() {
            drop(Arc::from_raw(info_raw.cast::<Mutex<FseventsQueue>>()));
            let _ = ready_tx.send(None);
            return;
        }
        let stream = FSEventStreamCreate(
            null(),
            fsevents_callback,
            &mut ctx,
            cf_paths.cast::<c_void>(),
            K_FS_EVENT_STREAM_EVENT_ID_SINCE_NOW,
            FSEVENTS_LATENCY_SECS,
            K_FS_EVENT_STREAM_CREATE_FLAG_NO_DEFER | K_FS_EVENT_STREAM_CREATE_FLAG_FILE_EVENTS,
        );
        CFRelease(cf_paths.cast::<c_void>());
        drop(Arc::from_raw(info_raw.cast::<Mutex<FseventsQueue>>()));
        if stream.is_null() {
            let _ = ready_tx.send(None);
            return;
        }

        let rl = CFRunLoopGetCurrent();
        FSEventStreamScheduleWithRunLoop(stream, rl, kCFRunLoopDefaultMode);
        if FSEventStreamStart(stream) == 0 {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            let _ = ready_tx.send(None);
            return;
        }

        let rl_retained = CFRetain(rl);
        let entry_state = Arc::new(EntrySignalState {
            ready_tx: Mutex::new(Some(ready_tx)),
            run_loop: rl_retained,
        });
        let obs_raw = Arc::into_raw(Arc::clone(&entry_state)).cast::<c_void>();
        let mut obs_ctx = CFRunLoopObserverContext {
            version: 0,
            info: obs_raw,
            retain: Some(arc_retain::<EntrySignalState>),
            release: Some(arc_release::<EntrySignalState>),
            copy_description: None,
        };
        let observer = if rl_retained.is_null() {
            null()
        } else {
            CFRunLoopObserverCreate(
                null(),
                K_CF_RUN_LOOP_ENTRY,
                0,
                0,
                runloop_entry_callback,
                &mut obs_ctx,
            )
        };
        drop(Arc::from_raw(obs_raw.cast::<EntrySignalState>()));
        if observer.is_null() {
            fail_entry_signal(&entry_state, rl_retained);
            FSEventStreamStop(stream);
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            return;
        }

        CFRunLoopAddObserver(rl, observer, kCFRunLoopDefaultMode);
        CFRunLoopRun();
        CFRunLoopRemoveObserver(rl, observer, kCFRunLoopDefaultMode);
        CFRelease(observer);
        fail_entry_signal(&entry_state, rl_retained);
        FSEventStreamStop(stream);
        FSEventStreamInvalidate(stream);
        FSEventStreamRelease(stream);
    }
}

#[allow(
    unsafe_code,
    reason = "Build CFMutableArray of UTF-8 CFStringRef paths."
)]
// SAFETY: Returned CFMutableArrayRef must be released by caller via CFRelease if non-null.
unsafe fn build_cf_path_array(c_strings: &[CString]) -> *mut c_void {
    #[allow(unsafe_code, reason = "Call CoreFoundation array/string constructors.")]
    // SAFETY: c_strings elements are NUL-terminated UTF-8 CStrings.
    unsafe {
        let arr = CFArrayCreateMutable(
            null(),
            isize::try_from(c_strings.len()).unwrap_or(0),
            (&raw const kCFTypeArrayCallBacks).cast::<c_void>(),
        );
        if arr.is_null() {
            return null_mut();
        }
        for cs in c_strings {
            let s = CFStringCreateWithCString(null(), cs.as_ptr(), CF_STRING_ENCODING_UTF8);
            if !s.is_null() {
                CFArrayAppendValue(arr, s);
                CFRelease(s);
            }
        }
        arr
    }
}

#[allow(
    unsafe_code,
    reason = "Signal error and release retained CFRunLoopRef when entry observer did not deliver ownership."
)]
// SAFETY: rl_retained is either null or owned CFRunLoopRef not yet sent to Drop.
unsafe fn fail_entry_signal(entry_state: &EntrySignalState, rl_retained: *const c_void) {
    if let Ok(mut tx_slot) = entry_state.ready_tx.lock()
        && let Some(tx) = tx_slot.take()
    {
        if !rl_retained.is_null() {
            #[allow(unsafe_code, reason = "Release unsent retained CFRunLoopRef.")]
            // SAFETY: rl_retained was never passed to SendRunLoop/Drop.
            unsafe {
                CFRelease(rl_retained);
            }
        }
        let _ = tx.send(None);
    }
}

#[allow(
    unsafe_code,
    reason = "CoreFoundation run-loop entry observer firing strictly after CFRunLoopRun starts."
)]
// SAFETY: Invoked by CoreFoundation once CFRunLoopRun has entered its event loop; prevents pre-entry CFRunLoopStop deadlock.
unsafe extern "C" fn runloop_entry_callback(
    _observer: *const c_void,
    _activity: usize,
    info: *mut c_void,
) {
    if info.is_null() {
        return;
    }
    #[allow(
        unsafe_code,
        reason = "Borrow EntrySignalState inside observer callback."
    )]
    // SAFETY: Observer context retains EntrySignalState Arc during callback execution.
    let state = unsafe { &*info.cast::<EntrySignalState>() };
    if let Ok(mut tx_slot) = state.ready_tx.lock()
        && let Some(tx) = tx_slot.take()
        && tx.send(Some(SendRunLoop(state.run_loop))).is_err()
    {
        #[allow(
            unsafe_code,
            reason = "Stop and release CFRunLoopRef if receiver disappeared."
        )]
        // SAFETY: state.run_loop was retained for Drop and unconsumed by channel.
        unsafe {
            CFRunLoopStop(state.run_loop);
            CFRelease(state.run_loop);
        }
    }
}

#[allow(unsafe_code, reason = "Generic CoreFoundation Arc retain callback.")]
// SAFETY: info originates from Arc::into_raw::<T>.
unsafe extern "C" fn arc_retain<T>(info: *const c_void) -> *const c_void {
    if !info.is_null() {
        #[allow(
            unsafe_code,
            reason = "Increment Arc strong count for CoreFoundation context."
        )]
        // SAFETY: Valid non-null Arc raw pointer.
        unsafe {
            Arc::increment_strong_count(info.cast::<T>());
        }
    }
    info
}

#[allow(unsafe_code, reason = "Generic CoreFoundation Arc release callback.")]
// SAFETY: Matches arc_retain::<T> on valid Arc raw pointer.
unsafe extern "C" fn arc_release<T>(info: *const c_void) {
    if !info.is_null() {
        #[allow(
            unsafe_code,
            reason = "Decrement Arc strong count for CoreFoundation context."
        )]
        // SAFETY: Matches prior Arc::into_raw / arc_retain.
        unsafe {
            Arc::decrement_strong_count(info.cast::<T>());
        }
    }
}

#[allow(
    unsafe_code,
    reason = "CoreServices FSEvents callback receiving C-string array of changed paths."
)]
// SAFETY: CoreServices invokes fsevents_callback with valid event_paths array of num_events pointers.
unsafe extern "C" fn fsevents_callback(
    _stream_ref: *const c_void,
    client_call_back_info: *mut c_void,
    num_events: usize,
    event_paths: *mut c_void,
    _event_flags: *const u32,
    _event_ids: *const u64,
) {
    if client_call_back_info.is_null() || event_paths.is_null() || num_events == 0 {
        return;
    }
    let count = num_events.min(MAX_CALLBACK_BATCH);
    #[allow(
        unsafe_code,
        reason = "Borrow FseventsQueue Arc and C-string path slice."
    )]
    // SAFETY: CoreServices retains context and supplies count non-null C-strings during callback.
    let (paths, queue) = unsafe {
        let pt_slice = std::slice::from_raw_parts(event_paths.cast::<*const c_char>(), count);
        let collected: Vec<PathBuf> = pt_slice
            .iter()
            .filter(|&&p| !p.is_null())
            .filter_map(|&p| {
                let s = CStr::from_ptr(p).to_string_lossy();
                (!s.is_empty()).then(|| PathBuf::from(canonicalize_macos_path(s.as_ref())))
            })
            .collect();
        (
            collected,
            &*client_call_back_info.cast::<Mutex<FseventsQueue>>(),
        )
    };
    if let Ok(mut guard) = queue.lock() {
        let prefixes = guard.target_prefixes.clone();
        for p in paths {
            let relevant = prefixes.is_empty()
                || prefixes
                    .iter()
                    .any(|pref| p.starts_with(pref) || pref.starts_with(&p));
            if !relevant {
                continue;
            }
            if guard.paths.len() >= MAX_QUEUED_EVENTS {
                guard.paths.pop_front();
                guard.dropped_events = guard.dropped_events.saturating_add(1);
            }
            guard.paths.push_back(p);
        }
    }
}
