//! A lock file kept fresh by a heartbeat thread while its holder lives: the dispatcher's
//! `.agent/state/dispatch.lock`, the machine-wide lock of a fable session and a printed session's
//! own. A lock whose file has not been touched for `[kit.lock] stale_beats` heartbeats belongs to
//! a holder that is gone, and an empty one to nobody: a holder empties the file as it lets go and
//! never removes it, so every taker locks the same file, and a living holder whose file someone
//! removed writes it again.

use std::fmt;
use std::fs::{self, File};
use std::io::{ErrorKind, Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};

use crate::config::limits::Limits;

#[derive(Debug)]
pub struct Lock {
    path: PathBuf,
    /// What this holder wrote, so letting go never empties a lock another holder took over.
    holder: String,
    released: Arc<AtomicBool>,
    /// Dropped with the lock, which ends the heartbeat thread's wait.
    _held: mpsc::Sender<()>,
}

/// A fresh holder has the lock.
#[derive(Debug)]
pub struct Busy(String);

impl Lock {
    /// Takes the lock at `path`, refreshed every `beat`; fails with [`Busy`], saying `busy`, while
    /// a fresh holder has it. The holder is read and replaced under an OS lock on the file, so two
    /// takers never both find it free, stale or released.
    pub fn take(path: PathBuf, beat: Duration, busy: &str) -> Result<Lock> {
        let stale_beats = Limits::built_with()?.kit.lock.stale_beats;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.lock()
            .with_context(|| format!("locking {}", path.display()))?;
        let mut holder = String::new();
        file.read_to_string(&mut holder)
            .with_context(|| format!("reading {}", path.display()))?;
        let fresh = within(
            file.metadata().and_then(|meta| meta.modified()),
            beat.saturating_mul(stale_beats),
        );
        if !holder.trim().is_empty() && fresh {
            return Err(Busy(format!("{busy} ({}: {})", path.display(), holder.trim())).into());
        }
        let pid_line = holder_line(std::process::id());
        file.set_len(0)
            .and_then(|()| file.rewind())
            .and_then(|()| file.write_all(pid_line.as_bytes()))
            .with_context(|| format!("writing {}", path.display()))?;
        let heartbeat = path.clone();
        let written = pid_line.clone();
        let released = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&released);
        let (held, let_go) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            // The wait ends when the lock drops its sender, so no heartbeat thread outlives its
            // lock by a beat; a process that takes many locks would run out of threads.
            while let Err(RecvTimeoutError::Timeout) = let_go.recv_timeout(beat) {
                if stop.load(Ordering::SeqCst) || !beat_once(&heartbeat, &written, &stop) {
                    return;
                }
            }
        });
        Ok(Lock {
            path,
            holder: pid_line,
            released,
            _held: held,
        })
    }

    /// Whether the lock at `path` names a holder that refreshed it within the last `stale_beats`
    /// beats. Without the limits, or while a taker's OS lock keeps the file from being read, the
    /// lock counts as held, so a second holder never starts beside the first.
    pub fn is_held(path: &Path, beat: Duration) -> bool {
        let named = match fs::read_to_string(path) {
            Ok(holder) => !holder.trim().is_empty(),
            Err(error) => error.kind() != ErrorKind::NotFound,
        };
        match Limits::built_with() {
            Ok(limits) => {
                let window = beat.saturating_mul(limits.kit.lock.stale_beats);
                named && within(fs::metadata(path).and_then(|meta| meta.modified()), window)
            }
            Err(_) => true,
        }
    }

    /// Empties the lock at `path` while it names the process `pid`, which was killed and so never
    /// let go of it; a lock another holder took since stays theirs.
    pub fn release_killed(path: &Path, pid: u32) -> std::io::Result<()> {
        release(path, &holder_line(pid))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        self.released.store(true, Ordering::SeqCst);
        let _ = release(&self.path, &self.holder);
    }
}

impl fmt::Display for Busy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Busy {}

fn holder_line(pid: u32) -> String {
    format!("pid {pid}\n")
}

/// One heartbeat of the holder that wrote `holder`; false, which stops the heartbeat, once another
/// holder's line fills a file this holder found removed. A beat that fails otherwise is tried
/// again on the next: while a handle keeps a file Windows is deleting, every open of it is refused
/// as access denied.
fn beat_once(path: &Path, holder: &str, released: &AtomicBool) -> bool {
    match touch(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            write_again(path, holder, released).unwrap_or(true)
        }
        _ => true,
    }
}

/// Moves the modification time and writes no bytes: on Windows a taker's OS lock blocks writes to
/// the file.
fn touch(path: &Path) -> std::io::Result<()> {
    File::options()
        .write(true)
        .open(path)?
        .set_modified(SystemTime::now())
}

/// Makes the removed lock file again with `holder` under the OS lock; false when another holder's
/// line is there by then. `released` is read under that lock, which letting go takes before it
/// empties the file, so a holder that let go never names itself again.
fn write_again(path: &Path, holder: &str, released: &AtomicBool) -> std::io::Result<bool> {
    let mut file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    file.lock()?;
    let mut named = String::new();
    file.read_to_string(&mut named)?;
    if !named.trim().is_empty() {
        return Ok(false);
    }
    if !released.load(Ordering::SeqCst) {
        file.set_len(0)?;
        file.rewind()?;
        file.write_all(holder.as_bytes())?;
    }
    Ok(true)
}

/// Empties the lock file under the OS lock while it still names `holder`.
fn release(path: &Path, holder: &str) -> std::io::Result<()> {
    let mut file = File::options().read(true).write(true).open(path)?;
    file.lock()?;
    let mut named = String::new();
    file.read_to_string(&mut named)?;
    if named == holder {
        file.set_len(0)?;
    }
    Ok(())
}

fn within(modified: std::io::Result<SystemTime>, window: Duration) -> bool {
    modified.is_ok_and(|modified| {
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default();
        age < window
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Win32's flag for a handle whose close deletes the file.
    #[cfg(windows)]
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;

    #[test]
    fn a_fresh_lock_refuses_a_second_holder_and_frees_on_drop() {
        let path = std::env::temp_dir().join(format!("xtask-lock-{}.lock", std::process::id()));
        let _ = fs::remove_file(&path);
        let beat = Duration::from_secs(30);
        let first = Lock::take(path.clone(), beat, "busy").unwrap();
        assert!(Lock::is_held(&path, beat));
        let second = Lock::take(path.clone(), beat, "busy");
        assert!(second.unwrap_err().to_string().starts_with("busy"));
        drop(first);
        assert!(!Lock::is_held(&path, beat));
        let third = Lock::take(path.clone(), beat, "busy").unwrap();
        assert!(Lock::is_held(&path, beat));
        drop(third);
        let _ = fs::remove_file(&path);
    }

    /// Even rounds start on a free lock, odd ones on a lock whose holder is gone.
    #[test]
    fn two_takers_racing_for_one_lock_never_both_hold_it() {
        use std::sync::Barrier;
        let beat = Duration::from_secs(30);
        let stale = SystemTime::now() - beat * 10;
        for round in 0..40 {
            let path = std::env::temp_dir().join(format!(
                "xtask-lock-race-{}-{round}.lock",
                std::process::id()
            ));
            let _ = fs::remove_file(&path);
            if round % 2 == 1 {
                fs::write(&path, "pid 0\n").unwrap();
                File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(stale)
                    .unwrap();
            }
            let barrier = Arc::new(Barrier::new(2));
            let takers: Vec<_> = (0..2)
                .map(|_| {
                    let path = path.clone();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        Lock::take(path, beat, "busy").ok()
                    })
                })
                .collect();
            let held: Vec<Lock> = takers
                .into_iter()
                .filter_map(|taker| taker.join().unwrap())
                .collect();
            assert_eq!(held.len(), 1, "round {round}");
            drop(held);
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn a_taker_racing_the_release_and_a_later_one_never_both_hold_the_lock() {
        use std::sync::Barrier;
        let beat = Duration::from_secs(30);
        for round in 0..2000 {
            let path = std::env::temp_dir().join(format!(
                "xtask-lock-release-{}-{round}.lock",
                std::process::id()
            ));
            let _ = fs::remove_file(&path);
            let holder = Lock::take(path.clone(), beat, "busy").unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let racing = {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    Lock::take(path, beat, "busy").ok()
                })
            };
            barrier.wait();
            drop(holder);
            let first = racing.join().unwrap();
            let second = Lock::take(path.clone(), beat, "busy").ok();
            assert!(first.is_none() || second.is_none(), "round {round}");
            drop((first, second));
            let _ = fs::remove_file(&path);
        }
    }

    #[test]
    fn a_holder_that_was_taken_over_leaves_the_new_holders_lock_alone() {
        let path =
            std::env::temp_dir().join(format!("xtask-lock-over-{}.lock", std::process::id()));
        let _ = fs::remove_file(&path);
        let beat = Duration::from_secs(30);
        let first = Lock::take(path.clone(), beat, "busy").unwrap();
        fs::write(&path, "pid 0\n").unwrap();
        drop(first);
        assert_eq!(fs::read_to_string(&path).unwrap(), "pid 0\n");
        assert!(Lock::is_held(&path, beat));
        let _ = fs::remove_file(&path);
    }

    /// Waits for the holder to write `line` to `path` again. It reads far more often than the
    /// holder beats, so a take right after it finds the lock fresh even on a loaded machine.
    fn wait_for_line(path: &Path, line: &str) {
        let started = std::time::Instant::now();
        while fs::read_to_string(path).unwrap_or_default() != line {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "the holder never wrote its lock again"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Someone deletes a stale-looking `dispatch.lock`; no second holder starts beside the first.
    #[test]
    fn a_removed_lock_file_is_written_again_while_its_holder_lives() {
        let path =
            std::env::temp_dir().join(format!("xtask-lock-removed-{}.lock", std::process::id()));
        let _ = fs::remove_file(&path);
        let beat = Duration::from_secs(1);
        let holder = Lock::take(path.clone(), beat, "busy").unwrap();
        let line = fs::read_to_string(&path).unwrap();
        fs::remove_file(&path).unwrap();
        wait_for_line(&path, &line);
        assert!(Lock::take(path.clone(), beat, "busy").is_err());
        drop(holder);
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
        let _ = fs::remove_file(&path);
    }

    /// While some handle keeps a file Windows is deleting, every open of it is refused as access
    /// denied.
    #[cfg(windows)]
    #[test]
    fn a_heartbeat_refused_by_a_pending_removal_writes_the_lock_once_it_is_gone() {
        use std::os::windows::fs::OpenOptionsExt as _;
        let path =
            std::env::temp_dir().join(format!("xtask-lock-pending-{}.lock", std::process::id()));
        let _ = fs::remove_file(&path);
        let beat = Duration::from_secs(1);
        let holder = Lock::take(path.clone(), beat, "busy").unwrap();
        let line = fs::read_to_string(&path).unwrap();
        let removing = File::options()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_DELETE_ON_CLOSE)
            .open(&path)
            .unwrap();
        let keeping = File::open(&path).unwrap();
        drop(removing);
        let refused = File::options().write(true).open(&path).unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::PermissionDenied);
        std::thread::sleep(beat * 3);
        drop(keeping);
        wait_for_line(&path, &line);
        drop(holder);
        let _ = fs::remove_file(&path);
    }

    /// A process that takes many locks, as the release race above does, keeps no waiting thread
    /// for a lock it let go of.
    #[test]
    fn a_heartbeat_ends_when_its_lock_is_dropped() {
        let path =
            std::env::temp_dir().join(format!("xtask-lock-ended-{}.lock", std::process::id()));
        let _ = fs::remove_file(&path);
        let lock = Lock::take(path.clone(), Duration::from_secs(60), "busy").unwrap();
        let released = Arc::clone(&lock.released);
        drop(lock);
        let started = std::time::Instant::now();
        // The heartbeat thread holds the only other clone.
        while Arc::strong_count(&released) > 1 {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the heartbeat still waits"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn a_killed_holders_lock_is_emptied_and_a_newer_holders_is_not() {
        let path =
            std::env::temp_dir().join(format!("xtask-lock-killed-{}.lock", std::process::id()));
        let _ = fs::remove_file(&path);
        let beat = Duration::from_secs(30);
        let held = Lock::take(path.clone(), beat, "busy").unwrap();
        Lock::release_killed(&path, std::process::id().wrapping_add(1)).unwrap();
        assert!(Lock::is_held(&path, beat), "another process's line stays");
        Lock::release_killed(&path, std::process::id()).unwrap();
        assert!(!Lock::is_held(&path, beat));
        drop(held);
        let _ = fs::remove_file(&path);
    }
}
