//! A lock file kept fresh by a heartbeat thread while its holder lives: the dispatcher's
//! `.agent/state/dispatch.lock` and the machine-wide lock of a fable session. A lock whose file
//! has not been touched for `[kit.lock] stale_beats` heartbeats belongs to a holder that is gone.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

use crate::config::limits::Limits;

#[derive(Debug)]
pub struct Lock {
    path: PathBuf,
    released: Arc<AtomicBool>,
}

impl Lock {
    /// Takes the lock at `path`, refreshed every `beat`; fails with `busy` while a fresh holder
    /// has it.
    pub fn take(path: PathBuf, beat: Duration, busy: &str) -> Result<Lock> {
        let stale_beats = Limits::built_with()?.kit.lock.stale_beats;
        if refreshed_within(&path, beat.saturating_mul(stale_beats)) {
            let holder = fs::read_to_string(&path).unwrap_or_default();
            bail!("{busy} ({}: {})", path.display(), holder.trim());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let pid_line = format!("pid {}\n", std::process::id());
        fs::write(&path, &pid_line).with_context(|| format!("writing {}", path.display()))?;
        let heartbeat = path.clone();
        let released = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&released);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(beat);
                if stop.load(Ordering::SeqCst) || fs::write(&heartbeat, &pid_line).is_err() {
                    return;
                }
            }
        });
        Ok(Lock { path, released })
    }

    /// Whether a holder refreshed the lock at `path` within the last `stale_beats` beats. Without
    /// the limits the lock counts as held, so a second holder never starts beside the first.
    pub fn is_held(path: &Path, beat: Duration) -> bool {
        match Limits::built_with() {
            Ok(limits) => refreshed_within(path, beat.saturating_mul(limits.kit.lock.stale_beats)),
            Err(_) => true,
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        self.released.store(true, Ordering::SeqCst);
        let _ = fs::remove_file(&self.path);
    }
}

fn refreshed_within(path: &Path, window: Duration) -> bool {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .is_ok_and(|modified| {
            let age = SystemTime::now()
                .duration_since(modified)
                .unwrap_or_default();
            age < window
        })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
