//! Child processes with captured output and a deadline. On a deadline the child is killed and the
//! output read so far is kept; after an exit the pipes are read for at most the drain grace. Either
//! way grandchildren that still hold the pipes do not delay the return.

use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::limits::Limits;

const CARGO: &str = "cargo";
const QUOTES: &[char] = &['"', '\''];

#[derive(Debug)]
pub enum Finished {
    Exited {
        code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    TimedOut {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

#[derive(Debug)]
pub struct Ran {
    pub finished: Finished,
    pub duration: Duration,
}

type Buffer = Arc<Mutex<Vec<u8>>>;

impl Ran {
    pub fn success(&self) -> bool {
        matches!(self.finished, Finished::Exited { code: Some(0), .. })
    }

    pub fn stdout(&self) -> String {
        match &self.finished {
            Finished::Exited { stdout, .. } | Finished::TimedOut { stdout, .. } => {
                String::from_utf8_lossy(stdout).into_owned()
            }
        }
    }

    pub fn stderr(&self) -> String {
        match &self.finished {
            Finished::Exited { stderr, .. } | Finished::TimedOut { stderr, .. } => {
                String::from_utf8_lossy(stderr).into_owned()
            }
        }
    }

    /// `exit 1`, `killed by signal`, or `timed out after 30 s`.
    pub fn describe(&self) -> String {
        match &self.finished {
            Finished::Exited {
                code: Some(code), ..
            } => format!("exit {code}"),
            Finished::Exited { code: None, .. } => "killed by signal".to_owned(),
            Finished::TimedOut { .. } => format!("timed out after {} s", self.duration.as_secs()),
        }
    }
}

/// Runs `command` with `input` on stdin (or no stdin at all), capturing stdout and stderr.
pub fn run(command: &mut Command, input: Option<&[u8]>, timeout: Duration) -> io::Result<Ran> {
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let limits = &Limits::built_with().map_err(io::Error::other)?.kit.process;
    let poll = limits.poll();
    let grace = limits.drain_grace();
    let mut child = command.spawn()?;
    // On Windows std starts one child at a time, so a spawn can wait behind other threads' spawns;
    // the deadline and the duration count only the child's own time.
    let started = Instant::now();
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        let bytes = bytes.to_vec();
        thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }
    let (stdout, stdout_reader) = drain(child.stdout.take());
    let (stderr, stderr_reader) = drain(child.stderr.take());
    let finished = match wait(&mut child, started, timeout, poll)? {
        Some(status) => {
            wait_for_eof(&[&stdout_reader, &stderr_reader], grace, poll);
            Finished::Exited {
                code: status.code(),
                stdout: collect(&stdout, stdout_reader),
                stderr: collect(&stderr, stderr_reader),
            }
        }
        None => Finished::TimedOut {
            stdout: snapshot(&stdout),
            stderr: snapshot(&stderr),
        },
    };
    Ok(Ran {
        finished,
        duration: started.elapsed(),
    })
}

/// `None` when the child was killed at the deadline.
fn wait(
    child: &mut Child,
    started: Instant,
    timeout: Duration,
    poll: Duration,
) -> io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        thread::sleep(poll);
    }
}

fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> (Buffer, Option<thread::JoinHandle<()>>) {
    let buffer: Buffer = Arc::default();
    let handle = pipe.map(|mut pipe| {
        let sink = Arc::clone(&buffer);
        thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            while let Ok(read) = pipe.read(&mut chunk) {
                if read == 0 {
                    break;
                }
                if let (Ok(mut out), Some(bytes)) = (sink.lock(), chunk.get(..read)) {
                    out.extend_from_slice(bytes);
                }
            }
        })
    });
    (buffer, handle)
}

/// Waits up to `grace` for the readers to reach the end of their pipes. A grandchild can hold
/// them open for good: on Windows, one its parent was killed while starting stays suspended.
fn wait_for_eof(readers: &[&Option<thread::JoinHandle<()>>], grace: Duration, poll: Duration) {
    let exited = Instant::now();
    let reading = || {
        readers
            .iter()
            .any(|reader| reader.as_ref().is_some_and(|reader| !reader.is_finished()))
    };
    while reading() && exited.elapsed() < grace {
        thread::sleep(poll);
    }
}

/// What the reader read; one still blocked on a pipe a grandchild holds is left running.
fn collect(buffer: &Buffer, handle: Option<thread::JoinHandle<()>>) -> Vec<u8> {
    if let Some(handle) = handle.filter(thread::JoinHandle::is_finished) {
        let _ = handle.join();
    }
    snapshot(buffer)
}

fn snapshot(buffer: &Buffer) -> Vec<u8> {
    buffer.lock().map(|out| out.clone()).unwrap_or_default()
}

/// The `cargo` to run. `CARGO` is set when cargo started this process; a hook started by Claude
/// Code has no such variable, so the rustup proxy in `CARGO_HOME` or `~/.cargo/bin` comes next,
/// then [`find_on_path`].
pub fn cargo() -> PathBuf {
    cargo_from(|name| std::env::var_os(name))
}

/// `program` itself, unless it is `cargo`, which [`cargo`] resolves.
pub fn program(program: &str) -> PathBuf {
    if program == CARGO {
        cargo()
    } else {
        PathBuf::from(program)
    }
}

fn cargo_from(lookup: impl Fn(&str) -> Option<OsString>) -> PathBuf {
    if let Some(cargo) = lookup("CARGO").filter(|value| !value.is_empty()) {
        return PathBuf::from(cargo);
    }
    let home = lookup("CARGO_HOME").map(PathBuf::from).or_else(|| {
        let user = lookup("USERPROFILE").or_else(|| lookup("HOME"))?;
        Some(PathBuf::from(user).join(".cargo"))
    });
    let proxy = home.map(|home| {
        home.join("bin")
            .join(format!("{CARGO}{}", std::env::consts::EXE_SUFFIX))
    });
    proxy
        .filter(|path| path.is_file())
        .or_else(|| {
            find_on_path(
                CARGO,
                lookup("PATH").as_deref(),
                lookup("PATHEXT").as_deref(),
            )
        })
        .unwrap_or_else(|| PathBuf::from(CARGO))
}

/// The first file named `name` in a directory of `path`. The platform's own search stops at a
/// malformed entry (on Windows an entry wrapped in quotes, or ending with one, hides every later
/// entry), so each entry is read alone: surrounding whitespace and quotes are stripped, and an
/// entry that is empty, relative or still holds a quote is skipped. `extensions` is `PATHEXT`,
/// whose suffixes are tried after the platform's executable suffix.
pub fn find_on_path(
    name: &str,
    path: Option<&OsStr>,
    extensions: Option<&OsStr>,
) -> Option<PathBuf> {
    let path = path?.to_string_lossy().into_owned();
    let separator = if cfg!(windows) { ';' } else { ':' };
    let mut suffixes = vec![std::env::consts::EXE_SUFFIX.to_owned()];
    if cfg!(windows) {
        let listed = extensions
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default();
        suffixes.extend(
            listed
                .split(';')
                .map(|suffix| suffix.trim().to_ascii_lowercase())
                .filter(|suffix| suffix.starts_with('.')),
        );
    }
    suffixes.push(String::new());
    path.split(separator)
        .filter_map(path_entry)
        .flat_map(|dir| {
            suffixes
                .iter()
                .map(move |suffix| dir.join(format!("{name}{suffix}")))
        })
        .find(|candidate| candidate.is_file())
}

fn path_entry(raw: &str) -> Option<PathBuf> {
    let entry = raw.trim().trim_matches(QUOTES).trim();
    let usable = !entry.is_empty() && !entry.contains(QUOTES) && Path::new(entry).is_absolute();
    usable.then(|| PathBuf::from(entry))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Holds the pipes it inherited until `stop` exists, a minute at most, then writes `gone`.
    const HOLDER_CMD: &str = "@echo off\r\nfor /l %%i in (1,1,60) do (\r\n  if exist stop goto gone\r\n  ping -n 2 127.0.0.1 >NUL\r\n)\r\n:gone\r\necho.>gone\r\n";
    const HOLDER_SH: &str = "i=0\nwhile [ ! -f stop ] && [ \"$i\" -lt 600 ]; do sleep 0.1; i=$((i+1)); done\n: > gone\n";

    fn shell(script: &str) -> Command {
        if cfg!(windows) {
            let mut command = Command::new("cmd");
            command.args(["/C", script]);
            command
        } else {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            command
        }
    }

    /// Whether `done` came true within 30 seconds.
    fn eventually(done: impl Fn() -> bool) -> bool {
        let started = Instant::now();
        while !done() {
            if started.elapsed() > Duration::from_secs(30) {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
        true
    }

    #[test]
    fn captures_output_and_exit_code() {
        let ran = run(
            &mut shell("echo hello && exit 3"),
            None,
            Duration::from_secs(20),
        )
        .unwrap();
        assert!(ran.stdout().contains("hello"));
        assert_eq!(ran.describe(), "exit 3");
        assert!(!ran.success());
    }

    /// The sleeper is the child itself: a shell killed while it starts its own child can leave
    /// that child suspended for good on Windows, holding the test runner's output pipe.
    #[test]
    fn deadline_kills_the_child() {
        let mut sleeper = if cfg!(windows) {
            let mut command = Command::new("ping");
            command.args(["-n", "3", "127.0.0.1"]);
            command
        } else {
            let mut command = Command::new("sleep");
            command.arg("2");
            command
        };
        let ran = run(&mut sleeper, None, Duration::from_millis(200)).unwrap();
        assert!(matches!(ran.finished, Finished::TimedOut { .. }));
        assert!(ran.duration < Duration::from_secs(2));
    }

    /// The shell exits at once and leaves a holder that keeps both pipes open until the run has
    /// returned, as a grandchild left suspended on Windows would keep them for good. The holder
    /// answers `stop` with `gone`, so it was still there when the run returned, and the test
    /// ends only after it has. The holder is named with `.\` because `cmd` does not look in the
    /// working directory when `NoDefaultCurrentDirectoryInExePath` is set.
    #[test]
    fn an_exit_returns_while_a_grandchild_still_holds_the_pipes() {
        let dir = std::env::temp_dir().join(format!("xtask-holder-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (holder, text, script) = if cfg!(windows) {
            (
                "holder.cmd",
                HOLDER_CMD,
                "start /b cmd /c .\\holder.cmd & echo early",
            )
        } else {
            ("holder.sh", HOLDER_SH, "sh holder.sh & echo early")
        };
        std::fs::write(dir.join(holder), text).unwrap();
        let mut command = shell(script);
        command.current_dir(&dir);
        let ran = run(&mut command, None, Duration::from_secs(60)).unwrap();
        let returned_first = !dir.join("gone").exists();
        std::fs::write(dir.join("stop"), "").unwrap();
        let answered = eventually(|| dir.join("gone").exists());
        let removed = eventually(|| std::fs::remove_dir_all(&dir).is_ok());
        assert!(answered, "the holder never answered stop");
        assert!(
            returned_first,
            "the run waited {:?} for the holder",
            ran.duration
        );
        assert!(removed, "{} is still there", dir.display());
        assert!(ran.success(), "{}", ran.describe());
        assert!(ran.stdout().contains("early"));
    }

    #[test]
    fn cargo_prefers_the_cargo_variable_then_the_rustup_proxy() {
        let from = |pairs: Vec<(&'static str, OsString)>| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            }
        };
        let set = from(vec![("CARGO", OsString::from("/toolchain/bin/cargo"))]);
        assert_eq!(cargo_from(set), PathBuf::from("/toolchain/bin/cargo"));
        let home = std::env::temp_dir().join(format!("xtask-cargo-home-{}", std::process::id()));
        let proxy = home
            .join("bin")
            .join(format!("cargo{}", std::env::consts::EXE_SUFFIX));
        std::fs::create_dir_all(proxy.parent().unwrap()).unwrap();
        std::fs::write(&proxy, "").unwrap();
        assert_eq!(
            cargo_from(from(vec![("CARGO_HOME", home.clone().into_os_string())])),
            proxy
        );
        assert_eq!(cargo_from(from(vec![])), PathBuf::from("cargo"));
        std::fs::remove_dir_all(home).unwrap();
        assert_eq!(program("git"), PathBuf::from("git"));
    }

    #[test]
    fn path_entries_with_stray_quotes_are_stripped_or_skipped() {
        let root = std::env::temp_dir().join(format!("xtask-find-path-{}", std::process::id()));
        let bin = root.join("tools bin");
        std::fs::create_dir_all(&bin).unwrap();
        let file = bin.join(format!("fake-tool{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&file, "").unwrap();
        let separator = if cfg!(windows) { ";" } else { ":" };
        let dir = bin.to_string_lossy();
        let entries = [
            format!("\"{}\"", root.join("missing").display()),
            format!("{}\"", root.join("broken").display()),
            "relative/dir".to_owned(),
            String::new(),
            format!("\"{dir}\""),
        ];
        let path = OsString::from(entries.join(separator));
        assert_eq!(
            find_on_path("fake-tool", Some(&path), None),
            Some(file.clone())
        );
        let trailing = OsString::from(format!("{}\"{separator}{dir}\"", root.display()));
        assert_eq!(find_on_path("fake-tool", Some(&trailing), None), Some(file));
        assert_eq!(find_on_path("absent-tool", Some(&path), None), None);
        assert_eq!(find_on_path("fake-tool", None, None), None);
        std::fs::remove_dir_all(root).unwrap();
    }
}
