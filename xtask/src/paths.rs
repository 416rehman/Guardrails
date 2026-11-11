//! Path normalisation: every path a hook or gate sees becomes a forward-slash path relative to the
//! repository root before any match, because a forward-slash glob never matches a Windows path
//! (team/03 section 1).

use std::fmt;
use std::path::Path;

/// A path relative to the repository root: forward slashes, no `.` or `..` segments, no leading
/// slash. The empty path is the root itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoPath(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    Inside(RepoPath),
    Outside(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Absolute {
    prefix: String,
    segments: Vec<String>,
}

enum Parsed {
    Absolute(Absolute),
    Relative(Vec<String>),
}

impl RepoPath {
    /// Accepts an already relative path in either slash style; refuses one that leaves the root.
    pub fn new(relative: &str) -> Option<RepoPath> {
        if relative.starts_with(['/', '\\']) || drive(relative).is_some() {
            return None;
        }
        let mut segments: Vec<&str> = Vec::new();
        for segment in relative.split(['/', '\\']) {
            match segment {
                "" | "." => {}
                ".." => return None,
                other => segments.push(other),
            }
        }
        Some(RepoPath(segments.join("/")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn extension(&self) -> Option<&str> {
        let name = self.0.rsplit('/').next()?;
        let (stem, extension) = name.rsplit_once('.')?;
        (!stem.is_empty()).then_some(extension)
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Absolute {
    fn on_drive(letter: char, rest: &str) -> Absolute {
        Absolute {
            prefix: format!("{}:", letter.to_ascii_lowercase()),
            segments: split(rest),
        }
    }

    fn push(&mut self, segments: Vec<String>) {
        for segment in segments {
            if segment == ".." {
                self.segments.pop();
            } else {
                self.segments.push(segment);
            }
        }
    }

    fn resolved(self) -> Absolute {
        let mut out = Absolute {
            prefix: self.prefix,
            segments: Vec::new(),
        };
        out.push(self.segments);
        out
    }

    fn display(&self) -> String {
        format!("{}/{}", self.prefix, self.segments.join("/"))
    }
}

/// Places `raw` (a tool path, a hook payload path, a Git Bash path) relative to `root`.
/// Relative input is taken against `cwd`. Comparison ignores case when the root is a Windows path.
pub fn normalise(root: &Path, cwd: &Path, raw: &str) -> Located {
    let root_text = root.to_string_lossy();
    let windows = is_windows_form(&root_text);
    let Parsed::Absolute(root_abs) = parse(&root_text, windows) else {
        return Located::Outside(raw.to_owned());
    };
    let root_abs = root_abs.resolved();
    let target = match parse(raw, windows) {
        Parsed::Absolute(absolute) => absolute,
        Parsed::Relative(segments) => {
            let mut base = match parse(&cwd.to_string_lossy(), windows) {
                Parsed::Absolute(absolute) => absolute,
                Parsed::Relative(cwd_segments) => {
                    let mut base = root_abs.clone();
                    base.push(cwd_segments);
                    base
                }
            };
            base.push(segments);
            base
        }
    }
    .resolved();
    let Some((head, rest)) = target.segments.split_at_checked(root_abs.segments.len()) else {
        return Located::Outside(target.display());
    };
    let inside = same(&target.prefix, &root_abs.prefix, windows)
        && head
            .iter()
            .zip(&root_abs.segments)
            .all(|(a, b)| same(a, b, windows));
    if !inside {
        return Located::Outside(target.display());
    }
    Located::Inside(RepoPath(rest.join("/")))
}

fn parse(raw: &str, windows: bool) -> Parsed {
    let text = forward_slashes(raw.trim());
    if let Some((letter, rest)) = drive(&text) {
        if !rest.starts_with('/') {
            return Parsed::Relative(split(rest));
        }
        return Parsed::Absolute(Absolute::on_drive(letter, rest));
    }
    if windows && let Some((letter, rest)) = bash_drive(&text) {
        return Parsed::Absolute(Absolute::on_drive(letter, rest));
    }
    if let Some(unc) = text.strip_prefix("//") {
        let mut parts = split(unc);
        let share: Vec<String> = parts.drain(..parts.len().min(2)).collect();
        return Parsed::Absolute(Absolute {
            prefix: format!("//{}", share.join("/")),
            segments: parts,
        });
    }
    if let Some(rest) = text.strip_prefix('/') {
        return Parsed::Absolute(Absolute {
            prefix: String::new(),
            segments: split(rest),
        });
    }
    Parsed::Relative(split(&text))
}

/// `text` with forward slashes and without a `\\?\`, `\\?\UNC\` or `\\.\` verbatim prefix.
pub fn forward_slashes(text: &str) -> String {
    let forward = text.replace('\\', "/");
    if let Some(rest) = forward.strip_prefix("//?/UNC/") {
        return format!("//{rest}");
    }
    for prefix in ["//?/", "//./"] {
        if let Some(rest) = forward.strip_prefix(prefix) {
            return rest.to_owned();
        }
    }
    forward
}

/// `/d/...` (Git Bash, MSYS) and `/cygdrive/d/...` (Cygwin) name drive `d:`.
fn bash_drive(text: &str) -> Option<(char, &str)> {
    let rest = text.strip_prefix("/cygdrive").unwrap_or(text);
    let mut chars = rest.chars();
    let (Some('/'), Some(letter)) = (chars.next(), chars.next()) else {
        return None;
    };
    if !letter.is_ascii_alphabetic() {
        return None;
    }
    let after = chars.as_str();
    let at_boundary = after.is_empty() || after.starts_with('/');
    at_boundary.then_some((letter, after))
}

/// The drive letter of `c:...` and the text after the colon.
fn drive(text: &str) -> Option<(char, &str)> {
    let mut chars = text.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    let rest = chars.as_str().strip_prefix(':')?;
    Some((letter, rest))
}

fn is_windows_form(text: &str) -> bool {
    let text = forward_slashes(text);
    drive(&text).is_some() || text.starts_with("//")
}

fn split(text: &str) -> Vec<String> {
    text.split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .map(str::to_owned)
        .collect()
}

fn same(a: &str, b: &str, windows: bool) -> bool {
    if windows {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inside(path: &str) -> Located {
        Located::Inside(RepoPath::new(path).unwrap())
    }

    fn windows(raw: &str) -> Located {
        let root = Path::new(r"D:\work\repo");
        normalise(root, root, raw)
    }

    #[test]
    fn windows_drive_paths_in_both_slash_styles() {
        assert_eq!(windows(r"D:\work\repo\Cargo.toml"), inside("Cargo.toml"));
        assert_eq!(
            windows("d:/work/REPO/xtask/src/main.rs"),
            inside("xtask/src/main.rs")
        );
        assert_eq!(
            windows(r"\\?\D:\work\repo\.agents\models.toml"),
            inside(".agents/models.toml")
        );
    }

    #[test]
    fn git_bash_and_cygwin_drive_forms() {
        assert_eq!(windows("/d/work/repo/docs/PLAN.md"), inside("docs/PLAN.md"));
        assert_eq!(
            windows("/cygdrive/d/work/repo/AGENTS.md"),
            inside("AGENTS.md")
        );
        assert!(matches!(windows("/c/Users/x"), Located::Outside(_)));
    }

    #[test]
    fn relative_paths_resolve_against_cwd() {
        let root = Path::new(r"D:\work\repo");
        let cwd = Path::new(r"D:\work\repo\xtask");
        assert_eq!(
            normalise(root, cwd, r"src\main.rs"),
            inside("xtask/src/main.rs")
        );
        assert_eq!(normalise(root, cwd, "../Cargo.toml"), inside("Cargo.toml"));
        assert_eq!(
            normalise(root, cwd, "./src/../Cargo.toml"),
            inside("xtask/Cargo.toml")
        );
        assert!(matches!(
            normalise(root, cwd, "../../repo-other/x"),
            Located::Outside(_)
        ));
    }

    #[test]
    fn sibling_directory_with_shared_prefix_is_outside() {
        assert!(matches!(
            windows("D:/work/repo-other/README.md"),
            Located::Outside(_)
        ));
    }

    #[test]
    fn unix_paths_are_case_sensitive() {
        let root = Path::new("/home/dev/grdr");
        assert_eq!(
            normalise(root, root, "/home/dev/grdr/xtask/Cargo.toml"),
            inside("xtask/Cargo.toml")
        );
        assert!(matches!(
            normalise(root, root, "/home/dev/GRDR/x"),
            Located::Outside(_)
        ));
        assert!(matches!(
            normalise(root, root, "/d/grdr/x"),
            Located::Outside(_)
        ));
        assert_eq!(
            normalise(root, root, "/home/dev/grdr"),
            Located::Inside(RepoPath::new("").unwrap())
        );
    }

    #[test]
    fn repo_path_rejects_escapes() {
        assert!(RepoPath::new("../x").is_none());
        assert!(RepoPath::new("/etc/passwd").is_none());
        assert!(RepoPath::new("C:/x").is_none());
        assert_eq!(RepoPath::new(r".\a\b.rs").unwrap().as_str(), "a/b.rs");
        assert_eq!(RepoPath::new("a/b.rs").unwrap().extension(), Some("rs"));
        assert_eq!(RepoPath::new("a/.gitignore").unwrap().extension(), None);
    }
}
