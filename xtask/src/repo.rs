//! The repository root and file access relative to it.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::paths::{self, Located, RepoPath};

const PROJECT_DIR_VARIABLE: &str = "CLAUDE_PROJECT_DIR";
const ROOT_MARKER: &str = "xtask/Cargo.toml";

#[derive(Debug, Clone)]
pub struct Repo {
    root: PathBuf,
}

impl Repo {
    /// `CLAUDE_PROJECT_DIR` when Claude Code set it; otherwise the nearest ancestor of the working
    /// directory that holds `xtask/Cargo.toml`; otherwise the root the installed kit binary sits in
    /// (`<root>/.agent/kit/bin/xtask`), so a hook started from any directory finds its repository.
    pub fn discover() -> Result<Repo> {
        if let Some(dir) = std::env::var_os(PROJECT_DIR_VARIABLE).map(PathBuf::from)
            && dir.is_dir()
        {
            return Ok(Repo { root: dir });
        }
        let cwd = std::env::current_dir().context("reading the working directory")?;
        if let Some(root) = cwd.ancestors().find(|dir| dir.join(ROOT_MARKER).is_file()) {
            return Ok(Repo {
                root: root.to_path_buf(),
            });
        }
        if let Some(root) = installed_binary_root() {
            return Ok(Repo { root });
        }
        bail!(
            "cannot find the repository root: set {PROJECT_DIR_VARIABLE} or run inside the repository"
        )
    }

    pub fn at(root: impl Into<PathBuf>) -> Repo {
        Repo { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The file system path of a root-relative path written with forward slashes.
    pub fn path(&self, relative: &str) -> PathBuf {
        relative
            .split('/')
            .filter(|segment| !segment.is_empty())
            .fold(self.root.clone(), |path, segment| path.join(segment))
    }

    /// Refuses `relative` when it, or a directory on the way to it below the root, is a link,
    /// junctions included, so a write there stays inside this checkout: a change can commit
    /// `.agent` as a link, and `.gitignore` ignores only a directory of that name.
    pub fn refuse_links(&self, relative: &str) -> Result<()> {
        let mut path = self.root.clone();
        for segment in relative.split('/').filter(|segment| !segment.is_empty()) {
            path.push(segment);
            match fs::symlink_metadata(&path) {
                Ok(found) if found.file_type().is_symlink() => bail!(
                    "{} is a link, so writing {relative} would write outside {}",
                    path.display(),
                    self.root.display()
                ),
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", path.display()));
                }
            }
        }
        Ok(())
    }

    /// Places a path from a tool call or hook payload; relative paths are taken against `cwd`,
    /// or against the root when the payload carries no working directory.
    pub fn locate(&self, raw: &str, cwd: Option<&Path>) -> Located {
        paths::normalise(&self.root, cwd.unwrap_or(&self.root), raw)
    }

    /// Where a write to `raw` lands: [`Repo::locate`] when no existing part of the path is a link,
    /// else the path the links lead to, placed against the resolved root, so a link in the
    /// checkout to a file outside it is judged as that file. A link that cannot be resolved, one
    /// that leads nowhere yet included, is an error.
    pub fn locate_through_links(&self, raw: &str, cwd: Option<&Path>) -> Result<Located> {
        let located = self.locate(raw, cwd);
        let target = match &located {
            Located::Inside(path) => self.path(path.as_str()),
            Located::Outside(absolute) => PathBuf::from(absolute),
        };
        let crosses_link = target.ancestors().any(|part| {
            fs::symlink_metadata(part).is_ok_and(|found| found.file_type().is_symlink())
        });
        if !crosses_link {
            return Ok(located);
        }
        let real = resolve_existing(&target)
            .with_context(|| format!("following the link on the way to {raw}"))?;
        let root = fs::canonicalize(&self.root)
            .with_context(|| format!("resolving {}", self.root.display()))?;
        Ok(paths::normalise(&root, &root, &real.to_string_lossy()))
    }

    /// The root-relative form of a file system path under the root.
    pub fn relative(&self, path: &Path) -> Option<RepoPath> {
        match self.locate(&path.to_string_lossy(), None) {
            Located::Inside(relative) => Some(relative),
            Located::Outside(_) => None,
        }
    }

    pub fn read(&self, relative: &str) -> Result<String> {
        fs::read_to_string(self.path(relative)).with_context(|| format!("reading {relative}"))
    }

    pub fn read_optional(&self, relative: &str) -> Result<Option<String>> {
        match fs::read_to_string(self.path(relative)) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("reading {relative}")),
        }
    }
}

/// Every file below `dir`, sorted; an absent directory has none.
pub fn walk_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let entries = match fs::read_dir(&next) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("listing {}", next.display())),
        };
        for entry in entries {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Writes `bytes` unless the file already holds them; reports whether it wrote.
pub fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<bool> {
    if fs::read(path).is_ok_and(|current| current == bytes) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// `path` with its longest existing part as the file system resolves it, links followed and
/// Windows short names expanded, and the rest as written.
pub fn resolve_existing(path: &Path) -> Result<PathBuf> {
    let Some(existing) = path
        .ancestors()
        .find(|part| fs::symlink_metadata(part).is_ok())
    else {
        return Ok(path.to_path_buf());
    };
    let resolved =
        fs::canonicalize(existing).with_context(|| format!("resolving {}", existing.display()))?;
    match path.strip_prefix(existing) {
        Ok(rest) if !rest.as_os_str().is_empty() => Ok(resolved.join(rest)),
        _ => Ok(resolved),
    }
}

fn installed_binary_root() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let bin = exe.parent()?;
    let kit = bin.parent()?;
    let agent = kit.parent()?;
    let in_kit_bin =
        bin.file_name()? == "bin" && kit.file_name()? == "kit" && agent.file_name()? == ".agent";
    let root = agent.parent()?;
    (in_kit_bin && root.join(ROOT_MARKER).is_file()).then(|| root.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_joins_forward_slash_segments() {
        let repo = Repo::at("root");
        assert_eq!(
            repo.path(".agents/kit/hooks.toml"),
            Path::new("root")
                .join(".agents")
                .join("kit")
                .join("hooks.toml")
        );
    }

    #[test]
    fn a_link_on_the_way_to_a_path_is_refused() {
        let temp = crate::testkit::TempRepo::create();
        let outside = crate::testkit::TempRepo::create();
        let repo = temp.repo();
        assert!(repo.refuse_links(".agent/state/item-9.json").is_ok());
        temp.write(".agent/state/item-9.json", "{}");
        assert!(repo.refuse_links(".agent/state/item-9.json").is_ok());
        fs::remove_dir_all(temp.root().join(".agent")).unwrap();
        crate::testkit::link_dir(&temp.root().join(".agent"), outside.root());
        let error = repo.refuse_links(".agent/state/item-9.json").unwrap_err();
        assert!(format!("{error:#}").contains("is a link"), "{error:#}");
    }

    #[test]
    fn relative_of_a_child_path() {
        let repo = Repo::at(std::env::temp_dir());
        let child = std::env::temp_dir().join("a").join("b.rs");
        assert_eq!(repo.relative(&child).unwrap().as_str(), "a/b.rs");
    }
}
