//! The cleanup plugin's sign-off, `<git-dir>/cleanup.ok`: the SHA-256 of `git diff --cached
//! <base>` (`cached`) and of `git diff <base>` (`tracked`) when the cleanup pass ran, with `base`
//! `HEAD` or the empty tree. The Stop gate requires it to match the uncommitted diff, or, on a
//! clean tree, the branch's last commit, whenever that diff adds lines to source files.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::state::sha256_hex;
use crate::git::{self, Base};
use crate::repo::Repo;

const MARKER: &str = "cleanup.ok";
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
/// The source extensions the plugin's gate treats as code (cleanup-gate.js `CODE_EXT`).
const CODE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx", "cs", "csx", "cshtml", "razor", "fs", "fsx",
    "vb", "java", "kt", "kts", "scala", "groovy", "gradle", "go", "rs", "swift", "m", "mm", "js",
    "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts", "vue", "svelte", "astro", "py", "pyi", "rb",
    "php", "pl", "pm", "lua", "r", "jl", "dart", "ex", "exs", "erl", "hrl", "hs", "clj", "cljs",
    "cljc", "sh", "bash", "zsh", "fish", "ps1", "psm1", "psd1", "bat", "cmd", "sql", "css", "scss",
    "sass", "less", "styl", "zig", "nim", "nix", "cmake", "tf", "hcl", "proto", "graphql", "gql",
    "sol", "shader", "hlsl", "glsl", "cginc", "compute",
];
const DIFF_OPTIONS: &[&str] = &["--no-color", "--no-ext-diff"];

/// Why the sign-off does not cover the work, or `None` when it does or there is nothing to sign.
pub fn problem(repo: &Repo, base: &Base) -> Result<Option<String>> {
    let Some(git_dir) = git::try_output(repo, &["rev-parse", "--absolute-git-dir"])? else {
        return Ok(None);
    };
    let marker = read_marker(&marker_path(&git_dir));
    let head = git::head(repo)?;
    let reference = uncommitted_base(head.is_some());
    if adds_code(repo, &["diff", reference, "--numstat"])? {
        let tracked = diff(repo, &["diff", reference])?;
        let cached = diff(repo, &["diff", "--cached", reference])?;
        let signed =
            marker.get("tracked") == Some(&tracked) || marker.get("cached") == Some(&cached);
        return Ok((!signed).then(|| {
            "the uncommitted change adds source lines the cleanup pass has not signed off; run the cleanup skill (cleanup:cleanup), then the sign-off it prints".to_owned()
        }));
    }
    let Some(head) = head else {
        return Ok(None);
    };
    if base.commit() == Some(head.as_str()) {
        return Ok(None);
    }
    let parent = git::try_output(repo, &["rev-parse", "--verify", "--quiet", "HEAD^"])?
        .map(|sha| sha.trim().to_owned())
        .unwrap_or_else(|| EMPTY_TREE.to_owned());
    if !adds_code(repo, &["diff", &parent, "HEAD", "--numstat"])? {
        return Ok(None);
    }
    let committed = diff(repo, &["diff", &parent, "HEAD"])?;
    let signed = marker.values().any(|digest| *digest == committed);
    Ok((!signed).then(|| {
        "the last commit adds source lines the cleanup pass did not sign off; run the cleanup skill on it and amend".to_owned()
    }))
}

/// SHA-256 of a diff's text, exactly as the plugin computes it.
fn diff(repo: &Repo, args: &[&str]) -> Result<String> {
    let mut full: Vec<&str> = args.to_vec();
    full.extend(DIFF_OPTIONS);
    Ok(sha256_hex(git::output(repo, &full)?.as_bytes()))
}

fn adds_code(repo: &Repo, args: &[&str]) -> Result<bool> {
    let numstat = git::output(repo, args)?;
    Ok(numstat.lines().any(|line| {
        let mut parts = line.splitn(3, '\t');
        let added = parts
            .next()
            .and_then(|count| count.parse::<u64>().ok())
            .unwrap_or(0);
        let path = parts.nth(1).unwrap_or_default();
        let path = path
            .rsplit(" => ")
            .next()
            .unwrap_or(path)
            .trim_end_matches('}');
        let extension = path
            .rsplit_once('.')
            .map(|(_, ext)| ext.to_ascii_lowercase());
        added > 0 && extension.is_some_and(|ext| CODE_EXTENSIONS.contains(&ext.as_str()))
    }))
}

fn read_marker(path: &Path) -> BTreeMap<String, String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            Some((parts.next()?.to_owned(), parts.next()?.to_owned()))
        })
        .collect()
}

/// Writes the marker the plugin's `--mark` would write for this tree: the hook self-test uses it.
pub fn sign(repo: &Repo) -> Result<()> {
    let git_dir = git::output(repo, &["rev-parse", "--absolute-git-dir"])?;
    let reference = uncommitted_base(git::head(repo)?.is_some());
    let cached = diff(repo, &["diff", "--cached", reference])?;
    let tracked = diff(repo, &["diff", reference])?;
    std::fs::write(
        marker_path(&git_dir),
        format!("cached {cached}\ntracked {tracked}\n"),
    )?;
    Ok(())
}

fn marker_path(git_dir: &str) -> PathBuf {
    PathBuf::from(git_dir.trim()).join(MARKER)
}

/// What the uncommitted diff is taken against: `HEAD`, or the empty tree before the first commit.
fn uncommitted_base(has_head: bool) -> &'static str {
    if has_head { "HEAD" } else { EMPTY_TREE }
}
