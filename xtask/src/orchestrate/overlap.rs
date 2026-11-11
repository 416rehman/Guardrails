//! Whether two glob lists can match one path, for questions such as "does this write set touch a
//! trust-core path" or "does this item change a protected path". Each pattern is turned into one
//! concrete path it matches and tested against the other list. A leading `**/` stands for the
//! root only, because nearly every broad write set could hold some `AGENTS.md` or `clippy.toml`,
//! and those files are protected anyway.

use anyhow::Result;

use crate::globs::{Case, GlobList};

const FILLER: &str = "x";

/// True when some path plausibly matches a pattern of `a` and a pattern of `b`.
pub fn overlaps<A: AsRef<str>, B: AsRef<str>>(a: &[A], b: &[B]) -> Result<bool> {
    let a: Vec<&str> = included(a);
    let b: Vec<&str> = included(b);
    let a_globs = GlobList::new(&a, Case::Insensitive)?;
    let b_globs = GlobList::new(&b, Case::Insensitive)?;
    for left in &a {
        for right in &b {
            if b_globs.is_match(&representative(left)) || a_globs.is_match(&representative(right)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// One path `pattern` matches.
pub fn representative(pattern: &str) -> String {
    let pattern = pattern
        .trim()
        .trim_start_matches("./")
        .trim_start_matches('/');
    let placed = pattern.strip_prefix("**/").unwrap_or(pattern);
    let filled = fill(placed);
    match filled.strip_suffix('/') {
        Some(directory) => format!("{directory}/{FILLER}"),
        None => filled,
    }
}

fn included<S: AsRef<str>>(patterns: &[S]) -> Vec<&str> {
    patterns
        .iter()
        .map(|pattern| pattern.as_ref().trim())
        .filter(|pattern| !pattern.is_empty() && !pattern.starts_with('!'))
        .collect()
}

/// Replaces every glob construct with one concrete choice.
fn fill(pattern: &str) -> String {
    let mut out = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                while chars.peek() == Some(&'*') {
                    chars.next();
                }
                out.push_str(FILLER);
            }
            '?' => out.push_str(FILLER),
            '[' => {
                for skipped in chars.by_ref() {
                    if skipped == ']' {
                        break;
                    }
                }
                out.push_str(FILLER);
            }
            '{' => out.push_str(&first_alternative(&mut chars)),
            other => out.push(other),
        }
    }
    out
}

/// The first choice of a `{a,b}` group, consuming the group up to its `}`.
fn first_alternative(chars: &mut impl Iterator<Item = char>) -> String {
    let group: String = chars.take_while(|c| *c != '}').collect();
    group.split(',').next().unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn representatives_are_concrete_paths() {
        assert_eq!(
            representative("crates/grdr-{proto,wire}/**"),
            "crates/grdr-proto/x"
        );
        assert_eq!(representative("**/clippy.toml"), "clippy.toml");
        assert_eq!(representative("programs/"), "programs/x");
        assert_eq!(representative("./src/*.rs"), "src/x.rs");
    }

    #[test]
    fn overlapping_lists() {
        let trust = ["crates/grdr-crypto/**", "**/clippy.toml", "xtask/**"];
        assert!(overlaps(&["crates/**"], &trust).unwrap());
        assert!(!overlaps(&["crates/grdr-core/**"], &trust).unwrap());
        assert!(overlaps(&["crates/grdr-core/clippy.toml"], &trust).unwrap());
        assert!(overlaps(&["xtask/src/orchestrate/**"], &trust).unwrap());
        assert!(!overlaps(&["web/app/**", "docs/guide.md"], &trust).unwrap());
        assert!(!overlaps(&["!crates/**"], &trust).unwrap());
        let empty: [&str; 0] = [];
        assert!(!overlaps(&empty, &trust).unwrap());
    }
}
