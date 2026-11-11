//! Glob lists over repository paths. `*` stops at `/`, `**` crosses it, `{a,b}` alternates, and a
//! leading `!` excludes. Patterns are written relative to the root; `./` and `/` prefixes are
//! dropped and a trailing `/` means everything below.

use anyhow::{Context, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Case {
    Sensitive,
    /// For deny lists: a case variant of a protected path is still protected on Windows and macOS.
    Insensitive,
}

#[derive(Debug, Clone)]
pub struct GlobList {
    include: GlobSet,
    include_patterns: Vec<String>,
    exclude: GlobSet,
}

impl GlobList {
    pub fn new<S: AsRef<str>>(patterns: &[S], case: Case) -> Result<GlobList> {
        let mut include = GlobSetBuilder::new();
        let mut exclude = GlobSetBuilder::new();
        let mut include_patterns = Vec::new();
        for raw in patterns {
            let raw = raw.as_ref();
            let trimmed = raw.trim();
            let (negated, body) = match trimmed.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, trimmed),
            };
            let pattern = normalise(body);
            let glob = GlobBuilder::new(&pattern)
                .literal_separator(true)
                .case_insensitive(case == Case::Insensitive)
                .build()
                .with_context(|| format!("invalid glob `{raw}`"))?;
            if negated {
                exclude.add(glob);
            } else {
                include.add(glob);
                include_patterns.push(trimmed.to_owned());
            }
        }
        Ok(GlobList {
            include: include.build()?,
            include_patterns,
            exclude: exclude.build()?,
        })
    }

    pub fn is_match(&self, path: &str) -> bool {
        self.first_match(path).is_some()
    }

    /// The first pattern, in list order, that matches `path`, unless an exclusion matches it.
    pub fn first_match(&self, path: &str) -> Option<&str> {
        if self.exclude.is_match(path) {
            return None;
        }
        let index = self.include.matches(path).into_iter().min()?;
        self.include_patterns.get(index).map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.include_patterns.is_empty()
    }
}

fn normalise(pattern: &str) -> String {
    let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
    let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    match pattern.strip_suffix('/') {
        Some(directory) => format!("{directory}/**"),
        None => pattern.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(patterns: &[&str]) -> GlobList {
        GlobList::new(patterns, Case::Sensitive).unwrap()
    }

    #[test]
    fn single_star_stays_in_one_directory() {
        let globs = list(&[".github/ISSUE_TEMPLATE/*"]);
        assert!(globs.is_match(".github/ISSUE_TEMPLATE/work-item.yml"));
        assert!(!globs.is_match(".github/ISSUE_TEMPLATE/forms/x.yml"));
    }

    #[test]
    fn double_star_matches_any_depth_including_none() {
        let globs = list(&["**/AGENTS.md", "xtask/src/gates/**"]);
        assert!(globs.is_match("AGENTS.md"));
        assert!(globs.is_match("crates/grdr-core/AGENTS.md"));
        assert!(globs.is_match("xtask/src/gates/structure/mod.rs"));
        assert!(!globs.is_match("xtask/src/kit/mod.rs"));
    }

    #[test]
    fn root_anchored_names_do_not_match_deeper() {
        let globs = list(&["Cargo.toml", "./rustfmt.toml", "/CLAUDE.md"]);
        assert!(globs.is_match("Cargo.toml"));
        assert!(!globs.is_match("xtask/Cargo.toml"));
        assert!(globs.is_match("rustfmt.toml"));
        assert!(globs.is_match("CLAUDE.md"));
    }

    #[test]
    fn alternates_negation_and_directory_suffix() {
        let globs = list(&["crates/grdr-{proto,wire}/**", "programs/", "!**/tests/**"]);
        assert!(globs.is_match("crates/grdr-wire/src/lib.rs"));
        assert!(!globs.is_match("crates/grdr-core/src/lib.rs"));
        assert!(globs.is_match("programs/grdr/src/main.rs"));
        assert!(!globs.is_match("crates/grdr-proto/tests/round_trip.rs"));
    }

    #[test]
    fn first_match_reports_pattern_in_list_order() {
        let globs = list(&["docs/**", "docs/design/**"]);
        assert_eq!(
            globs.first_match("docs/design/00-decisions.md"),
            Some("docs/**")
        );
    }

    #[test]
    fn insensitive_lists_catch_case_variants() {
        let globs = GlobList::new(&["Cargo.toml", ".claude/**"], Case::Insensitive).unwrap();
        assert!(globs.is_match("cargo.TOML"));
        assert!(globs.is_match(".CLAUDE/settings.json"));
        assert!(!list(&["Cargo.toml"]).is_match("cargo.toml"));
    }

    #[test]
    fn invalid_pattern_is_an_error() {
        assert!(GlobList::new(&["a/[b"], Case::Sensitive).is_err());
    }
}
