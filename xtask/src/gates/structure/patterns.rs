//! Regular expressions the checks compile once. A pattern that fails to compile matches nothing
//! instead of panicking; each module's tests compile every pattern it declares, so none ships
//! broken.

use std::sync::LazyLock;

use regex::{Match, Regex};

pub(crate) type Compiled = LazyLock<Option<Regex>>;

pub(crate) fn compile(source: &str) -> Option<Regex> {
    Regex::new(source).ok()
}

pub(crate) fn is_match(pattern: &Compiled, text: &str) -> bool {
    pattern.as_ref().is_some_and(|regex| regex.is_match(text))
}

pub(crate) fn find<'t>(pattern: &Compiled, text: &'t str) -> Option<Match<'t>> {
    pattern.as_ref().and_then(|regex| regex.find(text))
}

pub(crate) fn find_all<'t>(pattern: &Compiled, text: &'t str) -> Vec<Match<'t>> {
    pattern
        .as_ref()
        .map(|regex| regex.find_iter(text).collect())
        .unwrap_or_default()
}

/// Whether every pattern compiled, for the tests of the modules that declare them.
#[cfg(test)]
pub(crate) fn all_compile(patterns: &[&Compiled]) -> bool {
    patterns.iter().all(|pattern| pattern.is_some())
}
