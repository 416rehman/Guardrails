//! Gate V25: no em dash in changed Markdown (the owner's prose rules).

use anyhow::Result;

use super::{Context, Outcome};

const EM_DASH: char = '\u{2014}';

pub fn gate(context: &Context) -> Result<Outcome> {
    let mut problems = Vec::new();
    for path in context
        .changed
        .iter()
        .filter(|path| path.extension() == Some("md"))
    {
        let Ok(text) = std::fs::read_to_string(context.repo.path(path.as_str())) else {
            continue;
        };
        problems.extend(em_dashes(&text).into_iter().map(|line| {
            format!("{path}:{line}: em dash; use a comma, a colon, parentheses or a new sentence")
        }));
    }
    Ok(Outcome::from_problems(problems))
}

/// Line numbers holding an em dash.
pub fn em_dashes(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| line.contains(EM_DASH))
        .map(|(index, _)| index + 1)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_em_dashes_only() {
        let text = format!("one - two\nthree {EM_DASH} four\nfive \u{2013} six\n");
        assert_eq!(em_dashes(&text), vec![2]);
    }
}
