//! The two things governance-check reads from Markdown: the `## ` headings and one fenced block.

const FENCE: &str = "```";
const SECTION: &str = "## ";

/// The text of every `## ` heading outside fenced blocks.
pub fn sections(text: &str) -> Vec<&str> {
    let mut fenced = false;
    let mut found = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with(FENCE) {
            fenced = !fenced;
            continue;
        }
        if let Some(heading) = line.strip_prefix(SECTION).filter(|_| !fenced) {
            found.push(heading.trim());
        }
    }
    found
}

/// The lines of the first fenced block whose info string is `language`, or `None` when the text
/// has no such block or it never closes.
pub fn fenced_block(text: &str, language: &str) -> Option<String> {
    let mut lines = text.lines();
    lines.find(|line| line.trim().strip_prefix(FENCE) == Some(language))?;
    let mut block = String::new();
    for line in lines {
        if line.trim_start().starts_with(FENCE) {
            return Some(block);
        }
        block.push_str(line);
        block.push('\n');
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headings_inside_a_fence_do_not_count() {
        let text = "# Title\n\n## One\n\n```markdown\n## Quoted\n```\n\n## Two \n### Three\n";
        assert_eq!(sections(text), vec!["One", "Two"]);
    }

    #[test]
    fn the_block_is_the_first_one_in_the_language_and_must_close() {
        let text = "```text\nnot this\n```\n\n```toml\na = 1\nb = 2\n```\n";
        assert_eq!(
            fenced_block(text, "toml").as_deref(),
            Some("a = 1\nb = 2\n")
        );
        assert_eq!(fenced_block("```toml\na = 1\n", "toml"), None);
        assert_eq!(fenced_block("no block\n", "toml"), None);
    }
}
