//! The `static` lane's equivalence proof for Rust (owner instruction 8): two sources are equivalent
//! when their token streams are equal once comments and layout are removed. The lexer keeps every
//! string, raw string, byte string and character literal intact, and refuses (returns `None`) on
//! anything it cannot close, so an unreadable file never counts as equivalent.

/// The source as tokens with comments dropped and layout reduced to the spaces that separate two
/// word characters.
pub fn rust_tokens(source: &str) -> Option<String> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::new();
    let mut pending_space = false;
    let mut at = 0;
    while let Some(&c) = chars.get(at) {
        let next = chars.get(at + 1).copied();
        if c.is_whitespace() {
            pending_space = true;
            at += 1;
            continue;
        }
        if c == '/' && next == Some('/') {
            at = line_end(&chars, at);
            pending_space = true;
            continue;
        }
        if c == '/' && next == Some('*') {
            at = block_end(&chars, at)?;
            pending_space = true;
            continue;
        }
        let end = literal_end(&chars, at)?.unwrap_or(at + 1);
        if pending_space && out.chars().last().is_some_and(is_word) && is_word(c) {
            out.push(' ');
        }
        pending_space = false;
        out.extend(chars.get(at..end)?.iter());
        at = end;
    }
    Some(out)
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn line_end(chars: &[char], from: usize) -> usize {
    chars
        .iter()
        .skip(from)
        .position(|c| *c == '\n')
        .map_or(chars.len(), |offset| from + offset)
}

/// Past the end of a block comment starting at `from`; Rust block comments nest.
fn block_end(chars: &[char], from: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut at = from;
    loop {
        let c = *chars.get(at)?;
        let next = chars.get(at + 1).copied();
        if c == '/' && next == Some('*') {
            depth += 1;
            at += 2;
        } else if c == '*' && next == Some('/') {
            depth = depth.checked_sub(1)?;
            at += 2;
            if depth == 0 {
                return Some(at);
            }
        } else {
            at += 1;
        }
    }
}

/// `Some(Some(end))` past a literal starting at `from`, `Some(None)` when none starts there,
/// `None` for a literal that never closes.
fn literal_end(chars: &[char], from: usize) -> Option<Option<usize>> {
    let c = *chars.get(from)?;
    let prefix = matches!(c, 'b' | 'r');
    let previous_is_word = from > 0 && chars.get(from - 1).is_some_and(|p| is_word(*p));
    if prefix && previous_is_word {
        return Some(None);
    }
    let mut at = from;
    if c == 'b' && matches!(chars.get(at + 1), Some('"' | '\'' | 'r')) {
        at += 1;
    }
    let raw_start = chars.get(at) == Some(&'r') && matches!(chars.get(at + 1), Some('"' | '#'));
    if raw_start {
        let hashes = chars.iter().skip(at + 1).take_while(|c| **c == '#').count();
        let open = at + 1 + hashes;
        if chars.get(open) != Some(&'"') {
            return Some(None);
        }
        return raw_end(chars, open + 1, hashes).map(Some);
    }
    match chars.get(at) {
        Some('"') => quoted_end(chars, at + 1, '"').map(Some),
        Some('\'') => Some(char_end(chars, at)),
        _ => Some(None),
    }
}

fn raw_end(chars: &[char], from: usize, hashes: usize) -> Option<usize> {
    let mut at = from;
    loop {
        if *chars.get(at)? == '"' && (1..=hashes).all(|k| chars.get(at + k) == Some(&'#')) {
            return Some(at + 1 + hashes);
        }
        at += 1;
    }
}

fn quoted_end(chars: &[char], from: usize, quote: char) -> Option<usize> {
    let mut at = from;
    loop {
        match *chars.get(at)? {
            '\\' => at += 2,
            c if c == quote => return Some(at + 1),
            _ => at += 1,
        }
    }
}

/// A character literal, or `None` inside for a lifetime or label, which is not a literal.
fn char_end(chars: &[char], from: usize) -> Option<usize> {
    match chars.get(from + 1) {
        Some('\\') => quoted_end(chars, from + 1, '\''),
        Some(_) if chars.get(from + 2) == Some(&'\'') => Some(from + 3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_layout_do_not_count() {
        let before = "fn a(x: u8) -> u8 {\n    // add one\n    x + 1 /* inline */\n}\n";
        let after = "/// Adds one.\nfn a( x: u8 ) -> u8 { x + 1 }\n";
        assert_eq!(rust_tokens(before), rust_tokens(after));
        assert_ne!(
            rust_tokens(before),
            rust_tokens("fn a(x: u8) -> u8 { x + 2 }")
        );
    }

    #[test]
    fn literals_keep_their_contents() {
        let code = "let s = \"a // not a comment\"; let r = r#\"/* raw */\"#; let c = '\"'; let l: &'a str = \"x\";";
        let tokens = rust_tokens(code).unwrap();
        assert!(tokens.contains("\"a // not a comment\""));
        assert!(tokens.contains("r#\"/* raw */\"#"));
        assert_ne!(
            rust_tokens("let s = \"a  b\";"),
            rust_tokens("let s = \"a b\";")
        );
        assert_ne!(rust_tokens("let x = 1;"), rust_tokens("letx = 1;"));
        assert_ne!(rust_tokens("return\"a // b\""), rust_tokens("return\"a \""));
        assert!(rust_tokens("let r#type = 1;").is_some());
    }

    #[test]
    fn unclosed_input_is_refused() {
        assert!(rust_tokens("let s = \"open").is_none());
        assert!(rust_tokens("/* /* nested */").is_none());
        assert!(rust_tokens("/* /* nested */ */ fn f() {}").is_some());
    }
}
