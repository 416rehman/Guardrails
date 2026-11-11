//! The token scanner of `guard-command`: words with their quoting removed, operators,
//! redirections, here-documents and command substitutions, in Bash or PowerShell syntax
//! (team/03 section 4.1). A word whose value depends on an expansion the scanner cannot resolve
//! is marked opaque, so the rules can deny it instead of guessing. The per-dialect word readers
//! live in `dialect.rs` and the substitution scanner in `scan.rs`.

use super::scan::{find_close, is_descriptor, redirect_operator};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Bash,
    PowerShell,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Word {
    /// The value after quote removal, with the variables the caller can resolve substituted.
    pub value: String,
    pub raw: String,
    pub opaque: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectKind {
    Write,
    Read,
    /// A here-document or here-string: the target is the data on stdin.
    Document,
    /// `2>&1` and the like: the target is a descriptor, not a file.
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub kind: RedirectKind,
    pub target: Word,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Simple {
    pub words: Vec<Word>,
    pub redirects: Vec<Redirect>,
    pub after_pipe: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Scanned {
    pub commands: Vec<Simple>,
    /// Sources of command and process substitutions, each scanned again as a command.
    pub substitutions: Vec<(String, Dialect)>,
}

/// Resolves the variables whose value the hook knows to be the shell's too (`HOME`, `TMPDIR`).
pub type Resolve<'a> = &'a dyn Fn(&str) -> Option<String>;

struct PendingDocument {
    command: usize,
    redirect: usize,
    delimiter: String,
    strip_tabs: bool,
    literal: bool,
}

pub(super) struct Lexer<'a> {
    pub(super) chars: Vec<char>,
    pub(super) pos: usize,
    pub(super) dialect: Dialect,
    pub(super) resolve: Resolve<'a>,
    pub(super) depth: usize,
    max_depth: usize,
    pub(super) out: Scanned,
    current: Simple,
    pipe_pending: bool,
    documents: Vec<PendingDocument>,
}

impl Word {
    /// This word with `value` in place of its own, keeping its raw text and opacity.
    pub fn with_value(&self, value: &str) -> Word {
        Word {
            value: value.to_owned(),
            raw: self.raw.clone(),
            opaque: self.opaque,
        }
    }
}

impl Lexer<'_> {
    pub(super) fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.pos + ahead).copied()
    }

    pub(super) fn len(&self) -> usize {
        self.chars.len()
    }

    pub(super) fn starts_with(&self, prefix: &[char]) -> bool {
        self.rest(self.pos).starts_with(prefix)
    }

    /// The characters from `from` to the end; none when `from` is past it.
    fn rest(&self, from: usize) -> &[char] {
        self.chars.get(from..).unwrap_or_default()
    }

    /// The characters from `from` to `to`; none when the range is not inside the input.
    fn span(&self, from: usize, to: usize) -> &[char] {
        self.chars.get(from..to).unwrap_or_default()
    }

    pub(super) fn slice(&self, from: usize, to: usize) -> String {
        self.span(from, to).iter().collect()
    }

    /// The index of the next newline at or after `from`, or the end of the input.
    pub(super) fn line_end(&self, from: usize) -> usize {
        self.rest(from)
            .iter()
            .position(|c| *c == '\n')
            .map_or(self.chars.len(), |offset| from + offset)
    }

    fn bash(&self) -> bool {
        self.dialect == Dialect::Bash
    }

    fn run(&mut self) {
        while let Some(c) = self.peek(0) {
            match c {
                ' ' | '\t' | '\r' => self.pos += 1,
                '\n' => {
                    self.pos += 1;
                    self.end_command(false);
                    self.read_documents();
                }
                '#' => self.skip_line(),
                '<' if !self.bash() && self.peek(1) == Some('#') => self.skip_block_comment(),
                '<' | '>' if self.bash() && self.peek(1) == Some('(') => self.push_word(),
                ';' | '|' | '&' | '(' | ')' => self.operator(c),
                '{' | '}' if !self.bash() => {
                    self.pos += 1;
                    self.end_command(false);
                }
                '<' | '>' => self.redirect(),
                _ => self.word_or_redirect(),
            }
        }
        self.end_command(false);
    }

    pub(super) fn skip_line(&mut self) {
        while self.peek(0).is_some_and(|c| c != '\n') {
            self.pos += 1;
        }
    }

    fn skip_block_comment(&mut self) {
        self.pos += 2;
        while self.pos < self.chars.len()
            && !(self.peek(0) == Some('#') && self.peek(1) == Some('>'))
        {
            self.pos += 1;
        }
        self.pos = (self.pos + 2).min(self.chars.len());
    }

    fn operator(&mut self, c: char) {
        let next = self.peek(1);
        match (c, next) {
            (';', _) => {
                while self.peek(0).is_some_and(|c| c == ';' || c == '&') {
                    self.pos += 1;
                }
                self.end_command(false);
            }
            ('|', Some('|')) | ('&', Some('&')) => {
                self.pos += 2;
                self.end_command(false);
            }
            ('|', Some('&')) => {
                self.pos += 2;
                self.end_command(true);
            }
            ('|', _) => {
                self.pos += 1;
                self.end_command(true);
            }
            ('&', Some('>')) if self.bash() => self.redirect(),
            ('&', _) if !self.bash() && self.current.words.is_empty() => self.pos += 1,
            _ => {
                self.pos += 1;
                self.end_command(false);
            }
        }
    }

    fn end_command(&mut self, pipe_next: bool) {
        if !self.current.words.is_empty() || !self.current.redirects.is_empty() {
            let mut finished = std::mem::take(&mut self.current);
            finished.after_pipe = self.pipe_pending;
            self.out.commands.push(finished);
            self.pipe_pending = pipe_next;
        } else if pipe_next {
            self.pipe_pending = true;
        }
    }

    fn word_or_redirect(&mut self) {
        let digits = self
            .rest(self.pos)
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        let after = self.peek(digits);
        let fd_redirect = digits > 0 && matches!(after, Some('<' | '>'));
        let all_streams = !self.bash() && self.peek(0) == Some('*') && self.peek(1) == Some('>');
        if fd_redirect || all_streams {
            self.pos += digits.max(1);
            self.redirect();
            return;
        }
        self.push_word();
    }

    fn push_word(&mut self) {
        let word = self.read_word();
        self.current.words.push(word);
    }

    fn redirect(&mut self) {
        let rest: String = self.rest(self.pos).iter().take(3).collect();
        let (length, kind) = redirect_operator(&rest);
        self.pos += length;
        if rest.starts_with("<<") && !rest.starts_with("<<<") {
            self.here_document(rest.starts_with("<<-"));
            return;
        }
        self.skip_blanks();
        let target = if self.at_word() {
            self.read_word()
        } else {
            Word::default()
        };
        let kind = match kind {
            RedirectKind::Duplicate if !is_descriptor(&target.value) => RedirectKind::Write,
            other => other,
        };
        self.current.redirects.push(Redirect { kind, target });
    }

    fn here_document(&mut self, strip_tabs: bool) {
        self.skip_blanks();
        let delimiter = self.read_word();
        let literal = delimiter.raw.contains(['\'', '"', '\\']);
        self.documents.push(PendingDocument {
            command: self.out.commands.len(),
            redirect: self.current.redirects.len(),
            delimiter: delimiter.value,
            strip_tabs,
            literal,
        });
        self.current.redirects.push(Redirect {
            kind: RedirectKind::Document,
            target: Word::default(),
        });
    }

    fn read_documents(&mut self) {
        for pending in std::mem::take(&mut self.documents) {
            let mut body = String::new();
            while self.pos < self.chars.len() {
                let end = self.line_end(self.pos);
                let line = self.slice(self.pos, end);
                self.pos = (end + 1).min(self.chars.len());
                let line = line.trim_end_matches('\r');
                let line = if pending.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line
                };
                if line == pending.delimiter {
                    break;
                }
                body.push_str(line);
                body.push('\n');
            }
            let opaque = !pending.literal && body.contains(['$', '`']);
            let word = Word {
                raw: body.clone(),
                value: body,
                opaque,
            };
            if let Some(redirect) = self
                .out
                .commands
                .get_mut(pending.command)
                .and_then(|command| command.redirects.get_mut(pending.redirect))
            {
                redirect.target = word;
            }
        }
    }

    fn skip_blanks(&mut self) {
        while self.peek(0).is_some_and(|c| c == ' ' || c == '\t') {
            self.pos += 1;
        }
    }

    fn at_word(&self) -> bool {
        self.peek(0).is_some_and(|c| !self.is_delimiter(c))
    }

    fn is_delimiter(&self, c: char) -> bool {
        match self.dialect {
            Dialect::Bash => matches!(
                c,
                ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
            ),
            Dialect::PowerShell => {
                matches!(
                    c,
                    ' ' | '\t' | '\r' | '\n' | ';' | '&' | '|' | '(' | ')' | '>' | '{' | '}'
                )
            }
        }
    }

    fn read_word(&mut self) -> Word {
        let start = self.pos;
        let mut value = String::new();
        let mut opaque = false;
        while let Some(c) = self.peek(0) {
            let at_start = self.pos == start;
            if at_start && self.bash() && matches!(c, '<' | '>') && self.peek(1) == Some('(') {
                self.pos += 2;
                let inner = self.substitution_source(self.pos);
                self.out.substitutions.push((inner, Dialect::Bash));
                opaque = true;
                continue;
            }
            if self.is_delimiter(c) {
                break;
            }
            match self.dialect {
                Dialect::Bash => self.bash_char(c, at_start, &mut value, &mut opaque),
                Dialect::PowerShell => self.powershell_char(c, at_start, &mut value, &mut opaque),
            }
        }
        self.pos = self.pos.min(self.chars.len());
        let raw = self.span(start, self.pos).iter().collect();
        Word { value, raw, opaque }
    }

    pub(super) fn expand(&self, name: &str, value: &mut String, opaque: &mut bool) {
        let simple =
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        match (simple, simple.then(|| (self.resolve)(name)).flatten()) {
            (true, Some(resolved)) => value.push_str(&resolved),
            _ => *opaque = true,
        }
    }

    pub(super) fn take_name(&mut self, scoped: bool) -> String {
        let mut name = String::new();
        while let Some(c) = self.peek(0) {
            if c.is_ascii_alphanumeric() || c == '_' || (scoped && c == ':') {
                name.push(c);
                self.pos += 1;
            } else {
                break;
            }
        }
        name
    }

    pub(super) fn take_until(&mut self, close: char) -> String {
        let mut text = String::new();
        let mut depth = 1usize;
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            match c {
                '{' => depth += 1,
                c if c == close => {
                    depth -= 1;
                    if depth == 0 {
                        return text;
                    }
                }
                _ => {}
            }
            text.push(c);
        }
        text
    }

    /// The text up to the `)` that closes the substitution opened before `from`; moves past it.
    pub(super) fn substitution_source(&mut self, from: usize) -> String {
        let end = find_close(&self.chars, from, self.dialect).unwrap_or(self.chars.len());
        self.pos = (end + 1).min(self.chars.len());
        self.span(from, end).iter().collect()
    }

    /// Records a `$(...)` source and returns its literal value when it is a `cat` here-document,
    /// the form commit messages take.
    pub(super) fn substitute(&mut self, inner: &str) -> Option<String> {
        self.out
            .substitutions
            .push((inner.to_owned(), self.dialect));
        if self.depth >= self.max_depth {
            return None;
        }
        let nested = scan(
            inner,
            self.dialect,
            self.resolve,
            self.depth + 1,
            self.max_depth,
        );
        let [only] = nested.commands.as_slice() else {
            return None;
        };
        let is_cat = matches!(only.words.as_slice(), [word] if word.value == "cat" && !word.opaque);
        let [document] = only.redirects.as_slice() else {
            return None;
        };
        let literal = is_cat
            && nested.substitutions.is_empty()
            && document.kind == RedirectKind::Document
            && !document.target.opaque;
        literal.then(|| document.target.value.trim_end_matches('\n').to_owned())
    }
}

/// Scans `source` into simple commands. `depth` counts nested substitutions, which stop being
/// read at `max_depth`.
pub fn scan(
    source: &str,
    dialect: Dialect,
    resolve: Resolve,
    depth: usize,
    max_depth: usize,
) -> Scanned {
    let mut lexer = Lexer {
        chars: source.chars().collect(),
        pos: 0,
        dialect,
        resolve,
        depth,
        max_depth,
        out: Scanned::default(),
        current: Simple::default(),
        pipe_pending: false,
        documents: Vec::new(),
    };
    lexer.run();
    lexer.out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPTH: usize = 8;

    fn none(_: &str) -> Option<String> {
        None
    }

    fn bash(source: &str) -> Scanned {
        scan(source, Dialect::Bash, &none, 0, DEPTH)
    }

    fn values(simple: &Simple) -> Vec<&str> {
        simple
            .words
            .iter()
            .map(|word| word.value.as_str())
            .collect()
    }

    #[test]
    fn quotes_operators_and_pipes() {
        let scanned = bash("git commit -m 'a b' && echo \"x $y\" | sh; ls");
        assert_eq!(scanned.commands.len(), 4);
        assert_eq!(
            values(&scanned.commands[0]),
            vec!["git", "commit", "-m", "a b"]
        );
        assert!(scanned.commands[1].words[1].opaque);
        assert!(scanned.commands[2].after_pipe);
        assert!(!scanned.commands[3].after_pipe);
    }

    #[test]
    fn heredoc_commit_message_is_literal() {
        let source =
            "git commit -m \"$(cat <<'EOF'\nfix(kit): don't (ever) loop\n\nMore detail.\nEOF\n)\"";
        let scanned = bash(source);
        assert_eq!(scanned.commands.len(), 1);
        let message = &scanned.commands[0].words[3];
        assert!(!message.opaque, "{message:?}");
        assert_eq!(message.value, "fix(kit): don't (ever) loop\n\nMore detail.");
    }

    #[test]
    fn redirects_and_documents() {
        let scanned = bash("cat > Cargo.toml <<EOF\nx = $HOME\nEOF\necho hi 2>&1 >> out.log");
        let first = &scanned.commands[0];
        assert_eq!(first.redirects[0].kind, RedirectKind::Write);
        assert_eq!(first.redirects[0].target.value, "Cargo.toml");
        assert_eq!(first.redirects[1].kind, RedirectKind::Document);
        assert!(first.redirects[1].target.opaque);
        let second = &scanned.commands[1];
        assert_eq!(values(second), vec!["echo", "hi"]);
        assert_eq!(second.redirects[0].kind, RedirectKind::Duplicate);
        assert_eq!(second.redirects[1].target.value, "out.log");
    }

    #[test]
    fn substitutions_are_recorded_and_variables_resolve() {
        let resolve = |name: &str| (name == "HOME").then(|| "/home/dev".to_owned());
        let scanned = scan(
            "echo $(git push --force) ~/x \"$HOME/y\" `id`",
            Dialect::Bash,
            &resolve,
            0,
            DEPTH,
        );
        assert_eq!(scanned.substitutions.len(), 2);
        assert_eq!(scanned.substitutions[0].0, "git push --force");
        let words = &scanned.commands[0].words;
        assert!(words[1].opaque);
        assert_eq!(words[2].value, "/home/dev/x");
        assert_eq!(words[3].value, "/home/dev/y");
        assert!(!words[3].opaque);
    }

    #[test]
    fn powershell_quoting_and_here_strings() {
        let source = "git commit -m @'\nfeat: x\n\nMore detail.\n'@; Set-Content -Path \"Cargo.toml\" -Value `\"a`\"";
        let scanned = scan(source, Dialect::PowerShell, &none, 0, DEPTH);
        assert_eq!(scanned.commands.len(), 2);
        assert_eq!(
            scanned.commands[0].words[3].value,
            "feat: x\n\nMore detail."
        );
        assert_eq!(
            values(&scanned.commands[1]),
            vec!["Set-Content", "-Path", "Cargo.toml", "-Value", "\"a\""]
        );
        let call = scan(
            "& 'C:\\Program Files\\Git\\cmd\\git.exe' push",
            Dialect::PowerShell,
            &none,
            0,
            DEPTH,
        );
        assert_eq!(
            values(&call.commands[0]),
            vec!["C:\\Program Files\\Git\\cmd\\git.exe", "push"]
        );
        let block = scan(
            "1..3 | ForEach-Object { git push --force }",
            Dialect::PowerShell,
            &none,
            0,
            DEPTH,
        );
        assert!(
            block
                .commands
                .iter()
                .any(|c| values(c) == vec!["git", "push", "--force"])
        );
    }
}
