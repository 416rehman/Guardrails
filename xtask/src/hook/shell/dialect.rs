//! The per-dialect word readers of the lexer: Bash quoting, `$` expansions, ANSI-C strings and
//! backticks, and PowerShell quoting, here-strings and `$env:` variables, as methods on the
//! shared [`Lexer`].

use super::lexer::{Dialect, Lexer};

impl Lexer<'_> {
    pub(super) fn bash_char(
        &mut self,
        c: char,
        at_start: bool,
        value: &mut String,
        opaque: &mut bool,
    ) {
        match c {
            '\'' => {
                self.pos += 1;
                while let Some(ch) = self.peek(0) {
                    self.pos += 1;
                    if ch == '\'' {
                        return;
                    }
                    value.push(ch);
                }
                *opaque = true;
            }
            '"' => self.double_quoted(value, opaque),
            '\\' => self.escaped(value),
            '$' => self.dollar(value, opaque, false),
            '`' => self.backtick(opaque),
            '~' if at_start && matches!(self.peek(1), None | Some('/')) => {
                match (self.resolve)("HOME") {
                    Some(home) => value.push_str(&home),
                    None => value.push('~'),
                }
                self.pos += 1;
            }
            _ => {
                value.push(c);
                self.pos += 1;
            }
        }
    }

    /// The character after an escape; an escaped newline continues the line and adds nothing.
    fn escaped(&mut self, value: &mut String) {
        if let Some(next) = self.peek(1)
            && next != '\n'
        {
            value.push(next);
        }
        self.pos += 2;
    }

    pub(super) fn double_quoted(&mut self, value: &mut String, opaque: &mut bool) {
        self.pos += 1;
        while let Some(c) = self.peek(0) {
            match c {
                '"' => {
                    self.pos += 1;
                    return;
                }
                '\\' => match self.peek(1) {
                    Some(next @ ('"' | '\\' | '$' | '`')) => {
                        value.push(next);
                        self.pos += 2;
                    }
                    Some('\n') => self.pos += 2,
                    _ => {
                        value.push('\\');
                        self.pos += 1;
                    }
                },
                '$' => self.dollar(value, opaque, true),
                '`' => self.backtick(opaque),
                _ => {
                    value.push(c);
                    self.pos += 1;
                }
            }
        }
        *opaque = true;
    }

    fn dollar(&mut self, value: &mut String, opaque: &mut bool, quoted: bool) {
        match (self.peek(1), self.peek(2)) {
            (Some('('), Some('(')) => {
                self.pos += 2;
                let _ = self.substitution_source(self.pos);
                *opaque = true;
            }
            (Some('('), _) => {
                self.pos += 2;
                let inner = self.substitution_source(self.pos);
                match self.substitute(&inner) {
                    Some(text) => value.push_str(&text),
                    None => *opaque = true,
                }
            }
            (Some('{'), _) => {
                self.pos += 2;
                let name = self.take_until('}');
                self.expand(&name, value, opaque);
            }
            (Some('\''), _) if !quoted => {
                self.pos += 2;
                self.ansi_c(value);
            }
            (Some('"'), _) if !quoted => {
                self.pos += 1;
                self.double_quoted(value, opaque);
            }
            (Some(ch), _) if ch.is_ascii_alphabetic() || ch == '_' => {
                self.pos += 1;
                let name = self.take_name(false);
                self.expand(&name, value, opaque);
            }
            (Some(ch), _) if ch.is_ascii_digit() || "@*#?$!-".contains(ch) => {
                self.pos += 2;
                *opaque = true;
            }
            _ => {
                value.push('$');
                self.pos += 1;
            }
        }
    }

    fn ansi_c(&mut self, value: &mut String) {
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            match c {
                '\'' => return,
                '\\' => {
                    let Some(next) = self.peek(0) else {
                        return;
                    };
                    value.push(control_character(next));
                    self.pos += 1;
                }
                other => value.push(other),
            }
        }
    }

    fn backtick(&mut self, opaque: &mut bool) {
        self.pos += 1;
        let mut inner = String::new();
        while let Some(c) = self.peek(0) {
            self.pos += 1;
            match c {
                '`' => break,
                '\\' if self.peek(0) == Some('`') => {
                    inner.push('`');
                    self.pos += 1;
                }
                other => inner.push(other),
            }
        }
        self.out.substitutions.push((inner, self.dialect));
        *opaque = true;
    }

    pub(super) fn powershell_char(
        &mut self,
        c: char,
        at_start: bool,
        value: &mut String,
        opaque: &mut bool,
    ) {
        match c {
            '\'' => {
                self.pos += 1;
                while let Some(ch) = self.peek(0) {
                    self.pos += 1;
                    if ch == '\'' {
                        if self.peek(0) == Some('\'') {
                            value.push('\'');
                            self.pos += 1;
                            continue;
                        }
                        return;
                    }
                    value.push(ch);
                }
                *opaque = true;
            }
            '"' => self.powershell_double(value, opaque),
            '@' if at_start && matches!(self.peek(1), Some('\'' | '"')) => {
                self.here_string(value, opaque)
            }
            '`' => self.escaped(value),
            '$' => self.powershell_dollar(value, opaque),
            _ => {
                value.push(c);
                self.pos += 1;
            }
        }
    }

    fn powershell_double(&mut self, value: &mut String, opaque: &mut bool) {
        self.pos += 1;
        while let Some(c) = self.peek(0) {
            match c {
                '"' if self.peek(1) == Some('"') => {
                    value.push('"');
                    self.pos += 2;
                }
                '"' => {
                    self.pos += 1;
                    return;
                }
                '`' => {
                    let Some(next) = self.peek(1) else {
                        break;
                    };
                    value.push(control_character(next));
                    self.pos += 2;
                }
                '$' => self.powershell_dollar(value, opaque),
                _ => {
                    value.push(c);
                    self.pos += 1;
                }
            }
        }
        *opaque = true;
    }

    fn here_string(&mut self, value: &mut String, opaque: &mut bool) {
        let quote = self.peek(1).unwrap_or('\'');
        let closing = [quote, '@'];
        self.pos += 2;
        self.skip_line();
        self.pos = (self.pos + 1).min(self.len());
        let mut lines: Vec<String> = Vec::new();
        while self.pos < self.len() {
            let start = self.pos;
            if self.starts_with(&closing) {
                self.pos = start + 2;
                break;
            }
            let end = self.line_end(start);
            lines.push(self.slice(start, end).trim_end_matches('\r').to_owned());
            self.pos = (end + 1).min(self.len());
        }
        let body = lines.join("\n");
        if quote == '"' && body.contains('$') {
            *opaque = true;
        }
        value.push_str(&body);
    }

    fn powershell_dollar(&mut self, value: &mut String, opaque: &mut bool) {
        match self.peek(1) {
            Some('(') => {
                self.pos += 2;
                let inner = self.substitution_source(self.pos);
                self.out.substitutions.push((inner, Dialect::PowerShell));
                *opaque = true;
            }
            Some('{') => {
                self.pos += 2;
                let name = self.take_until('}');
                self.powershell_variable(&name, value, opaque);
            }
            Some(ch) if ch.is_ascii_alphabetic() || ch == '_' => {
                self.pos += 1;
                let name = self.take_name(true);
                self.powershell_variable(&name, value, opaque);
            }
            _ => {
                value.push('$');
                self.pos += 1;
            }
        }
    }

    fn powershell_variable(&self, name: &str, value: &mut String, opaque: &mut bool) {
        let lower = name.to_ascii_lowercase();
        let variable = match lower.strip_prefix("env:") {
            Some(_) => name.get("env:".len()..).unwrap_or_default().to_owned(),
            None if lower == "home" || lower == "pwd" => lower.to_ascii_uppercase(),
            None => {
                *opaque = true;
                return;
            }
        };
        self.expand(&variable, value, opaque);
    }
}

/// What an escaped letter stands for in an ANSI-C or PowerShell string: `n`, `t`, `r` and `0`
/// are control characters, any other character is itself.
fn control_character(letter: char) -> char {
    match letter {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        '0' => '\0',
        other => other,
    }
}
