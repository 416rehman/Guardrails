//! The YAML front matter of agent definitions and skills, read strictly enough to validate it:
//! top-level `key: value` lines, quoted scalars, and indented blocks (lists, nested maps, folded
//! text) attached to the key above them. Anything else at column zero is an error.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub key: String,
    pub line: usize,
    /// The scalar after `key:`, unquoted; empty when the value is an indented block.
    pub value: String,
    /// The text after `key:` as written, quotes included.
    pub raw: String,
    pub block: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontMatter {
    pub fields: Vec<Field>,
    /// 1-based line where the body starts, after the closing `---`.
    pub body_line: usize,
}

impl Field {
    /// Keys of an indented map under this field (`metadata:` with `version: "1"` below it).
    pub fn nested_keys(&self) -> Vec<String> {
        self.block
            .iter()
            .filter_map(|line| {
                let indented = line.starts_with(char::is_whitespace);
                let (key, _) = line.trim_start().split_once(':')?;
                (indented && !key.starts_with('-') && !key.contains(' ')).then(|| key.to_owned())
            })
            .collect()
    }

    /// Items of an indented `- item` list, or of an inline comma-separated scalar.
    pub fn list(&self) -> Vec<String> {
        let items: Vec<String> = self
            .block
            .iter()
            .filter_map(|line| line.trim_start().strip_prefix("- "))
            .map(|item| unquote(item.trim()))
            .collect();
        if !items.is_empty() {
            return items;
        }
        let inline = self
            .value
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');
        inline
            .split(',')
            .map(|item| unquote(item.trim()))
            .filter(|item| !item.is_empty())
            .collect()
    }
}

impl FrontMatter {
    pub fn get(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|field| field.key == key)
    }

    pub fn value(&self, key: &str) -> Option<&str> {
        self.get(key).map(|field| field.value.as_str())
    }
}

/// `Ok(None)` when the text has no front matter; `Err` names the first malformed line.
pub fn parse(text: &str) -> Result<Option<FrontMatter>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines = text.lines().enumerate();
    match lines.next() {
        Some((_, first)) if first.trim_end() == "---" => {}
        _ => return Ok(None),
    }
    let mut fields: Vec<Field> = Vec::new();
    for (index, line) in lines {
        let number = index + 1;
        if line.trim_end() == "---" {
            return check_duplicates(fields).map(|fields| {
                Some(FrontMatter {
                    fields,
                    body_line: number + 1,
                })
            });
        }
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if line.starts_with([' ', '\t', '-']) {
            let Some(field) = fields.last_mut() else {
                return Err(format!("line {number}: indented text before any key"));
            };
            field.block.push(line.to_owned());
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(format!("line {number}: expected `key: value`"));
        };
        let valid_key = !key.is_empty()
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !valid_key {
            return Err(format!("line {number}: `{key}` is not a key"));
        }
        let value = value.trim();
        let scalar = if matches!(value, ">" | "|" | ">-" | "|-") {
            String::new()
        } else {
            unquote(value)
        };
        fields.push(Field {
            key: key.to_owned(),
            line: number,
            value: scalar,
            raw: value.to_owned(),
            block: Vec::new(),
        });
    }
    Err("front matter is not closed by `---`".to_owned())
}

fn check_duplicates(fields: Vec<Field>) -> Result<Vec<Field>, String> {
    for (index, field) in fields.iter().enumerate() {
        if fields
            .iter()
            .take(index)
            .any(|earlier| earlier.key == field.key)
        {
            return Err(format!(
                "line {}: `{}` appears twice",
                field.line, field.key
            ));
        }
    }
    Ok(fields)
}

fn unquote(value: &str) -> String {
    if let Some(inner) = value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    {
        return serde_json::from_str::<String>(value).unwrap_or_else(|_| inner.to_owned());
    }
    if let Some(inner) = value
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
    {
        return inner.replace("''", "'");
    }
    value.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SKILL: &str = "---\nname: grdr-fix-bug\ndescription: \"Fix a bug: reproduce first.\"\nlicense: Apache-2.0\nmetadata:\n  version: \"1\"\n  closes-by: test\nskills:\n  - a\n  - 'b'\n---\n\n# Body\n";

    #[test]
    fn parses_fields_blocks_and_body_line() {
        let front = parse(SKILL).unwrap().unwrap();
        assert_eq!(front.value("name"), Some("grdr-fix-bug"));
        assert_eq!(
            front.value("description"),
            Some("Fix a bug: reproduce first.")
        );
        assert_eq!(
            front.get("metadata").unwrap().nested_keys(),
            vec!["version", "closes-by"]
        );
        assert_eq!(front.get("skills").unwrap().list(), vec!["a", "b"]);
        assert_eq!(front.body_line, 12);
    }

    #[test]
    fn inline_lists_and_missing_front_matter() {
        let front = parse("---\ntools: Read, Grep, Glob\n---\n")
            .unwrap()
            .unwrap();
        assert_eq!(
            front.get("tools").unwrap().list(),
            vec!["Read", "Grep", "Glob"]
        );
        assert_eq!(parse("# no front matter\n").unwrap(), None);
    }

    #[test]
    fn malformed_front_matter_is_an_error() {
        assert!(parse("---\nname x\n---\n").is_err());
        assert!(parse("---\nname: a\nname: b\n---\n").is_err());
        assert!(parse("---\nname: a\n").is_err());
        assert!(parse("---\n  stray\n---\n").is_err());
    }
}
