//! `audits/library.toml` and the prompt files (team/04 section 1, `audits/README.md`), read from
//! the base commit so a change cannot rewrite its own audits. An entry is merged over
//! `[defaults]`; its prompt file's front matter must agree with it, and every model it names must
//! be on `[rules] allowed_models` and resolve through `.agents/models.toml`.

use anyhow::{Context, Result, bail};

use super::check::FindingFormat;
use crate::config::models::Models;
use crate::frontmatter;
use crate::git::{Base, read_at};
use crate::repo::Repo;

pub const LIBRARY: &str = "audits/library.toml";
const AUDITS_DIR: &str = "audits";
const CONCEPT_LINE: &str = "Concept:";
const CLASS_KEYS_LINE: &str = "Class keys:";
pub const INJECTED_INSTRUCTION: &str = "injected-instruction";
const SECURITY_THEME: &str = "security";

/// One prompt, merged over the defaults and checked against its file.
#[derive(Debug, Clone)]
pub struct Entry {
    pub id: String,
    pub name: String,
    pub version: String,
    pub theme: String,
    pub paths: Vec<String>,
    pub closes_by: Vec<String>,
    pub blocking: Option<String>,
    pub finder_model: String,
    pub verifier_model: String,
    pub second_verifier_model: String,
    pub finder_turns: u32,
    pub verifier_turns: u32,
    pub max_findings: usize,
    pub class_keys: Vec<String>,
    pub concept: String,
    pub control_concept: String,
    pub prompt_text: String,
    pub preamble: String,
    pub verifier: String,
    pub format: FindingFormat,
    pub embargo_severity: Option<i64>,
    pub embargo_themes: Vec<String>,
}

impl Entry {
    /// The entry for `id`, with its texts, from the library at `base`.
    pub fn load(repo: &Repo, base: &Base, models: &Models, id: &str) -> Result<Entry> {
        let (text, source) = read_at(repo, base, LIBRARY)?;
        let library: toml::Table =
            crate::config::parse_toml(&text.context("audits/library.toml is missing")?, &source)?;
        let defaults = library
            .get("defaults")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let entry = library
            .get("prompt")
            .and_then(toml::Value::as_array)
            .and_then(|prompts| {
                prompts
                    .iter()
                    .find(|p| p.get("id").and_then(toml::Value::as_str) == Some(id))
            })
            .and_then(toml::Value::as_table)
            .with_context(|| format!("{LIBRARY} has no prompt {id}"))?;
        let mut merged = defaults;
        merged.extend(entry.clone());
        let files = library
            .get("files")
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let file = |key: &str| -> Result<String> {
            let relative = files
                .get(key)
                .and_then(toml::Value::as_str)
                .with_context(|| format!("{LIBRARY} [files] has no {key}"))?
                .replace("{id}", id);
            let path = format!("{AUDITS_DIR}/{relative}");
            read_at(repo, base, &path)?
                .0
                .with_context(|| format!("{path} is missing"))
        };
        let prompt_text = file("prompt")?;
        let preamble = file("preamble")?;
        let verifier = file("verifier")?;
        let format = FindingFormat::parse(&file("finding_schema")?)?;
        let text_of = |key: &str| {
            merged
                .get(key)
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let list_of = |key: &str| strings(merged.get(key));
        let count = |key: &str| -> Result<u32> {
            merged
                .get(key)
                .and_then(toml::Value::as_integer)
                .and_then(|value| u32::try_from(value).ok())
                .with_context(|| format!("{id}: {key} is not set in {LIBRARY}"))
        };
        let allowed = strings(
            library
                .get("rules")
                .and_then(|rules| rules.get("allowed_models")),
        );
        let model = |key: &str| -> Result<String> {
            let name = text_of(key);
            if !allowed.contains(&name) {
                bail!("{id}: {key} `{name}` is not in [rules] allowed_models");
            }
            models
                .id(&name)
                .map(str::to_owned)
                .with_context(|| format!(".agents/models.toml binds no `{name}`"))
        };
        let theme = text_of("theme");
        let finder_key = if theme == SECURITY_THEME && merged.contains_key("security_finder_model")
        {
            "security_finder_model"
        } else {
            "finder_model"
        };
        let embargo = library.get("embargo");
        let entry = Entry {
            id: id.to_owned(),
            name: text_of("name"),
            version: text_of("version"),
            paths: list_of("paths"),
            closes_by: list_of("closes-by"),
            blocking: merged
                .get("blocking")
                .and_then(toml::Value::as_str)
                .map(str::to_owned),
            finder_model: model(finder_key)?,
            verifier_model: model("verifier_model")?,
            second_verifier_model: model("second_verifier_model")?,
            finder_turns: count("finder_max_turns")?,
            verifier_turns: count("verifier_max_turns")?,
            max_findings: usize::try_from(count("max_findings")?)?,
            class_keys: class_keys(&prompt_text),
            concept: after_line(&prompt_text, CONCEPT_LINE)
                .with_context(|| format!("{id}: the prompt file has no `Concept:` line"))?,
            control_concept: text_of("control_concept"),
            embargo_severity: embargo
                .and_then(|e| e.get("severity"))
                .and_then(toml::Value::as_integer),
            embargo_themes: strings(embargo.and_then(|e| e.get("themes"))),
            theme,
            prompt_text,
            preamble,
            verifier,
            format,
        };
        entry.check_front_matter()?;
        Ok(entry)
    }

    /// The prompt file's front matter agrees with the entry (`audits/README.md`, step 1).
    pub fn check_front_matter(&self) -> Result<()> {
        let parsed = frontmatter::parse(&self.prompt_text)
            .map_err(|error| anyhow::anyhow!("{}: front matter: {error}", self.id))?;
        let Some(front) = parsed else {
            bail!("{}: the prompt file has no front matter", self.id);
        };
        let expected = format!("audit-{}-{}", self.id.to_ascii_lowercase(), self.name);
        if front.value("name") != Some(expected.as_str()) {
            bail!("{}: front matter name is not `{expected}`", self.id);
        }
        let metadata = flow_map(front.value("metadata").unwrap_or_default());
        let metadata_value = |key: &str| {
            metadata
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.as_str())
        };
        if metadata_value("version") != Some(self.version.as_str()) {
            bail!("{}: metadata.version is not {}", self.id, self.version);
        }
        let closes = metadata_value("closes-by").map(list_values);
        if closes.as_ref() != Some(&self.closes_by) {
            bail!(
                "{}: metadata.closes-by is not [{}]",
                self.id,
                self.closes_by.join(", ")
            );
        }
        Ok(())
    }

    pub fn major(&self) -> &str {
        self.version.split('.').next().unwrap_or_default()
    }

    /// A result is a security candidate: never an issue, comment or pull request (D-62).
    pub fn is_security_candidate(&self, severity: i64) -> bool {
        self.embargo_severity.is_some_and(|limit| severity <= limit)
            || self.embargo_themes.contains(&self.theme)
    }

    /// The preamble with the run's values filled in, ending with its `Concept:` line.
    pub fn fill_preamble(&self, scope: &str, commit: &str, run_id: &str, out: &str) -> String {
        self.preamble
            .replace("{prompt_id}", &self.id)
            .replace("{scope}", scope)
            .replace("{commit}", commit)
            .replace("{run_id}", run_id)
            .replace("{out}", out)
    }
}

fn strings(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Everything after the first line that is exactly `marker`.
pub fn after_line(text: &str, marker: &str) -> Option<String> {
    let mut lines = text.lines();
    lines.by_ref().find(|line| line.trim() == marker)?;
    Some(lines.collect::<Vec<_>>().join("\n").trim().to_owned())
}

/// The backticked keys of the `Class keys:` line.
pub fn class_keys(text: &str) -> Vec<String> {
    let Some(line) = text
        .lines()
        .find(|line| line.trim_start().starts_with(CLASS_KEYS_LINE))
    else {
        return Vec::new();
    };
    line.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// `{ version: 1.0.0, owner: agent-kit, closes-by: [type] }` as key and value pairs.
fn flow_map(text: &str) -> Vec<(String, String)> {
    let inner = text.trim().trim_start_matches('{').trim_end_matches('}');
    let mut pairs = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for c in inner.chars().chain(std::iter::once(',')) {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            _ => {}
        }
        if c == ',' && depth == 0 {
            if let Some((key, value)) = current.split_once(':') {
                pairs.push((
                    key.trim().to_owned(),
                    value.trim().trim_matches('"').to_owned(),
                ));
            }
            current.clear();
        } else {
            current.push(c);
        }
    }
    pairs
}

fn list_values(text: &str) -> Vec<String> {
    text.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|item| item.trim().trim_matches('"').to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_files_yield_their_parts() {
        let text = "---\nname: audit-a01-implicit-state-machines\nmetadata: { version: 1.0.0, owner: agent-kit, closes-by: [type, test] }\n---\n# A01\n\nConcept:\nFind every lifecycle in {scope}.\n\nClass keys: `implicit-state:exclusive-bools`, `implicit-state:no-exit`.\n";
        assert_eq!(
            after_line(text, "Concept:").unwrap().lines().next(),
            Some("Find every lifecycle in {scope}.")
        );
        assert_eq!(
            class_keys(text),
            vec!["implicit-state:exclusive-bools", "implicit-state:no-exit"]
        );
        let pairs = flow_map("{ version: 1.0.0, owner: agent-kit, closes-by: [type, test] }");
        assert_eq!(
            pairs[2],
            ("closes-by".to_owned(), "[type, test]".to_owned())
        );
        assert_eq!(list_values("[type, test]"), vec!["type", "test"]);
    }
}
