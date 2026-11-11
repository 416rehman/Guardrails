//! What the checks read besides the file: the three protected files that relax checks, in the
//! format their headers document, the kit's limits, the brand and vendor names S7 looks for and
//! the interface checks' configuration. All of it comes from the comparison base, so a change
//! cannot relax the check that judges it (team/05 section 2). The relaxing files are
//! `quality/file-size.toml` (the S1 ratchet, whose `code_lines` may only fall),
//! `quality/state-machine-exemptions.toml` (true S4 false positives keyed by path, type and
//! pattern) and `quality/hardcoded-exemptions.toml` (true S6 and S7 exceptions keyed by path,
//! check and value).

use anyhow::Result;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::hardcoded::Names;
use super::{Check, Key};
use crate::config::limits::{Limits, StructureLimits};
use crate::config::parse_toml;
use crate::gates::interface::Interface;
use crate::git::{self, Base};
use crate::repo::Repo;

pub const FILE_SIZE_PATH: &str = "quality/file-size.toml";
pub const EXEMPTIONS_PATH: &str = "quality/state-machine-exemptions.toml";
pub const HARDCODED_EXEMPTIONS_PATH: &str = "quality/hardcoded-exemptions.toml";

/// The S4 rule a finding broke, as an exemption names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Pattern {
    /// Three or more `bool` fields in one type.
    BoolFields,
    /// A `state`, `status`, `phase`, `stage` or `mode` field held as a string, integer or `bool`.
    StatusField,
    /// `Option` fields of one type whose presence is checked together.
    OptionGroup,
}

/// The checks `quality/hardcoded-exemptions.toml` may relax.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum HardcodedCheck {
    S6,
    S7,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSizeEntry {
    pub path: String,
    pub code_lines: usize,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSizeRatchet {
    #[serde(default)]
    pub files: Vec<FileSizeEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exemption {
    pub path: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub pattern: Pattern,
    pub reason: String,
    pub requested_in: String,
    pub added_by: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardcodedExemption {
    pub path: String,
    pub check: HardcodedCheck,
    /// The construct or literal exactly as the finding quotes it.
    pub value: String,
    pub reason: String,
    pub requested_in: String,
    pub added_by: String,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub ratchet: FileSizeRatchet,
    pub exemptions: Vec<Exemption>,
    pub hardcoded: Vec<HardcodedExemption>,
    pub limits: StructureLimits,
    pub names: Names,
    pub interface: Interface,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExemptionFile {
    #[serde(default)]
    exemptions: Vec<Exemption>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HardcodedFile {
    #[serde(default)]
    exemptions: Vec<HardcodedExemption>,
}

impl HardcodedCheck {
    fn is(self, check: Check) -> bool {
        matches!(
            (self, check),
            (HardcodedCheck::S6, Check::S6) | (HardcodedCheck::S7, Check::S7)
        )
    }
}

impl Policy {
    /// The base commit's copies, or the working tree's while the base has none.
    pub fn load(repo: &Repo, base: &Base) -> Result<Policy> {
        let ratchet = read_or_default::<FileSizeRatchet>(repo, base, FILE_SIZE_PATH)?;
        let exemptions = read_or_default::<ExemptionFile>(repo, base, EXEMPTIONS_PATH)?.exemptions;
        let hardcoded =
            read_or_default::<HardcodedFile>(repo, base, HARDCODED_EXEMPTIONS_PATH)?.exemptions;
        Ok(Policy {
            ratchet,
            exemptions,
            hardcoded,
            limits: Limits::load(repo, base)?.gates.structure,
            names: Names::load(repo, base)?,
            interface: Interface::load(repo, base)?,
        })
    }

    pub fn allowed_lines(&self, path: &str) -> Option<usize> {
        self.ratchet
            .files
            .iter()
            .find(|entry| entry.path == path)
            .map(|entry| entry.code_lines)
    }

    pub(crate) fn exempt(&self, path: &str, check: Check, key: &Key) -> bool {
        match key {
            Key::State { type_name, pattern } => self.exemptions.iter().any(|exemption| {
                exemption.path == path
                    && exemption.type_name == *type_name
                    && exemption.pattern == *pattern
            }),
            Key::Value(value) => self.hardcoded.iter().any(|exemption| {
                exemption.path == path && exemption.check.is(check) && exemption.value == *value
            }),
        }
    }
}

impl FileSizeRatchet {
    /// Entries added or raised since `base`: the ratchet may only fall.
    pub fn loosened_since(&self, base: &FileSizeRatchet) -> Vec<String> {
        self.files
            .iter()
            .filter_map(|entry| {
                let before = base.files.iter().find(|old| old.path == entry.path);
                match before {
                    None => Some(format!(
                        "`{}` was added to {FILE_SIZE_PATH} at {} code lines",
                        entry.path, entry.code_lines
                    )),
                    Some(old) if entry.code_lines > old.code_lines => Some(format!(
                        "`{}` was raised in {FILE_SIZE_PATH} from {} to {} code lines",
                        entry.path, old.code_lines, entry.code_lines
                    )),
                    Some(_) => None,
                }
            })
            .collect()
    }

    pub fn from_working_tree(repo: &Repo) -> Result<Option<FileSizeRatchet>> {
        repo.read_optional(FILE_SIZE_PATH)?
            .map(|text| parse_toml(&text, FILE_SIZE_PATH))
            .transpose()
    }
}

/// With a base commit, only its copy counts; a file the writer added is not yet policy.
pub(crate) fn read(repo: &Repo, base: &Base, path: &str) -> Result<Option<String>> {
    match base.commit() {
        Some(commit) => git::show(repo, commit, path),
        None => repo.read_optional(path),
    }
}

/// `path` as [`read`] finds it, parsed, or the default value when there is no such file.
pub(crate) fn read_or_default<T: DeserializeOwned + Default>(
    repo: &Repo,
    base: &Base,
    path: &str,
) -> Result<T> {
    let parsed = read(repo, base, path)?
        .map(|text| parse_toml(&text, path))
        .transpose()?;
    Ok(parsed.unwrap_or_default())
}

#[cfg(test)]
impl Policy {
    /// The shipped limits, no names, no exemptions and no interface configuration.
    pub fn for_tests() -> Policy {
        Policy {
            ratchet: FileSizeRatchet::default(),
            exemptions: Vec::new(),
            hardcoded: Vec::new(),
            limits: Limits::built_with().unwrap().gates.structure.clone(),
            names: Names::default(),
            interface: Interface::Unconfigured("no configuration in this test".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_empty_files_parse() {
        let ratchet: FileSizeRatchet =
            parse_toml("# header\nfiles = []\n", FILE_SIZE_PATH).unwrap();
        assert!(ratchet.files.is_empty());
        let exemptions: ExemptionFile = parse_toml("exemptions = []\n", EXEMPTIONS_PATH).unwrap();
        assert!(exemptions.exemptions.is_empty());
        let shipped = include_str!("../../../../quality/hardcoded-exemptions.toml");
        let hardcoded: HardcodedFile = parse_toml(shipped, HARDCODED_EXEMPTIONS_PATH).unwrap();
        assert!(hardcoded.exemptions.is_empty());
    }

    #[test]
    fn ratchet_may_only_fall() {
        let base: FileSizeRatchet = parse_toml(
            "files = [{ path = \"a.rs\", code_lines = 600 }, { path = \"b.rs\", code_lines = 700 }]\n",
            "base",
        )
        .unwrap();
        let now: FileSizeRatchet = parse_toml(
            "files = [\n  { path = \"a.rs\", code_lines = 590 },\n  { path = \"b.rs\", code_lines = 710 },\n  { path = \"c.rs\", code_lines = 501 },\n]\n",
            "now",
        )
        .unwrap();
        let loosened = now.loosened_since(&base);
        assert_eq!(loosened.len(), 2);
        assert!(loosened[0].contains("b.rs"));
        assert!(loosened[1].contains("c.rs"));
        let mut policy = Policy::for_tests();
        policy.ratchet = now;
        assert_eq!(policy.allowed_lines("a.rs"), Some(590));
    }

    #[test]
    fn exemptions_match_path_type_and_pattern() {
        let file: ExemptionFile = parse_toml(
            "exemptions = [{ path = \"a.rs\", type = \"Flags\", pattern = \"bool-fields\", reason = \"switches\", requested_in = \"#12\", added_by = \"lead-agent-kit\" }]\n",
            EXEMPTIONS_PATH,
        )
        .unwrap();
        let mut policy = Policy::for_tests();
        policy.exemptions = file.exemptions;
        let key = |type_name: &str, pattern| Key::State {
            type_name: type_name.into(),
            pattern,
        };
        assert!(policy.exempt("a.rs", Check::S4, &key("Flags", Pattern::BoolFields)));
        assert!(!policy.exempt("a.rs", Check::S4, &key("Flags", Pattern::StatusField)));
        assert!(!policy.exempt("a.rs", Check::S4, &key("Other", Pattern::BoolFields)));
        let unknown = "exemptions = [{ path = \"a.rs\", type = \"F\", pattern = \"anything\", reason = \"r\", requested_in = \"#1\", added_by = \"x\" }]\n";
        assert!(parse_toml::<ExemptionFile>(unknown, EXEMPTIONS_PATH).is_err());
    }

    #[test]
    fn hardcoded_exemptions_match_path_check_and_value() {
        let file: HardcodedFile = parse_toml(
            "exemptions = [{ path = \"a.rs\", check = \"S7\", value = \"0.0.0.0\", reason = \"the unspecified address is the meaning, not a host\", requested_in = \"#9\", added_by = \"lead-agent-kit\" }]\n",
            HARDCODED_EXEMPTIONS_PATH,
        )
        .unwrap();
        let mut policy = Policy::for_tests();
        policy.hardcoded = file.exemptions;
        let value = Key::Value("0.0.0.0".into());
        assert!(policy.exempt("a.rs", Check::S7, &value));
        assert!(!policy.exempt("a.rs", Check::S6, &value));
        assert!(!policy.exempt("b.rs", Check::S7, &value));
        let s3 = "exemptions = [{ path = \"a.rs\", check = \"S3\", value = \"x\", reason = \"r\", requested_in = \"#1\", added_by = \"x\" }]\n";
        assert!(parse_toml::<HardcodedFile>(s3, HARDCODED_EXEMPTIONS_PATH).is_err());
    }
}
