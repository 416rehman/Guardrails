//! The brand and vendor names S7 looks for in strings, read as data: the product, short and
//! legal names from `brand/brand.toml` (every string under a key `name`, `*_name`, `entity` or
//! `*_entity`), and the reference vendors from `.agents/kit/vendors.toml` (every `name` and
//! `aliases` entry outside `[sources]`). Either file may be absent; then there is nothing to find.

use anyhow::Result;

use super::super::policy::read_or_default;
use crate::git::Base;
use crate::repo::Repo;

pub const BRAND_PATH: &str = "brand/brand.toml";
pub const VENDORS_PATH: &str = ".agents/kit/vendors.toml";
const SOURCES_TABLE: &str = "sources";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameKind {
    Brand,
    Vendor,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names {
    pub brand: Vec<String>,
    pub vendors: Vec<String>,
}

impl Names {
    pub fn load(repo: &Repo, base: &Base) -> Result<Names> {
        let brand = brand_names(&read_or_default(repo, base, BRAND_PATH)?);
        let vendors = vendor_names(&read_or_default(repo, base, VENDORS_PATH)?);
        Ok(Names { brand, vendors })
    }

    /// The first brand or vendor name in `text` as a whole word, matched case-sensitively, so
    /// a lower-case word that happens to share a vendor's name is not a finding.
    pub(crate) fn find(&self, text: &str, kinds: &[NameKind]) -> Option<(NameKind, &str)> {
        let lists = [
            (NameKind::Brand, &self.brand),
            (NameKind::Vendor, &self.vendors),
        ];
        lists
            .into_iter()
            .filter(|(kind, _)| kinds.contains(kind))
            .flat_map(|(kind, names)| names.iter().map(move |name| (kind, name.as_str())))
            .find(|(_, name)| contains_word(text, name))
    }
}

fn brand_names(table: &toml::Table) -> Vec<String> {
    let mut found = Vec::new();
    collect(table.iter(), &mut found, &|key| {
        key == "name" || key.ends_with("_name") || key == "entity" || key.ends_with("_entity")
    });
    found.sort();
    found.dedup();
    found
}

fn vendor_names(table: &toml::Table) -> Vec<String> {
    let mut found = Vec::new();
    let vendors = table.iter().filter(|(key, _)| *key != SOURCES_TABLE);
    collect(vendors, &mut found, &|key| {
        key == "name" || key == "aliases"
    });
    found.sort();
    found.dedup();
    found
}

/// Every non-empty string under a key `wanted` accepts, at any depth below `entries`.
fn collect<'a>(
    entries: impl Iterator<Item = (&'a String, &'a toml::Value)>,
    found: &mut Vec<String>,
    wanted: &dyn Fn(&str) -> bool,
) {
    let mut stack: Vec<(Option<&str>, &toml::Value)> = entries
        .map(|(key, value)| (Some(key.as_str()), value))
        .collect();
    while let Some((key, value)) = stack.pop() {
        match value {
            toml::Value::String(text) if key.is_some_and(wanted) && !text.trim().is_empty() => {
                found.push(text.trim().to_owned());
            }
            toml::Value::Array(items) => stack.extend(items.iter().map(|item| (key, item))),
            toml::Value::Table(inner) => {
                stack.extend(inner.iter().map(|(key, value)| (Some(key.as_str()), value)));
            }
            _ => {}
        }
    }
}

fn contains_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(start, matched)| {
        let before = text.get(..start).and_then(|head| head.chars().next_back());
        let after = text
            .get(start + matched.len()..)
            .and_then(|tail| tail.chars().next());
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_come_from_both_files_and_match_whole_words() {
        let brand: toml::Table = toml::from_str(
            "[product]\nname = \"Acme Shield\"\nshort_name = \"Shield\"\n[company]\nlegal_entity = \"Acme Ltd\"\ndomain = \"shield.example\"\n",
        )
        .unwrap();
        let vendors: toml::Table = toml::from_str(
            "[[vendor]]\nname = \"Northwind\"\naliases = [\"NW Guard\"]\ndomains = [\"northwind.example\"]\n[sources.forums]\nname = \"Forum\"\n",
        )
        .unwrap();
        let names = Names {
            brand: brand_names(&brand),
            vendors: vendor_names(&vendors),
        };
        assert_eq!(names.brand, vec!["Acme Ltd", "Acme Shield", "Shield"]);
        assert_eq!(names.vendors, vec!["NW Guard", "Northwind"]);
        let both = [NameKind::Brand, NameKind::Vendor];
        assert_eq!(
            names.find("Welcome to Acme Shield", &both),
            Some((NameKind::Brand, "Acme Shield"))
        );
        assert_eq!(
            names.find("like Northwind does", &both),
            Some((NameKind::Vendor, "Northwind"))
        );
        assert_eq!(names.find("a shield, Shields, northwind", &both), None);
        assert_eq!(names.find("Forum rules", &both), None);
        assert_eq!(names.find("Northwind", &[NameKind::Brand]), None);
    }
}
