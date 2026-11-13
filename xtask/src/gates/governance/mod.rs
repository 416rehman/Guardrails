//! `cargo xtask governance-check [--base <ref>]` (design/30 sections 3 and 13 to 16, D-61): every
//! file `governance/governance.toml` lists exists, holds its sections and names the product as
//! `brand/brand.toml` gives it; `MAINTAINERS.md` lists only people, never a bot or a roster
//! agent; and no listed file names a human gate owner instruction 7 removed. The rules are read at
//! the comparison base and the files in the working tree. Exit 0 when every file passes, 2 when
//! one fails, 1 when the check cannot run.

mod markdown;
mod rules;
#[cfg(test)]
mod tests;

pub use rules::RULES_PATH;

use std::collections::BTreeSet;
use std::process::ExitCode;

use anyhow::{Result, bail};
use serde::Deserialize;

use super::structure::BRAND_PATH;
use super::{Context, Outcome};
use crate::cli::{self, Spec};
use crate::config::roster::Roster;
use crate::git::{self, Base};
use crate::repo::Repo;
use rules::{MaintainerRules, RemovedGate, RequiredFile, Rules};

const COMMAND: &str = "governance-check";

#[derive(Deserialize)]
struct BrandFile {
    identity: BrandIdentity,
}

#[derive(Deserialize)]
struct BrandIdentity {
    product_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintainerBlock {
    #[serde(default)]
    maintainer: Vec<Maintainer>,
}

/// One `[[maintainer]]` entry; the fields governance-sync reads are its own to check.
#[derive(Deserialize)]
struct Maintainer {
    name: String,
    handle: String,
    affiliation: String,
}

pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(
        args,
        &Spec {
            flags: &[],
            options: &["--base"],
        },
    )?;
    if let Some(extra) = parsed.positional.first() {
        bail!("{COMMAND} takes no argument, not `{extra}`");
    }
    let repo = Repo::discover()?;
    let base = git::base_for(&repo, parsed.value("--base"))?;
    let found = problems(&repo, &base)?;
    if found.is_empty() {
        println!("{COMMAND}: every governance file in {RULES_PATH} passes");
        return Ok(ExitCode::SUCCESS);
    }
    for problem in &found {
        println!("ERROR {COMMAND} {problem}");
    }
    Ok(ExitCode::from(2))
}

pub fn gate(context: &Context) -> Result<Outcome> {
    Ok(Outcome::from_problems(problems(
        &context.repo,
        &context.base,
    )?))
}

/// Every way the working tree's governance files break the rules the base holds.
pub fn problems(repo: &Repo, base: &Base) -> Result<Vec<String>> {
    let rules = Rules::at(repo, base)?;
    let product = product_name(repo)?;
    let agents: BTreeSet<String> = Roster::load(repo)?
        .agents
        .into_keys()
        .map(|name| name.to_lowercase())
        .collect();
    let mut found = Vec::new();
    for file in &rules.files {
        let Some(text) = repo.read_optional(&file.path)? else {
            found.push(format!(
                "{}: missing; design/30 sections 13 to 16 give its content",
                file.path
            ));
            continue;
        };
        found.extend(file_problems(file, &text, &product, &rules.removed_gates));
        if file.path == rules.maintainers.path {
            found.extend(maintainer_problems(&text, &rules.maintainers, &agents));
        }
    }
    Ok(found)
}

fn product_name(repo: &Repo) -> Result<String> {
    let brand: BrandFile = crate::config::parse_toml(&repo.read(BRAND_PATH)?, BRAND_PATH)?;
    Ok(brand.identity.product_name)
}

fn file_problems(
    file: &RequiredFile,
    text: &str,
    product: &str,
    removed_gates: &[RemovedGate],
) -> Vec<String> {
    let path = &file.path;
    let present = markdown::sections(text);
    let mut found: Vec<String> = file
        .sections
        .iter()
        .filter(|section| !present.contains(&section.as_str()))
        .map(|section| format!("{path}: no `## {section}` section"))
        .collect();
    if !text.contains(product) {
        found.push(format!(
            "{path}: never names the product `{product}` that {BRAND_PATH} gives"
        ));
    }
    for (index, line) in text.lines().enumerate() {
        let line = line.to_lowercase();
        found.extend(
            removed_gates
                .iter()
                .filter(|gate| line.contains(&gate.phrase.to_lowercase()))
                .map(|gate| {
                    format!(
                        "{path}:{}: names the removed human gate `{}`; {}",
                        index + 1,
                        gate.phrase,
                        gate.removed
                    )
                }),
        );
    }
    found
}

/// `agents` holds the roster's agent names in lower case.
fn maintainer_problems(
    text: &str,
    rules: &MaintainerRules,
    agents: &BTreeSet<String>,
) -> Vec<String> {
    let path = &rules.path;
    let Some(block) = markdown::fenced_block(text, &rules.language) else {
        return vec![format!(
            "{path}: no ```{} block with the [[maintainer]] entries",
            rules.language
        )];
    };
    let entries: MaintainerBlock = match toml::from_str(&block) {
        Ok(entries) => entries,
        Err(error) => {
            return vec![format!(
                "{path}: the maintainer block does not parse: {error}"
            )];
        }
    };
    if entries.maintainer.is_empty() {
        return vec![format!("{path}: lists no maintainer")];
    }
    let mut found = Vec::new();
    for maintainer in &entries.maintainer {
        let handle = &maintainer.handle;
        if is_bot(handle, rules, agents) {
            found.push(format!(
                "{path}: `{handle}` is a bot or agent handle; only people hold an entry (D-61)"
            ));
        }
        if maintainer.name.trim().is_empty() || maintainer.affiliation.trim().is_empty() {
            found.push(format!(
                "{path}: `{handle}` needs a name and a declared affiliation"
            ));
        }
    }
    found
}

fn is_bot(handle: &str, rules: &MaintainerRules, agents: &BTreeSet<String>) -> bool {
    let handle = handle.trim_start_matches('@').to_lowercase();
    agents.contains(&handle)
        || rules
            .bot_prefixes
            .iter()
            .any(|prefix| handle.starts_with(&prefix.to_lowercase()))
        || rules
            .bot_suffixes
            .iter()
            .any(|suffix| handle.ends_with(&suffix.to_lowercase()))
}
