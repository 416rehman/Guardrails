//! Interface checks UX1 to UX8 (team/05 section 8, owner instructions 19 and 21) on the web
//! languages of the interface paths: TypeScript, JavaScript, TSX, JSX and CSS.
//! They read the same sources as the structure checks, so `post-edit` and `stop-gate` run them
//! through [`structure::check_files`], and verify gate V26 runs [`gate`]. Every finding blocks;
//! there is no exemption file and no inline suppression, and a false positive is fixed in the
//! check and its fixture.

mod building;
mod config;
mod icons;
mod navigation;
mod patterns;
mod text;
mod visual;

pub use config::{CONFIG_PATH, Config, Exception, Interface, PATH_SKILLS_PATH};

use anyhow::Result;

use crate::gates::structure::{self, Family, Language, Policy, Raw, Source};
use crate::gates::{Context, Outcome};

/// The line `post-edit`, the stop gate and V26 print so the model loads the skills in order.
pub const HINT: &str = "load the ui-architect skill, then grdr-interface";

pub(crate) fn findings(source: &Source, policy: &Policy) -> Vec<Raw> {
    let Some(config) = policy.interface.config() else {
        return Vec::new();
    };
    if source.language == Language::Rust || !config.covers(source.path) {
        return Vec::new();
    }
    let mut found = Vec::new();
    found.extend(visual::findings(source));
    found.extend(building::findings(source, config));
    found.extend(text::findings(source, config, policy));
    found.extend(icons::findings(source, config));
    found.extend(patterns::findings(source, config));
    found.extend(navigation::findings(source, config));
    found
}

/// Gate V26: UX1 to UX8 on every changed file of the interface paths. It fails, rather than
/// passing silently, when the configuration cannot place files.
pub fn gate(context: &Context) -> Result<Outcome> {
    if let Interface::Unconfigured(reason) = Interface::load(&context.repo, &context.base)? {
        return Ok(Outcome::Error {
            reason: format!("the interface checks cannot place files: {reason}"),
        });
    }
    let report = structure::check_changed(&context.repo, &context.base, Family::Interface)?;
    let mut problems: Vec<String> = report.blocking().map(ToString::to_string).collect();
    if problems.is_empty() {
        return Ok(Outcome::Pass { notes: Vec::new() });
    }
    problems.push(HINT.to_owned());
    Ok(Outcome::Fail { problems })
}

#[cfg(test)]
pub(crate) mod testing {
    use super::config::fixtures;
    use crate::gates::structure::{Check, Policy, analyse};
    use crate::git::AddedLines;
    use crate::paths::RepoPath;

    pub(crate) fn policy() -> Policy {
        let mut policy = Policy::for_tests();
        policy.interface = super::Interface::Configured(Box::new(fixtures::config()));
        policy
    }

    /// The findings of `check` on `source` at `path`, as line and message.
    pub(crate) fn run(check: Check, path: &str, source: &str) -> Vec<(usize, String)> {
        analyse(
            &RepoPath::new(path).unwrap(),
            source,
            &AddedLines::All,
            &policy(),
        )
        .into_iter()
        .filter(|finding| finding.check == check)
        .map(|finding| (finding.line, finding.message))
        .collect()
    }

    pub(crate) fn lines(found: &[(usize, String)]) -> Vec<usize> {
        found.iter().map(|(line, _)| *line).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::config::fixtures;
    use super::*;
    use crate::gates::structure::{Check, check_files};
    use crate::git::Base;
    use crate::paths::RepoPath;

    #[test]
    fn post_edit_and_the_stop_gate_get_both_families_and_their_hints() {
        let temp = crate::testkit::TempRepo::create();
        temp.write(
            CONFIG_PATH,
            include_str!("../../../../quality/interface.toml"),
        );
        temp.write(PATH_SKILLS_PATH, fixtures::PATH_SKILLS);
        temp.write(
            "web/apps/console/src/Home.tsx",
            "export const Home = () => <p>Welcome back</p>;\nconst pause = setTimeout(go, 5000);\n",
        );
        let path = RepoPath::new("web/apps/console/src/Home.tsx").unwrap();
        let report = check_files(&temp.repo(), &Base::Unborn, &[path]).unwrap();
        let checks: Vec<Check> = report
            .findings
            .iter()
            .map(|finding| finding.check)
            .collect();
        assert!(checks.contains(&Check::UX3), "{checks:?}");
        assert!(checks.contains(&Check::S7), "{checks:?}");
        assert_eq!(report.hints(), vec![structure::SKILL_HINT, HINT]);
    }

    #[test]
    fn without_path_skills_nothing_is_an_interface_path() {
        let temp = crate::testkit::TempRepo::create();
        temp.write(
            CONFIG_PATH,
            include_str!("../../../../quality/interface.toml"),
        );
        let loaded = Interface::load(&temp.repo(), &Base::Unborn).unwrap();
        assert!(
            matches!(loaded, Interface::Unconfigured(reason) if reason.contains(PATH_SKILLS_PATH))
        );
    }
}
