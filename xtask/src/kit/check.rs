//! `cargo xtask kit check` (team/03 section 4.2 item 4): the tree equals a fresh render, rendered
//! definitions carry only fields Claude Code reads, the chief architect carries the owner's
//! sentence, every roster skill and hook handler exists, the project settings hold only
//! project-scope keys, every model a rendered file or a plugin agent names is one the rule
//! allows, vendors.toml names briefs and a skill that exist, and the marketplace catalogue agrees
//! with marketplace.toml and PINS.md with no installed plugin off its pin, every evaluator
//! `.agents/risk-tiers.toml` names is a roster evaluator, every label a template, skill or
//! prompt names is in `.github/labels.toml`, and no template, skill, prompt or workflow gives a
//! command JSON on standard input. [`all_problems`] adds the model rule and the skills lint.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use anyhow::Result;
use regex::Regex;

use super::claude_config::{self, USER_SETTINGS_FILE};
use super::render::{self, Rendered};
use super::{CHIEF_ARCHITECT, OWNERSHIP_SENTENCE, agents, install, plugins, research, settings};
use crate::config::Kit;
use crate::config::hooks::Action;
use crate::config::limits::Limits;
use crate::config::marketplace::{Catalogue, InstalledPlugins, PinState};
use crate::config::roster::Group;
use crate::frontmatter;
use crate::gates::{models, skills};
use crate::orchestrate::labels::{LABELS_FILE, LabelsFile};
use crate::orchestrate::tiers::{RiskPolicy, TIERS_FILE};
use crate::repo::{Repo, walk_files};

/// Where agents read the labels they file and set.
const LABEL_SOURCES: &[&str] = &[".agents/templates", ".agents/skills", ".agents/kit/prompts"];
/// Where agents read the commands they run.
const COMMAND_SOURCES: &[&str] = &[
    ".agents/templates",
    ".agents/skills",
    ".agents/kit/prompts",
    ".agents/kit/workflows",
];
/// Options that read JSON from standard input. An agent can feed it only from a here-document,
/// and Claude Code in `dontAsk` refuses a here-document that carries JSON.
const JSON_ON_STDIN: &[&str] = &["--draft -", "--input -"];
const MODEL_KEY: &str = "model";
const AVAILABLE_MODELS_KEY: &str = "availableModels";
const MODEL_VARIABLE_SUFFIX: &str = "_MODEL";
/// A whole label of a field group, in backticks.
static NAMED_LABEL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"`((?:status|agent|kind|squad|tier|priority|size):[a-z0-9][a-z0-9.-]*)`").ok()
});

/// The kit rules and the model rule and skills lint together.
pub fn all_problems(repo: &Repo, limits: &Limits) -> Result<Vec<String>> {
    let mut problems = kit_problems(repo)?;
    problems.extend(models::problems(repo)?);
    problems.extend(skills::problems(repo, &limits.gates.skills)?);
    Ok(problems)
}

pub fn kit_problems(repo: &Repo) -> Result<Vec<String>> {
    let kit = match Kit::load(repo) {
        Ok(kit) => kit,
        Err(error) => return Ok(vec![format!("kit sources: {error:#}")]),
    };
    let rendered = match render::render(repo, &kit) {
        Ok(rendered) => rendered,
        Err(error) => return Ok(vec![format!("kit render: {error:#}")]),
    };
    let mut problems: Vec<String> = rendered
        .drift(repo)?
        .iter()
        .map(ToString::to_string)
        .collect();
    problems.extend(rendered_problems(&kit, &rendered));
    problems.extend(skill_problems(repo, &kit)?);
    problems.extend(hook_problems(&kit, crate::hook::HANDLERS));
    problems.extend(crate::hook::limits_problem(repo));
    problems.extend(research::problems(repo, &kit)?);
    problems.extend(evaluator_problems(repo, &kit));
    problems.extend(label_problems(repo)?);
    problems.extend(stdin_json_problems(repo)?);
    problems.extend(marketplace_problems(
        repo,
        &kit,
        &install::read_installed()?,
    )?);
    let config_dir = claude_config::config_dir(claude_config::process_variable);
    let plugin_agents = plugins::plugin_agents(repo, &kit, config_dir.as_deref())?;
    problems.extend(plugins::model_problems(&kit, &plugin_agents));
    Ok(problems)
}

/// Every evaluator the risk policy names is an evaluator in the roster, so a renamed one fails
/// here instead of vanishing from review.
fn evaluator_problems(repo: &Repo, kit: &Kit) -> Vec<String> {
    let policy = match RiskPolicy::load(repo) {
        Ok(policy) => policy,
        Err(error) => return vec![format!("{TIERS_FILE}: {error:#}")],
    };
    policy
        .evaluator_names()
        .into_iter()
        .filter(|name| {
            kit.roster
                .agent(name)
                .is_none_or(|agent| agent.group != Group::Evaluator)
        })
        .map(|name| {
            format!("{TIERS_FILE} names `{name}`, which is not an evaluator in .agents/roster.toml")
        })
        .collect()
}

/// Every kit source that names a [`JSON_ON_STDIN`] option, which would get its session refused.
fn stdin_json_problems(repo: &Repo) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    for source in COMMAND_SOURCES {
        for path in walk_files(&repo.path(source))? {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            problems.extend(
                JSON_ON_STDIN
                    .iter()
                    .filter(|form| text.contains(**form))
                    .map(|form| {
                        format!(
                            "{} has `{form}`: an agent gives that JSON on a here-document, which dontAsk refuses; write a draft file or pass `gh api -f` fields",
                            display_path(repo, &path)
                        )
                    }),
            );
        }
    }
    Ok(problems)
}

fn display_path(repo: &Repo, path: &Path) -> String {
    repo.relative(path).map_or_else(
        || path.display().to_string(),
        |relative| relative.to_string(),
    )
}

/// Every label a template, skill or prompt names in backticks is in `.github/labels.toml`, so an
/// agent never files or sets a label `gh` would refuse.
fn label_problems(repo: &Repo) -> Result<Vec<String>> {
    let Some(pattern) = NAMED_LABEL.as_ref() else {
        return Ok(vec![
            "kit check: the label pattern does not compile".to_owned(),
        ]);
    };
    let mut named: BTreeSet<(String, String)> = BTreeSet::new();
    for source in LABEL_SOURCES {
        for path in walk_files(&repo.path(source))? {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let shown = display_path(repo, &path);
            named.extend(
                pattern
                    .captures_iter(&text)
                    .filter_map(|found| found.get(1))
                    .map(|label| (label.as_str().to_owned(), shown.clone())),
            );
        }
    }
    if named.is_empty() {
        return Ok(Vec::new());
    }
    let labels = match LabelsFile::load(repo) {
        Ok(labels) => labels,
        Err(error) => return Ok(vec![format!("{LABELS_FILE}: {error:#}")]),
    };
    Ok(named
        .into_iter()
        .filter(|(label, _)| !labels.knows(label))
        .map(|(label, path)| {
            format!("{path} names `{label}`, which is not a label in {LABELS_FILE}")
        })
        .collect())
}

/// The catalogue agrees with marketplace.toml and PINS.md, and no installed plugin of it has moved
/// off its pin (team/03 section 9 rules 1 and 2). A plugin not fetched yet is `kit install`'s
/// report, not a problem.
pub fn marketplace_problems(
    repo: &Repo,
    kit: &Kit,
    installed: &InstalledPlugins,
) -> Result<Vec<String>> {
    let catalogue = match Catalogue::load(repo, &kit.marketplace) {
        Ok(catalogue) => catalogue,
        Err(error) => return Ok(vec![format!("marketplace catalogue: {error:#}")]),
    };
    let mut problems = catalogue.problems(repo, &kit.marketplace)?;
    for (id, source) in catalogue.git_entries(&kit.marketplace) {
        if let PinState::Moved { installed, .. } = installed.pin_state(&id, source.sha()) {
            problems.push(format!(
                "pin mismatch: {id} is installed at {installed}, pinned at {}; `cargo xtask kit install` prints the commands that fix it",
                source.sha()
            ));
        }
    }
    Ok(problems)
}

/// Checks on the fresh render itself, independent of what is on disk.
pub fn rendered_problems(kit: &Kit, rendered: &Rendered) -> Vec<String> {
    let mut problems = Vec::new();
    for (path, bytes) in rendered
        .files
        .iter()
        .filter(|(path, _)| path.starts_with(agents::AGENTS_OUTPUT_DIR))
    {
        let text = String::from_utf8_lossy(bytes);
        match frontmatter::parse(&text) {
            Ok(Some(front)) => {
                for field in &front.fields {
                    let known = agents::ALLOWED_FIELDS.contains(&field.key.as_str());
                    if !known || agents::FORBIDDEN_FIELDS.contains(&field.key.as_str()) {
                        problems.push(format!(
                            "{path}: front-matter field `{}` is not allowed (team/02 section 1.1)",
                            field.key
                        ));
                    }
                }
            }
            Ok(None) => problems.push(format!("{path}: no front matter")),
            Err(error) => problems.push(format!("{path}: front matter: {error}")),
        }
    }
    let chief = agents::output_path(CHIEF_ARCHITECT);
    match rendered.files.get(&chief) {
        Some(bytes) if String::from_utf8_lossy(bytes).contains(OWNERSHIP_SENTENCE) => {}
        Some(_) => problems.push(format!(
            "{chief} lacks the owner's sentence (owner instruction 1): \"{OWNERSHIP_SENTENCE}\""
        )),
        None => problems.push(format!("the roster has no `{CHIEF_ARCHITECT}`")),
    }
    if let Some(bytes) = rendered.files.get(settings::SETTINGS_PATH)
        && let Ok(serde_json::Value::Object(root)) =
            serde_json::from_slice::<serde_json::Value>(bytes)
    {
        for key in settings::MANAGED_ONLY_KEYS
            .iter()
            .filter(|key| root.contains_key(**key))
        {
            problems.push(format!(
                "{}: `{key}` is honoured only from managed or user settings",
                settings::SETTINGS_PATH
            ));
        }
        if root
            .get("sandbox")
            .and_then(|sandbox| sandbox.get("network"))
            .is_some_and(|network| network.get("strictAllowlist").is_some())
        {
            problems.push(format!("{}: `sandbox.network.strictAllowlist` is honoured only from managed or user settings", settings::SETTINGS_PATH));
        }
    }
    problems.extend(model_id_problems(kit, rendered));
    if !kit.permissions.managed.contains_key("implementer") {
        problems.push(format!(
            ".agents/kit/permissions.toml has no [managed.implementer], so {} (team/03 section 8) is not rendered",
            settings::managed_path("implementer")
        ));
    }
    problems
}

/// In the rendered settings files, `model`, `availableModels` and every `*_MODEL` variable name
/// an id from models.toml.
fn model_id_problems(kit: &Kit, rendered: &Rendered) -> Vec<String> {
    let mut problems = Vec::new();
    let settings_files = rendered.files.iter().filter(|(path, _)| {
        path.as_str() == settings::SETTINGS_PATH
            || (path.starts_with(settings::MANAGED_DIR) && path.ends_with(".json"))
    });
    for (path, bytes) in settings_files {
        let Ok(serde_json::Value::Object(root)) = serde_json::from_slice(bytes) else {
            continue;
        };
        let mut named: Vec<(String, &str)> = Vec::new();
        if let Some(model) = root.get(MODEL_KEY).and_then(serde_json::Value::as_str) {
            named.push((MODEL_KEY.to_owned(), model));
        }
        if let Some(ids) = root
            .get(AVAILABLE_MODELS_KEY)
            .and_then(serde_json::Value::as_array)
        {
            named.extend(
                ids.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(|id| (AVAILABLE_MODELS_KEY.to_owned(), id)),
            );
        }
        if let Some(env) = root.get("env").and_then(serde_json::Value::as_object) {
            named.extend(
                env.iter()
                    .filter(|(name, _)| name.ends_with(MODEL_VARIABLE_SUFFIX))
                    .filter_map(|(name, value)| Some((format!("env {name}"), value.as_str()?))),
            );
        }
        problems.extend(
            named
                .into_iter()
                .filter(|(_, id)| !kit.models.is_id(id))
                .map(|(key, id)| {
                    format!("{path}: {key} `{id}` is not a model id from .agents/models.toml")
                }),
        );
    }
    problems
}

/// Every skill a roster entry or the path-skills mapping names exists: a project skill, a skill
/// of an enabled plugin (`plugin:skill`), or one harness.toml lists as built in, user-scope,
/// account or from a user plugin. Where `~/.claude` exists, the user-scope entries are checked
/// against what is installed.
pub fn skill_problems(repo: &Repo, kit: &Kit) -> Result<Vec<String>> {
    let project: BTreeSet<String> = skills::skill_files(repo)?
        .iter()
        .map(skills::SkillFile::name)
        .collect();
    let plugins: BTreeSet<&str> = kit.marketplace.skill_namespaces().collect();
    let external = &kit.harness.skills;
    let is_known = |skill: &String| {
        let from_plugin = skill.split_once(':').is_some_and(|(plugin, _)| {
            plugins.contains(plugin) || external.user_plugins.iter().any(|p| p == plugin)
        });
        project.contains(skill)
            || from_plugin
            || external.builtin.contains(skill)
            || external.user.contains(skill)
            || external.account.contains(skill)
    };
    let mut problems = installed_problems(external);
    for (agent, role) in &kit.roster.agents {
        for skill in role.skills.iter().filter(|skill| !is_known(skill)) {
            problems.push(format!(
                "agent `{agent}` names skill `{skill}`: {}",
                unknown_skill(skill)
            ));
        }
    }
    for skill in crate::hook::path_skill_names(repo)?
        .iter()
        .filter(|skill| !is_known(skill))
    {
        problems.push(format!(
            "the path-skills mapping names skill `{skill}`: {}",
            unknown_skill(skill)
        ));
    }
    Ok(problems)
}

fn unknown_skill(skill: &str) -> String {
    format!(
        "no .agents/skills/{skill}/SKILL.md, no enabled plugin, and not in harness.toml [skills]"
    )
}

/// On a machine with a `~/.claude`, every user-scope skill harness.toml lists is installed in
/// `~/.claude/skills`, and every user plugin is enabled in the user settings.
fn installed_problems(external: &crate::config::runtime::HarnessSkills) -> Vec<String> {
    let Some(home) =
        claude_config::config_dir(claude_config::process_variable).filter(|dir| dir.is_dir())
    else {
        return Vec::new();
    };
    let skills_dir = home.join("skills");
    let mut problems: Vec<String> = external
        .user
        .iter()
        .filter(|name| !skills_dir.join(name).join("SKILL.md").is_file())
        .map(|name| {
            format!(
                "harness.toml [skills] user names `{name}`, which {} does not hold",
                skills_dir.display()
            )
        })
        .collect();
    let enabled: Vec<String> = std::fs::read_to_string(home.join(USER_SETTINGS_FILE))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| {
            value
                .get("enabledPlugins")
                .and_then(serde_json::Value::as_object)
                .cloned()
        })
        .map(|plugins| {
            plugins
                .iter()
                .filter(|(_, on)| on.as_bool() == Some(true))
                .map(|(name, _)| name.split('@').next().unwrap_or(name).to_owned())
                .collect()
        })
        .unwrap_or_default();
    problems.extend(
        external
            .user_plugins
            .iter()
            .filter(|plugin| !enabled.contains(plugin))
            .map(|plugin| format!("harness.toml [skills] user_plugins names `{plugin}`, which the user settings do not enable")),
    );
    problems
}

/// Every command handler exists in this binary; prompt and agent hooks are not used (owner
/// instruction 8).
pub fn hook_problems(kit: &Kit, implemented: &[&str]) -> Vec<String> {
    let mut problems = Vec::new();
    for hook in &kit.hooks.hooks {
        match &hook.action {
            Action::Command { handler, .. } if !implemented.contains(&handler.as_str()) => {
                problems.push(format!("hooks.toml names handler `{handler}` ({}), which `xtask hook` does not implement", hook.event));
            }
            Action::Command { .. } => {}
            Action::Prompt { .. } => problems.push(format!(
                "hooks.toml has a {} prompt hook; owner instruction 8 replaces prompt hooks with deterministic checks in a command handler",
                hook.event
            )),
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::TempRepo;

    const HANDLERS: &[&str] = &["guard-path", "guard-extra", "stop-gate"];

    fn problems(temp: &TempRepo) -> Vec<String> {
        let repo = temp.repo();
        let kit = Kit::load(&repo).unwrap();
        let rendered = render::render(&repo, &kit).unwrap();
        let mut problems = rendered_problems(&kit, &rendered);
        problems.extend(skill_problems(&repo, &kit).unwrap());
        problems.extend(hook_problems(&kit, HANDLERS));
        problems.extend(models::rule_problems(&kit));
        problems
    }

    fn edit(temp: &TempRepo, path: &str, from: &str, to: &str) {
        let text = std::fs::read_to_string(temp.repo().path(path)).unwrap();
        assert!(text.contains(from), "{path} lacks {from}");
        temp.write(path, &text.replacen(from, to, 1));
    }

    #[test]
    fn the_fixture_kit_passes_every_rule() {
        let temp = TempRepo::create();
        assert_eq!(problems(&temp), Vec::<String>::new());
        let repo = temp.repo();
        render::render(&repo, &Kit::load(&repo).unwrap())
            .unwrap()
            .write(&repo)
            .unwrap();
        let mut all = all_problems(&repo, Limits::built_with().unwrap()).unwrap();
        all.retain(|problem| !problem.contains("does not implement"));
        assert_eq!(all, Vec::<String>::new());
    }

    #[test]
    fn templates_name_only_labels_the_labels_file_holds() {
        let temp = TempRepo::create();
        let repo = temp.repo();
        assert!(label_problems(&repo).unwrap().is_empty());
        temp.write(
            ".agents/templates/agents/impl-rust.md",
            "File a `status:proposed` issue labelled `agent:garden-x`.\n",
        );
        temp.write(
            LABELS_FILE,
            "[[label]]\nname = \"status:proposed\"\ncolor = \"ededed\"\ndescription = \"x\"\n",
        );
        let found = label_problems(&repo).unwrap();
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("`agent:garden-x`"), "{found:#?}");
    }

    #[test]
    fn the_risk_policy_names_only_roster_evaluators() {
        let temp = TempRepo::create();
        let repo = temp.repo();
        let kit = Kit::load(&repo).unwrap();
        assert!(evaluator_problems(&repo, &kit).is_empty());
        let tiers = crate::testkit::plain_tiers("[]", "[\"crates/**\"]", "[]").replacen(
            "evaluators = []",
            "evaluators = [\"eval-renamed\"]",
            1,
        );
        temp.write(TIERS_FILE, &crate::testkit::risk_tiers(&tiers, "[]"));
        let found = evaluator_problems(&repo, &kit);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("`eval-renamed`"), "{found:#?}");
    }

    #[test]
    fn a_kit_source_that_gives_json_on_standard_input_fails() {
        let temp = TempRepo::create();
        let repo = temp.repo();
        assert!(stdin_json_problems(&repo).unwrap().is_empty());
        temp.write(
            ".agents/skills/grdr-x/SKILL.md",
            "Run `cargo xtask kit handoff --item <n> --draft - <<'JSON'`.\n",
        );
        temp.write(
            ".agents/kit/workflows/post.js",
            "const command = `gh api --method POST repos/r/statuses/s --input -`\n",
        );
        let found = stdin_json_problems(&repo).unwrap();
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(
            found
                .iter()
                .any(|problem| problem.contains("post.js has `--input -`")),
            "{found:#?}"
        );
    }

    #[test]
    fn the_chief_architect_must_carry_the_owners_sentence() {
        let temp = TempRepo::create();
        temp.write(
            ".agents/templates/agents/chief-architect.md",
            "You are the chief architect.\n",
        );
        let found = problems(&temp);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("lacks the owner's sentence"));
    }

    #[test]
    fn unknown_skills_handlers_and_prompt_hooks_are_reported() {
        let temp = TempRepo::create();
        edit(
            &temp,
            ".agents/roster.toml",
            "\"simplify\"",
            "\"simplify\", \"no-such-skill\"",
        );
        temp.write(".agents/prompts/stop.md", "Decide.\n");
        let prompt_hook = "\n[[hook]]\nevent = \"Stop\"\ntype = \"prompt\"\nmodel = \"sonnet\"\nprompt_file = \"prompts/stop.md\"\n";
        edit(
            &temp,
            ".agents/kit/hooks.toml",
            "timeout = 600\n",
            &format!("timeout = 600\n{prompt_hook}"),
        );
        let repo = temp.repo();
        let kit = Kit::load(&repo).unwrap();
        let skills = skill_problems(&repo, &kit).unwrap();
        assert_eq!(skills.len(), 1);
        assert!(skills[0].contains("`no-such-skill`"));
        let hooks = hook_problems(&kit, &["guard-path"]);
        assert_eq!(hooks.len(), 3, "{hooks:#?}");
        assert!(hooks.iter().any(|problem| problem.contains("prompt hook")));
        let rendered = render::render(&repo, &kit).unwrap();
        let settings: serde_json::Value =
            serde_json::from_slice(&rendered.files[settings::SETTINGS_PATH]).unwrap();
        assert_eq!(
            settings["hooks"]["Stop"][0]["hooks"][1]["model"],
            "claude-sonnet-5-5"
        );
    }

    #[test]
    fn vendors_toml_names_existing_briefs_and_a_loaded_project_skill() {
        let temp = TempRepo::create();
        temp.write(
            ".agents/kit/vendors.toml",
            "[research]
skill = \"grdr-verify\"
egress_lists = []

[vendor.acme]
name = \"Acme\"
domains = [\"docs.acme.example\"]
brief = \"docs/references/research/01-acme.md\"
",
        );
        let repo = temp.repo();
        let found = research::problems(&repo, &Kit::load(&repo).unwrap()).unwrap();
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("01-acme.md, which does not exist"));
        temp.write(
            "docs/references/research/01-acme.md",
            "# Acme
",
        );
        edit(
            &temp,
            ".agents/kit/vendors.toml",
            "grdr-verify",
            "no-such-skill",
        );
        let found = research::problems(&repo, &Kit::load(&repo).unwrap()).unwrap();
        assert_eq!(found.len(), 2, "{found:#?}");
        assert!(found[0].contains("has no .agents/skills/no-such-skill/SKILL.md"));
        assert!(found[1].contains("no roster role loads `no-such-skill`"));
    }

    #[test]
    fn rendered_settings_name_only_bound_model_ids() {
        let temp = TempRepo::create();
        edit(
            &temp,
            ".agents/kit/permissions.toml",
            "[managed.implementer.permissions]",
            "[managed.implementer.env]
CLAUDE_CODE_SUBAGENT_MODEL = \"claude-haiku-4-5\"

[managed.implementer.permissions]",
        );
        let found = problems(&temp);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("env CLAUDE_CODE_SUBAGENT_MODEL `claude-haiku-4-5`"));
    }

    #[test]
    fn missing_managed_settings_are_reported() {
        let temp = TempRepo::create();
        let path = ".agents/kit/permissions.toml";
        let text = std::fs::read_to_string(temp.repo().path(path)).unwrap();
        temp.write(path, text.split_once("[managed.implementer]").unwrap().0);
        let found = problems(&temp);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("no [managed.implementer]"));
    }

    #[test]
    fn a_second_fable_agent_fails_render_and_the_model_rule() {
        let temp = TempRepo::create();
        edit(
            &temp,
            ".agents/roster.toml",
            "model = \"sonnet\"",
            "model = \"fable\"",
        );
        let repo = temp.repo();
        let kit = Kit::load(&repo).unwrap();
        assert!(render::render(&repo, &kit).is_err());
        let rule = models::rule_problems(&kit);
        assert_eq!(rule.len(), 1, "{rule:#?}");
        assert!(rule[0].contains("at most one agent, chief-architect, may run on fable"));
    }

    #[test]
    fn the_chief_architect_may_fall_back_from_fable() {
        let temp = TempRepo::create();
        edit(
            &temp,
            ".agents/roster.toml",
            "model = \"fable\"",
            "model = \"opus\"",
        );
        let kit = Kit::load(&temp.repo()).unwrap();
        assert_eq!(models::rule_problems(&kit), Vec::<String>::new());
    }

    #[test]
    fn model_rule_rejects_other_bindings_and_settings() {
        let temp = TempRepo::create();
        edit(
            &temp,
            ".agents/models.toml",
            "sonnet = \"claude-sonnet-5-5\"",
            "sonnet = \"claude-haiku-4-5\"\nhaiku = \"claude-haiku-4-5\"",
        );
        edit(
            &temp,
            ".agents/kit/permissions.toml",
            "model = \"claude-sonnet-5-5\"",
            "model = \"claude-opus-5-5\"",
        );
        let rule = models::rule_problems(&Kit::load(&temp.repo()).unwrap());
        let joined = rule.join("\n");
        assert!(
            joined.contains("must bind exactly fable, opus and sonnet"),
            "{joined}"
        );
        assert!(
            joined.contains("binds `sonnet` to `claude-haiku-4-5`"),
            "{joined}"
        );
        assert!(
            joined.contains("settings.model must be the sonnet id"),
            "{joined}"
        );
        assert!(joined.contains("available_models must list"), "{joined}");
    }
}
