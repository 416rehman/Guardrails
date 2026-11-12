//! Each role's `gh` calls (team/01 section 4, owner instructions 6 and 23). Every agent posts as
//! the owner's `gh` login, so separation of duties between agents is enforced here: who may
//! comment, push and open pull requests, file `status:proposed` issues, edit issues, set which
//! labels (`.github/labels.toml` `set_by`, `raise_only` and the status transitions' `by`), and post
//! check runs or, while no GitHub App exists, commit statuses (team/01 section 4). No agent posts
//! a kit record (`ready.v1`, `lease.v1`, `state.v1`, `handoff.v1`) by
//! hand: only `kit ready`, `kit handoff` and the dispatcher do, so a session cannot forge the
//! records the queue trusts. `gh pr merge` and release commands are denied to every session.

mod bodies;
mod labels;

use std::path::Path;

use super::Rules;
use crate::hook::identity::Role;
use crate::hook::shell::{Invocation, RedirectKind, Word};
use crate::orchestrate::labels::LabelsFile;
use labels::Statuses;

const VALUED: &[&str] = &[
    "-R",
    "--repo",
    "-t",
    "--title",
    "-b",
    "--body",
    "-F",
    "--body-file",
    "-l",
    "--label",
    "--add-label",
    "--remove-label",
    "-a",
    "--assignee",
    "--add-assignee",
    "--remove-assignee",
    "-m",
    "--milestone",
    "-p",
    "--project",
    "--add-project",
    "--remove-project",
    "-H",
    "--head",
    "-B",
    "--base",
    "-r",
    "--reviewer",
    "--add-reviewer",
    "--remove-reviewer",
    "-T",
    "--template",
    "-q",
    "--jq",
    "--json",
    "-L",
    "--limit",
    "-s",
    "--state",
    "-S",
    "--search",
    "-A",
    "--author",
    "--app",
    "--mention",
    "--type",
    "--parent",
    "--blocked-by",
    "--add-blocked-by",
    "--remove-blocked-by",
    "--add-sub-issue",
    "--remove-sub-issue",
    "-X",
    "--method",
    "-f",
    "--field",
    "--raw-field",
    "--input",
    "--hostname",
    "-c",
    "--comment",
    "--reason",
    "-e",
    "--color",
];
const BODY_FLAGS: &[&str] = &["-b", "--body", "-F", "--body-file"];
const LABEL_FLAGS: &[&str] = &["-l", "--label", "--add-label", "--remove-label"];
const TITLE_FLAGS: &[&str] = &["-t", "--title"];
const GRAPH_FLAGS: &[&str] = &[
    "--parent",
    "--blocked-by",
    "--add-blocked-by",
    "--remove-blocked-by",
    "--add-sub-issue",
    "--remove-sub-issue",
];
const BOARD_FLAGS: &[&str] = &["-m", "--milestone", "-p", "--project", "--add-project"];
const BASE_FLAGS: &[&str] = &["-B", "--base"];
const FIELD_FLAGS: &[&str] = &["-f", "--field", "-F", "--raw-field"];
const INPUT_FLAGS: &[&str] = &["--input"];
/// The commit-status context an evaluator posts under, with its roster name after it.
const STATUS_CONTEXT: &str = "grdr-evaluator/";
const READS: &[(&str, &[&str])] = &[
    ("issue", &["view", "list", "status"]),
    (
        "pr",
        &["view", "list", "diff", "checks", "status", "checkout"],
    ),
    ("repo", &["view", "clone"]),
    ("label", &["list"]),
    ("run", &["view", "list", "watch", "download"]),
    ("workflow", &["view", "list"]),
    ("release", &["view", "list"]),
    ("ruleset", &["view", "list", "check"]),
    ("auth", &["status"]),
    ("cache", &["list"]),
];
const READ_GROUPS: &[&str] = &["search", "status", "browse", "help", "version"];
const PLANNER_ISSUE: &[&str] = &[
    "create", "edit", "comment", "close", "reopen", "pin", "unpin", "develop",
];
const PLANNER_LABEL: &[&str] = &["create", "edit", "clone"];
/// The chief architect: file, label, answer and close issues (team/02 section 3).
const ARCHITECT_ISSUE: &[&str] = &["create", "edit", "comment", "close", "reopen"];

/// A `gh` command line split into its command, flags and arguments.
struct Call<'a> {
    group: &'a str,
    sub: &'a str,
    flags: Vec<(&'a str, Option<&'a Word>)>,
    positional: Vec<&'a Word>,
}

impl<'a> Call<'a> {
    fn parse(invocation: &'a Invocation) -> Result<Call<'a>, String> {
        let mut flags = Vec::new();
        let mut words: Vec<&Word> = Vec::new();
        let mut index = 0;
        while let Some(word) = invocation.args.get(index) {
            index += 1;
            let value = word.value.as_str();
            if !value.starts_with('-') || value == "-" {
                words.push(word);
                continue;
            }
            match value.split_once('=') {
                Some((name, _)) if value.starts_with("--") => flags.push((name, Some(word))),
                _ if VALUED.contains(&value) => {
                    flags.push((value, invocation.args.get(index)));
                    index += 1;
                }
                _ => flags.push((value, None)),
            }
        }
        let mut words = words.into_iter();
        let group = words.next();
        let takes_sub = group.is_some_and(|group| {
            !READ_GROUPS.contains(&group.value.as_str()) && group.value != "api"
        });
        let sub = if takes_sub { words.next() } else { None };
        if group.is_some_and(|w| w.opaque) || sub.is_some_and(|w| w.opaque) {
            return Err(
                "`gh` with a command built from an expansion; write it literally".to_owned(),
            );
        }
        Ok(Call {
            group: group.map_or("", |w| w.value.as_str()),
            sub: sub.map_or("", |w| w.value.as_str()),
            flags,
            positional: words.collect(),
        })
    }

    fn has(&self, names: &[&str]) -> bool {
        self.flags.iter().any(|(name, _)| names.contains(name))
    }

    /// The values of `names`, split at commas; `--label=a,b` included.
    fn values(&self, names: &[&str]) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for (name, word) in self.flags.iter().filter(|(name, _)| names.contains(name)) {
            let Some(word) = word else { continue };
            if word.opaque {
                return Err(format!(
                    "`gh {} {} {name}` takes a value built from an expansion; write it literally",
                    self.group, self.sub
                ));
            }
            let value = word
                .value
                .split_once('=')
                .filter(|_| word.value.starts_with("--"))
                .map_or(word.value.as_str(), |(_, v)| v);
            out.extend(
                value
                    .split(',')
                    .map(|label| label.trim().to_owned())
                    .filter(|label| !label.is_empty()),
            );
        }
        Ok(out)
    }

    /// The words given to `names`, unsplit: bodies, files and repositories.
    fn raw_values(&self, names: &[&str]) -> Vec<Word> {
        self.flags
            .iter()
            .filter(|(name, _)| names.contains(name))
            .filter_map(|(name, word)| {
                let word = (*word)?;
                let inline = word.value.starts_with("--") && word.value.starts_with(*name);
                Some(match word.value.split_once('=').filter(|_| inline) {
                    Some((_, value)) => word.with_value(value),
                    None => word.clone(),
                })
            })
            .collect()
    }

    fn is_read(&self) -> bool {
        READ_GROUPS.contains(&self.group)
            || READS
                .iter()
                .any(|(group, subs)| *group == self.group && subs.contains(&self.sub))
    }

    fn command(&self) -> String {
        format!("gh {} {}", self.group, self.sub)
            .trim_end()
            .to_owned()
    }
}

pub fn check(rules: &Rules, invocation: &Invocation, cwd: Option<&Path>) -> Vec<String> {
    let call = match Call::parse(invocation) {
        Ok(call) => call,
        Err(reason) => return vec![reason],
    };
    let everyone = match (call.group, call.sub) {
        ("pr", "merge") => {
            Some("`gh pr merge` is the merge queue's job; no session merges".to_owned())
        }
        ("release", sub) if !matches!(sub, "view" | "list") => Some(format!(
            "`gh release {sub}` publishes; release-please creates releases"
        )),
        _ => None,
    };
    if let Some(reason) = everyone {
        return vec![reason];
    }
    if rules.role == Role::Person || call.is_read() {
        return Vec::new();
    }
    if call.has(BOARD_FLAGS) {
        return vec![
            "milestones and projects are not used; issues and labels carry everything".to_owned(),
        ];
    }
    if let Err(reason) = bodies::repository(&call, &rules.github.repository)
        .and_then(|()| bodies::records(rules, &call, cwd, document(invocation)))
    {
        return vec![reason];
    }
    let file = match LabelsFile::load(&rules.context.repo) {
        Ok(file) => file,
        Err(error) => {
            return vec![format!(
                "guard-command cannot read .github/labels.toml: {error:#}"
            )];
        }
    };
    let result = Statuses::of(&file).and_then(|statuses| {
        let allowed = match rules.role {
            Role::Planner => Ok(planner(&call)),
            Role::Architect => Ok(architect(&call)),
            Role::Implementer | Role::Gardener => worker(rules, &call, &statuses, cwd),
            Role::Evaluator => evaluator(rules, &call, &statuses, document(invocation)),
            _ => commenter(&call, &statuses),
        }?;
        if allowed {
            labels::label_rules(rules, &call, &file, &statuses)?;
        }
        Ok(allowed)
    });
    match result {
        Ok(true) => Vec::new(),
        Ok(false) => vec![format!(
            "{} may not run `{}` (team/01 section 4 lists each role's gh calls)",
            rules.agent_name(),
            call.command()
        )],
        Err(reason) => vec![reason],
    }
}

/// Leads, the product lead and the programme manager create and edit issues and labels.
fn planner(call: &Call) -> bool {
    match call.group {
        "issue" => PLANNER_ISSUE.contains(&call.sub),
        "label" => PLANNER_LABEL.contains(&call.sub),
        "pr" => call.sub == "comment",
        _ => false,
    }
}

/// The chief architect files, labels, answers and closes issues and comments on pull requests.
fn architect(call: &Call) -> bool {
    match call.group {
        "issue" => ARCHITECT_ISSUE.contains(&call.sub),
        "pr" => call.sub == "comment",
        _ => false,
    }
}

/// Implementers and gardeners: comments (an implementer's on its own item), their own branch's
/// pull request, `status:proposed` issues, and label edits on their own item that
/// `.github/labels.toml` lets them make; never an issue body, title or dependency.
fn worker(
    rules: &Rules,
    call: &Call,
    statuses: &Statuses,
    cwd: Option<&Path>,
) -> Result<bool, String> {
    match (call.group, call.sub) {
        ("issue", "comment") if rules.role == Role::Implementer => own_issue(rules, call),
        ("issue" | "pr", "comment") => Ok(true),
        ("issue", "create") => proposed_issue(call, statuses),
        ("issue", "edit") => {
            if call.has(BODY_FLAGS) || call.has(TITLE_FLAGS) {
                return Err("implementers and gardeners may not edit an issue body or title; the spec and acceptance criteria belong to the lead who readied it".to_owned());
            }
            if call.has(GRAPH_FLAGS) {
                return Err("dependencies and sub-issues are the lead's (team/01 section 4); name the dependency in the hand-off".to_owned());
            }
            own_issue(rules, call)
        }
        ("pr", "create" | "edit" | "ready") => {
            let base = call.values(BASE_FLAGS)?;
            if let Some(other) = base.iter().find(|base| **base != rules.github.base) {
                return Err(format!(
                    "a pull request targets `{}`, not `{other}`; the merge queue lands only there",
                    rules.github.base
                ));
            }
            own_pull_request(rules, call, cwd)
        }
        _ => Ok(false),
    }
}

/// An implementer's or gardener's issue calls name its own item.
fn own_issue(rules: &Rules, call: &Call) -> Result<bool, String> {
    let Some(item) = rules.identity.item_number() else {
        return Err(format!(
            "`{}` needs a leased item; file a proposed issue instead",
            call.command()
        ));
    };
    let named = call
        .positional
        .first()
        .is_some_and(|word| !word.opaque && word.value.trim_start_matches('#') == item.to_string());
    if named {
        Ok(true)
    } else {
        Err(format!(
            "`{}` works only on your own item #{item}",
            call.command()
        ))
    }
}

/// Evaluators, `eval-architecture` among them: comments, check runs and their own commit
/// statuses on this repository, proposed issues and the labels `.github/labels.toml` gives them
/// (`tier:` and `trust-core` for eval-tier, `ui-baseline` for eval-ux), never an issue's body,
/// title or dependencies.
fn evaluator(
    rules: &Rules,
    call: &Call,
    statuses: &Statuses,
    stdin: Option<&Word>,
) -> Result<bool, String> {
    match (call.group, call.sub) {
        ("issue" | "pr", "comment") => Ok(true),
        ("issue", "create") => proposed_issue(call, statuses),
        ("issue" | "pr", "edit") => {
            if call.has(BODY_FLAGS) || call.has(TITLE_FLAGS) || call.has(GRAPH_FLAGS) {
                return Err("evaluators edit labels only; the spec belongs to the lead".to_owned());
            }
            Ok(call.has(LABEL_FLAGS))
        }
        ("api", _) => posts_verdict(call, &rules.github.repository, rules.agent_name(), stdin),
        _ => Ok(false),
    }
}

/// Council seats and everyone else: comments and proposed issues.
fn commenter(call: &Call, statuses: &Statuses) -> Result<bool, String> {
    match (call.group, call.sub) {
        ("issue" | "pr", "comment") => Ok(true),
        ("issue", "create") => proposed_issue(call, statuses),
        _ => Ok(false),
    }
}

/// A new issue filed with the status `.github/labels.toml` files issues as, and no dependencies.
fn proposed_issue(call: &Call, statuses: &Statuses) -> Result<bool, String> {
    let labels = call.values(LABEL_FLAGS)?;
    let filed_as = statuses.filed_as();
    if !labels.iter().any(|label| label == filed_as) {
        return Err(format!(
            "a new issue from this role carries `--label {filed_as}`; a lead readies it"
        ));
    }
    if call.has(GRAPH_FLAGS) {
        return Err("dependencies and sub-issues are the lead's (team/01 section 4); name them in the issue body".to_owned());
    }
    Ok(true)
}

/// The pull request of the session's own branch: `--head` or the checked-out branch.
fn own_pull_request(rules: &Rules, call: &Call, cwd: Option<&Path>) -> Result<bool, String> {
    let head = call.values(&["-H", "--head"])?.into_iter().next();
    let selector = call.positional.first().filter(|_| call.sub != "create");
    let numbered = selector.is_some_and(|word| {
        word.opaque || word.value.chars().all(|c| c.is_ascii_digit() || c == '#')
    });
    if numbered {
        return Err(
            "name your pull request by running the command on your branch, without a number"
                .to_owned(),
        );
    }
    let branch = head
        .or_else(|| selector.map(|word| word.value.clone()))
        .or_else(|| cwd.and_then(|dir| rules.branch(dir)))
        .unwrap_or_default();
    if rules.is_own_branch(&branch) {
        Ok(true)
    } else {
        Err(format!(
            "`{}` works only on your own agent branch, not `{branch}`",
            call.command()
        ))
    }
}

/// The here-document or here-string a command reads on stdin.
fn document(invocation: &Invocation) -> Option<&Word> {
    invocation
        .redirects
        .iter()
        .find(|redirect| redirect.kind == RedirectKind::Document)
        .map(|redirect| &redirect.target)
}

/// `gh api -X POST repos/<repository>/check-runs` and `PATCH .../check-runs/<id>`, or
/// `-X POST repos/<repository>/statuses/<sha>` under the context `grdr-evaluator/<agent>`, given
/// as a field or in the JSON body `--input -` reads from a literal here-document (the review
/// workflow's form).
fn posts_verdict(
    call: &Call,
    repository: &str,
    agent: &str,
    stdin: Option<&Word>,
) -> Result<bool, String> {
    let method = call
        .values(&["-X", "--method"])
        .ok()
        .and_then(|v| v.into_iter().next())
        .unwrap_or_default()
        .to_ascii_uppercase();
    let endpoint = call
        .positional
        .first()
        .map(|word| word.value.trim_start_matches('/'))
        .unwrap_or_default();
    let mut parts = endpoint.splitn(5, '/');
    let (repos, owner, name, kind, sha) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    );
    let this_repository = match (owner, name) {
        (Some(owner), Some(name)) => format!("{owner}/{name}").eq_ignore_ascii_case(repository),
        _ => false,
    };
    if repos != Some("repos") || !this_repository {
        return Ok(false);
    }
    match kind {
        Some("check-runs") => Ok(matches!(method.as_str(), "POST" | "PATCH")),
        Some("statuses") if method == "POST" && sha.is_some_and(is_commit) => {
            let context = format!("{STATUS_CONTEXT}{agent}");
            let fields = call.values(FIELD_FLAGS)?;
            let in_fields = fields
                .iter()
                .any(|field| *field == format!("context={context}"));
            let from_stdin = call
                .raw_values(INPUT_FLAGS)
                .iter()
                .any(|word| word.value == "-");
            let in_body = from_stdin
                && stdin
                    .filter(|body| !body.opaque)
                    .and_then(|body| serde_json::from_str::<serde_json::Value>(&body.value).ok())
                    .is_some_and(|body| {
                        body.get("context").and_then(serde_json::Value::as_str)
                            == Some(context.as_str())
                    });
            if in_fields || in_body {
                Ok(true)
            } else {
                Err(format!(
                    "a commit status from {agent} carries `-f context={context}`, or that context in the JSON `--input -` reads from a quoted here-document"
                ))
            }
        }
        _ => Ok(false),
    }
}

fn is_commit(sha: &str) -> bool {
    !sha.is_empty() && sha.chars().all(|c| c.is_ascii_hexdigit())
}
