//! The deny classes of team/03 section 4.1 that are not git, gh or writes (`writes.rs`): publish
//! commands; pipe-to-shell; snapshot acceptance; package additions by implementers; npm, npx,
//! yarn and bun in every session (owner instruction 24); another harness with its permission
//! checks off, or any nested harness from an agent; the session identity variables and the `gh`
//! variables that choose another repository, host or token; and, from an agent session, the kit
//! commands that rewrite the kit, start sessions or land pull requests.

use super::Rules;
use crate::hook::identity::Role;
use crate::hook::shell::Invocation;

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "pwsh",
    "powershell",
    "cmd",
];
const INTERPRETERS: &[&str] = &["python", "python3", "node", "perl", "ruby", "deno", "bun"];
const SNAPSHOT_RUNNERS: &[&str] = &["vitest", "jest", "playwright"];
const SNAPSHOT_FLAGS: &[&str] = &["-u", "--update", "--updatesnapshot", "--update-snapshots"];
const PACKAGE_RUNNERS: &[&str] = &["npm", "pnpm", "yarn", "bun"];
/// Package CLIs no session runs, by any runner, with what to do instead. Owner instruction 18:
/// the modern-web-guidance CLI downloads code on each run and sends telemetry, and its guides are
/// already files in the installed plugin.
const REFUSED_PACKAGES: &[(&str, &str)] = &[(
    "modern-web-guidance",
    "read the guides in the installed modern-web-guidance plugin's skills/modern-web-guidance/ directory",
)];
/// pnpm subcommands that run a package's executable.
const PNPM_RUNNERS: &[&str] = &["dlx", "exec"];
/// The wrappers the scanner records for pnpm's package runners (`exec`, `dlx` and `x`). An agent
/// never runs a program through them: `pnpm exec <prog>` and `pnpm dlx <pkg>` run an arbitrary
/// program, so the write set, the protected-path rules, the shell rules and the fetch list that
/// the guard applies to a named command do not reach what that program writes or fetches.
const PNPM_RUNNER_WRAPPERS: &[&str] = &["pnpm exec", "pnpm dlx", "pnpm x"];
/// Owner instruction 24: pnpm is the only JavaScript package manager. `npm publish` is denied as
/// a publish command instead.
const NOT_PNPM: &[(&str, &str)] = &[
    (
        "npm",
        "pnpm install --frozen-lockfile, pnpm add or pnpm run",
    ),
    (
        "yarn",
        "pnpm install --frozen-lockfile, pnpm add or pnpm run",
    ),
    ("bun", "pnpm install --frozen-lockfile or pnpm add"),
    ("npx", "pnpm dlx <package>@<version> or pnpm exec"),
    ("bunx", "pnpm dlx <package>@<version> or pnpm exec"),
    ("npm exec", "pnpm exec or pnpm dlx <package>@<version>"),
    ("npm x", "pnpm exec or pnpm dlx <package>@<version>"),
    ("yarn exec", "pnpm exec"),
    ("yarn dlx", "pnpm dlx <package>@<version>"),
];
/// The launcher sets these for the hooks; an agent never sets them.
const IDENTITY_PREFIX: &str = "GRDR_";
const IDENTITY_VARIABLES: &[&str] = &["CLAUDE_PROJECT_DIR", "CLAUDE_ENV_FILE", "CLAUDE_CONFIG_DIR"];
/// What `gh` reads its repository, host and token from; kit render sets `GH_REPO` for sessions.
const GH_VARIABLES: &[&str] = &[
    "GH_REPO",
    "GH_HOST",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "GH_CONFIG_DIR",
];
/// Global cargo options that take the next word as their value.
const CARGO_VALUED: &[&str] = &["--color", "-Z", "--config", "-C"];
/// cargo vet subcommands that only read; every other one writes supply-chain/ (`certify`, `trust`,
/// `regenerate`, `prune`, `fmt`, `add-exemption` and the rest), so an agent runs only these. An
/// empty subcommand is `check`, the default.
const CARGO_VET_READS: &[&str] = &["check", "inspect", "diff", "dump-graph", "explain-audit"];
/// cargo vet options that take the next word as their value, so vet's own subcommand is read past
/// them. These values are directories or files vet writes; writes.rs judges them as write targets.
const CARGO_VET_OUTPUTS: &[&str] = &["--output-file", "--log-file", "--store-path"];
/// `claude` options that replace the settings, and with them the kit's hooks.
const SETTINGS_FLAGS: &[&str] = &["--settings", "--setting-sources"];
/// Flags of other harnesses that turn their permission checks off.
const BYPASS_FLAGS: &[(&str, &[&str])] = &[
    (
        "claude",
        &[
            "--dangerously-skip-permissions",
            "--allow-dangerously-skip-permissions",
            "bypasspermissions",
            "--permission-mode=bypasspermissions",
            "--bare",
        ],
    ),
    (
        "codex",
        &[
            "--dangerously-bypass-approvals-and-sandbox",
            "--yolo",
            "--full-auto",
            "danger-full-access",
            "--sandbox=danger-full-access",
        ],
    ),
    ("gemini", &["--yolo", "-y", "--approval-mode=yolo", "yolo"]),
    ("qwen", &["--yolo", "-y", "--approval-mode=yolo", "yolo"]),
    ("copilot", &["--allow-all-tools", "--allow-all", "--yolo"]),
    ("cursor-agent", &["--force", "-f"]),
    ("amp", &["--dangerously-allow-all"]),
    ("aider", &["--yes-always"]),
];

/// `INSTA_UPDATE`, `INSTA_FORCE_PASS`, a git configuration that moves the hooks, and in an agent
/// session the identity variables the launcher sets.
pub fn environment(rules: &Rules, invocation: &Invocation) -> Vec<String> {
    let mut reasons = Vec::new();
    for (name, value) in &invocation.assignments {
        let upper = name.to_ascii_uppercase();
        let accepts = (upper == "INSTA_UPDATE" && !value.value.eq_ignore_ascii_case("no"))
            || upper == "INSTA_FORCE_PASS";
        if accepts {
            reasons.push(format!(
                "{name}={} accepts snapshots; snapshots change only through a reviewed fixture",
                value.value
            ));
        }
        if upper.starts_with("GIT_CONFIG") && value.value.to_ascii_lowercase().contains("hookspath")
        {
            reasons.push(format!(
                "{name} moves core.hooksPath; git hooks stay where the kit put them"
            ));
        }
        let identity =
            upper.starts_with(IDENTITY_PREFIX) || IDENTITY_VARIABLES.contains(&upper.as_str());
        if identity && rules.is_agent() {
            reasons.push(format!(
                "{name} is session identity that the launcher sets; an agent session never sets it"
            ));
        }
        if GH_VARIABLES.contains(&upper.as_str()) && rules.is_agent() {
            reasons.push(format!(
                "{name} chooses gh's repository, host or login; an agent session's gh calls go to {} as the session's login",
                rules.github.repository
            ));
        }
    }
    reasons
}

/// The rules for programs other than git and gh.
pub fn programs(rules: &Rules, invocation: &Invocation) -> Vec<String> {
    let Some(name) = invocation.name() else {
        return Vec::new();
    };
    let mut reasons = Vec::new();
    reasons.extend(pipe_to_shell(invocation, name));
    reasons.extend(bypass(rules, invocation, name));
    reasons.extend(snapshots(invocation, name));
    reasons.extend(not_pnpm(invocation, name));
    reasons.extend(refused_package(invocation, name));
    reasons.extend(pnpm_runner(rules, invocation));
    match name {
        "cargo" => reasons.extend(cargo(rules, invocation)),
        "xtask" if rules.is_agent() => {
            reasons.extend(kit_denial(rules, &lowercase(invocation)));
        }
        "twine" if invocation.leading(1).as_deref() == Some(&["upload"]) => {
            reasons.push(publish_reason("twine upload"))
        }
        "release-please" if rules.is_agent() => {
            reasons.push("release-please runs in CI, not in an agent session".to_owned())
        }
        _ => {}
    }
    if PACKAGE_RUNNERS.contains(&name) && invocation.leading(1).as_deref() == Some(&["publish"]) {
        reasons.push(publish_reason(&format!("{name} publish")));
    }
    if rules.role == Role::Implementer
        && let Some(addition) = package_addition(invocation, name)
    {
        reasons.push(format!(
            "`{addition}` adds a dependency; implementers ask for it in the hand-off and a lead files the item"
        ));
    }
    reasons
}

fn cargo(rules: &Rules, invocation: &Invocation) -> Vec<String> {
    let args = lowercase(invocation);
    let words: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|arg| !arg.starts_with('+'))
        .collect();
    let mut position = 0;
    while let Some(arg) = words.get(position).filter(|arg| arg.starts_with('-')) {
        position += if CARGO_VALUED.contains(arg) { 2 } else { 1 };
    }
    let sub = words.get(position).copied().unwrap_or_default();
    let after_sub: Vec<&str> = words.iter().skip(position + 1).copied().collect();
    let mut reasons = Vec::new();
    match sub {
        "publish" | "yank" | "owner" | "release" => reasons.push(publish_reason(&format!("cargo {sub}"))),
        "insta" if after_sub.iter().any(|arg| matches!(*arg, "accept" | "review" | "--accept" | "--review")) => {
            reasons.push("cargo insta accept and review accept snapshots; snapshots change only through a reviewed fixture".to_owned());
        }
        "add" | "install" if rules.role == Role::Implementer => reasons.push(format!(
            "`cargo {sub}` adds a dependency or a tool; implementers ask for it in the hand-off and a lead files the item"
        )),
        "vet" if rules.is_agent() => reasons.extend(cargo_vet(&after_sub)),
        "mutants" if rules.is_agent() && after_sub.contains(&"--in-place") => reasons.push(
            "`cargo mutants --in-place` rewrites the source it mutates; run it without --in-place so it works on a copy".to_owned(),
        ),
        "xtask" if rules.is_agent() => {
            reasons.extend(kit_denial(rules, &after_sub.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>()));
        }
        "run" if rules.is_agent() && runs_xtask(&words) => {
            let after: Vec<String> = words.iter().skip_while(|arg| **arg != "--").skip(1).map(|arg| (*arg).to_owned()).collect();
            reasons.extend(kit_denial(rules, &after));
        }
        _ => {}
    }
    reasons
}

/// cargo vet's own subcommand, when an agent runs one that is not read-only: `certify`, `trust`,
/// `regenerate`, `prune`, `fmt`, `add-exemption` and the rest write supply-chain/, which the
/// hooks never check through this binary. The `--locked` the allow rule keeps only stops vet
/// fetching imports. `words` is everything after `vet`.
fn cargo_vet(words: &[&str]) -> Option<String> {
    let mut index = 0;
    while let Some(word) = words.get(index).filter(|word| word.starts_with('-')) {
        let takes_value = CARGO_VET_OUTPUTS.contains(word) && !word.contains('=');
        index += if takes_value { 2 } else { 1 };
    }
    let sub = words.get(index).copied().unwrap_or("check");
    (!CARGO_VET_READS.contains(&sub)).then(|| {
        format!(
            "`cargo vet {sub}` writes supply-chain/, which is protected; an agent runs only cargo vet (check) and cargo vet check"
        )
    })
}

pub(super) fn runs_xtask(words: &[&str]) -> bool {
    words
        .windows(2)
        .any(|pair| matches!(pair, ["-p" | "--package" | "--bin", "xtask"]))
        || words
            .iter()
            .any(|arg| *arg == "--package=xtask" || *arg == "--bin=xtask")
}

/// From an agent session: `kit render` and `kit install`, which rewrite the kit that judges it;
/// `kit launch`, `kit claim` and `dispatch`, which start or lease sessions under another identity;
/// `queue`, the merge queue, which lands pull requests under the owner's login; and `labels sync`,
/// which rewrites the repository's labels. A protected-change lease may run `kit render`, so a
/// change to `.agents/` carries the tree it renders: the session's own settings do not change
/// under it (ConfigChange), its hooks run the installed binary, and V05 holds the rendered files to
/// the item's write set.
fn kit_denial(rules: &Rules, args: &[String]) -> Option<String> {
    let positionals: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|arg| !arg.starts_with('-'))
        .collect();
    let checking = args
        .iter()
        .any(|arg| arg == "--check" || arg == "--dry-run");
    match positionals.as_slice() {
        ["kit", "render", ..] if rules.identity.protected_lease => None,
        ["kit", "render" | "install", ..] => Some("`kit render` and `kit install` rewrite the kit that judges this session; they run outside agent sessions, and `kit render` in a protected-change lease".to_owned()),
        ["kit", sub @ ("launch" | "claim"), ..] => Some(format!("`kit {sub}` starts or leases a session under another identity; only the dispatcher and a person's session do")),
        ["dispatch", ..] => Some("`dispatch` runs the loop that starts every session; it never runs inside an agent session".to_owned()),
        ["queue", ..] if !checking => Some("`queue` is the merge queue, which lands pull requests; it runs only in the dispatcher or a person's session".to_owned()),
        ["labels", "sync", ..] if !checking => Some("`labels sync` rewrites the repository's labels; it runs outside agent sessions".to_owned()),
        _ => None,
    }
}

fn publish_reason(command: &str) -> String {
    format!("`{command}` publishes; release-please and the merge queue release, never a session")
}

fn pipe_to_shell(invocation: &Invocation, name: &str) -> Option<String> {
    let evaluates = matches!(name, "iex" | "invoke-expression");
    let has_command_flag = invocation.args.iter().any(|word| {
        let value = word.value.to_ascii_lowercase();
        value == "-c"
            || value == "/c"
            || value.starts_with("-command")
            || (value.starts_with('-') && !value.starts_with("--") && value.ends_with('c'))
    });
    let reads_stdin =
        invocation.positionals().next().is_none() || invocation.values().any(|value| value == "-");
    let shell = SHELLS.contains(&name) && !has_command_flag;
    let interpreter = INTERPRETERS.contains(&name) && reads_stdin;
    let piped = invocation.after_pipe && (shell || interpreter || evaluates);
    let substituted = (SHELLS.contains(&name) || matches!(name, "source" | "."))
        && invocation
            .args
            .iter()
            .any(|word| word.raw.starts_with("<("));
    (piped || substituted).then(|| {
        format!("piping into {name} runs code nobody read; download, read, then run the file")
    })
}

fn bypass(rules: &Rules, invocation: &Invocation, name: &str) -> Option<String> {
    let (_, flags) = BYPASS_FLAGS.iter().find(|(harness, _)| *harness == name)?;
    if rules.is_agent() {
        return Some(format!(
            "`{name}` starts another harness session inside an agent session; the dispatcher starts sessions"
        ));
    }
    let args = lowercase(invocation);
    if name == "claude"
        && let Some(flag) = args.iter().find(|arg| {
            SETTINGS_FLAGS
                .iter()
                .any(|flag| arg.split('=').next() == Some(*flag))
        })
    {
        return Some(format!(
            "`claude {flag}` replaces the settings that load the kit's hooks; start sessions with cargo xtask kit launch"
        ));
    }
    let flag = args.iter().find(|arg| flags.contains(&arg.as_str()))?;
    Some(format!(
        "`{name} {flag}` starts a harness with its permission checks off"
    ))
}

fn snapshots(invocation: &Invocation, name: &str) -> Option<String> {
    let args = lowercase(invocation);
    let runner = SNAPSHOT_RUNNERS.contains(&name)
        || (PACKAGE_RUNNERS.contains(&name)
            && args.iter().any(|arg| {
                arg == "test" || arg == "run" || SNAPSHOT_RUNNERS.contains(&arg.as_str())
            }));
    let flag = args
        .iter()
        .find(|arg| SNAPSHOT_FLAGS.contains(&arg.as_str()))
        .filter(|_| runner)?;
    Some(format!(
        "`{name} {flag}` accepts snapshots; snapshots change only through a reviewed fixture"
    ))
}

/// A refused package CLI run directly or through `pnpm dlx` or `pnpm exec`, with or without a
/// version.
fn refused_package(invocation: &Invocation, name: &str) -> Option<String> {
    let mut positionals = invocation.positionals().map(|word| word.value.as_str());
    let run = match name {
        "pnpm" => positionals
            .next()
            .filter(|sub| PNPM_RUNNERS.contains(sub))
            .and_then(|_| positionals.next()),
        _ => Some(name),
    }?;
    let package = run
        .rsplit_once('@')
        .filter(|(package, _)| !package.is_empty())
        .map_or(run, |(package, _)| package);
    let (refused, instead) = REFUSED_PACKAGES
        .iter()
        .find(|(refused, _)| *refused == package)?;
    Some(format!(
        "`{refused}` is not run in this repository; {instead}"
    ))
}

/// `pnpm exec <prog>` and `pnpm dlx <pkg>` from an agent session, which the scanner unwrapped to
/// the inner program: refused whatever the program is, because the guard applies the write set,
/// the protected-path rules and the fetch list to a named command, not to one pnpm runs for it.
fn pnpm_runner(rules: &Rules, invocation: &Invocation) -> Option<String> {
    if !rules.is_agent() {
        return None;
    }
    let runner = invocation
        .wrappers
        .iter()
        .find(|wrapper| PNPM_RUNNER_WRAPPERS.contains(&wrapper.as_str()))?;
    Some(format!(
        "`{runner}` runs an arbitrary program, so the write set, the protected-path rules and the fetch list do not reach what it writes or fetches; run a package's tools through its package.json scripts with pnpm run"
    ))
}

/// npm, npx, yarn, bun and bunx, as programs or as the wrapper in front of one; `npm exec` and
/// the like by their subcommand, so the message names the right replacement.
fn not_pnpm(invocation: &Invocation, name: &str) -> Option<String> {
    let sub = invocation
        .leading(1)
        .and_then(|words| words.first().copied())
        .unwrap_or_default();
    let publishing = name == "npm" && sub == "publish";
    let with_sub = format!("{name} {sub}");
    let own = NOT_PNPM
        .iter()
        .find(|(denied, _)| *denied == with_sub)
        .or_else(|| NOT_PNPM.iter().find(|(denied, _)| *denied == name))
        .filter(|_| !publishing);
    let (denied, replacement) = own.or_else(|| {
        invocation
            .wrappers
            .iter()
            .map(String::as_str)
            .find_map(|program| NOT_PNPM.iter().find(|(denied, _)| *denied == program))
    })?;
    Some(format!(
        "`{denied}`: this repository uses pnpm only (owner instruction 24); use {replacement}"
    ))
}

fn package_addition(invocation: &Invocation, name: &str) -> Option<String> {
    let positionals: Vec<&str> = invocation
        .positionals()
        .map(|word| word.value.as_str())
        .collect();
    let (sub, rest) = positionals.split_first()?;
    let adds = match (name, *sub) {
        ("npm" | "pnpm" | "bun", "install" | "i" | "add" | "isntall") => {
            !rest.is_empty() || *sub == "add"
        }
        ("yarn", "add") | ("uv", "add") | ("go", "get") => true,
        ("pip" | "pip3", "install") => !rest.is_empty(),
        ("uv" | "python" | "python3", "pip") => rest.first() == Some(&"install"),
        _ => false,
    };
    adds.then(|| format!("{name} {sub}"))
}

pub(super) fn lowercase(invocation: &Invocation) -> Vec<String> {
    invocation.values().map(str::to_ascii_lowercase).collect()
}
