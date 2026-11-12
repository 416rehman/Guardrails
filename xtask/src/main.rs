use std::process::ExitCode;

use xtask::{dispatch, gates, github, hook, kit, orchestrate};

const USAGE: &str = "\
usage: cargo xtask <command> [options]

  verify [--fast] [--base <ref>] [--json <path>]   run the gates (team/05 section 3)
  structure [--base <ref>] [<path>...]              run checks S1 to S7, and UX1 to UX8 on interface paths
  kit render [--out <dir>]                          render .claude/, deploy/fleet/, hook fixture index
  kit check                                         fail when the rendered tree or kit data is wrong
  kit install                                       build the kit binary into .agent/kit/bin/
  kit launch <agent> [--item <n>] [--seed] [...]    start a Claude Code session as one roster agent
  kit ready <n>                                     ready a proposed issue: ready.v1 and status:ready
  kit handoff [...]                                 post the hand-off, push, open the pull request
  kit digest <n>                                    the issue's acceptance digest beside its ready.v1 and lease.v1
  kit place [--stage] <path>...                     put a widened session's staged protected files in place
  kit claim --next                                  lease the next ready issue through the dispatcher
  kit ci-env --pull-request <n> [...]               print the lease identity CI runs a pull request's gates as, save its snapshot
  hook <handler>                                    one hook handler; JSON on stdin
  hooks selftest | hooks-selftest                   fire every handler against its fixtures
  dispatch [...]                                    lease ready issues and run routines
  queue [--once] [--dry-run]                        land pull requests whose lane passed (merge queue)
  labels sync|check                                 apply or compare .github/labels.toml
  risk [...]                                        classify a diff: tier and review lane
  prove --arm before|after|revert [...]             the three-arm proof of a bug fix
  audit run <id> [...]                              run one audit prompt of audits/library.toml
  github check                                      check gh, its login, the repository and its settings
";

const NOT_BUILT: &[&str] = &[
    "archlint",
    "bootstrap",
    "ci-endpoints",
    "evidence",
    "gates",
    "governance-sync",
    "matrix-run",
    "mutants",
    "new-crate",
    "protected",
    "queue-jobs",
    "ratchet",
    "security",
    "tools",
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(1);
    };
    match command.as_str() {
        "verify" => report(gates::verify_command(rest)),
        "structure" => report(gates::structure::command(rest)),
        "kit" => kit_command(rest),
        "hook" | "hooks" | "hooks-selftest" => hook::run(command, rest),
        "dispatch" => report(dispatch::run(command, rest)),
        "queue" => report(dispatch::merge::command(rest)),
        "labels" | "risk" | "prove" | "audit" => report(orchestrate::run(command, rest)),
        "github" => report(github::command(rest)),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        other if NOT_BUILT.contains(&other) => {
            eprintln!("xtask {other}: not built yet");
            ExitCode::from(1)
        }
        other => {
            eprint!("xtask: unknown command `{other}`\n{USAGE}");
            ExitCode::from(1)
        }
    }
}

fn kit_command(args: &[String]) -> ExitCode {
    let Some((sub, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(1);
    };
    match sub.as_str() {
        "render" => report(kit::render_command(rest)),
        "check" => report(kit::check_command(rest)),
        "install" => report(kit::install_command(rest)),
        "place" => report(kit::place::command(rest)),
        other => report(orchestrate::run(&format!("kit {other}"), rest)),
    }
}

fn report(result: anyhow::Result<ExitCode>) -> ExitCode {
    result.unwrap_or_else(|error| {
        eprintln!("error: {error:#}");
        ExitCode::from(1)
    })
}
