//! What stops the dispatcher before it leases or starts anything: a checkout Claude Code does
//! not trust, and a state file that does not parse.

use std::process::ExitCode;

use super::tests::Setup;
use crate::config::session::ItemStatus;
use crate::orchestrate::launch::owner_step_or;

#[test]
fn an_untrusted_checkout_leases_and_starts_nothing() {
    let setup = Setup::new("");
    let harness = setup.temp.repo().read(".agents/harness.toml").unwrap();
    let untrusted = harness.replace(
        "[workspace_trust]\ncheck = \"managed\"\n",
        "[workspace_trust]\ncheck = \"claude-config\"\nconfig_file = \".claude.json\"\nprojects_key = \"projects\"\naccepted_key = \"hasTrustDialogAccepted\"\nuntrusted = \"Run claude once in {root}.\"\nundecided = \"Run claude once in {root} ({why}).\"\n",
    );
    setup.temp.write(".agents/harness.toml", &untrusted);
    setup.ready_issue(7, &[], "lead-core");
    let mut dispatcher = setup.dispatcher();
    let error = dispatcher.step_github().unwrap_err();
    assert!(
        error.to_string().contains("Run claude once in"),
        "{error:#}"
    );
    assert!(dispatcher.run(true).is_err());
    assert_eq!(setup.status(7), Some(ItemStatus::Ready));
    assert!(setup.fake.calls().is_empty());
    assert_eq!(
        owner_step_or(error).unwrap(),
        ExitCode::from(crate::github::EXIT_OWNER_STEP)
    );
}

#[test]
fn a_state_file_that_does_not_parse_stops_the_dispatcher() {
    for file in [
        ".agent/state/dispatch-routines.json",
        ".agent/state/dispatch-assists.json",
    ] {
        let setup = Setup::new("");
        setup
            .temp
            .write(file, "{\"last_started\": {\"garden-docs\": ");
        let Some(error) = setup.try_dispatcher().err() else {
            panic!("{file} that does not parse is not read as empty");
        };
        assert!(format!("{error:#}").contains(file), "{error:#}");
    }
}
