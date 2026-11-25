use crate::{AppVm, Effect, Intent, ModeLevel, RulePreset, ThemeChoice};

/// Pure view-model state transition enforcing narrowing-immediate, widening-proposal, and
/// agent-caller refusal (`design/28` requirements R4 and R5).
pub fn reduce(app: &mut AppVm, intent: Intent) -> Vec<Effect> {
    match intent {
        Intent::Navigate(screen) => {
            app.screen = screen;
            Vec::new()
        }
        Intent::ToggleTheme => {
            app.preferences.theme = match app.preferences.theme {
                ThemeChoice::Light => ThemeChoice::Dark,
                ThemeChoice::Dark => ThemeChoice::Light,
            };
            Vec::new()
        }
        Intent::SelectSession(session_id) => {
            app.activity.selected_session_id = Some(session_id);
            Vec::new()
        }
        Intent::FilterActivity(filter) => {
            app.activity.filter = filter;
            Vec::new()
        }
        Intent::InspectReceipt { reference } => {
            app.activity.inspected_receipt_ref = Some(reference.clone());
            vec![Effect::InspectWhyCard { reference }]
        }
        Intent::DismissWhyCard => {
            app.activity.inspected_receipt_ref = None;
            Vec::new()
        }
        Intent::TriageReviewCluster { cluster_id, action } => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot modify review triage status.".to_owned(),
                }];
            }
            if let Some(cluster) = app
                .activity
                .review_clusters
                .iter_mut()
                .find(|c| c.id == cluster_id)
            {
                cluster.decided = true;
            }
            vec![Effect::ApplyReviewDecision { cluster_id, action }]
        }
        Intent::OpenWebConsole { route } => vec![Effect::OpenWebConsole { route }],
        Intent::SelectInstallProfile(profile) => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot modify install profile.".to_owned(),
                }];
            }
            app.first_run.selected_profile = profile;
            app.home.install_profile = profile;
            app.settings.install_profile = profile;
            Vec::new()
        }
        Intent::ConfirmProtection => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot confirm protection settings.".to_owned(),
                }];
            }
            let profile = app.first_run.selected_profile;
            app.home.install_profile = profile;
            app.settings.install_profile = profile;
            if let Some(step) = app
                .first_run
                .steps
                .iter_mut()
                .find(|s| s.id == "turn-on-protection")
            {
                step.done = true;
            }
            Vec::new()
        }
        Intent::OpenApproval { request_id } => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot approve requests.".to_owned(),
                }];
            }
            vec![Effect::LaunchApprove { request_id }]
        }
        Intent::SelectRulePreset(preset) => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot alter policy presets.".to_owned(),
                }];
            }
            if matches!(preset, RulePreset::WatchOnly) {
                return vec![Effect::ProposeWidening {
                    rule_id: "preset.watch_only".to_owned(),
                    target_mode: ModeLevel::Watch,
                }];
            }
            app.rules.preset = preset;
            Vec::new()
        }
        Intent::SetRuleMode { rule_id, next_mode } => {
            if app.agent_caller {
                return vec![Effect::NotifyReadOnly {
                    reason: "Agent callers cannot modify rule enforcement modes.".to_owned(),
                }];
            }
            let Some(rule) = app.rules.rules.iter_mut().find(|r| r.id == rule_id) else {
                return Vec::new();
            };
            if rule.mode.is_widening(next_mode) {
                app.rules.pending_widening_rule_id = Some(rule_id.clone());
                vec![Effect::ProposeWidening {
                    rule_id,
                    target_mode: next_mode,
                }]
            } else {
                rule.mode = next_mode;
                app.rules.pending_widening_rule_id = None;
                vec![Effect::ApplyLocalRuleMode {
                    rule_id,
                    mode: next_mode,
                }]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_run_opens_with_three_of_six_steps_ticked() {
        let vm = AppVm::demo();
        assert_eq!(vm.first_run.steps.len(), 6);
        assert_eq!(vm.first_run.steps.iter().filter(|s| s.done).count(), 3);
    }

    #[test]
    fn narrowing_applies_immediately_while_widening_emits_proposal() {
        let mut vm = AppVm::demo();
        let narrow = reduce(
            &mut vm,
            Intent::SetRuleMode {
                rule_id: "essentials.secret-exfil-egress".to_owned(),
                next_mode: ModeLevel::Ask,
            },
        );
        assert_eq!(
            narrow,
            vec![Effect::ApplyLocalRuleMode {
                rule_id: "essentials.secret-exfil-egress".to_owned(),
                mode: ModeLevel::Ask,
            }]
        );

        let widen = reduce(
            &mut vm,
            Intent::SetRuleMode {
                rule_id: "essentials.cred-store.read".to_owned(),
                next_mode: ModeLevel::Watch,
            },
        );
        assert_eq!(
            widen,
            vec![Effect::ProposeWidening {
                rule_id: "essentials.cred-store.read".to_owned(),
                target_mode: ModeLevel::Watch,
            }]
        );
    }

    #[test]
    fn inspect_receipt_and_triage_update_activity_state() {
        let mut vm = AppVm::demo();
        let why_eff = reduce(
            &mut vm,
            Intent::InspectReceipt {
                reference: "8F2KQ-M41TZW".to_owned(),
            },
        );
        assert_eq!(
            vm.activity.inspected_receipt_ref.as_deref(),
            Some("8F2KQ-M41TZW")
        );
        assert!(matches!(
            why_eff.as_slice(),
            [Effect::InspectWhyCard { .. }]
        ));

        let triage_eff = reduce(
            &mut vm,
            Intent::TriageReviewCluster {
                cluster_id: "rev-01".to_owned(),
                action: "suppress".to_owned(),
            },
        );
        assert!(
            vm.activity
                .review_clusters
                .iter()
                .any(|c| c.id == "rev-01" && c.decided)
        );
        assert!(matches!(
            triage_eff.as_slice(),
            [Effect::ApplyReviewDecision { .. }]
        ));
    }

    #[test]
    fn agent_caller_refuses_all_mutations() {
        let mut vm = AppVm::demo();
        vm.agent_caller = true;
        let out = reduce(
            &mut vm,
            Intent::OpenApproval {
                request_id: "apr-1".to_owned(),
            },
        );
        assert!(matches!(out.as_slice(), [Effect::NotifyReadOnly { .. }]));

        let out_triage = reduce(
            &mut vm,
            Intent::TriageReviewCluster {
                cluster_id: "rev-01".to_owned(),
                action: "promote".to_owned(),
            },
        );
        assert!(matches!(
            out_triage.as_slice(),
            [Effect::NotifyReadOnly { .. }]
        ));
    }
}
