use grdr_ui_model::{Intent, RulePreset};
use rune::{El, Tx, col, row, spacer, text};
use rune_kit::SegmentedControl;

use crate::kit::{DesktopApp, ledger_header, mode_segmented, quoted_chip, status_pill};
use crate::theme::StudioTheme;

#[must_use]
pub fn render(app: &DesktopApp, t: &StudioTheme) -> El {
    let vm = &app.vm.rules;
    let preset_idx = match vm.preset {
        RulePreset::Recommended => Some(0),
        RulePreset::Stricter => Some(1),
        RulePreset::WatchOnly => Some(2),
    };

    let preset_ctrl = SegmentedControl::new(&["Recommended", "Stricter", "Watch only"], preset_idx)
        .label("Policy preset")
        .fit()
        .on_pick(|s: &mut DesktopApp, idx: usize, _: &mut Tx| {
            let p = match idx {
                0 => RulePreset::Recommended,
                1 => RulePreset::Stricter,
                _ => RulePreset::WatchOnly,
            };
            s.dispatch(Intent::SelectRulePreset(p));
        })
        .build(&t.kit);

    let mut rules_col = col().w_full().gap(4.0).child(ledger_header(
        "Essentials pack",
        &format!("{} rule(s)", vm.rules.len()),
        t,
    ));

    for rule in &vm.rules {
        let mut title_row = row()
            .gap(8.0)
            .center_y()
            .child(text(&rule.title).font(t.body_strong).color(t.c.ink_primary));
        if rule.locked {
            title_row = title_row.child(status_pill("Floor", t.c.block_bg, t.c.block, t));
        }

        rules_col = rules_col.child(
            row()
                .key(rule.id.as_str())
                .w_full()
                .pt(12.0)
                .pb(12.0)
                .center_y()
                .gap(16.0)
                .child(
                    col()
                        .grow(1.0)
                        .gap(4.0)
                        .child(title_row)
                        .child(
                            text(&rule.description)
                                .font(t.caption)
                                .color(t.c.ink_secondary)
                                .wrap()
                                .w_full(),
                        )
                        .child(
                            row()
                                .gap(8.0)
                                .center_y()
                                .child(quoted_chip(&rule.target_pattern, t))
                                .child(
                                    text(&rule.effective_note)
                                        .font(t.caption)
                                        .color(t.c.ink_muted),
                                ),
                        ),
                )
                .child(spacer())
                .child(mode_segmented(rule.id.clone(), rule.mode, rule.locked, t)),
        );
    }

    col()
        .key("screen-rules")
        .w_full()
        .gap(24.0)
        .child(text("Rules").font(t.display_headline).color(t.c.ink_primary))
        .child(
            text("Tightening a rule applies locally right away. Lowering protection emits a step-up proposal to grdr-approve.")
                .font(t.body)
                .color(t.c.ink_secondary)
                .wrap()
                .w_full(),
        )
        .child(preset_ctrl)
        .child(rules_col)
}
