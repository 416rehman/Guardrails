use grdr_ui_model::{ActivityVm, Intent, Screen, SessionRowVm};
use rune::{El, col, icon, row, spacer, text};

use crate::icons;
use crate::kit::{
    ChipSurface, entity_link, quoted_box, quoted_chip, secondary_button, status_pill,
    status_pill_with_icon,
};
use crate::theme::StudioTheme;
use crate::viz::elevated_card;

#[must_use]
pub fn render_why_panel(
    ref_code: &str,
    vm: &ActivityVm,
    selected_session: Option<&SessionRowVm>,
    t: &StudioTheme,
) -> El {
    let matched_cluster = vm
        .review_clusters
        .iter()
        .find(|c| c.receipt_ref == ref_code);
    let fallback_card = selected_session.and_then(|s| s.block_card.as_ref());
    let (rule_id, pack_id, target_q, reason_text, agent_told) =
        if let Some(cluster) = matched_cluster {
            let count = cluster.occurrence_count;
            let event_word = if count == 1 { "event" } else { "events" };
            (
                cluster.rule_id.clone(),
                "essentials".to_owned(),
                cluster.target_preview.clone(),
                format!(
                    "Cluster {} matched {} local {} under {}.",
                    cluster.rule_title, count, event_word, cluster.rule_id
                ),
                format!(
                    "Guardrails ADR held {} [GRDR-DEC-DENY / rule {} / ref {}].\nReason: Workspace isolation boundary.\nNext: Review policy or request exception.",
                    cluster.target_preview, cluster.rule_id, ref_code
                ),
            )
        } else if let Some(card) = fallback_card {
            (
                card.rule_id.clone(),
                card.pack_id.clone(),
                card.target_quoted.clone(),
                card.reason.clone(),
                card.agent_told.clone(),
            )
        } else {
            (
                "essentials.control-files".to_owned(),
                "essentials".to_owned(),
                "~/.ssh/id_ed25519".to_owned(),
                "Reading private keys or policy control files requires explicit authorization."
                    .to_owned(),
                format!(
                    "Guardrails ADR blocked file.read [GRDR-DEC-DENY / ref {ref_code}].\nReason: Reading local secrets is blocked by boundary policy.\nNext: Do not retry or work around it."
                ),
            )
        };

    let body = col()
        .w_full()
        .padding(16.0)
        .gap(10.0)
        .child(
            row()
                .w_full()
                .center_y()
                .gap(8.0)
                .child(icon(&icons::KEY, 16.0).color(t.c.allow))
                .child(
                    text("Why this happened")
                        .font(t.body_strong)
                        .color(t.c.ink_primary),
                )
                .child(spacer())
                .child(status_pill("GRDR-DEC-DENY", t.c.block_bg, t.c.block, t))
                .child(status_pill_with_icon(
                    "Signed receipt",
                    Some(&icons::KEY),
                    t.c.allow_bg,
                    t.c.allow,
                    t,
                )),
        )
        .child(
            row()
                .gap(6.0)
                .center_y()
                .child(
                    text(format!("Receipt {ref_code}"))
                        .font(t.mono)
                        .color(t.c.ink_secondary),
                )
                .child(text("·").font(t.caption).color(t.c.ink_muted))
                .child(entity_link(
                    "why-panel-rule",
                    &icons::SHIELD_CHECK,
                    &rule_id,
                    t,
                    |s| s.dispatch(Intent::Navigate(Screen::Rules)),
                ))
                .child(text("·").font(t.caption).color(t.c.ink_muted))
                .child(
                    text(format!("Pack {pack_id}"))
                        .font(t.caption)
                        .color(t.c.ink_muted),
                ),
        )
        .child(quoted_chip(&target_q, ChipSurface::OnCanvas, t))
        .child(
            text(reason_text)
                .font(t.body)
                .color(t.c.ink_primary)
                .wrap()
                .w_full(),
        )
        .child(
            col()
                .w_full()
                .gap(4.0)
                .child(
                    text("What the agent was told (max 600 chars)")
                        .font(t.caption)
                        .color(t.c.ink_secondary),
                )
                .child(quoted_box(&agent_told, ChipSurface::OnCanvas, t)),
        )
        .child(
            row()
                .w_full()
                .center_y()
                .gap(8.0)
                .child(
                    text("Verified Ed25519 receipt store")
                        .font(t.caption)
                        .color(t.c.ink_muted),
                )
                .child(spacer())
                .child(secondary_button("why-panel-close-btn", "Close Why", t, |s| {
                    s.dispatch(Intent::DismissWhyCard);
                })),
        );

    elevated_card("act-why-card", 12.0, t, body).w_full()
}
