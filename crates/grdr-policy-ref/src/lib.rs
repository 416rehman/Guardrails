// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
//! Independent pure policy reference model (RFC 0013 / ADR-0053).
//!
//! Linked only to `grdr-model` with zero `grdr-core` or `cedar-policy` dependencies.

pub mod derive;
pub mod eval;

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use grdr_model::Mode;

pub use derive::{
    BoundaryObserver, ControlPointCaps, DeriveInput, DeterminingForbid, ExecutedVerb,
    FailureDisposition, HoldCapability, InputValidity, LossBehaviour, NotEvaluableRuleRef,
    ObligationSupport, PendingRuleRef, RemedyCapability, RuleMutability, TimelockAllowance,
    VerdictDiscriminant, degrade_verdict, derive_verdict,
};
pub use eval::{ReferenceDecision, evaluate_ref, evaluate_ref_mut};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefError {
    #[error("GRDR-POLREF-0001: layer `{layer}` attempted to widen locked ancestor `{rule_id}`")]
    LockedLayerViolation { layer: String, rule_id: String },
    #[error("GRDR-POLREF-0002: allow-list `{list_id}` widened beyond parent maximum")]
    AllowListWidening { list_id: String },
    #[error("GRDR-POLREF-0003: protect-list `{list_id}` dropped entry from parent minimum")]
    ProtectListWidening { list_id: String },
    #[error("GRDR-POLREF-0004: invalid reference input: {detail}")]
    InvalidInput { detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerLock {
    Default,
    Locked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerModeSetting {
    pub mode: Mode,
    pub lock: LayerLock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangePolarity {
    Unchanged,
    Narrowing,
    Widening,
}

pub fn effective_rule_mode(pack_mode: Mode, max_mode: Mode, rule_override: Option<Mode>) -> Mode {
    let base = match rule_override {
        Some(m) => m,
        None => pack_mode,
    };
    if base <= max_mode { base } else { max_mode }
}

pub fn resolve_layer_mode(
    layer_name: &str,
    rule_id: &str,
    parent: LayerModeSetting,
    child: LayerModeSetting,
) -> Result<(LayerModeSetting, ChangePolarity), RefError> {
    if parent.lock == LayerLock::Locked && child.mode < parent.mode {
        return Err(RefError::LockedLayerViolation {
            layer: layer_name.to_owned(),
            rule_id: rule_id.to_owned(),
        });
    }
    let polarity = if child.mode > parent.mode {
        ChangePolarity::Narrowing
    } else if child.mode < parent.mode {
        ChangePolarity::Widening
    } else {
        ChangePolarity::Unchanged
    };
    let effective_lock = match (parent.lock, child.lock) {
        (LayerLock::Locked, _) | (_, LayerLock::Locked) => LayerLock::Locked,
        (LayerLock::Default, LayerLock::Default) => LayerLock::Default,
    };
    Ok((
        LayerModeSetting {
            mode: child.mode,
            lock: effective_lock,
        },
        polarity,
    ))
}

pub fn check_list_containment(
    list_id: &str,
    is_allow_list: bool,
    parent: &BTreeSet<String>,
    child: &BTreeSet<String>,
) -> Result<ChangePolarity, RefError> {
    if is_allow_list {
        if !child.is_subset(parent) {
            return Err(RefError::AllowListWidening {
                list_id: list_id.to_owned(),
            });
        }
        return Ok(if child.len() < parent.len() {
            ChangePolarity::Narrowing
        } else {
            ChangePolarity::Unchanged
        });
    }
    if !parent.is_subset(child) {
        return Err(RefError::ProtectListWidening {
            list_id: list_id.to_owned(),
        });
    }
    Ok(if child.len() > parent.len() {
        ChangePolarity::Narrowing
    } else {
        ChangePolarity::Unchanged
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_ref_cargo_toml_has_no_core_or_cedar_normal_deps() {
        let manifest = include_str!("../Cargo.toml");
        let normal_deps_section = manifest
            .split("[dev-dependencies]")
            .next()
            .unwrap_or(manifest);
        assert!(!normal_deps_section.contains("grdr-core"));
        assert!(!normal_deps_section.contains("cedar-policy"));
    }

    #[test]
    fn layer_ceiling_and_list_containment_enforce_monotonicity() {
        let parent = LayerModeSetting {
            mode: Mode::Block,
            lock: LayerLock::Locked,
        };
        let looser = LayerModeSetting {
            mode: Mode::Ask,
            lock: LayerLock::Default,
        };
        assert!(matches!(
            resolve_layer_mode("user", "essentials.control-files", parent, looser),
            Err(RefError::LockedLayerViolation { .. })
        ));

        let allow_parent = BTreeSet::from(["api.example".to_owned(), "docs.example".to_owned()]);
        let allow_wider = BTreeSet::from(["api.example".to_owned(), "evil.example".to_owned()]);
        assert!(matches!(
            check_list_containment("org.egress", true, &allow_parent, &allow_wider),
            Err(RefError::AllowListWidening { .. })
        ));

        let protect_parent = BTreeSet::from([".ssh/".to_owned(), ".aws/".to_owned()]);
        let protect_narrower =
            BTreeSet::from([".ssh/".to_owned(), ".aws/".to_owned(), ".gnupg/".to_owned()]);
        assert_eq!(
            check_list_containment("cred-store", false, &protect_parent, &protect_narrower),
            Ok(ChangePolarity::Narrowing)
        );
    }
}
