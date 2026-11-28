// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::error::CODE_POLICY_DENIED;
use grdr_proto::common::ErrorClass;

use crate::auth::{AuthContext, AuthPlane};
use crate::connect_error::{ApiError, ApiErrorInner, CODE_API_BAD_REQUEST, ConnectCode};

use super::super::gitops::GitopsStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneRule {
    ConsoleOnly,
    OperatorOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorRule {
    AnyAuthenticated,
    HumanOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceRule {
    None,
    Confirmed,
    StepUp,
}

#[derive(Debug, Clone, Copy)]
pub struct RestPolicy {
    pub scope: &'static str,
    pub alt_scope: Option<&'static str>,
    pub assurance: AssuranceRule,
    pub actor: ActorRule,
    pub plane: PlaneRule,
}

impl RestPolicy {
    pub const fn read(scope: &'static str) -> Self {
        Self {
            scope,
            alt_scope: None,
            assurance: AssuranceRule::None,
            actor: ActorRule::AnyAuthenticated,
            plane: PlaneRule::ConsoleOnly,
        }
    }

    pub const fn human_write(scope: &'static str, assurance: AssuranceRule) -> Self {
        Self {
            scope,
            alt_scope: None,
            assurance,
            actor: ActorRule::HumanOnly,
            plane: PlaneRule::ConsoleOnly,
        }
    }
}

pub fn authorize_rest(auth: &AuthContext, policy: RestPolicy) -> Result<(), ApiError> {
    if policy.plane == PlaneRule::OperatorOnly && auth.plane != AuthPlane::Operator {
        return Err(permission_err(
            "GRDR-AUTH-0403",
            "PERMISSION_DENIED",
            "Operator endpoints require the dedicated Operator Plane listener and realm (D-70).",
            "Send operator requests to --operator-bind with --operator-token.",
        ));
    }
    if policy.plane == PlaneRule::ConsoleOnly && auth.plane == AuthPlane::Operator {
        return Err(permission_err(
            "GRDR-AUTH-0403",
            "PERMISSION_DENIED",
            "Operator Plane credentials cannot access tenant Console REST APIs (D-70).",
            "Administer tenant resources on the tenant Console listener.",
        ));
    }
    if policy.actor == ActorRule::HumanOnly && GitopsStore::is_agent_lineage(auth) {
        return Err(permission_err(
            CODE_POLICY_DENIED,
            "AGENT_SESSION_PROPOSE_ONLY",
            "AgentSession identities may only propose changes; direct mutations are blocked.",
            "Submit a proposal and await human review.",
        ));
    }
    let has_scope = auth.allows_scope(policy.scope)
        || policy.alt_scope.is_some_and(|alt| auth.allows_scope(alt));
    if !has_scope {
        return Err(permission_err(
            "GRDR-AUTH-0403",
            "PERMISSION_DENIED",
            &format!("Missing required scope `{}`.", policy.scope),
            "Authenticate with a principal carrying the required scope.",
        ));
    }
    if policy.assurance == AssuranceRule::StepUp && !auth.confirmation.is_step_up() {
        return Err(permission_err(
            CODE_POLICY_DENIED,
            "STEP_UP_REQUIRED",
            "Step-up authentication is required for this operation.",
            "Provide a verified step-up token via X-Grdr-Step-Up.",
        ));
    }
    if policy.assurance != AssuranceRule::None && !auth.confirmation.is_confirmed() {
        return Err(ApiError::new(ApiErrorInner {
            code: ConnectCode::FailedPrecondition,
            grdr_code: CODE_API_BAD_REQUEST.into(),
            reason: "CONFIRMATION_REQUIRED".into(),
            class: ErrorClass::Validation,
            message: "Explicit confirmation intent required for this action.".into(),
            fix: "Confirm explicitly via X-Grdr-Confirm before submitting.".into(),
            metadata: BTreeMap::new(),
        }));
    }
    Ok(())
}

pub fn permission_err(grdr_code: &str, reason: &str, message: &str, fix: &str) -> ApiError {
    ApiError::new(ApiErrorInner {
        code: ConnectCode::PermissionDenied,
        grdr_code: grdr_code.into(),
        reason: reason.into(),
        class: ErrorClass::Permission,
        message: message.into(),
        fix: fix.into(),
        metadata: BTreeMap::new(),
    })
}
