// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_model::{
    ActionClass, AssuranceLevel, AssuranceRecord, ControlStrength, InstallProfile, OnFailure,
    TamperGrade, Visibility,
};

use crate::es_tree::EsClientStatus;
use crate::network_ext::SlotRung;
use crate::seatbelt::MacOsContainmentMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacOsTier {
    Tier1HooksAndSeatbelt,
    Tier2NetworkExtension,
    Tier3EndpointSecurity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsCapabilityFlags {
    pub profile: InstallProfile,
    pub tier: MacOsTier,
    pub containment: MacOsContainmentMode,
    pub content_filter_rung: SlotRung,
    pub es_status: EsClientStatus,
}

pub fn compute_macos_assurance(
    caps: &MacOsCapabilityFlags,
    action_class: ActionClass,
) -> AssuranceRecord {
    if caps.profile == InstallProfile::User {
        return AssuranceRecord {
            visibility: Visibility::Claimed,
            control: ControlStrength::Request,
            on_failure: OnFailure::Open,
            tamper: TamperGrade::User,
        };
    }

    let es_active =
        caps.tier == MacOsTier::Tier3EndpointSecurity && caps.es_status == EsClientStatus::Active;
    let ne_active = caps.tier >= MacOsTier::Tier2NetworkExtension
        && caps.content_filter_rung == SlotRung::Enforce;

    if es_active {
        let (visibility, on_failure) = match action_class {
            ActionClass::Elevate => (Visibility::Observed, OnFailure::Closed),
            _ => (Visibility::CrossChecked, OnFailure::Closed),
        };
        return AssuranceRecord {
            visibility,
            control: ControlStrength::MandatoryBoundary,
            on_failure,
            tamper: TamperGrade::Admin,
        };
    }

    let scoped_by_launcher = match caps.containment {
        MacOsContainmentMode::Delegate | MacOsContainmentMode::WrapAgent => matches!(
            action_class,
            ActionClass::Exec
                | ActionClass::FileRead
                | ActionClass::FileWrite
                | ActionClass::FileDelete
                | ActionClass::NetConnect
                | ActionClass::Elevate
                | ActionClass::ConfigChange
        ),
        MacOsContainmentMode::WrapTools => matches!(
            action_class,
            ActionClass::Exec | ActionClass::NetConnect | ActionClass::Elevate
        ),
        MacOsContainmentMode::RequestOnly => false,
    };

    if ne_active && action_class == ActionClass::NetConnect {
        return AssuranceRecord {
            visibility: Visibility::Observed,
            control: ControlStrength::MandatoryBoundary,
            on_failure: OnFailure::Open,
            tamper: TamperGrade::Admin,
        };
    }

    AssuranceRecord {
        visibility: Visibility::Claimed,
        control: if scoped_by_launcher {
            ControlStrength::ScopedBoundary
        } else {
            ControlStrength::Request
        },
        on_failure: if scoped_by_launcher {
            OnFailure::Closed
        } else {
            OnFailure::Open
        },
        tamper: TamperGrade::Admin,
    }
}

pub fn macos_session_level(caps: &MacOsCapabilityFlags) -> AssuranceLevel {
    if caps.profile == InstallProfile::User {
        return AssuranceLevel::Al2Guided;
    }
    let exec_rec = compute_macos_assurance(caps, ActionClass::Exec);
    let file_rec = compute_macos_assurance(caps, ActionClass::FileWrite);
    let net_rec = compute_macos_assurance(caps, ActionClass::NetConnect);
    exec_rec.level().min(file_rec.level()).min(net_rec.level())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_truthful_al2_al3_al4_tiers_without_overstating() {
        let tier1_request = MacOsCapabilityFlags {
            profile: InstallProfile::Protected,
            tier: MacOsTier::Tier1HooksAndSeatbelt,
            containment: MacOsContainmentMode::RequestOnly,
            content_filter_rung: SlotRung::None,
            es_status: EsClientStatus::MissingEntitlement,
        };
        assert_eq!(
            macos_session_level(&tier1_request),
            AssuranceLevel::Al2Guided
        );
        assert_eq!(
            compute_macos_assurance(&tier1_request, ActionClass::Exec).visibility,
            Visibility::Claimed
        );

        let tier1_wrap_tools = MacOsCapabilityFlags {
            containment: MacOsContainmentMode::WrapTools,
            ..tier1_request
        };
        assert_eq!(
            compute_macos_assurance(&tier1_wrap_tools, ActionClass::Exec).level(),
            AssuranceLevel::Al3Contained
        );
        assert_eq!(
            compute_macos_assurance(&tier1_wrap_tools, ActionClass::FileWrite).level(),
            AssuranceLevel::Al2Guided
        );
        assert_eq!(
            macos_session_level(&tier1_wrap_tools),
            AssuranceLevel::Al2Guided
        );

        let tier2_ne = MacOsCapabilityFlags {
            tier: MacOsTier::Tier2NetworkExtension,
            containment: MacOsContainmentMode::WrapAgent,
            content_filter_rung: SlotRung::Enforce,
            ..tier1_request
        };
        assert_eq!(
            compute_macos_assurance(&tier2_ne, ActionClass::NetConnect).visibility,
            Visibility::Observed
        );
        assert_eq!(macos_session_level(&tier2_ne), AssuranceLevel::Al3Contained);

        let tier3_no_fda = MacOsCapabilityFlags {
            tier: MacOsTier::Tier3EndpointSecurity,
            es_status: EsClientStatus::NotPermittedFda,
            ..tier2_ne
        };
        assert_eq!(
            macos_session_level(&tier3_no_fda),
            AssuranceLevel::Al3Contained
        );

        let tier3_es = MacOsCapabilityFlags {
            es_status: EsClientStatus::Active,
            ..tier3_no_fda
        };
        assert_eq!(macos_session_level(&tier3_es), AssuranceLevel::Al4Enforced);
    }
}
