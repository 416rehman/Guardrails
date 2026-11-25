// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod activity;
pub mod inventory;
pub mod operator;
pub mod overview;
pub mod policy;
pub mod response;
pub mod surfaces;
pub mod surfaces_comply;
pub mod tenancy;
pub mod verdict;

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use crate::common::{
        ALL_METHODS, ActionClass, AuditClass, Device, IdempotencyLevel, Mode, PageInfo, PolicyRule,
        RateClass, RuleMatch, find_method,
    };

    use super::inventory::{ListDevicesRequest, ListDevicesResponse};
    use super::policy::UpdateRuleModeRequest;

    #[test]
    fn proto_binary_and_json_roundtrip_match_connect_contract() {
        let req = ListDevicesRequest {
            page_size: 25,
            page_token: "sealed_cursor_abc".into(),
            filter: "online = true".into(),
            order_by: "hostname asc".into(),
        };

        let wire = req.encode_to_vec();
        let decoded_wire = ListDevicesRequest::decode(wire.as_slice()).unwrap();
        assert_eq!(req, decoded_wire);

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"pageSize\":25"));
        assert!(json.contains("\"pageToken\":\"sealed_cursor_abc\""));
        assert!(json.contains("\"orderBy\":\"hostname asc\""));
        let decoded_json: ListDevicesRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, decoded_json);

        let snake_json =
            r#"{"page_size":10,"page_token":"tok","filter":"os = linux","order_by":"id desc"}"#;
        let from_snake: ListDevicesRequest = serde_json::from_str(snake_json).unwrap();
        assert_eq!(from_snake.page_size, 10);
        assert_eq!(from_snake.page_token, "tok");
        assert_eq!(from_snake.order_by, "id desc");

        let resp = ListDevicesResponse {
            devices: vec![Device {
                id: "dev-1".into(),
                hostname: "macbook-pro".into(),
                os: "macos".into(),
                arch: "arm64".into(),
                online: true,
                ..Default::default()
            }],
            page_info: Some(PageInfo {
                next_page_token: "next_tok".into(),
                prev_page_token: String::new(),
                total_size_estimate: 42,
                has_more: true,
            }),
            revision: None,
        };
        let resp_wire = resp.encode_to_vec();
        assert_eq!(
            resp,
            ListDevicesResponse::decode(resp_wire.as_slice()).unwrap()
        );
    }

    #[test]
    fn enum_serde_accepts_proto_names_short_aliases_and_tags() {
        let canonical = r#"{"id":"r1","mode":"MODE_BLOCK","replayConfirmed":true}"#;
        let short_alias = r#"{"id":"r1","mode":"block","replay_confirmed":true}"#;
        let numeric = r#"{"id":"r1","mode":4,"replayConfirmed":true}"#;

        for payload in [canonical, short_alias, numeric] {
            let parsed: UpdateRuleModeRequest = serde_json::from_str(payload).unwrap();
            assert_eq!(parsed.mode, Mode::Block as i32);
            assert_eq!(parsed.replay_confirmed, Some(true));
        }

        let rule = PolicyRule {
            id: "r1".into(),
            mode: Mode::Ask as i32,
            matcher: Some(RuleMatch {
                action_classes: vec![ActionClass::FileRead as i32, ActionClass::NetRequest as i32],
                ..Default::default()
            }),
            ..Default::default()
        };
        let encoded = serde_json::to_string(&rule).unwrap();
        assert!(encoded.contains("\"MODE_ASK\""));
        assert!(encoded.contains("\"ACTION_CLASS_FILE_READ\""));
        let back: PolicyRule = serde_json::from_str(&encoded).unwrap();
        assert_eq!(back, rule);
    }

    #[test]
    fn method_descriptors_enforce_scope_audit_rate_and_mcp_policy_boundary() {
        assert!(!ALL_METHODS.is_empty());
        for method in ALL_METHODS
            .iter()
            .chain(crate::common::SURFACES_AND_OPERATOR_METHODS.iter())
        {
            assert!(!method.scope.is_empty());
            assert!(method.path.starts_with('/'));
            assert_ne!(method.rate_class, RateClass::Unspecified);
            assert_ne!(method.audit, AuditClass::Unspecified);
            if method.service.contains(".policy.") || method.method.contains("Approval") {
                assert!(
                    !method.mcp_exposed,
                    "{} must never be MCP exposed",
                    method.path
                );
            }
            if method.mcp_exposed {
                assert_eq!(method.idempotency, IdempotencyLevel::NoSideEffects);
            }
        }
        assert!(find_method("/grdr.api.inventory.v1alpha1.InventoryService/ListDevices").is_some());
    }
}
