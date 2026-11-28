// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

mod enrol;
mod enrol_json;
mod enrol_validate;
mod id_jag;
mod instances;
mod instances_ops;
mod oauth_token;
mod oidc;
mod oidc_authzen;
mod persist;
mod runtime;
mod scim;
mod scim_resources;
mod ssf;
#[cfg(test)]
mod tests;
mod types;

use axum::Router;
use axum::routing::{get, post};

pub use types::FederationState;

pub fn public_routes(state: FederationState) -> Router<()> {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(oidc::get_oidc_discovery),
        )
        .route("/.well-known/jwks.json", get(oidc::get_jwks))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oidc::get_protected_resource),
        )
        .route(
            "/.well-known/ssf-configuration",
            get(ssf::get_ssf_configuration),
        )
        .route("/clients/mcp-broker", get(oidc::get_cimd_document))
        .route("/oauth2/status-list", get(oidc::get_status_list))
        .route(
            "/oauth2/device_authorization",
            post(oidc::post_device_authorization),
        )
        .route("/oauth2/token", post(oauth_token::post_oauth_token))
        .with_state(state)
}

pub fn protected_routes(state: FederationState) -> Router<()> {
    Router::new()
        .route(
            "/oauth2/device_authorize",
            post(oidc::post_device_authorize),
        )
        .route(
            "/oauth2/transaction-token",
            post(oidc_authzen::post_transaction_token),
        )
        .route(
            "/access/v1/evaluation",
            post(oidc_authzen::post_authzen_evaluate),
        )
        .route(
            "/scim/v2/Users",
            get(scim::list_scim_users).post(scim::create_scim_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(scim::get_scim_user)
                .patch(scim::patch_scim_user)
                .delete(scim::delete_scim_user),
        )
        .route(
            "/scim/v2/Groups",
            get(scim_resources::list_scim_groups).post(scim_resources::create_scim_group),
        )
        .route("/scim/v2/Agents", get(scim_resources::list_scim_agents))
        .route(
            "/ssf/streams",
            get(ssf::get_ssf_streams).post(ssf::post_ssf_streams),
        )
        .route("/ssf/poll", post(ssf::post_ssf_poll))
        .route("/ssf/events", post(ssf::post_ssf_event))
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/ListInstances",
            get(instances::list_instances).post(instances::list_instances),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/RegisterInstance",
            post(instances::register_instance),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/RegisterTrustAnchor",
            post(instances::register_trust_anchor),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/TransferSponsor",
            post(instances::transfer_sponsor),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/RetireInstance",
            post(instances::retire_instance),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/ReportRetiredSeen",
            post(instances::report_retired_seen),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/CorrelateRegistries",
            post(instances_ops::correlate_registries),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/AdoptCredential",
            post(instances_ops::adopt_credential),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/RevokeLease",
            post(instances_ops::revoke_lease),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/RecordOutwardReceipt",
            post(instances_ops::record_outward_receipt),
        )
        .route(
            "/grdr.api.identity.v1alpha1.IdentityService/LookupOutwardReceipts",
            get(instances_ops::lookup_outward_receipts)
                .post(instances_ops::lookup_outward_receipts),
        )
        .route(
            "/grdr.api.connect.v1alpha1.ConnectService/AdmitDeploymentKey",
            post(enrol::admit_deployment_key),
        )
        .route(
            "/grdr.api.connect.v1alpha1.ConnectService/EnrolWorkloadOidc",
            post(enrol::enrol_workload_oidc),
        )
        .route(
            "/grdr.api.connect.v1alpha1.ConnectService/EnrolAttestedHardware",
            post(enrol::enrol_attested_hardware),
        )
        .route(
            "/grdr.api.connect.v1alpha1.ConnectService/ValidateMdmArtifact",
            post(enrol_validate::validate_mdm_artifact),
        )
        .route(
            "/grdr.api.connect.v1alpha1.ConnectService/CheckGoldenImagePrepare",
            post(enrol_validate::check_golden_image_prepare),
        )
        .with_state(state)
}
