// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub fn path_is_collection(path: &str) -> bool {
    matches!(
        path,
        "/devices"
            | "/agents"
            | "/mcp-servers"
            | "/artifacts"
            | "/sessions"
            | "/findings"
            | "/incidents"
            | "/approvals"
            | "/audit-events"
            | "/users"
            | "/change-feed"
            | "/policy-changes"
            | "/webhook-endpoints"
    )
}

pub fn rest_endpoint_specs() -> &'static [(&'static str, &'static str, &'static str, bool)] {
    &[
        (
            "/openapi.json",
            "get",
            "OpenAPI 3.1 specification document",
            false,
        ),
        ("/health", "get", "Service health status", false),
        ("/overview", "get", "Control plane overview metrics", false),
        (
            "/guard",
            "post",
            "Gateway Guardrail decision evaluation",
            false,
        ),
        (
            "/ingest",
            "post",
            "Ingest SDK or device attempt telemetry",
            false,
        ),
        (
            "/devices",
            "get",
            "List devices with cursor pagination and AIP-160 filters",
            false,
        ),
        ("/agents", "get", "List discovered agents", false),
        ("/mcp-servers", "get", "List discovered MCP servers", false),
        (
            "/artifacts",
            "get",
            "List discovered skills and plugin artifacts",
            false,
        ),
        ("/sessions", "get", "List sessions", false),
        (
            "/sessions/{id}",
            "get",
            "Get single session timeline and receipts",
            false,
        ),
        ("/findings", "get", "List findings", false),
        ("/findings/{id}", "patch", "Update finding lifecycle", false),
        ("/incidents", "get", "List correlated incidents", false),
        (
            "/approvals",
            "get",
            "List pending and decided approval requests",
            false,
        ),
        (
            "/approvals/{id}:decide",
            "post",
            "Approve or deny an approval request",
            true,
        ),
        ("/kill-switch", "get", "Get kill switch state", false),
        ("/kill-switch", "put", "Update kill switch state", false),
        (
            "/audit-events",
            "get",
            "List tamper-evident audit events",
            false,
        ),
        ("/users", "get", "List tenant users", false),
        ("/packs", "get", "List policy packs", false),
        (
            "/browser-policies",
            "get",
            "List Browser AI policies",
            false,
        ),
        (
            "/browser-policies/{id}",
            "put",
            "Update Browser AI policy",
            false,
        ),
        (
            "/rules",
            "post",
            "Create a policy rule (GitOps-lock aware)",
            true,
        ),
        ("/rules/{id}", "patch", "Update a policy rule", false),
        ("/rules/{id}", "delete", "Delete a policy rule", false),
        ("/rules/{id}:mode", "post", "Update policy rule mode", true),
        (
            "/rules/{id}:replay",
            "post",
            "Replay rule against historical telemetry",
            false,
        ),
        (
            "/policy-changes",
            "get",
            "List GitOps policy changes",
            false,
        ),
        (
            "/policy-changes",
            "post",
            "Create candidate PolicyChange",
            true,
        ),
        (
            "/policy-changes/{id}",
            "get",
            "Get PolicyChange details and diff",
            false,
        ),
        (
            "/policy-changes/{id}:check",
            "post",
            "Check Cedar policy compilation and semantic diff",
            false,
        ),
        (
            "/policy-changes/{id}:simulate",
            "post",
            "Run 4-bucket historical replay simulation",
            false,
        ),
        (
            "/policy-changes/{id}:apply",
            "post",
            "Apply PolicyChange or transition to awaiting approval",
            true,
        ),
        (
            "/policy-changes/{id}:approve",
            "post",
            "Human approval of PolicyChange",
            true,
        ),
        (
            "/policy-changes/{id}:deny",
            "post",
            "Deny a PolicyChange",
            true,
        ),
        (
            "/policy-changes/{id}:cancel",
            "post",
            "Cancel or halt a PolicyChange",
            true,
        ),
        (
            "/policy-changes/{id}:resume",
            "post",
            "Resume a halted PolicyChange",
            true,
        ),
        (
            "/gitops-binding",
            "get",
            "Get active GitOps repository binding and drift state",
            false,
        ),
        (
            "/gitops-binding",
            "put",
            "Bind tenant policy writes to Git or Terraform",
            false,
        ),
        (
            "/gitops-binding:edit-anyway",
            "post",
            "Dual-approver emergency policy write while GitOps locked",
            true,
        ),
        (
            "/gitops-binding:reconcile",
            "post",
            "Reconcile GitOps bundle commit hash",
            true,
        ),
        (
            "/gitops-bundle",
            "get",
            "Export canonical signed policy bundle for Git or Terraform",
            false,
        ),
        ("/webhook-endpoints", "get", "List webhook endpoints", false),
        (
            "/webhook-endpoints",
            "post",
            "Create webhook endpoint",
            true,
        ),
        (
            "/webhook-endpoints/{id}",
            "get",
            "Get webhook endpoint details",
            false,
        ),
        (
            "/webhook-endpoints/{id}",
            "delete",
            "Delete webhook endpoint",
            false,
        ),
        (
            "/webhook-endpoints/{id}:send-test",
            "post",
            "Send signed Standard Webhooks test delivery",
            false,
        ),
        (
            "/webhook-endpoints/{id}:rotate-key",
            "post",
            "Rotate webhook signing key with dual-key grace period",
            true,
        ),
        (
            "/change-feed",
            "get",
            "Poll signed export change feed",
            false,
        ),
        (
            "/operations/{id}",
            "get",
            "Get async operation job status",
            false,
        ),
        (
            "/operations/{id}:cancel",
            "post",
            "Cancel an async operation",
            true,
        ),
        ("/integrations", "get", "List integrations", false),
        ("/deployment-keys", "post", "Create deployment key", true),
        (
            "/deployment-keys/{id}",
            "delete",
            "Revoke deployment key",
            false,
        ),
        ("/tenancy/groups", "get", "List identity groups", false),
        ("/tenancy/groups", "post", "Create identity group", true),
        (
            "/tenancy/role-bindings",
            "post",
            "Create role binding",
            true,
        ),
        (
            "/tenancy/service-accounts",
            "post",
            "Create service account",
            true,
        ),
        (
            "/tenancy/federated-identities",
            "post",
            "Create federated identity",
            true,
        ),
        (
            "/tenancy/identity-providers",
            "post",
            "Create identity provider",
            true,
        ),
        ("/tenancy/roles", "get", "List roles", false),
        (
            "/export-destinations",
            "post",
            "Create export destination",
            true,
        ),
        (
            "/provider/organisations",
            "post",
            "Create provider organisation",
            true,
        ),
        (
            "/provider/organisation-sets",
            "post",
            "Create provider organisation set",
            true,
        ),
        (
            "/provider/delegations",
            "post",
            "Create provider delegation",
            true,
        ),
        (
            "/provider/branding-profiles",
            "post",
            "Create branding profile",
            true,
        ),
    ]
}
