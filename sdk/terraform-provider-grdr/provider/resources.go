// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

package provider

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
)

func defaultResourceSpecs() []ResourceSpec {
	return []ResourceSpec{
		{TypeName: "grdr_group", Endpoint: "/v1/tenancy/groups", ItemsKey: "groups", ServerFields: []string{"createdAt", "updatedAt"}},
		{TypeName: "grdr_role_binding", Endpoint: "/v1/tenancy/role-bindings", ItemsKey: "roleBindings", ServerFields: []string{"createdAt"}},
		{TypeName: "grdr_service_account", Endpoint: "/v1/tenancy/service-accounts", ItemsKey: "serviceAccounts", Sensitive: []string{"token", "secret"}, ServerFields: []string{"createdAt"}},
		{TypeName: "grdr_federated_identity", Endpoint: "/v1/tenancy/federated-identities", ItemsKey: "federatedIdentities", ServerFields: []string{"createdAt"}},
		{TypeName: "grdr_identity_provider", Endpoint: "/v1/tenancy/identity-providers", ItemsKey: "identityProviders", Sensitive: []string{"clientSecret"}, ServerFields: []string{"createdAt"}},
		{TypeName: "grdr_integration", Endpoint: "/v1/integrations", ItemsKey: "integrations", Sensitive: []string{"credentials"}, ServerFields: []string{"status", "lastCheckedAt"}},
		{TypeName: "grdr_export_destination", Endpoint: "/v1/export-destinations", ItemsKey: "destinations", Sensitive: []string{"secret"}, ServerFields: []string{"createdAt"}},
		{TypeName: "grdr_webhook_endpoint", Endpoint: "/v1/webhook-endpoints", ItemsKey: "endpoints", Sensitive: []string{"secret"}, ServerFields: []string{"createdAt", "signingPublicKey"}},
		{TypeName: "grdr_deployment_key", Endpoint: "/v1/deployment-keys", ItemsKey: "keys", Sensitive: []string{"plaintextToken"}, ServerFields: []string{"createdAt"}},
		{TypeName: "grdr_gitops_binding", Endpoint: "/v1/gitops-binding", ItemsKey: "binding", ServerFields: []string{"driftStatus", "lastReconciledAt"}},
		{TypeName: "grdr_policy_source", Endpoint: "/v1/policy-changes", ItemsKey: "change", ServerFields: []string{"state", "effectiveHash", "isWidening"}},
		{TypeName: "grdr_operator_setting", Endpoint: "/v1/operator/settings", ItemsKey: "setting", OperatorOnly: true, ServerFields: []string{"revision"}},
		{TypeName: "grdr_organisation", Endpoint: "/v1/provider/organisations", ItemsKey: "organisations", ServerFields: []string{"createdAt"}},
		{TypeName: "grdr_organisation_set", Endpoint: "/v1/provider/organisation-sets", ItemsKey: "organisationSets", ServerFields: []string{"createdAt"}},
		{TypeName: "grdr_delegation", Endpoint: "/v1/provider/delegations", ItemsKey: "delegations", ServerFields: []string{"createdAt"}},
		{TypeName: "grdr_branding_profile", Endpoint: "/v1/provider/branding-profiles", ItemsKey: "brandingProfiles", ServerFields: []string{"updatedAt"}},
	}
}

func defaultDataSourceSpecs() []DataSourceSpec {
	return []DataSourceSpec{
		{TypeName: "grdr_effective_policy", Endpoint: "/v1/packs"},
		{TypeName: "grdr_devices", Endpoint: "/v1/devices"},
		{TypeName: "grdr_roles", Endpoint: "/v1/tenancy/roles"},
	}
}

func attrsDifferFromChange(change map[string]any, attrs map[string]any) bool {
	for k, desiredVal := range attrs {
		if existingVal, exists := change[k]; exists && !reflect.DeepEqual(existingVal, desiredVal) {
			return true
		}
	}
	return false
}

func (p *Provider) applyPolicySource(
	ctx context.Context,
	existingChangeID string,
	attrs map[string]any,
) (map[string]any, error) {
	changeID := existingChangeID
	var change map[string]any
	if changeID != "" {
		existing, err := p.client.Get(ctx, "/v1/policy-changes/"+url.PathEscape(changeID))
		if err == nil {
			change = unwrapChange(existing)
			state, _ := change["state"].(string)
			switch state {
			case "APPLIED":
				if !attrsDifferFromChange(change, attrs) {
					return existing, nil
				}
			case "APPROVED":
				applied, err := p.client.ApplyPolicyChange(ctx, changeID, "")
				if err != nil {
					return nil, err
				}
				return validateFinalPolicyChange(applied, changeID)
			case "AWAITING_APPROVAL":
				return existing, fmt.Errorf("%w (change_id=%s)", ErrWideningPendingApproval, changeID)
			}
		}
	}

	payload := make(map[string]any, len(attrs)+1)
	for k, v := range attrs {
		payload[k] = v
	}
	payload["proposerKind"] = "terraform"
	created, err := p.client.CreatePolicyChange(ctx, payload, "")
	if err != nil {
		return nil, err
	}
	change = unwrapChange(created)
	changeID, _ = change["id"].(string)
	if changeID == "" {
		return created, fmt.Errorf("policy change creation did not return id")
	}

	if _, err := p.client.CheckPolicyChange(ctx, changeID); err != nil {
		return nil, err
	}
	if _, err := p.client.SimulatePolicyChange(ctx, changeID); err != nil {
		return nil, err
	}
	applied, err := p.client.ApplyPolicyChange(ctx, changeID, "")
	if err != nil {
		return nil, err
	}
	return validateFinalPolicyChange(applied, changeID)
}

func validateFinalPolicyChange(applied map[string]any, changeID string) (map[string]any, error) {
	finalChange := unwrapChange(applied)
	state, _ := finalChange["state"].(string)
	widening, _ := finalChange["isWidening"].(bool)
	if state == "FAILED" || state == "DENIED" || state == "ROLLED_BACK" {
		return applied, fmt.Errorf("%w (change_id=%s, state=%s)", ErrPolicyChangeFailedOrDenied, changeID, state)
	}
	if state == "AWAITING_APPROVAL" || (widening && state != "APPLIED") {
		return applied, fmt.Errorf("%w (change_id=%s, state=%s)", ErrWideningPendingApproval, changeID, state)
	}
	return applied, nil
}

func unwrapChange(doc map[string]any) map[string]any {
	if inner, ok := doc["change"].(map[string]any); ok {
		return inner
	}
	return doc
}
