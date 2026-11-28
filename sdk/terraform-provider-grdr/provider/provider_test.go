// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/416rehman/Guardrails/sdk/go/grdr"
)

func TestTerraformProviderResourcesDataSourcesAndWideningGate(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	changes := map[string]map[string]any{}
	resources := map[string]map[string]any{}
	opResources := map[string]map[string]any{}
	nextChangeSeq := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/operator/") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"permission_denied","message":"operator plane isolated"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		var payload map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&payload)
		}

		if r.URL.Path == "/v1/packs" || r.URL.Path == "/v1/devices" || r.URL.Path == "/v1/tenancy/roles" {
			_, _ = w.Write([]byte(`{"items":[],"packs":[],"devices":[],"roles":[]}`))
			return
		}
		if r.URL.Path == "/v1/gitops-binding" {
			if r.Method == http.MethodPut {
				mu.Lock()
				resources["gitops-binding"] = payload
				mu.Unlock()
			}
			mu.Lock()
			cur := resources["gitops-binding"]
			mu.Unlock()
			if cur == nil {
				cur = map[string]any{"source": "none"}
			}
			_ = json.NewEncoder(w).Encode(cur)
			return
		}
		if r.URL.Path == "/v1/policy-changes" && r.Method == http.MethodPost {
			mu.Lock()
			nextChangeSeq++
			id := fmt.Sprintf("chg-tf-%d", nextChangeSeq)
			widening, _ := payload["widening"].(bool)
			forceState, _ := payload["forceState"].(string)
			chg := map[string]any{
				"id":         id,
				"title":      payload["title"],
				"state":      "DRAFT",
				"isWidening": widening,
				"forceState": forceState,
			}
			changes[id] = chg
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"change": chg})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v1/policy-changes/") {
			trimmed := strings.TrimPrefix(r.URL.Path, "/v1/policy-changes/")
			parts := strings.Split(trimmed, ":")
			id := parts[0]
			action := ""
			if len(parts) > 1 {
				action = parts[1]
			}
			mu.Lock()
			chg := changes[id]
			if chg != nil {
				switch action {
				case "check":
					chg["state"] = "CHECKED"
				case "simulate":
					chg["state"] = "CHECKED"
				case "apply":
					if fs, _ := chg["forceState"].(string); fs != "" {
						chg["state"] = fs
					} else if st, _ := chg["state"].(string); st == "APPROVED" {
						chg["state"] = "APPLIED"
					} else if wFlag, _ := chg["isWidening"].(bool); wFlag {
						chg["state"] = "AWAITING_APPROVAL"
					} else {
						chg["state"] = "APPLIED"
					}
				case "approve":
					chg["state"] = "APPROVED"
				}
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"change": chg})
			return
		}

		// Generic resource persistence by path + method
		switch r.Method {
		case http.MethodPost:
			id := "res-1"
			doc := map[string]any{"id": id}
			for k, v := range payload {
				doc[k] = v
			}
			mu.Lock()
			resources[r.URL.Path+"/"+id] = doc
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(doc)
		case http.MethodGet:
			mu.Lock()
			doc := resources[r.URL.Path]
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(doc)
		case http.MethodPut:
			doc := map[string]any{}
			for k, v := range payload {
				doc[k] = v
			}
			mu.Lock()
			resources[r.URL.Path] = doc
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(doc)
		case http.MethodDelete:
			mu.Lock()
			delete(resources, r.URL.Path)
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	opSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("Authorization") != "Bearer op-tok" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":"unauthenticated","message":"operator token required"}`))
			return
		}
		var payload map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&payload)
		}
		switch r.Method {
		case http.MethodPost:
			doc := map[string]any{"id": "op-res-1"}
			for k, v := range payload {
				doc[k] = v
			}
			mu.Lock()
			opResources[r.URL.Path+"/op-res-1"] = doc
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(doc)
		case http.MethodGet:
			mu.Lock()
			doc := opResources[r.URL.Path]
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(doc)
		case http.MethodPut:
			doc := map[string]any{}
			for k, v := range payload {
				doc[k] = v
			}
			mu.Lock()
			opResources[r.URL.Path] = doc
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(doc)
		case http.MethodDelete:
			mu.Lock()
			delete(opResources, r.URL.Path)
			mu.Unlock()
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer opSrv.Close()

	client := grdr.NewClient(grdr.ClientOptions{BaseURL: srv.URL, Token: "tf-tok"})
	prov := NewProvider(client)
	ctx := context.Background()

	// Operator settings resource must fail closed before isolated operator client is configured (D-70).
	if _, err := prov.Read(ctx, "grdr_operator_setting", "op-res-1"); !errors.Is(err, ErrOperatorClientRequired) {
		t.Fatalf("expected ErrOperatorClientRequired, got %v", err)
	}
	prov.SetOperatorClient(grdr.NewClient(grdr.ClientOptions{BaseURL: opSrv.URL, Token: "op-tok"}))

	if len(prov.ResourceTypes()) != 16 {
		t.Fatalf("expected 16 Terraform resources, got %d", len(prov.ResourceTypes()))
	}
	if len(prov.DataSourceTypes()) != 3 {
		t.Fatalf("expected 3 Terraform data sources, got %d", len(prov.DataSourceTypes()))
	}

	// Verify CRUD + drift planning across every resource except special workflow grdr_policy_source
	for _, resType := range prov.ResourceTypes() {
		if resType == "grdr_policy_source" {
			continue
		}
		initial := map[string]any{"name": "tf-" + resType}
		created, err := prov.ApplyCreate(ctx, resType, initial)
		if err != nil {
			t.Fatalf("create %s failed: %v", resType, err)
		}
		planSame, err := prov.Plan(resType, created, initial)
		if err != nil || planSame.Action != PlanNoOp {
			t.Fatalf("expected PlanNoOp for %s, got %+v err=%v", resType, planSame, err)
		}
		updatedDesired := map[string]any{"name": "tf-updated-" + resType}
		planDrift, err := prov.Plan(resType, created, updatedDesired)
		if err != nil || planDrift.Action != PlanUpdate {
			t.Fatalf("expected PlanUpdate drift for %s, got %+v err=%v", resType, planDrift, err)
		}
		id, _ := created["id"].(string)
		if _, err := prov.ApplyUpdate(ctx, resType, id, updatedDesired); err != nil {
			t.Fatalf("update %s failed: %v", resType, err)
		}
		if _, err := prov.Read(ctx, resType, id); err != nil {
			t.Fatalf("read %s failed: %v", resType, err)
		}
		if err := prov.ApplyDelete(ctx, resType, id); err != nil {
			t.Fatalf("delete %s failed: %v", resType, err)
		}
	}

	for _, dsType := range prov.DataSourceTypes() {
		if _, err := prov.ReadDataSource(ctx, dsType); err != nil {
			t.Fatalf("read data source %s failed: %v", dsType, err)
		}
	}

	// Narrowing policy change converges automatically
	narrowOut, err := prov.ApplyCreate(ctx, "grdr_policy_source", map[string]any{
		"title":    "narrow",
		"widening": false,
	})
	if err != nil {
		t.Fatalf("expected narrowing grdr_policy_source apply to succeed, got %v", err)
	}
	if unwrapChange(narrowOut)["state"] != "APPLIED" {
		t.Fatalf("expected APPLIED state for narrowing change, got %#v", narrowOut)
	}

	// Widening policy change fails closed awaiting human approval, then converges once approved
	wideOut, err := prov.ApplyCreate(ctx, "grdr_policy_source", map[string]any{
		"title":    "widen",
		"widening": true,
	})
	if !errors.Is(err, ErrWideningPendingApproval) {
		t.Fatalf("expected ErrWideningPendingApproval, got %v", err)
	}
	changeID, _ := unwrapChange(wideOut)["id"].(string)
	if _, err := client.ApprovePolicyChange(ctx, changeID, map[string]any{"actor": "human-admin"}); err != nil {
		t.Fatalf("human approval failed: %v", err)
	}
	converged, err := prov.ApplyUpdate(ctx, "grdr_policy_source", changeID, map[string]any{
		"title":    "widen",
		"widening": true,
	})
	if err != nil {
		t.Fatalf("expected post-approval Terraform re-apply to converge, got %v", err)
	}
	if unwrapChange(converged)["state"] != "APPLIED" {
		t.Fatalf("expected APPLIED state post-approval, got %#v", converged)
	}

	// Modifying an already APPLIED policy source submits and converges a new PolicyChange.
	narrowID, _ := unwrapChange(narrowOut)["id"].(string)
	updatedApplied, err := prov.ApplyUpdate(ctx, "grdr_policy_source", narrowID, map[string]any{
		"title":    "narrow-v2",
		"widening": false,
	})
	if err != nil {
		t.Fatalf("expected APPLIED update to create & apply new change, got %v", err)
	}
	if unwrapChange(updatedApplied)["id"] == narrowID || unwrapChange(updatedApplied)["title"] != "narrow-v2" {
		t.Fatalf("expected new applied change on modified attrs, got %#v", updatedApplied)
	}

	// Terminal FAILED / DENIED state must cause ApplyCreate to return an error.
	for _, failState := range []string{"FAILED", "DENIED"} {
		if _, err := prov.ApplyCreate(ctx, "grdr_policy_source", map[string]any{
			"title":      "bad",
			"widening":   false,
			"forceState": failState,
		}); !errors.Is(err, ErrPolicyChangeFailedOrDenied) {
			t.Fatalf("expected ErrPolicyChangeFailedOrDenied for state=%s, got %v", failState, err)
		}
	}
}
