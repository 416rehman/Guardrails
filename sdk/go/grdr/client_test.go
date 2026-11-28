// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

package grdr

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestGoClientPaginationETagAndIdempotency(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	seen := map[string]string{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/devices":
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("page_token") == "p2" {
				_, _ = w.Write([]byte(`{"devices":[{"id":"dev-2"}],"pageInfo":{"nextPageToken":""}}`))
			} else {
				_, _ = w.Write([]byte(`{"devices":[{"id":"dev-1"}],"pageInfo":{"nextPageToken":"p2"}}`))
			}
		case r.Method == http.MethodGet && r.URL.Path == "/v1/health":
			const etag = `"rev-go-1"`
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/rules":
			var bodyBytes []byte
			bodyBytes = make([]byte, 0)
			if r.Body != nil {
				buf := make([]byte, 4096)
				n, _ := r.Body.Read(buf)
				bodyBytes = buf[:n]
			}
			key := r.Header.Get("Idempotency-Key")
			mu.Lock()
			prev, exists := seen[key]
			if exists && prev != string(bodyBytes) {
				mu.Unlock()
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = w.Write([]byte(`{"code":"failed_precondition","reason":"IDEMPOTENCY_KEY_REUSED","message":"conflict"}`))
				return
			}
			seen[key] = string(bodyBytes)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if exists {
				_, _ = w.Write([]byte(`{"replayed":true}`))
			} else {
				_, _ = w.Write([]byte(`{"replayed":false}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewClient(ClientOptions{BaseURL: srv.URL, Token: "tok"})
	ctx := context.Background()

	devices, err := client.ListDevices(ctx, "")
	if err != nil {
		t.Fatalf("ListDevices failed: %v", err)
	}
	if len(devices) != 2 || devices[0]["id"] != "dev-1" || devices[1]["id"] != "dev-2" {
		t.Fatalf("unexpected devices: %#v", devices)
	}

	changed1, h1, err := client.GetConditional(ctx, "/v1/health")
	if err != nil || !changed1 || h1["status"] != "healthy" {
		t.Fatalf("first GetConditional unexpected: changed=%v body=%v err=%v", changed1, h1, err)
	}
	changed2, h2, err := client.GetConditional(ctx, "/v1/health")
	if err != nil || changed2 || h2 != nil {
		t.Fatalf("second GetConditional should return 304: changed=%v body=%v err=%v", changed2, h2, err)
	}

	out1, err := client.Mutate(ctx, http.MethodPost, "/v1/rules", map[string]any{"title": "a"}, "idem-go-1")
	if err != nil || out1["replayed"] != false {
		t.Fatalf("first Mutate unexpected: out=%v err=%v", out1, err)
	}
	out2, err := client.Mutate(ctx, http.MethodPost, "/v1/rules", map[string]any{"title": "a"}, "idem-go-1")
	if err != nil || out2["replayed"] != true {
		t.Fatalf("replay Mutate unexpected: out=%v err=%v", out2, err)
	}
	_, err = client.Mutate(ctx, http.MethodPost, "/v1/rules", map[string]any{"title": "b"}, "idem-go-1")
	var apiErr *ApiError
	if !errors.As(err, &apiErr) || apiErr.Reason != "IDEMPOTENCY_KEY_REUSED" {
		t.Fatalf("expected IDEMPOTENCY_KEY_REUSED, got: %v", err)
	}
}

func TestStandardWebhooksVerificationV1AndV1a(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "webhooks-vectors.json"))
	if err != nil {
		t.Fatalf("read webhooks-vectors.json: %v", err)
	}
	var doc struct {
		StandardWebhooks struct {
			WebhookID        string `json:"webhook_id"`
			WebhookTimestamp int64  `json:"webhook_timestamp"`
			HmacSecretB64    string `json:"hmac_secret_b64"`
			Payload          string `json:"payload"`
		} `json:"standard_webhooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	sw := doc.StandardWebhooks

	hmacSig, err := SignV1Hmac(sw.WebhookID, sw.WebhookTimestamp, []byte(sw.Payload), sw.HmacSecretB64)
	if err != nil {
		t.Fatalf("SignV1Hmac failed: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	edSig := SignV1aEd25519(sw.WebhookID, sw.WebhookTimestamp, []byte(sw.Payload), priv)

	now := sw.WebhookTimestamp + 15
	hdr := http.Header{}
	hdr.Set("webhook-id", sw.WebhookID)
	hdr.Set("webhook-timestamp", "1795737600")
	hdr.Set("webhook-signature", hmacSig)
	res1, err := VerifyWebhook(VerifyWebhookOptions{
		Headers:     hdr,
		Payload:     []byte(sw.Payload),
		HmacSecrets: []string{sw.HmacSecretB64},
		NowUnix:     &now,
	})
	if err != nil || res1.Algorithm != "v1" {
		t.Fatalf("v1 verification failed: res=%v err=%v", res1, err)
	}

	hdr.Set("webhook-signature", edSig)
	res2, err := VerifyWebhook(VerifyWebhookOptions{
		Headers:           hdr,
		Payload:           []byte(sw.Payload),
		Ed25519PublicKeys: []ed25519.PublicKey{pub},
		NowUnix:           &now,
	})
	if err != nil || res2.Algorithm != "v1a" {
		t.Fatalf("v1a verification failed: res=%v err=%v", res2, err)
	}

	stale := sw.WebhookTimestamp + 601
	_, err = VerifyWebhook(VerifyWebhookOptions{
		Headers:           hdr,
		Payload:           []byte(sw.Payload),
		Ed25519PublicKeys: []ed25519.PublicKey{pub},
		NowUnix:           &stale,
	})
	if !errors.Is(err, ErrTimestampOutOfWindow) {
		t.Fatalf("expected ErrTimestampOutOfWindow, got %v", err)
	}
}

func TestGoClientGuardConformanceAndRedirectProtection(t *testing.T) {
	t.Parallel()
	redirectTargetHit := false
	trapSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer trapSrv.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/redirect-me":
			w.Header().Set("Location", trapSrv.URL+"/steal")
			w.WriteHeader(http.StatusFound)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/policy-changes/"):
			_, _ = w.Write([]byte(`{"escapedRawPath":"` + r.URL.EscapedPath() + `"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/guard":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			target, _ := req["target"].(string)
			ac, _ := req["action_class"].(string)
			verdict, ruleID := "allow", ""
			if strings.Contains(target, "--dangerously-skip-permissions") {
				verdict, ruleID = "block", "essentials.bypass-flags"
			} else if strings.Contains(target, ".claude/settings.json") && ac == "file.write" {
				verdict, ruleID = "block", "essentials.control-files"
			} else if strings.Contains(target, "id_rsa") && ac == "file.read" {
				verdict, ruleID = "ask", "essentials.cred-store"
			} else if ac == "file.delete" && target == "/etc/passwd" {
				verdict, ruleID = "ask", "essentials.destructive-delete"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"receipt": map[string]any{"verdict": verdict, "ruleId": ruleID},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewClient(ClientOptions{BaseURL: srv.URL, Token: "secret-tok"})
	ctx := context.Background()

	// 1. Conformance guard-vectors.json & rest-gitops-vectors.json
	guardRaw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "guard-vectors.json"))
	if err != nil {
		t.Fatalf("read guard-vectors.json: %v", err)
	}
	var gv struct {
		Vectors []struct {
			AgentName          string   `json:"agent_name"`
			ControlPoint       string   `json:"control_point"`
			ActionClass        string   `json:"action_class"`
			Target             string   `json:"target"`
			ExpectedVerdicts   []string `json:"expected_verdicts"`
			ExpectedRulePrefix string   `json:"expected_rule_prefix"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(guardRaw, &gv); err != nil {
		t.Fatalf("parse guard-vectors.json: %v", err)
	}
	for _, vec := range gv.Vectors {
		out, err := client.Guard(ctx, map[string]any{
			"agent_name":    vec.AgentName,
			"control_point": vec.ControlPoint,
			"action_class":  vec.ActionClass,
			"target":        vec.Target,
		})
		if err != nil {
			t.Fatalf("Guard failed for %s: %v", vec.Target, err)
		}
		rcpt, _ := out["receipt"].(map[string]any)
		verdict, _ := rcpt["verdict"].(string)
		ruleID, _ := rcpt["ruleId"].(string)
		matchedVerdict := false
		for _, exp := range vec.ExpectedVerdicts {
			if verdict == exp {
				matchedVerdict = true
			}
		}
		if !matchedVerdict || (vec.ExpectedRulePrefix != "" && !strings.HasPrefix(ruleID, vec.ExpectedRulePrefix)) {
			t.Fatalf("vector mismatch verdict=%s rule=%s want=%v prefix=%s", verdict, ruleID, vec.ExpectedVerdicts, vec.ExpectedRulePrefix)
		}
	}

	// 2. Redirect protection & path escaping
	_, _, _, err = client.Request(ctx, http.MethodGet, "/v1/redirect-me", nil, nil)
	var apiErr *ApiError
	if !errors.As(err, &apiErr) || apiErr.Reason != "REDIRECT_BLOCKED" || redirectTargetHit {
		t.Fatalf("expected REDIRECT_BLOCKED without following redirect, got err=%v hit=%v", err, redirectTargetHit)
	}
	escapedOut, err := client.CheckPolicyChange(ctx, "chg/1?evil=2")
	if err != nil || escapedOut["escapedRawPath"] != "/v1/policy-changes/chg%2F1%3Fevil=2:check" {
		t.Fatalf("expected URL-encoded path, got %v err=%v", escapedOut, err)
	}

	// 3. Conformance rest-gitops-vectors.json contract validation
	gitopsRaw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "rest-gitops-vectors.json"))
	if err != nil {
		t.Fatalf("read rest-gitops-vectors.json: %v", err)
	}
	var rgv struct {
		Schema                  string `json:"schema"`
		PolicyChangeTransitions []struct {
			Name               string `json:"name"`
			ProposerKind       string `json:"proposer_kind"`
			DiffEffect         string `json:"diff_effect"`
			ExpectedAfterApply string `json:"expected_after_apply"`
		} `json:"policy_change_transitions"`
		GitopsLockRules struct {
			LockedSource           string `json:"locked_source"`
			UiWriteErrorCode       string `json:"ui_write_error_code"`
			UiWriteHttpStatus      int    `json:"ui_write_http_status"`
			EditAnywayMinApprovers int    `json:"edit_anyway_min_approvers"`
		} `json:"gitops_lock_rules"`
	}
	if err := json.Unmarshal(gitopsRaw, &rgv); err != nil {
		t.Fatalf("parse rest-gitops-vectors.json: %v", err)
	}
	if rgv.Schema != "grdr.conformance.rest-gitops.v1alpha1" || len(rgv.PolicyChangeTransitions) != 3 {
		t.Fatalf("unexpected rest-gitops conformance header/vectors: %+v", rgv)
	}
	if rgv.GitopsLockRules.LockedSource != "git" ||
		rgv.GitopsLockRules.UiWriteErrorCode != "GITOPS_LOCKED" ||
		rgv.GitopsLockRules.UiWriteHttpStatus != http.StatusPreconditionFailed ||
		rgv.GitopsLockRules.EditAnywayMinApprovers != 2 {
		t.Fatalf("unexpected gitops_lock_rules: %+v", rgv.GitopsLockRules)
	}
	for _, tc := range rgv.PolicyChangeTransitions {
		requiresHuman := tc.ProposerKind == "agent_session" || tc.DiffEffect == "widening"
		expected := "ROLLING_OUT"
		if requiresHuman {
			expected = "AWAITING_APPROVAL"
		}
		if expected != tc.ExpectedAfterApply {
			t.Fatalf("transition %s mismatch: got %s want %s", tc.Name, expected, tc.ExpectedAfterApply)
		}
	}
}
