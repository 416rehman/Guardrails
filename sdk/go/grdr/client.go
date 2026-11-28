// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

package grdr

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ApiError struct {
	Status  int            `json:"status"`
	Code    string         `json:"code"`
	Reason  string         `json:"reason"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func (e *ApiError) Error() string {
	return fmt.Sprintf("HTTP %d [%s/%s]: %s", e.Status, e.Code, e.Reason, e.Message)
}

type PageInfo struct {
	NextPageToken     string `json:"nextPageToken"`
	PrevPageToken     string `json:"prevPageToken"`
	TotalSizeEstimate uint64 `json:"totalSizeEstimate"`
	HasMore           bool   `json:"hasMore"`
}

type ClientOptions struct {
	BaseURL    string
	Token      string
	UserAgent  string
	HTTPClient *http.Client
}

type Client struct {
	baseURL    string
	token      string
	userAgent  string
	httpClient *http.Client
	mu         sync.Mutex
	etags      map[string]string
}

func NewClient(opts ClientOptions) *Client {
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = "grdr-go/0.1.0"
	}
	return &Client{
		baseURL:    strings.TrimRight(opts.BaseURL, "/"),
		token:      opts.Token,
		userAgent:  ua,
		httpClient: hc,
		etags:      make(map[string]string),
	}
}

func newIdempotencyKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (c *Client) Request(
	ctx context.Context,
	method string,
	reqPath string,
	body any,
	extraHeaders map[string]string,
) (int, map[string]any, http.Header, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+reqPath, reader)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return resp.StatusCode, nil, resp.Header, nil
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, nil, resp.Header, &ApiError{
			Status:  resp.StatusCode,
			Code:    "redirect_blocked",
			Reason:  "REDIRECT_BLOCKED",
			Message: "HTTP redirect blocked to protect Authorization header",
			Details: map[string]any{"location": resp.Header.Get("Location")},
		}
	}
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return resp.StatusCode, nil, resp.Header, err
	}
	var out map[string]any
	if len(bytes.TrimSpace(respBytes)) > 0 {
		if err := json.Unmarshal(respBytes, &out); err != nil {
			out = map[string]any{"raw": string(respBytes)}
		}
	} else {
		out = map[string]any{}
	}
	if resp.StatusCode >= 400 {
		code, _ := out["code"].(string)
		reason, _ := out["reason"].(string)
		msg, _ := out["message"].(string)
		if msg == "" {
			msg = string(respBytes)
		}
		return resp.StatusCode, out, resp.Header, &ApiError{
			Status:  resp.StatusCode,
			Code:    code,
			Reason:  reason,
			Message: msg,
			Details: out,
		}
	}
	return resp.StatusCode, out, resp.Header, nil
}

func (c *Client) Mutate(
	ctx context.Context,
	method string,
	reqPath string,
	body any,
	idempotencyKey string,
) (map[string]any, error) {
	if idempotencyKey == "" {
		idempotencyKey = newIdempotencyKey()
	}
	_, out, _, err := c.Request(ctx, method, reqPath, body, map[string]string{
		"Idempotency-Key": idempotencyKey,
	})
	return out, err
}

func (c *Client) Get(ctx context.Context, reqPath string) (map[string]any, error) {
	_, out, _, err := c.Request(ctx, http.MethodGet, reqPath, nil, nil)
	return out, err
}

func (c *Client) GetConditional(ctx context.Context, reqPath string) (bool, map[string]any, error) {
	c.mu.Lock()
	etag := c.etags[reqPath]
	c.mu.Unlock()
	var hdr map[string]string
	if etag != "" {
		hdr = map[string]string{"If-None-Match": etag}
	}
	status, out, respHdr, err := c.Request(ctx, http.MethodGet, reqPath, nil, hdr)
	if err != nil {
		return false, nil, err
	}
	if status == http.StatusNotModified {
		return false, nil, nil
	}
	if next := respHdr.Get("ETag"); next != "" {
		c.mu.Lock()
		c.etags[reqPath] = next
		c.mu.Unlock()
	}
	return true, out, nil
}

func (c *Client) Health(ctx context.Context) (map[string]any, error) {
	return c.Get(ctx, "/v1/health")
}

func (c *Client) Overview(ctx context.Context) (map[string]any, error) {
	return c.Get(ctx, "/v1/overview")
}

func (c *Client) Guard(ctx context.Context, payload map[string]any) (map[string]any, error) {
	return c.Mutate(ctx, http.MethodPost, "/v1/guard", payload, "")
}

func (c *Client) ListAll(
	ctx context.Context,
	reqPath string,
	itemsKey string,
	pageSize int,
	filter string,
) ([]map[string]any, error) {
	if pageSize <= 0 {
		pageSize = 50
	}
	var all []map[string]any
	token := ""
	for {
		q := url.Values{}
		q.Set("page_size", fmt.Sprintf("%d", pageSize))
		if token != "" {
			q.Set("page_token", token)
		}
		if filter != "" {
			q.Set("filter", filter)
		}
		out, err := c.Get(ctx, reqPath+"?"+q.Encode())
		if err != nil {
			return nil, err
		}
		if rawItems, ok := out[itemsKey].([]any); ok {
			for _, item := range rawItems {
				if m, ok := item.(map[string]any); ok {
					all = append(all, m)
				}
			}
		}
		next := ""
		if pi, ok := out["pageInfo"].(map[string]any); ok {
			if tok, ok := pi["nextPageToken"].(string); ok {
				next = tok
			}
		}
		if next == "" {
			break
		}
		token = next
	}
	return all, nil
}

func (c *Client) ListDevices(ctx context.Context, filter string) ([]map[string]any, error) {
	return c.ListAll(ctx, "/v1/devices", "devices", 50, filter)
}

func (c *Client) CreatePolicyChange(ctx context.Context, payload map[string]any, idem string) (map[string]any, error) {
	return c.Mutate(ctx, http.MethodPost, "/v1/policy-changes", payload, idem)
}

func (c *Client) CheckPolicyChange(ctx context.Context, changeID string) (map[string]any, error) {
	return c.Mutate(ctx, http.MethodPost, "/v1/policy-changes/"+url.PathEscape(changeID)+":check", map[string]any{}, "")
}

func (c *Client) SimulatePolicyChange(ctx context.Context, changeID string) (map[string]any, error) {
	return c.Mutate(ctx, http.MethodPost, "/v1/policy-changes/"+url.PathEscape(changeID)+":simulate", map[string]any{}, "")
}

func (c *Client) ApplyPolicyChange(ctx context.Context, changeID string, idem string) (map[string]any, error) {
	return c.Mutate(ctx, http.MethodPost, "/v1/policy-changes/"+url.PathEscape(changeID)+":apply", map[string]any{}, idem)
}

func (c *Client) ApprovePolicyChange(ctx context.Context, changeID string, payload map[string]any) (map[string]any, error) {
	return c.Mutate(ctx, http.MethodPost, "/v1/policy-changes/"+url.PathEscape(changeID)+":approve", payload, "")
}

func (c *Client) GetGitopsBinding(ctx context.Context) (map[string]any, error) {
	return c.Get(ctx, "/v1/gitops-binding")
}

func (c *Client) UpsertGitopsBinding(ctx context.Context, payload map[string]any) (map[string]any, error) {
	return c.Mutate(ctx, http.MethodPut, "/v1/gitops-binding", payload, "")
}
