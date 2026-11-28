// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

package grdr

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrMissingWebhookHeaders = errors.New("missing Standard Webhooks headers")
	ErrInvalidTimestamp      = errors.New("invalid webhook-timestamp header")
	ErrTimestampOutOfWindow  = errors.New("webhook timestamp outside tolerance window")
	ErrInvalidSignature      = errors.New("no matching webhook signature")
	ErrInvalidSecret         = errors.New("invalid whsec webhook secret")
)

type VerifiedWebhook struct {
	WebhookID string
	Timestamp int64
	Algorithm string
	Payload   []byte
}

func DecodeWhsec(secret string) ([]byte, error) {
	raw := strings.TrimPrefix(secret, "whsec_")
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(decoded) == 0 {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSecret, err)
	}
	return decoded, nil
}

func SignV1Hmac(webhookID string, timestamp int64, payload []byte, secret string) (string, error) {
	key, err := DecodeWhsec(secret)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s.%d.", webhookID, timestamp)
	_, _ = mac.Write(payload)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func SignV1aEd25519(webhookID string, timestamp int64, payload []byte, priv ed25519.PrivateKey) string {
	prefix := fmt.Sprintf("%s.%d.", webhookID, timestamp)
	signed := make([]byte, 0, len(prefix)+len(payload))
	signed = append(signed, prefix...)
	signed = append(signed, payload...)
	sig := ed25519.Sign(priv, signed)
	return "v1a," + base64.StdEncoding.EncodeToString(sig)
}

type VerifyWebhookOptions struct {
	Headers           http.Header
	Payload           []byte
	HmacSecrets       []string
	Ed25519PublicKeys []ed25519.PublicKey
	ToleranceSeconds  int64
	NowUnix           *int64
}

func VerifyWebhook(opts VerifyWebhookOptions) (*VerifiedWebhook, error) {
	msgID := strings.TrimSpace(opts.Headers.Get("webhook-id"))
	tsRaw := strings.TrimSpace(opts.Headers.Get("webhook-timestamp"))
	sigHeader := strings.TrimSpace(opts.Headers.Get("webhook-signature"))
	if msgID == "" || tsRaw == "" || sigHeader == "" {
		return nil, ErrMissingWebhookHeaders
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return nil, ErrInvalidTimestamp
	}
	now := time.Now().Unix()
	if opts.NowUnix != nil {
		now = *opts.NowUnix
	}
	tol := opts.ToleranceSeconds
	if tol <= 0 {
		tol = 300
	}
	diff := math.Abs(float64(now - ts))
	if diff > float64(tol) {
		return nil, ErrTimestampOutOfWindow
	}

	prefix := fmt.Sprintf("%s.%d.", msgID, ts)
	signed := make([]byte, 0, len(prefix)+len(opts.Payload))
	signed = append(signed, prefix...)
	signed = append(signed, opts.Payload...)

	for _, token := range strings.Fields(sigHeader) {
		if strings.HasPrefix(token, "v1a,") {
			sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(token, "v1a,"))
			if err != nil {
				continue
			}
			for _, pub := range opts.Ed25519PublicKeys {
				if len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, signed, sigBytes) {
					return &VerifiedWebhook{
						WebhookID: msgID,
						Timestamp: ts,
						Algorithm: "v1a",
						Payload:   opts.Payload,
					}, nil
				}
			}
		} else if strings.HasPrefix(token, "v1,") {
			sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(token, "v1,"))
			if err != nil {
				continue
			}
			for _, sec := range opts.HmacSecrets {
				key, err := DecodeWhsec(sec)
				if err != nil {
					continue
				}
				mac := hmac.New(sha256.New, key)
				_, _ = mac.Write(signed)
				if hmac.Equal(mac.Sum(nil), sigBytes) {
					return &VerifiedWebhook{
						WebhookID: msgID,
						Timestamp: ts,
						Algorithm: "v1",
						Payload:   opts.Payload,
					}, nil
				}
			}
		}
	}
	return nil, ErrInvalidSignature
}
