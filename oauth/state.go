package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/oauth2"
)

const (
	// FlowCookieName holds the in-flight authorization request's state and
	// nonce between OAuthStart and OAuthCallback.
	FlowCookieName = "oauth_flow"
	FlowMaxAge     = 10 * time.Minute
)

// Flow is the CSRF state + OIDC nonce + PKCE verifier for one in-progress
// login attempt, scoped to a single provider.
type Flow struct {
	Provider  string `json:"provider"`
	State     string `json:"state"`
	Nonce     string `json:"nonce"`
	Verifier  string `json:"verifier"`
	CreatedAt int64  `json:"created_at"`
}

// NewFlow generates a fresh state/nonce/PKCE-verifier set for provider. The
// verifier is always generated, even for providers/deployments that don't
// require PKCE - sending an unrequested code_challenge is harmless (RFC
// 7636 servers that don't support it simply ignore the extra parameter),
// so this stays safe across every provider without per-provider config.
func NewFlow(provider string) (*Flow, error) {
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()
	return &Flow{Provider: provider, State: state, Nonce: nonce, Verifier: verifier, CreatedAt: time.Now().Unix()}, nil
}

// Encode serializes the flow for storage in a cookie.
func (f *Flow) Encode() (string, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// DecodeFlow parses a flow cookie value, rejecting malformed, incomplete,
// or expired ones.
func DecodeFlow(value string) (*Flow, error) {
	if value == "" {
		return nil, errors.New("oauth: empty flow cookie")
	}
	b, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	var f Flow
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Provider == "" || f.State == "" || f.Nonce == "" || f.Verifier == "" {
		return nil, errors.New("oauth: incomplete flow cookie")
	}
	if time.Now().Unix()-f.CreatedAt > int64(FlowMaxAge.Seconds()) {
		return nil, errors.New("oauth: flow cookie expired")
	}
	return &f, nil
}
