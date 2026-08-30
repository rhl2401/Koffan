package oauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

const (
	// FlowCookieName holds the in-flight authorization request's state and
	// nonce between OAuthStart and OAuthCallback.
	FlowCookieName = "oauth_flow"
	FlowMaxAge     = 10 * time.Minute
)

// Flow is the CSRF state + OIDC nonce for one in-progress login attempt,
// scoped to a single provider.
type Flow struct {
	Provider  string `json:"provider"`
	State     string `json:"state"`
	Nonce     string `json:"nonce"`
	CreatedAt int64  `json:"created_at"`
}

// NewFlow generates a fresh state/nonce pair for provider.
func NewFlow(provider string) (*Flow, error) {
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &Flow{Provider: provider, State: state, Nonce: nonce, CreatedAt: time.Now().Unix()}, nil
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
	if f.Provider == "" || f.State == "" || f.Nonce == "" {
		return nil, errors.New("oauth: incomplete flow cookie")
	}
	if time.Now().Unix()-f.CreatedAt > int64(FlowMaxAge.Seconds()) {
		return nil, errors.New("oauth: flow cookie expired")
	}
	return &f, nil
}
