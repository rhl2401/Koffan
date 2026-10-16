package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/oauth2"
)

const (
	// FlowCookieName carries one login attempt's state, nonce and PKCE
	// verifier from the start of the flow to the callback.
	FlowCookieName = "oidc_flow"
	// FlowMaxAge bounds how long a person may take at the identity provider.
	FlowMaxAge = 10 * time.Minute
)

// Flow is one login attempt in progress, bound to the provider it started at.
type Flow struct {
	Provider  string `json:"provider"`
	State     string `json:"state"`
	Nonce     string `json:"nonce"`
	Verifier  string `json:"verifier"`
	CreatedAt int64  `json:"created_at"`
}

// NewFlow draws a fresh state, nonce and PKCE verifier for a provider.
func NewFlow(provider string) (*Flow, error) {
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		return nil, err
	}
	return &Flow{Provider: provider, State: state, Nonce: nonce, Verifier: oauth2.GenerateVerifier(), CreatedAt: time.Now().Unix()}, nil
}

// Encode serializes the flow for its cookie.
func (f *Flow) Encode() string {
	b, _ := json.Marshal(f)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeFlow parses a flow cookie and refuses incomplete or expired ones.
func DecodeFlow(value string) (*Flow, error) {
	if value == "" {
		return nil, errors.New("oidc: no login attempt in progress")
	}
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	var f Flow
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Provider == "" || f.State == "" || f.Nonce == "" || f.Verifier == "" {
		return nil, errors.New("oidc: incomplete login attempt")
	}
	age := time.Now().Unix() - f.CreatedAt
	if age < 0 || age > int64(FlowMaxAge.Seconds()) {
		return nil, errors.New("oidc: login attempt expired")
	}
	return &f, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
