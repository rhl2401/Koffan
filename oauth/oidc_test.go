package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newTestOIDCServer serves a minimal discovery document so newOIDCProvider
// can complete discovery without a real identity provider.
func newTestOIDCServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var issuer string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []interface{}{}})
	})
	srv := httptest.NewServer(mux)
	issuer = srv.URL
	t.Cleanup(srv.Close)
	return srv
}

func TestOIDCProviderAuthCodeURLIncludesPKCEChallenge(t *testing.T) {
	srv := newTestOIDCServer(t)

	provider, err := newOIDCProvider(context.Background(), "generic", "Test", srv.URL, "client-id", "client-secret", []string{"openid"}, false)
	if err != nil {
		t.Fatalf("newOIDCProvider: %v", err)
	}

	flow, err := NewFlow("generic")
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}

	authURL := provider.AuthCodeURL("https://koffan.example.com/auth/generic/callback", flow.State, flow.Nonce, flow.Verifier)

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", authURL, err)
	}

	// A PKCE challenge is sent unconditionally - see the comment on
	// AuthCodeURL in oidc.go for why this is safe even against providers
	// that never asked for it.
	q := parsed.Query()
	if q.Get("code_challenge") == "" {
		t.Fatalf("AuthCodeURL = %s, want a code_challenge parameter", authURL)
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if !strings.HasPrefix(authURL, srv.URL) {
		t.Fatalf("AuthCodeURL = %s, want it to point at the discovered authorization_endpoint %s", authURL, srv.URL)
	}
}
