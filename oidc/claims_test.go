package oidc

import (
	"encoding/json"
	"testing"
)

func claims(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()
	var out map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIdentityFromClaimsIsLenientAboutTypes(t *testing.T) {
	cfg := Config{UsernameClaim: "preferred_username", GroupsClaim: "groups"}

	id := identityFromClaims(cfg, claims(t, `{"email":" Alice@Example.com ","email_verified":"true","name":"Alice A","preferred_username":"alice","groups":["family","admins"]}`))
	if id.Email != "Alice@Example.com" || !id.EmailVerified || id.Name != "Alice A" || id.Username != "alice" || !id.InGroup("admins") || id.InGroup("nope") {
		t.Fatalf("identity = %#v", id)
	}

	// A single group as a string, email_verified as a boolean, and a name
	// assembled from given and family name.
	id = identityFromClaims(cfg, claims(t, `{"email_verified":true,"given_name":"Bob","family_name":"B","groups":"family"}`))
	if id.EmailVerified != true || id.Name != "Bob B" || len(id.Groups) != 1 || id.Groups[0] != "family" || id.Username != "" {
		t.Fatalf("identity = %#v", id)
	}

	// Another claim can be the username; missing claims are empty, not errors.
	id = identityFromClaims(Config{UsernameClaim: "sub_name", GroupsClaim: "roles"}, claims(t, `{"sub_name":"carol","roles":[]}`))
	if id.Username != "carol" || len(id.Groups) != 0 || id.Email != "" || id.EmailVerified {
		t.Fatalf("identity = %#v", id)
	}
}

func TestLoadReadsTheEnvironment(t *testing.T) {
	t.Setenv(EnvIssuerURL, "")
	t.Setenv(EnvClientID, "")
	t.Setenv(EnvClientSecret, "")
	if Configured() {
		t.Fatal("configured without any variables")
	}
	t.Setenv(EnvIssuerURL, " https://idp.example.com ")
	t.Setenv(EnvClientID, "koffan")
	if Configured() {
		t.Fatal("configured without a client secret")
	}
	t.Setenv(EnvClientSecret, "s3cret")
	t.Setenv(EnvAutoCreateUsers, "false")
	t.Setenv(EnvDefaultWorkspaceID, "7")
	t.Setenv(EnvScopes, "openid email")
	cfgs := Configs()
	if len(cfgs) != 1 || cfgs[0].Name != DefaultProviderName || cfgs[0].IssuerURL != "https://idp.example.com" {
		t.Fatalf("configs = %#v", cfgs)
	}
	cfg := cfgs[0]
	if cfg.AutoCreateUsers || cfg.DefaultWorkspaceID != 7 || len(cfg.Scopes) != 2 || cfg.UsernameClaim != "preferred_username" || cfg.GroupsClaim != "groups" {
		t.Fatalf("config = %#v", cfg)
	}
	if _, ok := Lookup("other"); ok {
		t.Fatal("unknown provider found")
	}
	if PasswordLoginDisabled() {
		t.Fatal("password login disabled by default")
	}
}
