// Package oidc signs people in through an OpenID Connect identity provider
// (Authelia, Authentik, Keycloak, PocketID, Google, ...). It only produces a
// verified Identity; mapping that identity to an account is the handlers'
// job, and it is only meaningful with MULTI_USER=true.
package oidc

import (
	"os"
	"strconv"
	"strings"
)

// Environment variables. OIDC_ISSUER_URL, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET
// together switch single sign-on on; the rest tune it.
const (
	EnvIssuerURL            = "OIDC_ISSUER_URL"
	EnvClientID             = "OIDC_CLIENT_ID"
	EnvClientSecret         = "OIDC_CLIENT_SECRET"
	EnvScopes               = "OIDC_SCOPES"
	EnvRedirectURL          = "OIDC_REDIRECT_URL"
	EnvButtonLabel          = "OIDC_BUTTON_LABEL"
	EnvUsernameClaim        = "OIDC_USERNAME_CLAIM"
	EnvGroupsClaim          = "OIDC_GROUPS_CLAIM"
	EnvAdminGroup           = "OIDC_ADMIN_GROUP"
	EnvAutoCreateUsers      = "OIDC_AUTO_CREATE_USERS"
	EnvDefaultWorkspaceID   = "OIDC_DEFAULT_WORKSPACE_ID"
	EnvDisablePasswordLogin = "OIDC_DISABLE_PASSWORD_LOGIN"
)

// DefaultProviderName is the route slug and registry key of the provider
// configured through the plain OIDC_* variables. It is what operators
// register at their identity provider: /auth/oidc/callback.
const DefaultProviderName = "oidc"

// Config describes one identity provider. Today exactly one is read from the
// environment (see Configs); the Name keeps room for more, each with its own
// routes and button, without changing the stored identity links, which are
// keyed by issuer rather than by this name.
type Config struct {
	// Name is the provider's slug in routes (/auth/{name}/start) and logs.
	Name string

	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	// RedirectURL is the callback registered at the identity provider. When
	// empty it is derived from the incoming request.
	RedirectURL string
	// ButtonLabel replaces the translated "Sign in with SSO" button text.
	ButtonLabel string
	// UsernameClaim names the claim that becomes the Koffan username
	// (default preferred_username, falling back to email).
	UsernameClaim string
	// GroupsClaim names the claim that lists the person's groups (default
	// groups). AdminGroup, when set, makes members of that group
	// administrators and everyone else a regular account on every login.
	GroupsClaim string
	AdminGroup  string
	// AutoCreateUsers creates an account on the first login (default true).
	// With false, only accounts an administrator created, or that were linked
	// before, can sign in.
	AutoCreateUsers bool
	// DefaultWorkspaceID is the workspace newly created accounts join; 0
	// leaves them without a workspace until an administrator adds them.
	DefaultWorkspaceID int64
}

// Load reads the default provider's configuration from the environment. Use
// Configs or Lookup to find out whether it is complete.
func Load() Config {
	cfg := Config{
		Name:            DefaultProviderName,
		IssuerURL:       strings.TrimSpace(os.Getenv(EnvIssuerURL)),
		ClientID:        strings.TrimSpace(os.Getenv(EnvClientID)),
		ClientSecret:    os.Getenv(EnvClientSecret),
		Scopes:          strings.Fields(os.Getenv(EnvScopes)),
		RedirectURL:     strings.TrimSpace(os.Getenv(EnvRedirectURL)),
		ButtonLabel:     strings.TrimSpace(os.Getenv(EnvButtonLabel)),
		UsernameClaim:   strings.TrimSpace(os.Getenv(EnvUsernameClaim)),
		GroupsClaim:     strings.TrimSpace(os.Getenv(EnvGroupsClaim)),
		AdminGroup:      strings.TrimSpace(os.Getenv(EnvAdminGroup)),
		AutoCreateUsers: os.Getenv(EnvAutoCreateUsers) != "false",
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "preferred_username"
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if v, err := strconv.ParseInt(os.Getenv(EnvDefaultWorkspaceID), 10, 64); err == nil && v > 0 {
		cfg.DefaultWorkspaceID = v
	}
	return cfg
}

// Configured reports whether the three required settings are present.
func (c Config) Configured() bool {
	return c.IssuerURL != "" && c.ClientID != "" && c.ClientSecret != ""
}

// Configs lists every completely configured provider, in display order. It
// is the one place to extend when a second provider (another set of
// variables, or a fixed preset) is added.
func Configs() []Config {
	var out []Config
	if cfg := Load(); cfg.Configured() {
		out = append(out, cfg)
	}
	return out
}

// Lookup returns the configured provider with that name.
func Lookup(name string) (Config, bool) {
	for _, cfg := range Configs() {
		if cfg.Name == name {
			return cfg, true
		}
	}
	return Config{}, false
}

// Configured reports whether at least one provider is configured in the
// environment. It does not say whether that provider is reachable: see Get.
func Configured() bool {
	return len(Configs()) > 0
}

// PasswordLoginDisabled reports whether the environment asks to hide the
// password form. Callers only honour it while a provider is configured.
func PasswordLoginDisabled() bool {
	return os.Getenv(EnvDisablePasswordLogin) == "true"
}
