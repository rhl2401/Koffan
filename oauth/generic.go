package oauth

// This file must stay provider-agnostic: no vendor-specific naming,
// config, or assumptions. It builds an OIDC client for any
// standards-compliant provider via discovery (e.g. Authelia, Keycloak,
// Authentik, PocketID, ...).

import (
	"context"
	"os"
	"strings"
)

const defaultGenericButtonLabel = "Sign in with SSO"

func newGenericProvider(ctx context.Context, issuerURL, clientID, clientSecret string) (Provider, error) {
	scopes := strings.Fields(os.Getenv("OAUTH_GENERIC_SCOPES"))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	label := os.Getenv("OAUTH_GENERIC_BUTTON_LABEL")
	if label == "" {
		label = defaultGenericButtonLabel
	}

	return newOIDCProvider(ctx, "generic", label, issuerURL, clientID, clientSecret, scopes, false)
}
