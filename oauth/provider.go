package oauth

import "context"

// Provider is implemented by every OAuth/OIDC login method Koffan supports.
type Provider interface {
	// Name is the stable slug used in routes ("/auth/{name}/...") and in
	// the oauth_identities.provider column.
	Name() string
	// DisplayName is the sign-in button label.
	DisplayName() string
	// UsesFormPost reports whether the provider's callback arrives as a
	// POST with a form-encoded body rather than GET query params (true
	// only for Apple).
	UsesFormPost() bool
	// AuthCodeURL builds the URL to redirect the browser to in order to
	// start the flow.
	AuthCodeURL(redirectURI, state, nonce string) string
	// Exchange trades an authorization code for a verified Identity. For
	// OIDC-shaped providers this also verifies the id_token's nonce claim
	// against nonce; providers without an id_token (Facebook) ignore it.
	Exchange(ctx context.Context, code, nonce, redirectURI string) (*Identity, error)
}
