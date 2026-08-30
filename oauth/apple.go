package oauth

import "context"

// Apple's login flow is OIDC-shaped (discovery document + signed
// id_token) but has two quirks Koffan deliberately does not fully
// automate:
//
//   - The client secret Apple requires is itself a short-lived JWT signed
//     with ES256 using a private key, Team ID, and Key ID from Apple
//     Developer. Koffan does not generate or rotate this - the operator
//     creates it out-of-band and supplies it as an opaque string via
//     OAUTH_APPLE_CLIENT_SECRET, which must be regenerated (Apple allows
//     up to 6 months validity) before it expires.
//   - When the name/email scopes are granted, Apple includes them in the
//     id_token only on the very first authorization for a given user, and
//     posts the callback via response_mode=form_post (a POST with a
//     form-encoded body) rather than a GET redirect with query params -
//     see UsesFormPost / handlers.OAuthCallback.
func newAppleProvider(ctx context.Context, clientID, clientSecret string) (Provider, error) {
	return newOIDCProvider(ctx, "apple", "Apple", "https://appleid.apple.com", clientID, clientSecret,
		[]string{"openid", "name", "email"}, true)
}
