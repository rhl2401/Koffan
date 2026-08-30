package oauth

import "context"

func newGoogleProvider(ctx context.Context, clientID, clientSecret string) (Provider, error) {
	return newOIDCProvider(ctx, "google", "Google", "https://accounts.google.com", clientID, clientSecret,
		[]string{"openid", "profile", "email"}, false)
}
