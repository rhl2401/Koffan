package oauth

// Facebook is not a real OIDC provider - there is no discovery document
// and no id_token. Identity is fetched with a plain authorization-code
// exchange followed by a call to the Graph API's /me endpoint.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

type facebookProvider struct {
	oauth2Cfg oauth2.Config
}

func newFacebookProvider(appID, appSecret string) Provider {
	return &facebookProvider{
		oauth2Cfg: oauth2.Config{
			ClientID:     appID,
			ClientSecret: appSecret,
			Endpoint:     facebook.Endpoint,
			Scopes:       []string{"email", "public_profile"},
		},
	}
}

func (p *facebookProvider) Name() string        { return "facebook" }
func (p *facebookProvider) DisplayName() string { return "Facebook" }
func (p *facebookProvider) UsesFormPost() bool  { return false }

// AuthCodeURL ignores verifier - Facebook's authorization-code flow here
// doesn't use PKCE, unlike the shared OIDC providers.
func (p *facebookProvider) AuthCodeURL(redirectURI, state, _, _ string) string {
	return p.oauth2Cfg.AuthCodeURL(state, oauth2.SetAuthURLParam("redirect_uri", redirectURI))
}

// Exchange ignores nonce and verifier - Facebook issues no id_token, so
// there is nothing to bind a nonce to, and this flow doesn't use PKCE;
// CSRF protection here rests entirely on the state parameter checked by
// handlers.OAuthCallback before this is called.
func (p *facebookProvider) Exchange(ctx context.Context, code, _, _, redirectURI string) (*Identity, error) {
	token, err := p.oauth2Cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("redirect_uri", redirectURI))
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	endpoint := "https://graph.facebook.com/me?fields=" + url.QueryEscape("id,name,email") +
		"&access_token=" + url.QueryEscape(token.AccessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graph api request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read graph api response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("graph api returned status %d: %s", resp.StatusCode, body)
	}

	return parseFacebookProfile(body)
}

// parseFacebookProfile is split out from Exchange so it's unit-testable
// against hand-written JSON fixtures without any network dependency.
func parseFacebookProfile(body []byte) (*Identity, error) {
	var profile struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse graph api response: %w", err)
	}
	if profile.ID == "" {
		return nil, fmt.Errorf("graph api response missing id")
	}
	return &Identity{
		Provider: "facebook",
		Subject:  profile.ID,
		// Facebook only ever returns a verified, account-owned email (or
		// none at all if the permission was denied).
		Email:         profile.Email,
		EmailVerified: profile.Email != "",
		Name:          profile.Name,
	}, nil
}
