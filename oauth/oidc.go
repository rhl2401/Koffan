package oauth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// oidcProvider backs every provider that speaks real OIDC (discovery
// document + signed id_token): generic, Google, and Apple.
type oidcProvider struct {
	name        string
	displayName string
	formPost    bool
	oauth2Cfg   oauth2.Config
	verifier    *oidc.IDTokenVerifier
}

// flexBool accepts email_verified as either a JSON boolean or a JSON
// string ("true"/"false") - some OIDC providers (Apple included) send it
// as a string, and this client supports arbitrary generic providers.
type flexBool bool

func (f *flexBool) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	*f = flexBool(s == "true" || s == "1")
	return nil
}

func newOIDCProvider(ctx context.Context, name, displayName, issuerURL, clientID, clientSecret string, scopes []string, formPost bool) (*oidcProvider, error) {
	p, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}
	return &oidcProvider{
		name:        name,
		displayName: displayName,
		formPost:    formPost,
		oauth2Cfg: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     p.Endpoint(),
			Scopes:       scopes,
		},
		verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

func (p *oidcProvider) Name() string        { return p.name }
func (p *oidcProvider) DisplayName() string { return p.displayName }
func (p *oidcProvider) UsesFormPost() bool  { return p.formPost }

func (p *oidcProvider) AuthCodeURL(redirectURI, state, nonce string) string {
	opts := []oauth2.AuthCodeOption{
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("redirect_uri", redirectURI),
	}
	if p.formPost {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}
	return p.oauth2Cfg.AuthCodeURL(state, opts...)
}

func (p *oidcProvider) Exchange(ctx context.Context, code, nonce, redirectURI string) (*Identity, error) {
	token, err := p.oauth2Cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("redirect_uri", redirectURI))
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("token response did not include an id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	var claims struct {
		Email         string   `json:"email"`
		EmailVerified flexBool `json:"email_verified"`
		Name          string   `json:"name"`
		Picture       string   `json:"picture"`
		Nonce         string   `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return nil, fmt.Errorf("id_token nonce mismatch")
	}

	return &Identity{
		Provider:      p.name,
		Subject:       idToken.Subject,
		Email:         strings.TrimSpace(claims.Email),
		EmailVerified: bool(claims.EmailVerified),
		Name:          claims.Name,
		Picture:       claims.Picture,
	}, nil
}
