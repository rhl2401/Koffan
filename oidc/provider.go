package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is what a completed login proves about the person: the stable
// subject at the issuer, and whatever profile claims the provider shared.
type Identity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	// Username is the value of the configured username claim, or "" when
	// the provider did not send it.
	Username string
	// Groups is the configured groups claim, or nil when absent.
	Groups []string
}

// Provider is an initialized OpenID Connect client for one issuer.
type Provider struct {
	name     string
	cfg      Config
	issuer   string
	provider *gooidc.Provider
	oauth2   oauth2.Config
	verifier *gooidc.IDTokenVerifier
}

// retryAfter is how long a failed discovery is remembered before the next
// login attempt tries again. Identity providers often start after Koffan
// (both in one compose file), so discovery is lazy and retried.
const retryAfter = 30 * time.Second

// entry is the registry's memory of one provider: either a working client
// or the last failure, so a provider that is down does not slow every login.
type entry struct {
	key         string
	provider    *Provider
	lastError   error
	lastFailure time.Time
}

var (
	mu       sync.Mutex
	registry = map[string]*entry{}
)

// ErrNotConfigured is returned by Get for a name that is not configured.
var ErrNotConfigured = errors.New("oidc: not configured")

// Get returns the named provider, discovering its issuer on first use. A
// failed discovery is retried at most every retryAfter.
func Get(ctx context.Context, name string) (*Provider, error) {
	cfg, ok := Lookup(name)
	if !ok {
		return nil, ErrNotConfigured
	}
	key := cfg.IssuerURL + "\x00" + cfg.ClientID + "\x00" + cfg.ClientSecret + "\x00" + strings.Join(cfg.Scopes, " ")

	mu.Lock()
	defer mu.Unlock()
	e := registry[name]
	if e != nil && e.key == key {
		if e.provider != nil {
			e.provider.cfg = cfg // the tuning variables may change without rediscovery
			return e.provider, nil
		}
		if time.Since(e.lastFailure) < retryAfter {
			return nil, e.lastError
		}
	}
	p, err := newProvider(ctx, cfg)
	if err != nil {
		registry[name] = &entry{key: key, lastError: err, lastFailure: time.Now()}
		return nil, err
	}
	registry[name] = &entry{key: key, provider: p}
	log.Printf("[OIDC] Provider %q ready: issuer %s", name, cfg.IssuerURL)
	return p, nil
}

// Reset forgets every discovered provider (tests, and after configuration
// changes in the same process).
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	registry = map[string]*entry{}
}

func newProvider(ctx context.Context, cfg Config) (*Provider, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	provider, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery at %s failed: %w", cfg.IssuerURL, err)
	}
	return &Provider{
		name:     cfg.Name,
		cfg:      cfg,
		issuer:   cfg.IssuerURL,
		provider: provider,
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		verifier: provider.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// Name is the provider's slug in routes and logs.
func (p *Provider) Name() string { return p.name }

// Config returns the configuration the provider was built with.
func (p *Provider) Config() Config { return p.cfg }

// AuthCodeURL is where the browser goes to sign in. Every request carries a
// nonce (bound to the id_token) and a PKCE S256 challenge; providers that do
// not use PKCE ignore the extra parameters.
func (p *Provider) AuthCodeURL(redirectURL string, flow *Flow) string {
	return p.oauth2.AuthCodeURL(flow.State,
		gooidc.Nonce(flow.Nonce),
		oauth2.SetAuthURLParam("redirect_uri", redirectURL),
		oauth2.S256ChallengeOption(flow.Verifier),
	)
}

// Exchange trades the authorization code for a verified identity. The
// id_token's signature, issuer, audience, expiry and nonce are all checked.
func (p *Provider) Exchange(ctx context.Context, code, redirectURL string, flow *Flow) (*Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	token, err := p.oauth2.Exchange(ctx, code,
		oauth2.SetAuthURLParam("redirect_uri", redirectURL),
		oauth2.VerifierOption(flow.Verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange failed: %w", err)
	}
	raw, _ := token.Extra("id_token").(string)
	if raw == "" {
		return nil, errors.New("oidc: token response has no id_token")
	}
	idToken, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("oidc: id_token rejected: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(flow.Nonce)) != 1 {
		return nil, errors.New("oidc: id_token nonce mismatch")
	}
	var claims map[string]json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: cannot read id_token claims: %w", err)
	}
	// Providers may leave profile claims out of the id_token and only serve
	// them from the UserInfo endpoint. Fill in what is missing from there;
	// failing to reach it is not fatal, the id_token already proved identity.
	if _, ok := claims[p.cfg.UsernameClaim]; !ok || claims["email"] == nil || claims["name"] == nil {
		p.mergeUserInfo(ctx, token, idToken.Subject, claims)
	}
	identity := identityFromClaims(p.cfg, claims)
	identity.Issuer = p.issuer
	identity.Subject = idToken.Subject
	if identity.Subject == "" {
		return nil, errors.New("oidc: id_token has no subject")
	}
	return identity, nil
}

// mergeUserInfo adds claims from the UserInfo endpoint that the id_token did
// not carry. UserInfo answers for the same subject only.
func (p *Provider) mergeUserInfo(ctx context.Context, token *oauth2.Token, subject string, claims map[string]json.RawMessage) {
	info, err := p.provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
	if err != nil || info.Subject != subject {
		return
	}
	var extra map[string]json.RawMessage
	if err := info.Claims(&extra); err != nil {
		return
	}
	for k, v := range extra {
		if _, ok := claims[k]; !ok {
			claims[k] = v
		}
	}
}

// identityFromClaims maps the configured claims onto an Identity. It is
// lenient about types: email_verified arrives as a string from some
// providers, and groups as a single string from others.
func identityFromClaims(cfg Config, claims map[string]json.RawMessage) *Identity {
	id := &Identity{
		Email:    claimString(claims, "email"),
		Name:     claimString(claims, "name"),
		Username: claimString(claims, cfg.UsernameClaim),
		Groups:   claimStrings(claims, cfg.GroupsClaim),
	}
	switch strings.Trim(string(claims["email_verified"]), `"`) {
	case "true", "1":
		id.EmailVerified = true
	}
	if id.Name == "" {
		given, family := claimString(claims, "given_name"), claimString(claims, "family_name")
		id.Name = strings.TrimSpace(given + " " + family)
	}
	return id
}

func claimString(claims map[string]json.RawMessage, name string) string {
	raw, ok := claims[name]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	// Numbers and booleans are rare for these claims but harmless as text.
	var v interface{}
	if json.Unmarshal(raw, &v) == nil {
		switch v := v.(type) {
		case float64, bool:
			return strings.TrimSpace(fmt.Sprint(v))
		}
	}
	return ""
}

func claimStrings(claims map[string]json.RawMessage, name string) []string {
	raw, ok := claims[name]
	if !ok {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

// InGroup reports whether the identity carries the named group.
func (id *Identity) InGroup(group string) bool {
	for _, g := range id.Groups {
		if g == group {
			return true
		}
	}
	return false
}
