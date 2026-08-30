package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"shopping-list/oauth"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// setupFacebookProvider enables the Facebook provider without any network
// call (unlike generic/Google/Apple, it needs no OIDC discovery), and
// restores global oauth state once env vars are unset again.
func setupFacebookProvider(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { oauth.Init(context.Background()) })
	t.Setenv("OAUTH_FACEBOOK_APP_ID", "test-app-id")
	t.Setenv("OAUTH_FACEBOOK_APP_SECRET", "test-app-secret")
	if err := oauth.Init(context.Background()); err != nil {
		t.Fatalf("oauth.Init: %v", err)
	}
}

func TestOAuthCallbackRejectsMissingStateCookie(t *testing.T) {
	setupFacebookProvider(t)

	app := fiber.New()
	app.Get("/auth/:provider/callback", OAuthCallback)

	req := httptest.NewRequest(http.MethodGet, "/auth/facebook/callback?code=abc&state=xyz", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if loc := resp.Header.Get("Location"); loc != "/login?error=oauth_state" {
		t.Fatalf("Location = %q, want /login?error=oauth_state", loc)
	}
}

func TestOAuthCallbackRejectsMismatchedState(t *testing.T) {
	setupFacebookProvider(t)

	flow, err := oauth.NewFlow("facebook")
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}
	encoded, err := flow.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	app := fiber.New()
	app.Get("/auth/:provider/callback", OAuthCallback)

	req := httptest.NewRequest(http.MethodGet, "/auth/facebook/callback?code=abc&state=not-the-real-state", nil)
	req.AddCookie(&http.Cookie{Name: oauth.FlowCookieName, Value: encoded})
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if loc := resp.Header.Get("Location"); loc != "/login?error=oauth_state" {
		t.Fatalf("Location = %q, want /login?error=oauth_state", loc)
	}
}

func TestOAuthCallbackRejectsProviderMismatch(t *testing.T) {
	setupFacebookProvider(t)

	// Flow cookie was started for "google" but the callback path claims "facebook".
	flow, err := oauth.NewFlow("google")
	if err != nil {
		t.Fatalf("NewFlow: %v", err)
	}
	encoded, err := flow.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	app := fiber.New()
	app.Get("/auth/:provider/callback", OAuthCallback)

	req := httptest.NewRequest(http.MethodGet, "/auth/facebook/callback?code=abc&state="+flow.State, nil)
	req.AddCookie(&http.Cookie{Name: oauth.FlowCookieName, Value: encoded})
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if loc := resp.Header.Get("Location"); loc != "/login?error=oauth_state" {
		t.Fatalf("Location = %q, want /login?error=oauth_state", loc)
	}
}

func TestOAuthCallbackRejectsUnknownProvider(t *testing.T) {
	setupFacebookProvider(t)

	app := fiber.New()
	app.Get("/auth/:provider/callback", OAuthCallback)

	req := httptest.NewRequest(http.MethodGet, "/auth/not-a-real-provider/callback", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if loc := resp.Header.Get("Location"); loc != "/login?error=oauth_unavailable" {
		t.Fatalf("Location = %q, want /login?error=oauth_unavailable", loc)
	}
}

func TestOAuthProviderViewsBuildsExpectedFields(t *testing.T) {
	setupFacebookProvider(t)

	views := oauthProviderViews()
	if len(views) != 1 {
		t.Fatalf("oauthProviderViews() = %+v, want exactly one enabled provider", views)
	}
	view := views[0]
	if view.Name != "facebook" {
		t.Fatalf("Name = %q, want facebook", view.Name)
	}
	if view.StartURL != "/auth/facebook/start" {
		t.Fatalf("StartURL = %q, want /auth/facebook/start", view.StartURL)
	}
	if view.DisplayLabel == "" {
		t.Fatal("DisplayLabel should not be empty")
	}
}
