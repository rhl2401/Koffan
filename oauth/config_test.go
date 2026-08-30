package oauth

import (
	"context"
	"testing"
)

func resetProviders(t *testing.T) {
	t.Helper()
	mu.Lock()
	providers = map[string]Provider{}
	mu.Unlock()
}

func TestPasswordAuthAllowed(t *testing.T) {
	t.Run("stays on when the flag is unset", func(t *testing.T) {
		resetProviders(t)
		t.Setenv("DISABLE_PASSWORD_AUTH", "")
		if !PasswordAuthAllowed() {
			t.Fatal("expected password auth to remain allowed")
		}
	})

	t.Run("flag set but no provider enabled falls back to allowing it", func(t *testing.T) {
		resetProviders(t)
		t.Setenv("DISABLE_PASSWORD_AUTH", "true")
		if !PasswordAuthAllowed() {
			t.Fatal("expected fallback to password auth when no provider is ready")
		}
	})

	t.Run("flag set and a provider enabled disables it", func(t *testing.T) {
		t.Cleanup(func() { Init(context.Background()) })
		t.Setenv("OAUTH_FACEBOOK_APP_ID", "app-id")
		t.Setenv("OAUTH_FACEBOOK_APP_SECRET", "app-secret")
		t.Setenv("DISABLE_PASSWORD_AUTH", "true")
		if err := Init(context.Background()); err != nil {
			t.Fatalf("Init: %v", err)
		}
		if PasswordAuthAllowed() {
			t.Fatal("expected password auth to be disabled once a provider is ready")
		}
	})
}

func TestEnabledReturnsOnlyConfiguredProvidersInStableOrder(t *testing.T) {
	t.Cleanup(func() { Init(context.Background()) })
	t.Setenv("OAUTH_FACEBOOK_APP_ID", "app-id")
	t.Setenv("OAUTH_FACEBOOK_APP_SECRET", "app-secret")
	if err := Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	enabled := Enabled()
	if len(enabled) != 1 || enabled[0].Name() != "facebook" {
		t.Fatalf("Enabled() = %+v, want exactly [facebook]", enabled)
	}
	if !AnyEnabled() {
		t.Fatal("AnyEnabled() = false, want true")
	}
	if _, ok := Get("facebook"); !ok {
		t.Fatal("Get(\"facebook\") not found")
	}
	if _, ok := Get("google"); ok {
		t.Fatal("Get(\"google\") unexpectedly found - it was never configured")
	}
}
