package oauth

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/gofiber/fiber/v2"
)

// providerOrder is the stable display/registration order used by Enabled.
var providerOrder = []string{"generic", "google", "apple", "facebook"}

var (
	mu        sync.RWMutex
	providers = map[string]Provider{}
)

// Init builds every OAuth provider whose required env vars are configured.
// A provider that fails to initialize (e.g. unreachable OIDC discovery
// endpoint) is logged and skipped rather than treated as fatal, so a
// transient IdP outage at boot doesn't take down the whole app - it just
// disables that one provider until the next restart.
func Init(ctx context.Context) error {
	mu.Lock()
	defer mu.Unlock()
	providers = map[string]Provider{}

	var errs []string

	if issuer, clientID, clientSecret := os.Getenv("OAUTH_GENERIC_ISSUER_URL"), os.Getenv("OAUTH_GENERIC_CLIENT_ID"), os.Getenv("OAUTH_GENERIC_CLIENT_SECRET"); issuer != "" && clientID != "" && clientSecret != "" {
		p, err := newGenericProvider(ctx, issuer, clientID, clientSecret)
		if err != nil {
			errs = append(errs, fmt.Sprintf("generic: %v", err))
			log.Printf("[OAUTH] generic provider disabled: %v", err)
		} else {
			providers["generic"] = p
		}
	}

	if clientID, clientSecret := os.Getenv("OAUTH_GOOGLE_CLIENT_ID"), os.Getenv("OAUTH_GOOGLE_CLIENT_SECRET"); clientID != "" && clientSecret != "" {
		p, err := newGoogleProvider(ctx, clientID, clientSecret)
		if err != nil {
			errs = append(errs, fmt.Sprintf("google: %v", err))
			log.Printf("[OAUTH] google provider disabled: %v", err)
		} else {
			providers["google"] = p
		}
	}

	if clientID, clientSecret := os.Getenv("OAUTH_APPLE_CLIENT_ID"), os.Getenv("OAUTH_APPLE_CLIENT_SECRET"); clientID != "" && clientSecret != "" {
		p, err := newAppleProvider(ctx, clientID, clientSecret)
		if err != nil {
			errs = append(errs, fmt.Sprintf("apple: %v", err))
			log.Printf("[OAUTH] apple provider disabled: %v", err)
		} else {
			providers["apple"] = p
		}
	}

	if appID, appSecret := os.Getenv("OAUTH_FACEBOOK_APP_ID"), os.Getenv("OAUTH_FACEBOOK_APP_SECRET"); appID != "" && appSecret != "" {
		providers["facebook"] = newFacebookProvider(appID, appSecret)
	}

	if len(providers) > 0 {
		names := make([]string, 0, len(providers))
		for n := range providers {
			names = append(names, n)
		}
		sort.Strings(names)
		log.Printf("[OAUTH] enabled providers: %s", strings.Join(names, ", "))
	}

	if len(errs) > 0 {
		return fmt.Errorf("some OAuth providers failed to initialize: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Enabled returns every successfully-initialized provider, in a stable
// order (generic, google, apple, facebook).
func Enabled() []Provider {
	mu.RLock()
	defer mu.RUnlock()
	result := make([]Provider, 0, len(providers))
	for _, name := range providerOrder {
		if p, ok := providers[name]; ok {
			result = append(result, p)
		}
	}
	return result
}

// Get looks up an enabled provider by name.
func Get(name string) (Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[name]
	return p, ok
}

// AnyEnabled reports whether at least one OAuth provider is ready.
func AnyEnabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return len(providers) > 0
}

// PasswordAuthAllowed reports whether the password login form/endpoint
// should remain active. DISABLE_PASSWORD_AUTH only takes effect once at
// least one OAuth provider is actually enabled, so a misconfigured
// deployment can't lock every user out.
func PasswordAuthAllowed() bool {
	if !strings.EqualFold(os.Getenv("DISABLE_PASSWORD_AUTH"), "true") {
		return true
	}
	if !AnyEnabled() {
		log.Println("[OAUTH] DISABLE_PASSWORD_AUTH is set but no OAuth provider is ready; falling back to password auth")
		return true
	}
	return false
}

// RedirectURIFor builds the callback URL to use for the given provider.
// OAUTH_REDIRECT_BASE_URL (recommended in production) takes precedence;
// otherwise it's derived from the incoming request, trusting
// X-Forwarded-Proto/Host the same way handlers.isSecureConnection does.
func RedirectURIFor(c *fiber.Ctx, providerName string) string {
	base := os.Getenv("OAUTH_REDIRECT_BASE_URL")
	if base == "" {
		scheme := "http"
		if c.Get("X-Forwarded-Proto") == "https" || c.Protocol() == "https" {
			scheme = "https"
		}
		base = scheme + "://" + c.Hostname()
	}
	base = strings.TrimSuffix(base, "/")
	return base + "/auth/" + providerName + "/callback"
}
