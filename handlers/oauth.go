package handlers

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"log"
	"shopping-list/db"
	"shopping-list/oauth"
	"time"

	"github.com/gofiber/fiber/v2"
)

// OAuthStart begins an OAuth/OIDC login attempt: it stores a fresh
// state+nonce pair in a short-lived cookie and redirects the browser to
// the provider's authorization endpoint.
func OAuthStart(c *fiber.Ctx) error {
	providerName := c.Params("provider")
	provider, ok := oauth.Get(providerName)
	if !ok {
		return c.Redirect("/login?error=oauth_unavailable")
	}

	flow, err := oauth.NewFlow(providerName)
	if err != nil {
		log.Printf("[OAUTH] failed to create flow for %s: %v", providerName, err)
		return c.Redirect("/login?error=oauth_failed")
	}

	encoded, err := flow.Encode()
	if err != nil {
		log.Printf("[OAUTH] failed to encode flow for %s: %v", providerName, err)
		return c.Redirect("/login?error=oauth_failed")
	}

	c.Cookie(&fiber.Cookie{
		Name:     oauth.FlowCookieName,
		Value:    encoded,
		Expires:  time.Now().Add(oauth.FlowMaxAge),
		HTTPOnly: true,
		Secure:   isSecureConnection(c),
		SameSite: "Lax",
		Path:     "/auth",
	})

	redirectURI := oauth.RedirectURIFor(c, providerName)
	return c.Redirect(provider.AuthCodeURL(redirectURI, flow.State, flow.Nonce))
}

// OAuthCallback completes an OAuth/OIDC login attempt. It's registered
// for both GET (the common redirect-based callback) and POST (Apple's
// response_mode=form_post).
func OAuthCallback(c *fiber.Ctx) error {
	providerName := c.Params("provider")
	provider, ok := oauth.Get(providerName)
	if !ok {
		return c.Redirect("/login?error=oauth_unavailable")
	}

	cookieVal := c.Cookies(oauth.FlowCookieName)
	clearFlowCookie(c)

	flow, err := oauth.DecodeFlow(cookieVal)
	if err != nil {
		log.Printf("[OAUTH] invalid flow cookie for %s: %v", providerName, err)
		return c.Redirect("/login?error=oauth_state")
	}
	if flow.Provider != providerName {
		log.Printf("[OAUTH] flow/provider mismatch: cookie=%s path=%s", flow.Provider, providerName)
		return c.Redirect("/login?error=oauth_state")
	}

	state := c.Query("state")
	if state == "" {
		state = c.FormValue("state")
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(flow.State)) != 1 {
		log.Printf("[OAUTH] state mismatch for %s", providerName)
		return c.Redirect("/login?error=oauth_state")
	}

	code := c.Query("code")
	if code == "" {
		code = c.FormValue("code")
	}
	if code == "" {
		log.Printf("[OAUTH] callback for %s missing code (provider error: %s)", providerName, c.Query("error"))
		return c.Redirect("/login?error=oauth_failed")
	}

	redirectURI := oauth.RedirectURIFor(c, providerName)
	identity, err := provider.Exchange(c.Context(), code, flow.Nonce, redirectURI)
	if err != nil {
		log.Printf("[OAUTH] exchange failed for %s: %v", providerName, err)
		return c.Redirect("/login?error=oauth_failed")
	}

	user, err := resolveUser(*identity)
	if err != nil {
		log.Printf("[OAUTH] failed to resolve user for %s: %v", providerName, err)
		return sendError(c, 500, "error.session_failed")
	}

	sessionID := generateSessionID()
	expiresAt := time.Now().Add(SessionDuration).Unix()
	if err := db.CreateSessionForUser(sessionID, expiresAt, user.ID); err != nil {
		log.Printf("[OAUTH] failed to create session: %v", err)
		return sendError(c, 500, "error.session_failed")
	}
	log.Printf("[AUTH] New OAuth session created via %s: %s... (user: %d, expires: %d)", providerName, sessionIDPrefix(sessionID), user.ID, expiresAt)

	c.Cookie(&fiber.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Expires:  time.Now().Add(SessionDuration),
		HTTPOnly: true,
		Secure:   isSecureConnection(c),
		SameSite: "Lax",
		Path:     "/",
	})

	return c.Redirect("/")
}

func clearFlowCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     oauth.FlowCookieName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   isSecureConnection(c),
		SameSite: "Lax",
		Path:     "/auth",
	})
}

// resolveUser maps a verified OAuth identity to a local user, creating or
// linking one as needed:
//  1. an existing (provider, subject) identity always resolves to its user.
//  2. otherwise, a non-empty email matching an existing user links this
//     identity to that user (same person, another sign-in method).
//  3. otherwise, a brand new user is created.
//
// In the two "found" cases, the user's profile is best-effort backfilled
// from this identity without ever blanking a previously-known value -
// see db.UpdateUserProfile.
func resolveUser(identity oauth.Identity) (*db.User, error) {
	existing, err := db.FindOAuthIdentity(identity.Provider, identity.Subject)
	if err == nil {
		user, err := db.GetUserByID(existing.UserID)
		if err != nil {
			return nil, err
		}
		if err := db.UpdateUserProfile(user.ID, identity.Name, identity.Picture); err != nil {
			log.Printf("[OAUTH] failed to update profile for user %d: %v", user.ID, err)
		}
		return user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	if identity.Email != "" {
		user, err := db.FindUserByEmail(identity.Email)
		if err == nil {
			if _, err := db.CreateOAuthIdentity(user.ID, identity.Provider, identity.Subject, identity.Email); err != nil {
				return nil, err
			}
			if err := db.UpdateUserProfile(user.ID, identity.Name, identity.Picture); err != nil {
				log.Printf("[OAUTH] failed to update profile for user %d: %v", user.ID, err)
			}
			return user, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}

	user, err := db.CreateUser(identity.Email, identity.Name, identity.Picture)
	if err != nil {
		return nil, err
	}
	if _, err := db.CreateOAuthIdentity(user.ID, identity.Provider, identity.Subject, identity.Email); err != nil {
		return nil, err
	}
	return user, nil
}
