package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"shopping-list/db"
	"shopping-list/i18n"
	"time"

	"github.com/gofiber/fiber/v2"
)

// GetCurrentUser retrieves the authenticated user from Fiber locals.
func GetCurrentUser(c *fiber.Ctx) (db.User, bool) {
	user, ok := c.Locals("user").(db.User)
	return user, ok
}

// GetCurrentUserID returns the current user's ID (0 if not authenticated or auth disabled).
func GetCurrentUserID(c *fiber.Ctx) int64 {
	user, ok := GetCurrentUser(c)
	if !ok {
		return 0
	}
	return user.ID
}

const (
	SessionCookieName = "session"
	SessionDuration   = 7 * 24 * time.Hour // 7 days
)

func getAppPassword() string {
	pass := os.Getenv("APP_PASSWORD")
	if pass == "" {
		pass = "shopping123" // Default password for development
	}
	return pass
}

func isAuthDisabled() bool {
	return os.Getenv("DISABLE_AUTH") == "true"
}

// isSecureConnection checks if the request came over HTTPS
// Works both directly and behind reverse proxies
func isSecureConnection(c *fiber.Ctx) bool {
	// Check X-Forwarded-Proto header (set by reverse proxies)
	if c.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	// Check direct connection protocol
	return c.Protocol() == "https"
}

func generateSessionID() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatal("Failed to generate secure random bytes:", err)
	}
	return hex.EncodeToString(bytes)
}

// LoginPage renders the login page
func LoginPage(c *fiber.Ctx) error {
	// Check if already logged in
	sessionID := c.Cookies(SessionCookieName)
	if sessionID != "" {
		session, err := db.GetSession(sessionID)
		if err == nil && session.ExpiresAt > time.Now().Unix() {
			return c.Redirect("/")
		}
	}
	return c.Render("login", fiber.Map{
		"Error":            c.Query("error"),
		"Translations":     i18n.GetAllLocales(),
		"Locales":          i18n.AvailableLocales(),
		"DefaultLang":      i18n.GetDefaultLang(),
		"GoogleEnabled":    os.Getenv("GOOGLE_CLIENT_ID") != "",
		"MicrosoftEnabled": os.Getenv("MICROSOFT_CLIENT_ID") != "",
		"PocketIDEnabled":  os.Getenv("POCKETID_CLIENT_ID") != "",
	}, "")
}

// Login handles login form submission
func Login(c *fiber.Ctx) error {
	ip := c.IP()
	password := c.FormValue("password")

	if password != getAppPassword() {
		// Record failed attempt
		if loginLimiter != nil {
			if loginLimiter.RecordAttempt(ip) {
				return c.Redirect("/login?error=rate_limited")
			}
		}
		return c.Redirect("/login?error=1")
	}

	// Successful login - reset attempts
	if loginLimiter != nil {
		loginLimiter.ResetAttempts(ip)
	}

	// Find or create the local admin user
	localUser, err := db.GetOrCreateLocalUser()
	if err != nil {
		log.Printf("[AUTH] Failed to get/create local user: %v", err)
		return sendError(c, 500, "error.session_failed")
	}

	// Add local user to Shared group so they see legacy lists
	db.AddAllUsersToSharedGroup()

	// Accept any pending invites for local admin (by email)
	if invites, err := db.GetPendingInvitesForEmail(localUser.Email); err == nil {
		for _, inv := range invites {
			db.AcceptGroupInvite(inv.ID, localUser.ID)
		}
	}

	// Create session
	sessionID := generateSessionID()
	expiresAt := time.Now().Add(SessionDuration).Unix()

	err = db.CreateSession(sessionID, expiresAt, localUser.ID)
	if err != nil {
		return sendError(c, 500, "error.session_failed")
	}
	log.Printf("[AUTH] New session created: %s... (expires: %d)", sessionID[:8], expiresAt)

	// Set cookie
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

// Logout handles logout
func Logout(c *fiber.Ctx) error {
	sessionID := c.Cookies(SessionCookieName)
	if sessionID != "" {
		db.DeleteSession(sessionID)
	}

	// Clear cookie
	c.Cookie(&fiber.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   isSecureConnection(c),
		SameSite: "Lax",
		Path:     "/",
	})

	return c.Redirect("/login")
}

// AuthMiddleware checks if user is authenticated
func AuthMiddleware(c *fiber.Ctx) error {
	if isAuthDisabled() {
		return c.Next()
	}

	// Skip auth for login page and static files
	path := c.Path()
	if path == "/login" || path == "/static" || len(path) > 7 && path[:8] == "/static/" {
		return c.Next()
	}

	sessionID := c.Cookies(SessionCookieName)
	if sessionID == "" {
		log.Printf("[AUTH] No session cookie for %s %s (HX-Request: %s)", c.Method(), path, c.Get("HX-Request"))
		if c.Get("HX-Request") == "true" {
			c.Set("HX-Redirect", "/login")
			return c.SendStatus(401)
		}
		return c.Redirect("/login")
	}

	session, err := db.GetSession(sessionID)
	if err != nil {
		// Check if it's a "not found" error vs database error
		if err.Error() == "sql: no rows in result set" {
			log.Printf("[AUTH] Session not found in DB for %s %s (sessionID: %s...)", c.Method(), path, sessionID[:8])
			// Only delete if session truly doesn't exist
			db.DeleteSession(sessionID)
		} else {
			// Database error (e.g., locked) - don't delete session, just log and retry
			log.Printf("[AUTH] Database error for %s %s: %v", c.Method(), path, err)
			// Return 503 Service Unavailable for temporary DB issues
			return sendError(c, 503, "error.database_unavailable")
		}
		c.Cookie(&fiber.Cookie{
			Name:     SessionCookieName,
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			Secure:   isSecureConnection(c),
			SameSite: "Lax",
			Path:     "/",
		})
		if c.Get("HX-Request") == "true" {
			c.Set("HX-Redirect", "/login")
			return c.SendStatus(401)
		}
		return c.Redirect("/login")
	}

	if session.ExpiresAt < time.Now().Unix() {
		log.Printf("[AUTH] Session expired for %s %s (expired: %d, now: %d)", c.Method(), path, session.ExpiresAt, time.Now().Unix())
		db.DeleteSession(sessionID)
		c.Cookie(&fiber.Cookie{
			Name:     SessionCookieName,
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			Secure:   isSecureConnection(c),
			SameSite: "Lax",
			Path:     "/",
		})
		if c.Get("HX-Request") == "true" {
			c.Set("HX-Redirect", "/login")
			return c.SendStatus(401)
		}
		return c.Redirect("/login")
	}

	// Load user from session and store in locals
	if session.UserID > 0 {
		if user, err := db.GetUserByID(session.UserID); err == nil {
			c.Locals("user", *user)
		}
	}

	return c.Next()
}
