package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/url"
	"shopping-list/db"
	"shopping-list/oidc"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Single sign-on through an OpenID Connect provider. It only exists together
// with accounts (MULTI_USER=true): a verified identity is mapped to an
// account, which then gets an ordinary session in its workspace.

// The routes carry the provider's name so that more providers can be added
// without changing what operators register at their identity provider.
const (
	OIDCStartPath    = "/auth/:provider/start"
	OIDCCallbackPath = "/auth/:provider/callback"
)

// SSOProvider is what the login page needs for one sign-in button.
type SSOProvider struct {
	Name     string
	Label    string // "" shows the translated default label
	StartURL string
}

// SSOProviders lists the configured providers for the login page.
func SSOProviders() []SSOProvider {
	if !OIDCEnabled() {
		return nil
	}
	var out []SSOProvider
	for _, cfg := range oidc.Configs() {
		out = append(out, SSOProvider{Name: cfg.Name, Label: cfg.ButtonLabel, StartURL: "/auth/" + cfg.Name + "/start"})
	}
	return out
}

// errNoSSOAccount is returned when the identity has no account and accounts
// are not created automatically.
var errNoSSOAccount = errors.New("no account for this identity")

// oidcErrors are the codes the login page has a message for.
var oidcErrors = map[string]bool{
	"oidc_failed": true, "oidc_state": true, "oidc_unavailable": true, "oidc_no_account": true,
}

// OIDCEnabled reports whether single sign-on is configured and usable, which
// needs accounts.
func OIDCEnabled() bool {
	return MultiUser() && oidc.Configured()
}

// PasswordLoginAllowed reports whether the username/password form is offered.
// It can only be switched off while single sign-on is configured, so a
// misconfiguration cannot lock everyone out.
func PasswordLoginAllowed() bool {
	return !OIDCEnabled() || !oidc.PasswordLoginDisabled()
}

// oidcRedirectURL is the callback registered at the identity provider:
// OIDC_REDIRECT_URL when set, otherwise derived from the request the same way
// the session cookie decides whether it is Secure.
func oidcRedirectURL(c *fiber.Ctx, cfg oidc.Config) string {
	if cfg.RedirectURL != "" {
		return cfg.RedirectURL
	}
	scheme := "http"
	if isSecureConnection(c) {
		scheme = "https"
	}
	host := c.Hostname()
	if forwarded, _, _ := strings.Cut(c.Get(fiber.HeaderXForwardedHost), ","); strings.TrimSpace(forwarded) != "" {
		host = strings.TrimSpace(forwarded)
	}
	return scheme + "://" + host + "/auth/" + cfg.Name + "/callback"
}

func oidcLoginError(c *fiber.Ctx, code string) error {
	return c.Redirect("/login?error=" + url.QueryEscape(code))
}

func setFlowCookie(c *fiber.Ctx, value string, expires time.Time) {
	c.Cookie(&fiber.Cookie{
		Name:     oidc.FlowCookieName,
		Value:    value,
		Expires:  expires,
		HTTPOnly: true,
		Secure:   isSecureConnection(c),
		SameSite: "Lax",
		Path:     "/auth/",
	})
}

// OIDCStart begins a login: it remembers state, nonce and PKCE verifier in a
// short-lived cookie and sends the browser to the identity provider.
func OIDCStart(c *fiber.Ctx) error {
	name := c.Params("provider")
	if _, ok := oidc.Lookup(name); !ok || !OIDCEnabled() {
		return notFound(c)
	}
	provider, err := oidc.Get(c.Context(), name)
	if err != nil {
		log.Printf("[OIDC] %v", err)
		return oidcLoginError(c, "oidc_unavailable")
	}
	flow, err := oidc.NewFlow(name)
	if err != nil {
		log.Printf("[OIDC] cannot start login: %v", err)
		return oidcLoginError(c, "oidc_failed")
	}
	setFlowCookie(c, flow.Encode(), time.Now().Add(oidc.FlowMaxAge))
	return c.Redirect(provider.AuthCodeURL(oidcRedirectURL(c, provider.Config()), flow))
}

// OIDCCallback completes a login: it checks the state against the flow cookie,
// exchanges the code, verifies the id_token and signs the account in.
func OIDCCallback(c *fiber.Ctx) error {
	name := c.Params("provider")
	if _, ok := oidc.Lookup(name); !ok || !OIDCEnabled() {
		return notFound(c)
	}
	cookie := c.Cookies(oidc.FlowCookieName)
	setFlowCookie(c, "", time.Now().Add(-time.Hour))
	flow, err := oidc.DecodeFlow(cookie)
	if err != nil {
		log.Printf("[OIDC] callback without a valid login attempt: %v", err)
		return oidcLoginError(c, "oidc_state")
	}
	if flow.Provider != name {
		log.Printf("[OIDC] callback for %q but the login started at %q", name, flow.Provider)
		return oidcLoginError(c, "oidc_state")
	}
	if subtle.ConstantTimeCompare([]byte(c.Query("state")), []byte(flow.State)) != 1 {
		log.Printf("[OIDC] callback state mismatch")
		return oidcLoginError(c, "oidc_state")
	}
	if problem := c.Query("error"); problem != "" {
		log.Printf("[OIDC] the identity provider refused the login: %s %s", problem, c.Query("error_description"))
		return oidcLoginError(c, "oidc_failed")
	}
	code := c.Query("code")
	if code == "" {
		return oidcLoginError(c, "oidc_failed")
	}
	provider, err := oidc.Get(c.Context(), name)
	if err != nil {
		log.Printf("[OIDC] %v", err)
		return oidcLoginError(c, "oidc_unavailable")
	}
	identity, err := provider.Exchange(c.Context(), code, oidcRedirectURL(c, provider.Config()), flow)
	if err != nil {
		log.Printf("[OIDC] %v", err)
		return oidcLoginError(c, "oidc_failed")
	}

	user, err := resolveSSOUser(provider.Config(), identity)
	if err != nil {
		if errors.Is(err, errNoSSOAccount) {
			log.Printf("[OIDC] no account for subject %q (username %q) and OIDC_AUTO_CREATE_USERS=false", identity.Subject, identity.Username)
			return oidcLoginError(c, "oidc_no_account")
		}
		log.Printf("[OIDC] cannot map identity %q to an account: %v", identity.Subject, err)
		return oidcLoginError(c, "oidc_failed")
	}

	sessionID := generateSessionID()
	expiresAt := time.Now().Add(SessionDuration).Unix()
	workspaceID, _ := db.ResolveSessionWorkspace(user.ID, 0)
	if err := db.CreateUserSession(sessionID, expiresAt, user.ID, workspaceID); err != nil {
		return sendError(c, 500, "error.session_failed")
	}
	log.Printf("[AUTH] New session created by single sign-on for %q: %s... (expires: %d)", user.Username, sessionIDPrefix(sessionID), expiresAt)
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

// resolveSSOUser finds the account for a verified identity:
//  1. the account this subject signed in with before;
//  2. otherwise the account whose username matches the username claim (or
//     the e-mail address), which links an account an administrator created
//     ahead of time, or an existing password account, to its identity;
//  3. otherwise a new account, unless OIDC_AUTO_CREATE_USERS=false.
//
// On every login the display name follows the provider and, when
// OIDC_ADMIN_GROUP is set, so does the administrator flag.
func resolveSSOUser(cfg oidc.Config, identity *oidc.Identity) (*db.User, error) {
	user, err := db.UserByOIDCIdentity(identity.Issuer, identity.Subject)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if user == nil {
		for _, candidate := range ssoUsernameCandidates(identity) {
			existing, err := db.GetUserByUsername(candidate)
			if err == nil {
				user = existing
				break
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
		}
		if user != nil {
			if err := db.LinkOIDCIdentity(user.ID, identity.Issuer, identity.Subject); err != nil {
				return nil, err
			}
			log.Printf("[OIDC] linked account %q to subject %q", user.Username, identity.Subject)
		}
	}
	if user == nil {
		if !cfg.AutoCreateUsers {
			return nil, errNoSSOAccount
		}
		user, err = createSSOUser(cfg, identity)
		if err != nil {
			return nil, err
		}
		return user, nil
	}
	syncSSOProfile(cfg, identity, user)
	return user, nil
}

// ssoUsernameCandidates lists, in order of preference, the usernames an
// identity could have: the configured claim, then the e-mail address.
func ssoUsernameCandidates(identity *oidc.Identity) []string {
	var out []string
	for _, candidate := range []string{identity.Username, identity.Email} {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" && len(candidate) <= MaxUsernameLength && ValidUsername(candidate) {
			out = append(out, candidate)
		}
	}
	return out
}

// createSSOUser makes the account for a first login. When neither the username
// claim nor the e-mail is usable, or the name is taken by an account that is
// linked to another subject, a name derived from the subject is used.
func createSSOUser(cfg oidc.Config, identity *oidc.Identity) (*db.User, error) {
	displayName := cleanDisplayName(identity.Name)
	if len(displayName) > MaxDisplayNameLength {
		displayName = displayName[:MaxDisplayNameLength]
	}
	isAdmin := cfg.AdminGroup != "" && identity.InGroup(cfg.AdminGroup)
	candidates := append(ssoUsernameCandidates(identity), ssoFallbackUsername(identity))
	var user *db.User
	for _, candidate := range candidates {
		created, err := db.CreateSSOUser(candidate, displayName, isAdmin)
		if err == nil {
			user = created
			break
		}
		if !errors.Is(err, db.ErrUserExists) {
			return nil, err
		}
	}
	if user == nil {
		return nil, db.ErrUserExists
	}
	if err := db.LinkOIDCIdentity(user.ID, identity.Issuer, identity.Subject); err != nil {
		return nil, err
	}
	if cfg.DefaultWorkspaceID > 0 {
		if _, err := db.GetWorkspace(cfg.DefaultWorkspaceID); err == nil {
			db.AddMember(cfg.DefaultWorkspaceID, user.ID, db.RoleMember)
		} else {
			log.Printf("[OIDC] OIDC_DEFAULT_WORKSPACE_ID=%d: that workspace does not exist; %q starts without a workspace", cfg.DefaultWorkspaceID, user.Username)
		}
	}
	log.Printf("[OIDC] created account %q for subject %q (administrator: %t)", user.Username, identity.Subject, isAdmin)
	return user, nil
}

// ssoFallbackUsername is stable for a subject and never collides with a name
// someone could type by accident.
func ssoFallbackUsername(identity *oidc.Identity) string {
	sum := sha256.Sum256([]byte(identity.Issuer + "\x00" + identity.Subject))
	return "sso-" + hex.EncodeToString(sum[:])[:12]
}

// syncSSOProfile copies the display name from the provider and, with
// OIDC_ADMIN_GROUP, the administrator flag. The last administrator is never
// demoted, so a group mistake at the provider cannot leave Koffan unmanaged.
func syncSSOProfile(cfg oidc.Config, identity *oidc.Identity, user *db.User) {
	if name := cleanDisplayName(identity.Name); name != "" && name != user.DisplayName && len(name) <= MaxDisplayNameLength {
		if err := db.UpdateDisplayName(user.ID, name); err == nil {
			user.DisplayName = name
		}
	}
	if cfg.AdminGroup == "" {
		return
	}
	want := identity.InGroup(cfg.AdminGroup)
	if want == user.IsAdmin {
		return
	}
	changed, err := db.SetAdmin(user.ID, want)
	switch {
	case err != nil:
		log.Printf("[OIDC] cannot update administrator flag of %q: %v", user.Username, err)
	case !changed:
		log.Printf("[OIDC] %q left group %q but stays an administrator: it is the last one", user.Username, cfg.AdminGroup)
	default:
		user.IsAdmin = want
		log.Printf("[OIDC] %q is now administrator=%t (group %q)", user.Username, want, cfg.AdminGroup)
	}
}
