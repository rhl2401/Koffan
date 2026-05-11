package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"shopping-list/db"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

const oauthStateCookie = "oauth_state"

type oauthProvider struct {
	Name         string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	ClientID     string
	ClientSecret string
	Scopes       []string
}

func getProviders() map[string]oauthProvider {
	providers := map[string]oauthProvider{}

	if id := os.Getenv("GOOGLE_CLIENT_ID"); id != "" {
		providers["google"] = oauthProvider{
			Name:         "Google",
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			UserInfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
			ClientID:     id,
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			Scopes:       []string{"openid", "email", "profile"},
		}
	}

	if id := os.Getenv("MICROSOFT_CLIENT_ID"); id != "" {
		tenant := os.Getenv("MICROSOFT_TENANT")
		if tenant == "" {
			tenant = "common"
		}
		providers["microsoft"] = oauthProvider{
			Name:         "Microsoft",
			AuthURL:      fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenant),
			TokenURL:     fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenant),
			UserInfoURL:  "https://graph.microsoft.com/v1.0/me",
			ClientID:     id,
			ClientSecret: os.Getenv("MICROSOFT_CLIENT_SECRET"),
			Scopes:       []string{"openid", "email", "profile", "User.Read"},
		}
	}

	if id := os.Getenv("POCKETID_CLIENT_ID"); id != "" {
		base := strings.TrimRight(os.Getenv("POCKETID_URL"), "/")
		providers["pocketid"] = oauthProvider{
			Name:         "PocketID",
			AuthURL:      base + "/authorize",
			TokenURL:     base + "/api/oidc/token",
			UserInfoURL:  base + "/api/oidc/userinfo",
			ClientID:     id,
			ClientSecret: os.Getenv("POCKETID_CLIENT_SECRET"),
			Scopes:       []string{"openid", "email", "profile"},
		}
	}

	return providers
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func redirectURI(c *fiber.Ctx, provider string) string {
	scheme := "http"
	if isSecureConnection(c) {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/auth/%s/callback", scheme, c.Hostname(), provider)
}

// OAuthBegin redirects the user to the OAuth provider.
func OAuthBegin(c *fiber.Ctx) error {
	providerName := c.Params("provider")
	providers := getProviders()
	p, ok := providers[providerName]
	if !ok {
		return c.Status(400).SendString("Unknown OAuth provider")
	}

	state := generateState()
	c.Cookie(&fiber.Cookie{
		Name:     oauthStateCookie,
		Value:    state,
		Expires:  time.Now().Add(10 * time.Minute),
		HTTPOnly: true,
		Secure:   isSecureConnection(c),
		SameSite: "Lax",
		Path:     "/",
	})

	params := url.Values{
		"client_id":     {p.ClientID},
		"redirect_uri":  {redirectURI(c, providerName)},
		"response_type": {"code"},
		"scope":         {strings.Join(p.Scopes, " ")},
		"state":         {state},
	}
	return c.Redirect(p.AuthURL + "?" + params.Encode())
}

// OAuthCallback handles the OAuth provider callback.
func OAuthCallback(c *fiber.Ctx) error {
	providerName := c.Params("provider")
	providers := getProviders()
	p, ok := providers[providerName]
	if !ok {
		return c.Status(400).SendString("Unknown OAuth provider")
	}

	// Validate state
	storedState := c.Cookies(oauthStateCookie)
	if storedState == "" || storedState != c.Query("state") {
		return c.Redirect("/login?error=oauth_state")
	}
	// Clear state cookie
	c.Cookie(&fiber.Cookie{
		Name:    oauthStateCookie,
		Value:   "",
		Expires: time.Now().Add(-time.Hour),
		Path:    "/",
	})

	code := c.Query("code")
	if code == "" {
		return c.Redirect("/login?error=oauth_no_code")
	}

	// Exchange code for access token
	accessToken, err := exchangeCode(p, code, redirectURI(c, providerName))
	if err != nil {
		log.Printf("[OAUTH] Token exchange failed for %s: %v", providerName, err)
		return c.Redirect("/login?error=oauth_token")
	}

	// Fetch user info
	info, err := fetchUserInfo(p, accessToken)
	if err != nil {
		log.Printf("[OAUTH] UserInfo failed for %s: %v", providerName, err)
		return c.Redirect("/login?error=oauth_userinfo")
	}

	// Find or create user
	user, err := db.GetOrCreateUser(providerName, info.ID, info.Email, info.Name, info.Picture)
	if err != nil {
		log.Printf("[OAUTH] GetOrCreateUser failed: %v", err)
		return c.Redirect("/login?error=oauth_user")
	}

	// Auto-add to Shared group (for legacy lists)
	db.AddAllUsersToSharedGroup()

	// Accept any pending invites
	if invites, err := db.GetPendingInvitesForEmail(user.Email); err == nil {
		for _, inv := range invites {
			db.AcceptGroupInvite(inv.ID, user.ID)
		}
	}

	// Create session
	sessionID := generateSessionID()
	expiresAt := time.Now().Add(SessionDuration).Unix()
	if err := db.CreateSession(sessionID, expiresAt, user.ID); err != nil {
		return c.Redirect("/login?error=session")
	}

	c.Cookie(&fiber.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Expires:  time.Now().Add(SessionDuration),
		HTTPOnly: true,
		Secure:   isSecureConnection(c),
		SameSite: "Lax",
		Path:     "/",
	})

	log.Printf("[OAUTH] User %s (%s) logged in via %s", user.Name, user.Email, providerName)
	return c.Redirect("/")
}

type tokenResp struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

func exchangeCode(p oauthProvider, code, redirectURI string) (string, error) {
	vals := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
	}
	resp, err := http.PostForm(p.TokenURL, vals)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var t tokenResp
	if err := json.Unmarshal(body, &t); err != nil {
		return "", err
	}
	if t.Error != "" {
		return "", fmt.Errorf("token endpoint error: %s", t.Error)
	}
	if t.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}
	return t.AccessToken, nil
}

type userInfoResult struct {
	ID      string
	Email   string
	Name    string
	Picture string
}

func fetchUserInfo(p oauthProvider, accessToken string) (*userInfoResult, error) {
	req, err := http.NewRequest("GET", p.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	info := &userInfoResult{}

	// Provider-specific field mapping
	switch p.Name {
	case "Microsoft":
		info.ID = str(raw["id"])
		info.Email = str(raw["mail"])
		if info.Email == "" {
			info.Email = str(raw["userPrincipalName"])
		}
		info.Name = str(raw["displayName"])
	default:
		// Google and PocketID follow standard OIDC
		info.ID = str(raw["sub"])
		info.Email = str(raw["email"])
		info.Name = str(raw["name"])
		info.Picture = str(raw["picture"])
	}

	if info.ID == "" {
		return nil, fmt.Errorf("could not determine user ID from provider response")
	}
	if info.Name == "" {
		info.Name = info.Email
	}

	return info, nil
}

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}
