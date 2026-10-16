package handlers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"shopping-list/db"
	"shopping-list/oidc"

	"github.com/gofiber/fiber/v2"
)

// fakeIDP is a small OpenID Connect provider: discovery, JWKS, the token
// endpoint (with PKCE and client authentication checks) and UserInfo. Tests
// decide what it says about the person who signs in.
type fakeIDP struct {
	srv          *httptest.Server
	key          *rsa.PrivateKey
	clientID     string
	clientSecret string

	mu       sync.Mutex
	subject  string
	claims   map[string]interface{} // extra id_token claims
	userInfo map[string]interface{} // extra UserInfo claims
	codes    map[string]pendingLogin
	tokens   int
}

type pendingLogin struct {
	nonce, challenge, method, redirectURI string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{key: key, clientID: "koffan", clientSecret: "s3cret", subject: "sub-1", codes: map[string]pendingLogin{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	issuer := f.srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"userinfo_endpoint":                     issuer + "/userinfo",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		pub := key.PublicKey
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "test",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id != f.clientID || secret != f.clientSecret {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		pending, found := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case r.PostForm.Get("grant_type") != "authorization_code" || !found:
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		case pending.redirectURI != r.PostForm.Get("redirect_uri"):
			http.Error(w, `{"error":"invalid_grant","error_description":"redirect_uri"}`, http.StatusBadRequest)
			return
		case pending.method != "S256" || base64.RawURLEncoding.EncodeToString(sum[:]) != pending.challenge:
			http.Error(w, `{"error":"invalid_grant","error_description":"pkce"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.tokens++
		claims := map[string]interface{}{
			"iss": issuer, "sub": f.subject, "aud": f.clientID, "nonce": pending.nonce,
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		}
		for k, v := range f.claims {
			claims[k] = v
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "access-token", "token_type": "Bearer", "expires_in": 3600, "id_token": f.sign(claims),
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		info := map[string]interface{}{"sub": f.subject}
		for k, v := range f.userInfo {
			info[k] = v
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})
	return f
}

// sign makes an RS256 JWT.
func (f *fakeIDP) sign(claims map[string]interface{}) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// authorize plays the person signing in at the provider: it checks the
// authorization request Koffan sent and hands back a code and the state.
func (f *fakeIDP) authorize(t *testing.T, location, wantRedirectURI string) (code, state string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, f.srv.URL+"/authorize?") {
		t.Fatalf("not sent to the provider: %q", location)
	}
	q := u.Query()
	if q.Get("client_id") != f.clientID || q.Get("response_type") != "code" || !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("bad authorization request: %s", q.Encode())
	}
	if q.Get("redirect_uri") != wantRedirectURI {
		t.Fatalf("redirect_uri = %q, want %q", q.Get("redirect_uri"), wantRedirectURI)
	}
	if q.Get("nonce") == "" || q.Get("code_challenge") == "" || q.Get("state") == "" {
		t.Fatalf("missing nonce, PKCE challenge or state: %s", q.Encode())
	}
	raw := make([]byte, 16)
	rand.Read(raw)
	code = hex.EncodeToString(raw)
	f.mu.Lock()
	f.codes[code] = pendingLogin{q.Get("nonce"), q.Get("code_challenge"), q.Get("code_challenge_method"), q.Get("redirect_uri")}
	f.mu.Unlock()
	return code, q.Get("state")
}

func (f *fakeIDP) set(subject string, claims, userInfo map[string]interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subject, f.claims, f.userInfo = subject, claims, userInfo
}

const testRedirectURI = "http://koffan.test/auth/oidc/callback"

// ssoEnv configures single sign-on against the fake provider.
func ssoEnv(t *testing.T, idp *fakeIDP) {
	t.Helper()
	t.Setenv("MULTI_USER", "true")
	t.Setenv(oidc.EnvIssuerURL, idp.srv.URL)
	t.Setenv(oidc.EnvClientID, idp.clientID)
	t.Setenv(oidc.EnvClientSecret, idp.clientSecret)
	t.Setenv(oidc.EnvRedirectURL, testRedirectURI)
	for _, name := range []string{oidc.EnvAutoCreateUsers, oidc.EnvAdminGroup, oidc.EnvDefaultWorkspaceID, oidc.EnvDisablePasswordLogin, oidc.EnvUsernameClaim} {
		t.Setenv(name, "")
	}
	oidc.Reset()
	t.Cleanup(oidc.Reset)
}

func ssoApp() *fiber.App {
	app := fiber.New()
	app.Post("/login", Login)
	app.Get(OIDCStartPath, OIDCStart)
	app.Get(OIDCCallbackPath, OIDCCallback)
	app.Use(AuthMiddleware)
	RegisterRoutes(app)
	return app
}

func cookieValue(header http.Header, name string) string {
	for _, c := range header.Values("Set-Cookie") {
		if strings.HasPrefix(c, name+"=") {
			return strings.TrimPrefix(strings.SplitN(c, ";", 2)[0], name+"=")
		}
	}
	return ""
}

// ssoLogin walks through a whole login: start, provider, callback.
func ssoLogin(t *testing.T, app *fiber.App, idp *fakeIDP) authResult {
	t.Helper()
	start := authDo(t, app, "", "GET", "/auth/oidc/start", nil, nil)
	if start.status != http.StatusFound {
		t.Fatalf("start: %d %q %s", start.status, start.location, start.body)
	}
	flow := cookieValue(start.header, oidc.FlowCookieName)
	if flow == "" || !strings.Contains(strings.Join(start.header.Values("Set-Cookie"), "\n"), "HttpOnly") {
		t.Fatalf("flow cookie missing or not HttpOnly: %v", start.header.Values("Set-Cookie"))
	}
	code, state := idp.authorize(t, start.location, testRedirectURI)
	return authDo(t, app, "", "GET", "/auth/oidc/callback?code="+code+"&state="+state, nil,
		map[string]string{"Cookie": oidc.FlowCookieName + "=" + flow})
}

func sessionUser(t *testing.T, result authResult) *db.Session {
	t.Helper()
	if result.status != http.StatusFound || result.location != "/" {
		t.Fatalf("callback: %d %q %s", result.status, result.location, result.body)
	}
	sessionID := cookieValue(result.header, SessionCookieName)
	session, err := db.GetSession(sessionID)
	if err != nil {
		t.Fatalf("session %q: %v", sessionID, err)
	}
	return session
}

func bootstrapAdmin(t *testing.T) {
	t.Helper()
	if err := db.EnsureBootstrapAdmin("admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
}

func TestSSOCreatesAnAccountAndRecognisesItAgain(t *testing.T) {
	idp := newFakeIDP(t)
	ssoEnv(t, idp)
	initTestDatabase(t)
	bootstrapAdmin(t)
	app := ssoApp()

	idp.set("sub-alice", map[string]interface{}{"preferred_username": "alice", "name": "Alice", "email": "alice@example.com"}, nil)
	session := sessionUser(t, ssoLogin(t, app, idp))
	alice, err := db.GetUserByUsername("alice")
	if err != nil || session.UserID != alice.ID || alice.IsAdmin || alice.DisplayName != "Alice" {
		t.Fatalf("session %#v, alice %#v (%v)", session, alice, err)
	}
	if db.HasPassword(alice.ID) {
		t.Fatal("an account created by single sign-on must not have a password")
	}
	if session.WorkspaceID != 0 {
		t.Fatalf("workspace = %d, want none until an administrator adds them", session.WorkspaceID)
	}
	if !db.OIDCLinkedUsers()[alice.ID] {
		t.Fatal("alice is not listed as linked")
	}

	// The same subject with a new username and name is still Alice.
	idp.set("sub-alice", map[string]interface{}{"preferred_username": "alice.renamed", "name": "Alice Renamed"}, nil)
	again := sessionUser(t, ssoLogin(t, app, idp))
	if again.UserID != alice.ID || db.CountUsers() != 2 {
		t.Fatalf("second login: user %d (want %d), %d accounts", again.UserID, alice.ID, db.CountUsers())
	}
	if u, _ := db.GetUserByID(alice.ID); u.DisplayName != "Alice Renamed" || u.Username != "alice" {
		t.Fatalf("after rename: %#v", u)
	}

	// The signed-in account reaches the app like any other session.
	page := authDo(t, app, again.ID, "GET", "/workspaces", nil, nil)
	if page.status == http.StatusFound && page.location == "/login" {
		t.Fatal("the single sign-on session was not accepted")
	}
}

func TestSSOLinksAnExistingAccountByUsernameOrEmail(t *testing.T) {
	idp := newFakeIDP(t)
	ssoEnv(t, idp)
	initTestDatabase(t)
	bootstrapAdmin(t)
	bob, err := db.CreateUser("bob", "Bob", "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	app := ssoApp()

	idp.set("sub-bob", map[string]interface{}{"preferred_username": "BOB", "name": "Bob"}, nil)
	session := sessionUser(t, ssoLogin(t, app, idp))
	if session.UserID != bob.ID || db.CountUsers() != 2 || !db.HasPassword(bob.ID) {
		t.Fatalf("bob was not linked: session %#v, %d accounts", session, db.CountUsers())
	}

	// Without a username claim the e-mail address is the username.
	mail, err := db.CreateUser("carol@example.com", "Carol", "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	idp.set("sub-carol", map[string]interface{}{"email": "carol@example.com"}, nil)
	if s := sessionUser(t, ssoLogin(t, app, idp)); s.UserID != mail.ID {
		t.Fatalf("carol was not linked by e-mail: %#v", s)
	}

	// An unusable username falls back to a name derived from the subject.
	idp.set("sub-odd", map[string]interface{}{"preferred_username": "has spaces, and commas", "name": "Odd"}, nil)
	s := sessionUser(t, ssoLogin(t, app, idp))
	odd, _ := db.GetUserByID(s.UserID)
	if odd == nil || !strings.HasPrefix(odd.Username, "sso-") || odd.DisplayName != "Odd" {
		t.Fatalf("odd = %#v", odd)
	}
}

func TestSSOTakesMissingClaimsFromUserInfo(t *testing.T) {
	idp := newFakeIDP(t)
	ssoEnv(t, idp)
	initTestDatabase(t)
	bootstrapAdmin(t)
	app := ssoApp()

	idp.set("sub-dave", nil, map[string]interface{}{"preferred_username": "dave", "name": "Dave"})
	session := sessionUser(t, ssoLogin(t, app, idp))
	dave, err := db.GetUserByUsername("dave")
	if err != nil || dave.ID != session.UserID || dave.DisplayName != "Dave" {
		t.Fatalf("dave = %#v (%v), session %#v", dave, err, session)
	}
}

func TestSSOWithoutAutoCreateOnlyAdmitsKnownAccounts(t *testing.T) {
	idp := newFakeIDP(t)
	ssoEnv(t, idp)
	t.Setenv(oidc.EnvAutoCreateUsers, "false")
	initTestDatabase(t)
	bootstrapAdmin(t)
	app := ssoApp()

	idp.set("sub-eve", map[string]interface{}{"preferred_username": "eve"}, nil)
	refused := ssoLogin(t, app, idp)
	if refused.location != "/login?error=oidc_no_account" || cookieValue(refused.header, SessionCookieName) != "" || db.CountUsers() != 1 {
		t.Fatalf("eve got in: %d %q, %d accounts", refused.status, refused.location, db.CountUsers())
	}

	// An account the administrator created ahead of time is linked and admitted.
	eve, _ := db.CreateUser("eve", "Eve", "correct horse battery", false)
	if s := sessionUser(t, ssoLogin(t, app, idp)); s.UserID != eve.ID {
		t.Fatalf("eve not linked: %#v", s)
	}
}

func TestSSOAdminGroupAndDefaultWorkspace(t *testing.T) {
	idp := newFakeIDP(t)
	ssoEnv(t, idp)
	t.Setenv(oidc.EnvAdminGroup, "koffan-admins")
	t.Setenv(oidc.EnvDefaultWorkspaceID, "1")
	initTestDatabase(t)
	bootstrapAdmin(t)
	app := ssoApp()

	idp.set("sub-frank", map[string]interface{}{"preferred_username": "frank", "groups": []string{"family", "koffan-admins"}}, nil)
	session := sessionUser(t, ssoLogin(t, app, idp))
	frank, _ := db.GetUserByID(session.UserID)
	if !frank.IsAdmin || session.WorkspaceID != db.DefaultWorkspaceID || db.MemberRole(db.DefaultWorkspaceID, frank.ID) != db.RoleMember {
		t.Fatalf("frank = %#v, session %#v", frank, session)
	}

	// Leaving the group takes the flag away again...
	idp.set("sub-frank", map[string]interface{}{"preferred_username": "frank", "groups": []string{"family"}}, nil)
	sessionUser(t, ssoLogin(t, app, idp))
	if frank, _ = db.GetUserByID(frank.ID); frank.IsAdmin {
		t.Fatal("frank is still an administrator")
	}
	// ...except for the last administrator.
	idp.set("sub-admin", map[string]interface{}{"preferred_username": "admin", "groups": []string{}}, nil)
	sessionUser(t, ssoLogin(t, app, idp))
	if admin, _ := db.GetUserByUsername("admin"); !admin.IsAdmin {
		t.Fatal("the last administrator was demoted")
	}
}

func TestSSORejectsTamperedCallbacks(t *testing.T) {
	idp := newFakeIDP(t)
	ssoEnv(t, idp)
	initTestDatabase(t)
	bootstrapAdmin(t)
	app := ssoApp()

	start := authDo(t, app, "", "GET", "/auth/oidc/start", nil, nil)
	flow := cookieValue(start.header, oidc.FlowCookieName)
	code, state := idp.authorize(t, start.location, testRedirectURI)
	cookie := map[string]string{"Cookie": oidc.FlowCookieName + "=" + flow}

	cases := map[string]authResult{
		"wrong state":  authDo(t, app, "", "GET", "/auth/oidc/callback?code="+code+"&state=other", nil, cookie),
		"no cookie":    authDo(t, app, "", "GET", "/auth/oidc/callback?code="+code+"&state="+state, nil, nil),
		"other cookie": authDo(t, app, "", "GET", "/auth/oidc/callback?code="+code+"&state="+state, nil, map[string]string{"Cookie": oidc.FlowCookieName + "=garbage"}),
	}
	for name, result := range cases {
		if result.location != "/login?error=oidc_state" || cookieValue(result.header, SessionCookieName) != "" {
			t.Errorf("%s: %d %q", name, result.status, result.location)
		}
	}
	denied := authDo(t, app, "", "GET", "/auth/oidc/callback?error=access_denied&state="+state, nil, cookie)
	if denied.location != "/login?error=oidc_failed" {
		t.Errorf("provider refusal: %d %q", denied.status, denied.location)
	}
	// The code was never exchanged, and a forged code is refused by the provider.
	forged := authDo(t, app, "", "GET", "/auth/oidc/callback?code=forged&state="+state, nil, cookie)
	if forged.location != "/login?error=oidc_failed" || idp.tokens != 0 {
		t.Errorf("forged code: %d %q (tokens issued: %d)", forged.status, forged.location, idp.tokens)
	}
	if unknown := authDo(t, app, "", "GET", "/auth/nope/start", nil, nil); unknown.status != http.StatusNotFound {
		t.Errorf("unknown provider: %d", unknown.status)
	}
}

func TestSSOIsOffWithoutAccountsOrConfiguration(t *testing.T) {
	idp := newFakeIDP(t)
	ssoEnv(t, idp)
	initTestDatabase(t)
	app := ssoApp()

	t.Setenv("MULTI_USER", "false")
	if r := authDo(t, app, "", "GET", "/auth/oidc/start", nil, nil); r.status != http.StatusNotFound || SSOProviders() != nil || OIDCEnabled() {
		t.Fatalf("single sign-on answered without accounts: %d", r.status)
	}
	t.Setenv("MULTI_USER", "true")
	t.Setenv(oidc.EnvClientSecret, "")
	if r := authDo(t, app, "", "GET", "/auth/oidc/start", nil, nil); r.status != http.StatusNotFound || SSOProviders() != nil {
		t.Fatalf("single sign-on answered without a client secret: %d", r.status)
	}
	if !PasswordLoginAllowed() {
		t.Fatal("password login must stay on without single sign-on")
	}
	t.Setenv(oidc.EnvClientSecret, idp.clientSecret)
	providers := SSOProviders()
	if len(providers) != 1 || providers[0].Name != "oidc" || providers[0].StartURL != "/auth/oidc/start" {
		t.Fatalf("providers = %#v", providers)
	}
}

func TestPasswordLoginCanOnlyBeTurnedOffWithSSO(t *testing.T) {
	idp := newFakeIDP(t)
	ssoEnv(t, idp)
	t.Setenv(oidc.EnvDisablePasswordLogin, "true")
	initTestDatabase(t)
	bootstrapAdmin(t)
	app := ssoApp()

	form := url.Values{"username": {"admin"}, "password": {"correct horse battery"}}
	if r := authDo(t, app, "", "POST", "/login", form, nil); r.status != http.StatusForbidden || PasswordLoginAllowed() {
		t.Fatalf("password login accepted: %d %q", r.status, r.location)
	}
	// Without a configured provider the switch is ignored, so nobody is locked out.
	t.Setenv(oidc.EnvIssuerURL, "")
	if r := authDo(t, app, "", "POST", "/login", form, nil); r.status != http.StatusFound || r.location != "/" {
		t.Fatalf("password login refused without single sign-on: %d %q", r.status, r.location)
	}
}

func TestSSORedirectURLIsDerivedFromTheRequest(t *testing.T) {
	idp := newFakeIDP(t)
	ssoEnv(t, idp)
	t.Setenv(oidc.EnvRedirectURL, "")
	initTestDatabase(t)
	bootstrapAdmin(t)
	app := ssoApp()

	start := authDo(t, app, "", "GET", "/auth/oidc/start", nil, map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "lists.example.com"})
	u, _ := url.Parse(start.location)
	if got := u.Query().Get("redirect_uri"); got != "https://lists.example.com/auth/oidc/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
	// Without forwarding headers the request's own host and scheme are used.
	resp, err := app.Test(httptest.NewRequest("GET", "http://koffan.lan:3000/auth/oidc/start", nil), 30_000)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	u, _ = url.Parse(resp.Header.Get("Location"))
	if got := u.Query().Get("redirect_uri"); got != "http://koffan.lan:3000/auth/oidc/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
}
