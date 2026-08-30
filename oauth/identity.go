package oauth

// Identity is the normalized result of a completed OAuth/OIDC exchange,
// regardless of which provider produced it.
type Identity struct {
	Provider      string
	Subject       string // stable, provider-side user id
	Email         string // may be empty if the provider didn't grant/return one
	EmailVerified bool
	Name          string
	Picture       string
}
