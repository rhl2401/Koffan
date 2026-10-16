package db

import (
	"log"
	"strings"
)

// Single sign-on links an account to the subject the identity provider gives
// it. The link is keyed by issuer and subject: pointing Koffan at another
// identity provider must not silently hand existing accounts to its users.

// migrateOIDC adds the identity links. It is idempotent and only adds
// structure, so an older release keeps working on the same database.
func migrateOIDC() {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS oidc_identities (
			issuer TEXT NOT NULL,
			subject TEXT NOT NULL,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
			PRIMARY KEY (issuer, subject)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_oidc_identities_user ON oidc_identities(user_id)`,
	}
	for _, stmt := range stmts {
		if _, err := DB.Exec(stmt); err != nil {
			log.Fatal("Single sign-on migration failed:", err)
		}
	}
}

// UserByOIDCIdentity returns the account linked to a subject at an issuer, or
// sql.ErrNoRows when no account was linked yet.
func UserByOIDCIdentity(issuer, subject string) (*User, error) {
	var u User
	err := DB.QueryRow(`SELECT u.id, u.username, u.display_name, u.is_admin
		FROM oidc_identities i JOIN users u ON u.id = i.user_id
		WHERE i.issuer = ? AND i.subject = ?`, issuer, subject).
		Scan(&u.ID, &u.Username, &u.DisplayName, &u.IsAdmin)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// LinkOIDCIdentity attaches a subject at an issuer to an account. A subject
// that is already linked to another account is moved, which only happens
// when an administrator deleted and recreated the account in between.
func LinkOIDCIdentity(userID int64, issuer, subject string) error {
	_, err := DB.Exec(`INSERT INTO oidc_identities (issuer, subject, user_id) VALUES (?, ?, ?)
		ON CONFLICT(issuer, subject) DO UPDATE SET user_id = excluded.user_id`, issuer, subject, userID)
	return err
}

// OIDCLinkedUsers returns the ids of every account that has signed in with
// single sign-on, for the accounts list.
func OIDCLinkedUsers() map[int64]bool {
	rows, err := DB.Query(`SELECT DISTINCT user_id FROM oidc_identities`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			out[id] = true
		}
	}
	return out
}

// CreateSSOUser creates an account that has no password: it can only sign in
// through the identity provider until an administrator sets a password.
func CreateSSOUser(username, displayName string, isAdmin bool) (*User, error) {
	username = strings.TrimSpace(username)
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		displayName = username
	}
	res, err := DB.Exec(`INSERT INTO users (username, display_name, password_hash, is_admin) VALUES (?, ?, '', ?)`,
		username, displayName, isAdmin)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrUserExists
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Username: username, DisplayName: displayName, IsAdmin: isAdmin}, nil
}

// HasPassword reports whether an account can sign in with a password at all.
func HasPassword(userID int64) bool {
	var hash string
	if err := DB.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&hash); err != nil {
		return false
	}
	return hash != ""
}

// SetAdmin grants or revokes administrator rights. Revoking never leaves the
// instance without an administrator: in that case the account stays one and
// the result is false.
func SetAdmin(userID int64, isAdmin bool) (bool, error) {
	if isAdmin {
		_, err := DB.Exec(`UPDATE users SET is_admin = TRUE WHERE id = ?`, userID)
		return err == nil, err
	}
	res, err := DB.Exec(`UPDATE users SET is_admin = FALSE WHERE id = ? AND
		(is_admin = FALSE OR EXISTS (SELECT 1 FROM users o WHERE o.is_admin = TRUE AND o.id <> ?))`, userID, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// UpdateDisplayName changes the shown name of an account.
func UpdateDisplayName(userID int64, displayName string) error {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return nil
	}
	_, err := DB.Exec(`UPDATE users SET display_name = ? WHERE id = ?`, displayName, userID)
	return err
}
