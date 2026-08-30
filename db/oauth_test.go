package db

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func initTestDB(t *testing.T) {
	t.Helper()
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "test.db"))
	Init()
	t.Cleanup(Close)
}

func TestFindUserByEmailCaseInsensitive(t *testing.T) {
	initTestDB(t)

	created, err := CreateUser("Ada@Example.com", "Ada", "")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	found, err := FindUserByEmail("ada@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail: %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("FindUserByEmail returned user %d, want %d", found.ID, created.ID)
	}

	if _, err := FindUserByEmail("nobody@example.com"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("FindUserByEmail for unknown email: err = %v, want sql.ErrNoRows", err)
	}
}

func TestOAuthIdentitiesLinkToSameUser(t *testing.T) {
	initTestDB(t)

	user, err := CreateUser("person@example.com", "Person", "")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := CreateOAuthIdentity(user.ID, "generic", "sub-1", "person@example.com"); err != nil {
		t.Fatalf("CreateOAuthIdentity(generic): %v", err)
	}
	if _, err := CreateOAuthIdentity(user.ID, "google", "sub-2", "person@example.com"); err != nil {
		t.Fatalf("CreateOAuthIdentity(google): %v", err)
	}

	generic, err := FindOAuthIdentity("generic", "sub-1")
	if err != nil {
		t.Fatalf("FindOAuthIdentity(generic): %v", err)
	}
	google, err := FindOAuthIdentity("google", "sub-2")
	if err != nil {
		t.Fatalf("FindOAuthIdentity(google): %v", err)
	}
	if generic.UserID != user.ID || google.UserID != user.ID {
		t.Fatalf("expected both identities to link to user %d, got %d and %d", user.ID, generic.UserID, google.UserID)
	}
}

func TestCreateSessionLeavesUserIDNull(t *testing.T) {
	initTestDB(t)

	if err := CreateSession("session-1", 9999999999); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	session, err := GetSession("session-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if session.UserID.Valid {
		t.Fatalf("expected a password-login session to have a NULL user_id, got %v", session.UserID.Int64)
	}
}

func TestCreateSessionForUserSetsUserID(t *testing.T) {
	initTestDB(t)

	user, err := CreateUser("person@example.com", "Person", "")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := CreateSessionForUser("session-2", 9999999999, user.ID); err != nil {
		t.Fatalf("CreateSessionForUser: %v", err)
	}

	session, err := GetSession("session-2")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !session.UserID.Valid || session.UserID.Int64 != user.ID {
		t.Fatalf("expected session.UserID = %d, got %+v", user.ID, session.UserID)
	}
}

func TestOAuthMigrationsAreIdempotent(t *testing.T) {
	t.Setenv("DB_PATH", filepath.Join(t.TempDir(), "test.db"))
	Init()
	Close()

	// Re-running Init against the same file must not error or duplicate schema.
	Init()
	t.Cleanup(Close)

	if _, err := CreateUser("idempotent@example.com", "", ""); err != nil {
		t.Fatalf("CreateUser after second Init: %v", err)
	}
}
