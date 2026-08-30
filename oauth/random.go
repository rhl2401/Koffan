package oauth

import (
	"crypto/rand"
	"encoding/hex"
)

// randomToken returns a 32-byte cryptographically random value, hex-encoded.
// Same idiom as handlers.generateSessionID.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
