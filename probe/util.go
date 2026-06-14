package probe

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"
)

func nowUnix() int64 { return time.Now().Unix() }

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// S256 returns the base64url-encoded SHA-256 of s (used for PKCE-style hashes
// and the DPoP ath claim).
func S256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64url(sum[:])
}
