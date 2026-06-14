package probe

import (
	"crypto/rand"
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
