package probe

import (
	"encoding/base64"
	"net/http"
	"net/url"
)

const (
	AuthClientSecretPost  = "client_secret_post"
	AuthClientSecretBasic = "client_secret_basic"
)

// ApplyClientAuth applies a client-authentication method to a token request.
//
//   - client_secret_basic: client_id + client_secret go into an
//     Authorization: Basic header (RFC 6749 §2.3.1); neither is placed in the
//     body. Returns the header set.
//   - client_secret_post (default): client_id (always) and client_secret (when
//     present) go into the form body. Returns nil.
//
// A non-empty clientID with an empty secret is treated as a public/anonymous
// client: client_id only, no header.
func ApplyClientAuth(form url.Values, method, clientID, clientSecret string) http.Header {
	if method == AuthClientSecretBasic && clientSecret != "" {
		h := http.Header{}
		cred := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
		h.Set("Authorization", "Basic "+cred)
		return h
	}
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	return nil
}
