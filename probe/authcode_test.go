package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPKCEPairVerifies(t *testing.T) {
	v, ch := NewPKCE()
	if len(v) < 43 {
		t.Fatalf("verifier too short: %d", len(v))
	}
	if ch == v {
		t.Fatal("S256 challenge must differ from verifier")
	}
	if !VerifyPKCE(v, ch) {
		t.Fatal("challenge should verify against verifier")
	}
}

func TestAuthCodeFlowAgainstAutoConsentAS(t *testing.T) {
	// A fake AS that immediately redirects back with a code (no human), then
	// exchanges the code for a token at /token.
	var as *httptest.Server
	as = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			redir := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			http.Redirect(w, r, fmt.Sprintf("%s?code=GOODCODE&state=%s", redir, state), http.StatusFound)
		case "/token":
			_ = r.ParseForm()
			if r.Form.Get("code") == "GOODCODE" && r.Form.Get("code_verifier") != "" {
				fmt.Fprint(w, `{"access_token":"USER_TOKEN","token_type":"Bearer"}`)
				return
			}
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant"}`)
		}
	}))
	defer as.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tok, err := RunAuthCode(ctx, AuthCodeConfig{
		AuthorizationEndpoint: as.URL + "/authorize",
		TokenEndpoint:         as.URL + "/token",
		ClientID:              "client1",
		// openBrowser is injected so the test "logs in" by hitting the URL itself.
		openBrowser: func(u string) error {
			go http.Get(u) // the fake AS will 302 to our callback with the code
			return nil
		},
	})
	if err != nil {
		t.Fatalf("auth_code: %v", err)
	}
	if !strings.Contains(tok, "USER_TOKEN") {
		t.Fatalf("expected USER_TOKEN, got %q", tok)
	}
}
