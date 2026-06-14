package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	// a fake AS that immediately redirects back with a code (no human), then
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
	res, err := RunAuthCode(ctx, AuthCodeConfig{
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
	if !strings.Contains(res.AccessToken, "USER_TOKEN") {
		t.Fatalf("expected USER_TOKEN, got %q", res.AccessToken)
	}
}

func TestRunAuthCode_PushesPARFirst(t *testing.T) {
	var parHit bool
	var authQuery url.Values
	mux := http.NewServeMux()
	mux.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		parHit = true
		_ = r.ParseForm()
		if r.Form.Get("code_challenge") == "" {
			t.Errorf("PAR body missing PKCE challenge")
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"request_uri":"urn:fake:1","expires_in":90}`)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"tok"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := AuthCodeConfig{
		AuthorizationEndpoint: srv.URL + "/authorize",
		TokenEndpoint:         srv.URL + "/token",
		PAREndpoint:           srv.URL + "/par",
		UsePAR:                true,
		ClientID:              "cid",
		HTTPClient:            srv.Client(),
		openBrowser: func(u string) error {
			parsed, _ := url.Parse(u)
			authQuery = parsed.Query()
			// simulate the AS redirecting back with a code.
			go func() {
				cb := authQuery.Get("redirect_uri")
				st := authQuery.Get("state")
				http.Get(cb + "?state=" + st + "&code=xyz")
			}()
			return nil
		},
	}
	res, err := RunAuthCode(context.Background(), cfg)
	if err != nil {
		t.Fatalf("auth code: %v", err)
	}
	if res.AccessToken != "tok" {
		t.Fatalf("token = %q", res.AccessToken)
	}
	if !parHit {
		t.Fatalf("PAR endpoint was not called")
	}
	if authQuery.Get("request_uri") != "urn:fake:1" {
		t.Fatalf("authorize URL missing request_uri: %v", authQuery)
	}
	if authQuery.Get("code_challenge") != "" {
		t.Fatalf("with PAR, params must not be in the authorize URL: %v", authQuery)
	}
}
