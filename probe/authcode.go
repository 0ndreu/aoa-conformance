package probe

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"

	"golang.org/x/oauth2"
)

// NewPKCE returns a (verifier, S256-challenge) pair.
func NewPKCE() (verifier, challenge string) {
	verifier = randHex(48) // 96 hex chars; > 43, URL-safe
	sum := sha256.Sum256([]byte(verifier))
	return verifier, b64url(sum[:])
}

func VerifyPKCE(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return b64url(sum[:]) == challenge
}

// AuthCodeConfig configures the interactive flow.
type AuthCodeConfig struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	ClientID              string
	ClientSecret          string // optional (public clients omit)
	Scopes                []string
	// HTTPClient is used for the code-for-token exchange. nil ⇒ http.DefaultClient.
	HTTPClient *http.Client

	openBrowser func(string) error // injected in tests; defaults to the OS opener
}

// RunAuthCode performs an interactive authorization_code + PKCE flow: it starts
// a localhost callback server, opens the authorize URL in the user's browser,
// waits for the redirect, and exchanges the code for a token. Returns the
// access token string.
func RunAuthCode(ctx context.Context, cfg AuthCodeConfig) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	redirectURI := fmt.Sprintf("http://%s/callback", ln.Addr().String())

	oc := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Scopes:       cfg.Scopes,
		RedirectURL:  redirectURI,
		Endpoint:     oauth2.Endpoint{AuthURL: cfg.AuthorizationEndpoint, TokenURL: cfg.TokenEndpoint},
	}
	verifier, challenge := NewPKCE()
	state := randHex(16)
	authURL := oc.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			errCh <- errors.New("state mismatch")
			return
		}
		if e := r.URL.Query().Get("error"); e != "" {
			errCh <- fmt.Errorf("authorize error: %s", e)
			return
		}
		fmt.Fprintln(w, "aoa-conform: login complete, you can close this tab.")
		codeCh <- r.URL.Query().Get("code")
	})}
	go srv.Serve(ln)
	defer srv.Close()

	open := cfg.openBrowser
	if open == nil {
		open = openInBrowser
	}
	fmt.Printf("Open this URL to log in:\n  %s\n", authURL)
	_ = open(authURL)

	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	}

	// Exchange the code ourselves rather than via oauth2.Exchange: oauth2 keys
	// token parsing off the response Content-Type and treats anything that is
	// not JSON-typed as a urlencoded form, silently dropping a JSON body served
	// as text/plain. Our PostForm + JSON parse is content-type-agnostic and also
	// captures evidence, matching the rest of the probe package.
	form := FormString(
		"grant_type", "authorization_code",
		"code", code,
		"redirect_uri", redirectURI,
		"client_id", cfg.ClientID,
		"code_verifier", verifier,
	)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := PostForm(ctx, httpClient, cfg.TokenEndpoint, form, nil)
	if err != nil {
		return "", err
	}
	at, _ := resp.JSON()["access_token"].(string)
	if at == "" {
		return "", fmt.Errorf("token endpoint returned no access_token (HTTP %d)", resp.StatusCode)
	}
	return at, nil
}

func openInBrowser(u string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}
