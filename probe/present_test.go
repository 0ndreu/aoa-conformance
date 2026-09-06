package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPresentToken_Header(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	resp, err := PresentToken(context.Background(), srv.Client(), PresentInput{
		ResourceURL: srv.URL, Token: "abc", Method: "header",
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("present: %v / %d", err, resp.StatusCode)
	}
	if sawAuth != "Bearer abc" {
		t.Fatalf("Authorization = %q", sawAuth)
	}
}

func TestPresentToken_Query(t *testing.T) {
	var sawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawQuery = r.URL.Query().Get("access_token")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	_, err := PresentToken(context.Background(), srv.Client(), PresentInput{ResourceURL: srv.URL, Token: "abc", Method: "query"})
	if err != nil {
		t.Fatal(err)
	}
	if sawQuery != "abc" {
		t.Fatalf("query access_token = %q", sawQuery)
	}
}

func TestPresentToken_UnsupportedMethodErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("server should not be contacted for an unsupported bearer method")
	}))
	defer srv.Close()

	_, err := PresentToken(context.Background(), srv.Client(), PresentInput{ResourceURL: srv.URL, Token: "abc", Method: "mac"})
	if err == nil {
		t.Fatal("expected an error for an unrecognized bearer method, got nil")
	}
}

func TestPresentToken_Body(t *testing.T) {
	var sawForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		sawForm = r.Form.Get("access_token")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	_, err := PresentToken(context.Background(), srv.Client(), PresentInput{ResourceURL: srv.URL, Token: "abc", Method: "body"})
	if err != nil {
		t.Fatal(err)
	}
	if sawForm != "abc" {
		t.Fatalf("form access_token = %q", sawForm)
	}
}

// TestPresentTokenDPoPBindsTheMCPPost covers presenting a DPoP-bound token to
// the resource: the credential switches from Bearer to the DPoP scheme and the
// accompanying proof is bound to the request the resource actually saw
// (htm=POST, htu=the MCP endpoint, ath=hash of the presented token), per
// RFC 9449 §7.
func TestPresentTokenDPoPBindsTheMCPPost(t *testing.T) {
	var gotAuth, gotProof string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotProof = r.Header.Get("DPoP")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	key, err := NewProofKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	resp, err := PresentToken(context.Background(), srv.Client(), PresentInput{
		ResourceURL: srv.URL, Token: "at-1", Method: "header", DPoP: key, DPoPNonce: "n-1",
	})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("present: %v / %v", err, resp)
	}

	if gotAuth != "DPoP at-1" {
		t.Fatalf("Authorization = %q, want the DPoP scheme", gotAuth)
	}
	_, claims := decodeJWS(t, gotProof)
	if claims["htm"] != http.MethodPost {
		t.Errorf("htm = %v, want POST (the MCP call)", claims["htm"])
	}
	if claims["htu"] != srv.URL {
		t.Errorf("htu = %v, want %q", claims["htu"], srv.URL)
	}
	if claims["ath"] != S256("at-1") {
		t.Errorf("ath = %v, not the hash of the presented token", claims["ath"])
	}
	if claims["nonce"] != "n-1" {
		t.Errorf("nonce = %v, the server-supplied nonce was dropped", claims["nonce"])
	}
}
