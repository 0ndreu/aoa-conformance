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
