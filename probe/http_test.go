package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPostFormCapturesEvidenceAndParsesJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "client_credentials" {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"unsupported_grant_type"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"abc","token_type":"Bearer"}`))
	}))
	defer srv.Close()

	resp, err := PostForm(context.Background(), http.DefaultClient, srv.URL,
		url.Values{"grant_type": {"client_credentials"}}, nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp.JSON()["access_token"] != "abc" {
		t.Fatalf("json parse: %+v", resp.JSON())
	}
	if !strings.Contains(string(resp.Evidence), "access_token") {
		t.Fatal("evidence should contain the response body")
	}
}
