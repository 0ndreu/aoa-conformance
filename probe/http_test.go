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

// TestGetWithHeadersPassesExtraHeaders confirms caller headers reach the wire
// alongside the default Accept, which is what lets a check present a bearer
// token on a metadata-style GET.
func TestGetWithHeadersPassesExtraHeaders(t *testing.T) {
	var gotAuth, gotAccept, gotProto string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccept = r.Header.Get("Accept")
		gotProto = r.Header.Get("MCP-Protocol-Version")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	resp, err := GetWithHeaders(context.Background(), srv.Client(), srv.URL, http.Header{
		"Authorization":        {"Bearer tok"},
		"MCP-Protocol-Version": {"2026-07-28"},
	})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if gotAuth != "Bearer tok" || gotProto != "2026-07-28" {
		t.Fatalf("headers not forwarded: auth=%q proto=%q", gotAuth, gotProto)
	}
	if gotAccept != "application/json" {
		t.Fatalf("Accept = %q, want the default preserved", gotAccept)
	}
}
