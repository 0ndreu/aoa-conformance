package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// modernMCP serves a 2026-07-28 endpoint and records what the client sent.
type modernMCP struct {
	*httptest.Server
	gotAccept      string
	gotContentType string
	gotVersion     string
	gotMethod      string
	gotAuth        string
	gotBody        map[string]any
	calls          int
}

func newModernMCP(t *testing.T) *modernMCP {
	t.Helper()
	m := &modernMCP{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			// 2026-07-28: GET on the MCP endpoint is Method Not Allowed.
			w.WriteHeader(405)
			return
		}
		m.calls++
		m.gotAccept = r.Header.Get("Accept")
		m.gotContentType = r.Header.Get("Content-Type")
		m.gotVersion = r.Header.Get("MCP-Protocol-Version")
		m.gotMethod = r.Header.Get("Mcp-Method")
		m.gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		m.gotBody = map[string]any{}
		_ = json.Unmarshal(body, &m.gotBody)
		writeRPC(w, 200, `{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[]}}`)
	}))
	t.Cleanup(m.Close)
	return m
}

func writeRPC(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, body)
}

func TestMCPRequest_ModernPostSucceeds(t *testing.T) {
	srv := newModernMCP(t)

	res, err := MCPRequest(context.Background(), srv.Client(), MCPInput{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("mcp request: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if res.Era != EraModern {
		t.Errorf("era = %q, want modern", res.Era)
	}
	if res.Version != MCPVersionModern {
		t.Errorf("version = %q", res.Version)
	}
	if srv.gotAccept != "application/json, text/event-stream" {
		t.Errorf("Accept = %q", srv.gotAccept)
	}
	if srv.gotContentType != "application/json" {
		t.Errorf("Content-Type = %q", srv.gotContentType)
	}
	if srv.gotVersion != MCPVersionModern {
		t.Errorf("MCP-Protocol-Version = %q", srv.gotVersion)
	}
	if srv.gotMethod != "tools/list" {
		t.Errorf("Mcp-Method = %q", srv.gotMethod)
	}

	params, _ := srv.gotBody["params"].(map[string]any)
	meta, _ := params["_meta"].(map[string]any)
	if meta["io.modelcontextprotocol/protocolVersion"] != MCPVersionModern {
		t.Errorf("_meta protocolVersion = %v", meta["io.modelcontextprotocol/protocolVersion"])
	}
	if _, ok := meta["io.modelcontextprotocol/clientInfo"]; !ok {
		t.Error("_meta clientInfo missing")
	}
	if _, ok := meta["io.modelcontextprotocol/clientCapabilities"]; !ok {
		t.Error("_meta clientCapabilities missing")
	}
}

func TestMCPRequest_LegacyEndpointFallsBackToInitialize(t *testing.T) {
	var sawInitialize bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var doc struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &doc)
		if doc.Method == "initialize" {
			sawInitialize = true
			writeRPC(w, 200, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"legacy","version":"1"}}}`)
			return
		}
		// an initialize-era server rejects the modern call without any
		// spec-reserved error code.
		writeRPC(w, 400, `{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Bad Request: Server not initialized"}}`)
	}))
	defer srv.Close()

	res, err := MCPRequest(context.Background(), srv.Client(), MCPInput{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("mcp request: %v", err)
	}
	if !sawInitialize {
		t.Fatal("expected an initialize fallback")
	}
	if res.Era != EraLegacy {
		t.Errorf("era = %q, want legacy", res.Era)
	}
	if res.Version != MCPVersionLegacy {
		t.Errorf("version = %q", res.Version)
	}
	if res.StatusCode != 200 {
		t.Errorf("status = %d, want the initialize response", res.StatusCode)
	}
}

func TestMCPRequest_ModernErrorDoesNotFallBack(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var doc struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &doc)
		methods = append(methods, doc.Method)
		writeRPC(w, 404, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`)
	}))
	defer srv.Close()

	res, err := MCPRequest(context.Background(), srv.Client(), MCPInput{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("mcp request: %v", err)
	}
	if res.Era != EraModern {
		t.Errorf("era = %q, want modern", res.Era)
	}
	if len(methods) != 1 || methods[0] != "tools/list" {
		t.Errorf("calls = %v, want a single modern call and no initialize", methods)
	}
}

func TestMCPRequest_RetriesWithSupportedVersion(t *testing.T) {
	const newer = "2027-01-01"
	var versions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("MCP-Protocol-Version")
		versions = append(versions, v)
		if v != newer {
			writeRPC(w, 400, fmt.Sprintf(
				`{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["%s","2025-11-25"],"requested":"%s"}}}`,
				newer, v))
			return
		}
		writeRPC(w, 200, `{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","tools":[]}}`)
	}))
	defer srv.Close()

	res, err := MCPRequest(context.Background(), srv.Client(), MCPInput{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("mcp request: %v", err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("status = %d after retry", res.StatusCode)
	}
	if res.Version != newer {
		t.Errorf("version = %q, want the retried %s", res.Version, newer)
	}
	if len(res.SupportedVersions) != 2 {
		t.Errorf("supported = %v", res.SupportedVersions)
	}
	if len(versions) != 2 || versions[1] != newer {
		t.Errorf("versions sent = %v", versions)
	}
}

func TestMCPRequest_CarriesBearerToken(t *testing.T) {
	srv := newModernMCP(t)

	if _, err := MCPRequest(context.Background(), srv.Client(), MCPInput{Endpoint: srv.URL, Token: "abc"}); err != nil {
		t.Fatalf("mcp request: %v", err)
	}
	if srv.gotAuth != "Bearer abc" {
		t.Fatalf("Authorization = %q", srv.gotAuth)
	}
}

// TestDiscover_MCPEndpointRejectingGET is the case a bare GET could not
// handle: the server answers GET with 406 and only carries the challenge on a
// real MCP POST.
func TestDiscover_MCPEndpointRejectingGET(t *testing.T) {
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			writeRPC(w, 200, fmt.Sprintf(`{"issuer":%q,"token_endpoint":%q}`, "http://"+r.Host, "http://"+r.Host+"/token"))
			return
		}
		w.WriteHeader(404)
	}))
	defer as.Close()

	var rs *httptest.Server
	rs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-protected-resource" {
			writeRPC(w, 200, fmt.Sprintf(`{"resource":%q,"authorization_servers":[%q]}`, rs.URL, as.URL))
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(406) // gates on Accept, exactly as deepwiki does
			return
		}
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, rs.URL))
		w.WriteHeader(401)
	}))
	defer rs.Close()

	d, err := Discover(context.Background(), rs.Client(), DiscoverInput{MCPURL: rs.URL + "/mcp"})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if d.TokenEndpoint != as.URL+"/token" {
		t.Fatalf("token endpoint = %q", d.TokenEndpoint)
	}
	if d.MCPEra != EraUnknown {
		t.Errorf("era = %q; a 401 arrives before the protocol layer", d.MCPEra)
	}
}

func TestPresentToken_HeaderUsesMCPPost(t *testing.T) {
	srv := newModernMCP(t)

	resp, err := PresentToken(context.Background(), srv.Client(), PresentInput{
		ResourceURL: srv.URL, Token: "abc", Method: "header",
	})
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if srv.gotMethod != "tools/list" {
		t.Errorf("Mcp-Method = %q; --present must exercise a real MCP call", srv.gotMethod)
	}
	if srv.gotAuth != "Bearer abc" {
		t.Errorf("Authorization = %q", srv.gotAuth)
	}
}
