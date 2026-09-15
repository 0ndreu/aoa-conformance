package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"sort"
)

// MCP protocol versions this probe speaks. The modern one carries per-request
// metadata; the legacy one still requires an initialize handshake.
const (
	MCPVersionModern = "2026-07-28"
	MCPVersionLegacy = "2025-06-18"
)

// clientInfo identifies the probe to the server. Self-reported and unverified,
// but servers log it and operators appreciate knowing who knocked.
const (
	mcpClientName    = "aoa-conform"
	mcpClientVersion = "0.1.0"
)

// MCPEra is the protocol generation a server answered on. The distinction is
// observable: a modern server replies to an unknown method or version with a
// JSON-RPC error from the spec's reserved code range, a legacy one does not.
type MCPEra string

const (
	// EraUnknown: the exchange did not reach the protocol layer, typically
	// because the server answered 401 before parsing the body.
	EraUnknown MCPEra = ""
	// EraModern: per-request metadata, no initialize handshake (2026-07-28+).
	EraModern MCPEra = "modern"
	// EraLegacy: the server wanted an initialize handshake (2025-11-25 and
	// earlier).
	EraLegacy MCPEra = "legacy"
)

// MCPInput describes one JSON-RPC call to an MCP endpoint.
type MCPInput struct {
	Endpoint string
	// Method is the JSON-RPC method; defaults to "tools/list".
	Method string
	// Name mirrors params.name / params.uri into the Mcp-Name header. Only
	// tools/call, resources/read and prompts/get need it.
	Name string
	// Params are merged into the JSON-RPC params alongside _meta.
	Params map[string]any
	// ProtocolVersion overrides the modern version sent on the first attempt.
	ProtocolVersion string

	// Token, when set, is presented in the Authorization header.
	Token string
	// AuthScheme defaults to "Bearer"; DPoP presentation passes "DPoP".
	AuthScheme string
	// ExtraHeaders are merged last (e.g. a DPoP proof).
	ExtraHeaders http.Header
}

// MCPResult is the response to an MCP call plus what the exchange revealed
// about the server's protocol era.
type MCPResult struct {
	*Response
	// Era is the protocol generation the server demonstrated, or EraUnknown
	// when the response never reached the protocol layer.
	Era MCPEra
	// Version is the protocol version the returned Response was obtained
	// with.
	Version string
	// SupportedVersions is the server's own list, present only when it
	// answered UnsupportedProtocolVersion.
	SupportedVersions []string
}

// -32020..-32099 is the sub-range the MCP specification reserves for its own
// error codes (HeaderMismatch, MissingRequiredClientCapability,
// UnsupportedProtocolVersion). Seeing any of them — or -32601 on a 404 —
// proves the peer speaks a modern version.
const (
	errReservedHigh               = -32020
	errReservedLow                = -32099
	errUnsupportedProtocolVersion = -32022
	errMethodNotFound             = -32601
)

// MCPRequest performs a modern MCP call and, when the server turns out to be
// an initialize-era implementation, falls back to the legacy handshake. The
// returned Response is the one that carries the server's real answer, so
// callers can read a 401 challenge off it exactly as they would off a GET.
func MCPRequest(ctx context.Context, c *http.Client, in MCPInput) (*MCPResult, error) {
	version := in.ProtocolVersion
	if version == "" {
		version = MCPVersionModern
	}

	resp, err := postModern(ctx, c, in, version)
	if err != nil {
		return nil, err
	}
	res := &MCPResult{Response: resp, Version: version}

	if !isEraAmbiguous(resp.StatusCode) {
		if resp.StatusCode < 300 {
			res.Era = EraModern
		}
		return res, nil
	}

	rpcErr, ok := modernError(resp.Body)
	if !ok {
		// not a protocol answer we recognise: an initialize-era server, or
		// something that is not an MCP endpoint at all.
		legacy, err := postLegacyInitialize(ctx, c, in)
		if err != nil {
			return res, nil // keep the modern evidence; the fallback is best-effort
		}
		res.Response = legacy
		res.Version = MCPVersionLegacy
		if legacy.StatusCode < 300 {
			res.Era = EraLegacy
		}
		return res, nil
	}

	res.Era = EraModern
	if rpcErr.Code != errUnsupportedProtocolVersion {
		return res, nil
	}

	res.SupportedVersions = rpcErr.Data.Supported
	retry := highestModernVersion(rpcErr.Data.Supported)
	if retry == "" || retry == version {
		return res, nil
	}
	resp2, err := postModern(ctx, c, in, retry)
	if err != nil {
		return res, nil
	}
	res.Response = resp2
	res.Version = retry
	return res, nil
}

// isEraAmbiguous reports the statuses the spec says a client must inspect the
// body of before deciding the server's era.
func isEraAmbiguous(status int) bool {
	return status == http.StatusBadRequest ||
		status == http.StatusNotFound ||
		status == http.StatusMethodNotAllowed
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Supported []string `json:"supported"`
		Requested string   `json:"requested"`
	} `json:"data"`
}

// modernError reports whether the body is a JSON-RPC error carrying a code the
// MCP specification defines. Codes in -32020..-32099 are reserved for the
// spec, and -32601 on an unknown method is the other documented signal; a
// legacy server answering 404 emits neither.
func modernError(body []byte) (jsonRPCError, bool) {
	var doc struct {
		JSONRPC string        `json:"jsonrpc"`
		Error   *jsonRPCError `json:"error"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.Error == nil {
		return jsonRPCError{}, false
	}
	code := doc.Error.Code
	switch {
	case code <= errReservedHigh && code >= errReservedLow:
		return *doc.Error, true
	case code == errMethodNotFound:
		return *doc.Error, true
	}
	return jsonRPCError{}, false
}

// highestModernVersion picks the newest version in the server's supported list
// that is still a modern (per-request-metadata) revision. Versions are ISO
// dates, so lexicographic order is chronological order.
func highestModernVersion(supported []string) string {
	var modern []string
	for _, v := range supported {
		if v >= MCPVersionModern {
			modern = append(modern, v)
		}
	}
	if len(modern) == 0 {
		return ""
	}
	sort.Strings(modern)
	return modern[len(modern)-1]
}

func postModern(ctx context.Context, c *http.Client, in MCPInput, version string) (*Response, error) {
	method := in.Method
	if method == "" {
		method = "tools/list"
	}

	params := map[string]any{}
	maps.Copy(params, in.Params)
	params["_meta"] = map[string]any{
		"io.modelcontextprotocol/protocolVersion": version,
		"io.modelcontextprotocol/clientInfo": map[string]any{
			"name":    mcpClientName,
			"version": mcpClientVersion,
		},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, err
	}

	h := http.Header{}
	h.Set("MCP-Protocol-Version", version)
	h.Set("Mcp-Method", method)
	if in.Name != "" {
		h.Set("Mcp-Name", in.Name)
	}
	return postJSONRPC(ctx, c, in, h, body, fmt.Sprintf("MCP %s (protocol %s)", method, version))
}

func postLegacyInitialize(ctx context.Context, c *http.Client, in MCPInput) (*Response, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": MCPVersionLegacy,
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    mcpClientName,
				"version": mcpClientVersion,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	// the legacy revision does not expect MCP-Protocol-Version on initialize:
	// the version is negotiated by this very request.
	return postJSONRPC(ctx, c, in, http.Header{}, body, "MCP initialize (legacy fallback, protocol "+MCPVersionLegacy+")")
}

func postJSONRPC(ctx context.Context, c *http.Client, in MCPInput, h http.Header, body []byte, label string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if in.Token != "" {
		scheme := in.AuthScheme
		if scheme == "" {
			scheme = "Bearer"
		}
		req.Header.Set("Authorization", scheme+" "+in.Token)
	}
	for k, vs := range in.ExtraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return do(c, req, fmt.Sprintf("POST %s\n%s\nbody: %s", in.Endpoint, label, body))
}
