package main

import (
	"encoding/json"
	"net/http"

	"github.com/0ndreu/aoa"
)

// downstreamHandler is the protected resource the gateway tool calls with an
// exchanged token. It echoes the validated subject so callers can see whose
// (downscoped) token reached it.
func downstreamHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sub := ""
		if c, ok := aoa.ClaimsFromContext(r.Context()); ok {
			sub = c.Subject
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"service": "downstream",
			"subject": sub,
			"data":    "secret resource payload",
		})
	})
}
