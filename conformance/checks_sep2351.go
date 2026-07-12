package conformance

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerSEP2351(r *Registry) {
	r.Add(Check{
		ID: "sep2351.discovery.suffix_path", Profile: ProfileJuly28RC, RFC: "SEP-2351", Section: "well-known suffix",
		Severity:     SeverityMUST,
		Description:  "RFC 9728 PRM is reachable at the suffix-inserted well-known path for the resource",
		Precondition: func(t *Target) bool { return t.MCPURL != "" },
		Run: func(t *Target) Result {
			suffixURL, err := suffixPRMURL(t.MCPURL)
			if err != nil {
				return Result{Status: StatusError, Message: "cannot parse target URL: " + err.Error()}
			}
			resp, err := probe.Get(t.Context(), t.httpClient(), suffixURL)
			if err != nil {
				return Result{Status: StatusError, Message: "fetch " + suffixURL + ": " + err.Error()}
			}
			if resp.StatusCode != 200 {
				return Result{Status: StatusFail,
					Message:  "PRM not reachable at suffix path " + suffixURL + " (HTTP " + strconv.Itoa(resp.StatusCode) + ")",
					Evidence: resp.Evidence}
			}
			var m map[string]any
			if err := json.Unmarshal(resp.Body, &m); err != nil {
				return Result{Status: StatusFail,
					Message:  "suffix-path PRM is not valid JSON: " + err.Error(),
					Evidence: resp.Body}
			}
			return Result{Status: StatusPass, Message: "PRM resolves at suffix path " + suffixURL, Evidence: resp.Body}
		},
	})
}

// suffixPRMURL builds the RFC 9728 §3.1 suffix-inserted well-known path for a
// resource: origin + /.well-known/oauth-protected-resource + resource-path.
// for https://host/mcp it returns https://host/.well-known/oauth-protected-resource/mcp.
func suffixPRMURL(mcpURL string) (string, error) {
	u, err := url.Parse(mcpURL)
	if err != nil {
		return "", err
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimRight(u.Path, "/")
	return origin + "/.well-known/oauth-protected-resource" + path, nil
}
