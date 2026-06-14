package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/0ndreu/aoa-conformance/conformance"
	"github.com/0ndreu/aoa-conformance/probe"
)

type options struct {
	Target       string
	Issuer       string
	ClientID     string
	ClientSecret string
	SubjectToken string
	Scope        string // space-separated scopes to request (--scope)
	Profile      string // "", "core", "extended"
	Format       string // "md" | "json"
	Present      bool
	Strict       bool
	AuthCode     bool
	CACert       string
	Insecure     bool

	TokenAuthMethod   string
	RegistrationToken string
}

func main() {
	var o options
	flag.StringVar(&o.Target, "target", "", "MCP server URL (walk the agent loop)")
	flag.StringVar(&o.Issuer, "issuer", "", "OAuth issuer URL (probe the AS directly)")
	flag.StringVar(&o.ClientID, "client-id", "", "client id (Tier 1)")
	flag.StringVar(&o.ClientSecret, "client-secret", "", "client secret (Tier 1)")
	flag.StringVar(&o.SubjectToken, "subject-token", "", "user token to exchange (Tier 2)")
	flag.StringVar(&o.Scope, "scope", "", "space-separated scopes to request when obtaining a token")
	flag.StringVar(&o.Profile, "profile", "", "limit to: core | extended (default: all)")
	flag.StringVar(&o.Format, "format", "md", "report format: md | json")
	flag.BoolVar(&o.Present, "present", false, "complete the agent loop: present a token to the resource server")
	flag.BoolVar(&o.Strict, "strict", false, "treat SHOULD violations as failures")
	flag.BoolVar(&o.AuthCode, "auth-code", false, "obtain a user token interactively (authorization_code + PKCE)")
	flag.StringVar(&o.CACert, "cacert", "", "PEM file of CA(s) to trust for TLS (e.g. a dev self-signed cert)")
	flag.BoolVar(&o.Insecure, "insecure-skip-verify", false, "skip TLS certificate verification (dev only)")
	flag.StringVar(&o.TokenAuthMethod, "token-auth-method", "", "override token-endpoint auth method: client_secret_post | client_secret_basic")
	flag.StringVar(&o.RegistrationToken, "registration-token", "", "RFC 7591 initial access token for dynamic client registration")
	flag.Parse()

	if o.Target == "" && o.Issuer == "" {
		fmt.Fprintln(os.Stderr, "error: one of --target or --issuer is required")
		os.Exit(2)
	}
	os.Exit(run(o, os.Stdout))
}

func run(o options, w io.Writer) int {
	reg := conformance.DefaultRegistry()
	switch o.Profile {
	case "core":
		reg = reg.FilterProfiles(conformance.ProfileCore)
	case "extended":
		reg = reg.FilterProfiles(conformance.ProfileExtended)
	}

	client, err := buildHTTPClient(o)
	if err != nil {
		fmt.Fprintln(w, "error:", err)
		return 2
	}
	tgt := &conformance.Target{
		MCPURL: o.Target,
		Issuer: o.Issuer,
		Client: client,
		Creds: conformance.Creds{
			SubjectToken:   o.SubjectToken,
			Scopes:         splitScopes(o.Scope),
			PresentEnabled: o.Present,
		},
	}

	ro := resolveOptionsFrom(o)

	if o.AuthCode {
		ctx := context.Background()
		if err := discoverInto(ctx, tgt); err != nil {
			fmt.Fprintln(os.Stderr, "auth-code: discovery failed:", err)
			return 1
		}
		plan, _ := conformance.Resolve(ctx, tgt.Client, tgt.Discovered, ro)
		tgt.Plan = plan
		defer cleanupRegistration(ctx, tgt)
		res, err := probe.RunAuthCode(ctx, probe.AuthCodeConfig{
			AuthorizationEndpoint: tgt.Discovered.AuthorizationEndpoint,
			TokenEndpoint:         tgt.Discovered.TokenEndpoint,
			ClientID:              plan.ClientID,
			ClientSecret:          plan.ClientSecret,
			Scopes:                plan.Scopes,
			UsePAR:                plan.UsePAR,
			PAREndpoint:           plan.PAREndpoint,
			HTTPClient:            tgt.Client,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "auth-code: interactive flow failed:", err)
			return 1
		}
		tgt.Creds.SubjectToken = res.AccessToken
		tgt.Creds.AuthCodeAvailable = true
		if tgt.Hints == nil {
			tgt.Hints = map[string]string{}
		}
		tgt.Hints["authorize_iss"] = res.CallbackISS
		rep := (&conformance.Runner{Registry: reg}).Run(tgt)
		return finish(o, w, rep)
	}

	rep := (&conformance.Runner{Registry: reg, ResolveOpts: &ro}).Run(tgt)
	defer cleanupRegistration(context.Background(), tgt)
	return finish(o, w, rep)
}

func finish(o options, w io.Writer, rep conformance.Report) int {
	var err error
	switch o.Format {
	case "json":
		err = (conformance.JSONReporter{}).Write(w, rep)
	default:
		err = (conformance.MarkdownReporter{}).Write(w, rep)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "report error:", err)
		return 1
	}
	s := rep.Summarize()
	if s.Fail > 0 || s.Error > 0 {
		return 1
	}
	if o.Strict && shouldViolations(rep) {
		return 1
	}
	return 0
}

// resolveOptionsFrom maps the CLI options into resolver inputs.
func resolveOptionsFrom(o options) conformance.ResolveOptions {
	return conformance.ResolveOptions{
		ClientID:          o.ClientID,
		ClientSecret:      o.ClientSecret,
		TokenAuthMethod:   o.TokenAuthMethod,
		RegistrationToken: o.RegistrationToken,
		Scopes:            splitScopes(o.Scope),
	}
}

// cleanupRegistration best-effort deletes a DCR'd ephemeral client (RFC 7591 §4).
func cleanupRegistration(ctx context.Context, tgt *conformance.Target) {
	if !tgt.Plan.Registered || tgt.Plan.RegistrationClientURI == "" {
		return
	}
	if err := probe.DeleteRegistration(ctx, tgt.Client, tgt.Plan.RegistrationClientURI, tgt.Plan.RegistrationAccessToken); err != nil {
		fmt.Fprintln(os.Stderr, "cleanup: could not delete ephemeral client:", err)
	}
}

// discoverInto runs a discovery-only pass so the interactive auth-code flow can
// read the resolved authorization/token endpoints. The full run re-discovers,
// but that is cheap and keeps the two phases independent.
func discoverInto(ctx context.Context, tgt *conformance.Target) error {
	d, err := probe.Discover(ctx, tgt.Client, probe.DiscoverInput{
		MCPURL: tgt.MCPURL,
		Issuer: tgt.Issuer,
	})
	if d != nil {
		tgt.Discovered.AuthorizationEndpoint = d.AuthorizationEndpoint
		tgt.Discovered.TokenEndpoint = d.TokenEndpoint
		tgt.Discovered.PRMScopesSupported = d.PRMScopesSupported
	}
	if err != nil {
		return err
	}
	if tgt.Discovered.AuthorizationEndpoint == "" || tgt.Discovered.TokenEndpoint == "" {
		return fmt.Errorf("discovery did not resolve authorization/token endpoints")
	}
	return nil
}

// splitScopes parses a space-separated --scope value into individual scopes,
// dropping empty fields. Returns nil for an empty value so no scope parameter
// is sent.
func splitScopes(s string) []string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return nil
	}
	return f
}

func shouldViolations(rep conformance.Report) bool {
	for _, e := range rep.Entries {
		if e.Result.Status == conformance.StatusFail && e.Check.Severity == conformance.SeveritySHOULD {
			return true
		}
	}
	return false
}

func buildHTTPClient(o options) (*http.Client, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	if o.CACert == "" && !o.Insecure {
		return client, nil
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: o.Insecure} //nolint:gosec // dev-only flag
	if o.CACert != "" {
		pem, err := os.ReadFile(o.CACert)
		if err != nil {
			return nil, fmt.Errorf("read cacert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("cacert %s: no valid certificates found", o.CACert)
		}
		tlsCfg.RootCAs = pool
	}
	client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	return client, nil
}
