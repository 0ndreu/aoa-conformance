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
	Profile      string // "", "core", "extended"
	Format       string // "md" | "json"
	Present      bool
	Strict       bool
	AuthCode     bool
	CACert       string
	Insecure     bool
}

func main() {
	var o options
	flag.StringVar(&o.Target, "target", "", "MCP server URL (walk the agent loop)")
	flag.StringVar(&o.Issuer, "issuer", "", "OAuth issuer URL (probe the AS directly)")
	flag.StringVar(&o.ClientID, "client-id", "", "client id (Tier 1)")
	flag.StringVar(&o.ClientSecret, "client-secret", "", "client secret (Tier 1)")
	flag.StringVar(&o.SubjectToken, "subject-token", "", "user token to exchange (Tier 2)")
	flag.StringVar(&o.Profile, "profile", "", "limit to: core | extended (default: all)")
	flag.StringVar(&o.Format, "format", "md", "report format: md | json")
	flag.BoolVar(&o.Present, "present", false, "complete the agent loop: present a token to the resource server")
	flag.BoolVar(&o.Strict, "strict", false, "treat SHOULD violations as failures")
	flag.BoolVar(&o.AuthCode, "auth-code", false, "obtain a user token interactively (authorization_code + PKCE)")
	flag.StringVar(&o.CACert, "cacert", "", "PEM file of CA(s) to trust for TLS (e.g. a dev self-signed cert)")
	flag.BoolVar(&o.Insecure, "insecure-skip-verify", false, "skip TLS certificate verification (dev only)")
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
			ClientID: o.ClientID, ClientSecret: o.ClientSecret, UsePostAuth: true,
			SubjectToken:   o.SubjectToken,
			PresentEnabled: o.Present,
		},
	}

	// interactive authorization_code wiring (Decision 5): obtaining a user
	// token requires the AS endpoints, which only exist after discovery. Run a
	// discovery-only pass to populate tgt.Discovered, then drive the browser
	// flow and stash the resulting token as the Tier-2 subject token.
	if o.AuthCode {
		ctx := context.Background()
		if err := discoverInto(ctx, tgt); err != nil {
			fmt.Fprintln(os.Stderr, "auth-code: discovery failed:", err)
			return 1
		}
		token, err := probe.RunAuthCode(ctx, probe.AuthCodeConfig{
			AuthorizationEndpoint: tgt.Discovered.AuthorizationEndpoint,
			TokenEndpoint:         tgt.Discovered.TokenEndpoint,
			ClientID:              o.ClientID,
			ClientSecret:          o.ClientSecret,
			HTTPClient:            tgt.Client,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "auth-code: interactive flow failed:", err)
			return 1
		}
		tgt.Creds.SubjectToken = token
		tgt.Creds.AuthCodeAvailable = true
	}

	rep := (&conformance.Runner{Registry: reg}).Run(tgt)

	var rep2err error
	switch o.Format {
	case "json":
		rep2err = (conformance.JSONReporter{}).Write(w, rep)
	default:
		rep2err = (conformance.MarkdownReporter{}).Write(w, rep)
	}
	if rep2err != nil {
		fmt.Fprintln(os.Stderr, "report error:", rep2err)
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
	}
	if err != nil {
		return err
	}
	if tgt.Discovered.AuthorizationEndpoint == "" || tgt.Discovered.TokenEndpoint == "" {
		return fmt.Errorf("discovery did not resolve authorization/token endpoints")
	}
	return nil
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
