package conformance

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

// defaultRedirectURI is the loopback callback registered when the caller has no
// listener of its own yet. RFC 7591 §2 makes redirect_uris effectively
// mandatory for any client that will ever run authorization_code, and an AS
// that only issues public clients rejects a registration without it.
const defaultRedirectURI = "http://127.0.0.1:8765/callback"

// resolveTokenAuthMethod picks the token-endpoint auth method:
// explicit override > intersection(advertised, what we implement) > default.
// With no secret in hand, an advertised "none" wins: that is the public-client
// case, and sending a secret we do not have is not an option. Among the secret
// methods, post is preferred over basic; the default is post.
func resolveTokenAuthMethod(explicit string, advertised []string, hasSecret bool) string {
	if explicit != "" {
		return explicit
	}
	has := map[string]bool{}
	for _, m := range advertised {
		has[m] = true
	}
	if !hasSecret && has[probe.AuthNone] {
		return probe.AuthNone
	}
	if has[probe.AuthClientSecretPost] {
		return probe.AuthClientSecretPost
	}
	if has[probe.AuthClientSecretBasic] {
		return probe.AuthClientSecretBasic
	}
	return probe.AuthClientSecretPost
}

// registrationGrantTypes is what to ask for on DCR: the grants this run can
// exercise, intersected with what the AS says it supports. Asking for
// client_credentials at an AS that does not offer it gets the whole
// registration rejected, which is how one missing grant used to cost the run
// its client entirely. An AS that advertises no grant_types_supported gets the
// full wish list.
func registrationGrantTypes(advertised []string) []string {
	wanted := []string{"authorization_code", "client_credentials"}
	if len(advertised) == 0 {
		return wanted
	}
	has := map[string]bool{}
	for _, g := range advertised {
		has[g] = true
	}
	var out []string
	for _, g := range wanted {
		if has[g] {
			out = append(out, g)
		}
	}
	return out
}

// registrationApplicationType classifies the client for SEP-837: a loopback or
// custom-scheme redirect is a native client, anything else is a web client.
func registrationApplicationType(redirectURIs []string) string {
	for _, raw := range redirectURIs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "native" // private-use URI scheme
		}
		host := u.Hostname()
		if host == "localhost" || host == "::1" {
			return "native"
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return "native"
		}
		return "web"
	}
	return "native"
}

// ResolveOptions carries the explicit (CLI) inputs to resolution.
type ResolveOptions struct {
	ClientID          string
	ClientSecret      string
	TokenAuthMethod   string   // explicit --token-auth-method
	RegistrationToken string   // --registration-token (RFC 7591 initial access token)
	ClientName        string   // --client-name (RFC 7591 client_name); omit from DCR when empty
	Scopes            []string // explicit --scope
	RedirectURIs      []string // for DCR; the auth-code callback URI when known
}

// Resolve computes the AuthPlan once, after discovery. Field selection is pure;
// the only side effect is DCR (when no client is supplied and a
// registration_endpoint is advertised). DCR failure is non-fatal: the plan is
// returned without a client, carrying RegistrationError so the run can report
// why rather than silently skipping every client-dependent check.
func Resolve(ctx context.Context, client *http.Client, d Discovered, opts ResolveOptions) (AuthPlan, error) {
	if client == nil {
		client = http.DefaultClient
	}
	plan := AuthPlan{
		ClientID:        opts.ClientID,
		ClientSecret:    opts.ClientSecret,
		TokenAuthMethod: resolveTokenAuthMethod(opts.TokenAuthMethod, d.TokenEndpointAuthMethodsSupported, opts.ClientSecret != ""),
		Scopes:          EffectiveScopes(opts.Scopes, d.PRMScopesSupported),
		UsePAR:          d.RequirePushedAuthorizationRequests,
		PAREndpoint:     d.PushedAuthorizationRequestEndpoint,
	}
	plan.DPoPRequired = d.PRMDPoPBoundAccessTokensRequired

	// only register a client when none was supplied and the AS advertises a
	// registration endpoint.
	if plan.ClientID == "" && d.RegistrationEndpoint != "" {
		redirects := opts.RedirectURIs
		if len(redirects) == 0 {
			redirects = []string{defaultRedirectURI}
		}
		res, err := probe.Register(ctx, client, probe.RegisterInput{
			RegistrationEndpoint:    d.RegistrationEndpoint,
			RedirectURIs:            redirects,
			GrantTypes:              registrationGrantTypes(d.GrantTypesSupported),
			TokenEndpointAuthMethod: plan.TokenAuthMethod,
			Scope:                   strings.Join(plan.Scopes, " "),
			ApplicationType:         registrationApplicationType(redirects),
			ClientName:              opts.ClientName,
			InitialAccessToken:      opts.RegistrationToken,
		})
		if err != nil {
			plan.RegistrationError = err.Error()
			var re *probe.RegistrationError
			if errors.As(err, &re) {
				plan.RegistrationEvidence = re.Evidence
			}
			return plan, nil // non-fatal: continue without a client
		}
		plan.ClientID = res.ClientID
		plan.ClientSecret = res.ClientSecret
		plan.TokenAuthMethod = registeredAuthMethod(opts.TokenAuthMethod, res, d.TokenEndpointAuthMethodsSupported)
		plan.Registered = true
		plan.RegistrationAccessToken = res.RegistrationAccessToken
		plan.RegistrationClientURI = res.RegistrationClientURI
		plan.RegisteredApplicationType = res.ApplicationType
		plan.RegistrationEvidence = res.Evidence
	}
	return plan, nil
}

// registeredAuthMethod settles how to authenticate the client the AS just
// issued. The AS's echoed token_endpoint_auth_method is authoritative for that
// client; otherwise re-resolve, now that whether a secret came back is known.
func registeredAuthMethod(explicit string, res *probe.RegisterResult, advertised []string) string {
	if explicit != "" {
		return explicit
	}
	if probe.ImplementsClientAuth(res.TokenEndpointAuthMethod) {
		return res.TokenEndpointAuthMethod
	}
	return resolveTokenAuthMethod("", advertised, res.ClientSecret != "")
}
