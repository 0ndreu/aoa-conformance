package conformance

import (
	"context"
	"net/http"
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

// resolveTokenAuthMethod picks the token-endpoint auth method:
// explicit override > intersection(advertised, what we implement) > default.
// The default is client_secret_post, preserving prior behavior. Among methods
// we implement, post is preferred over basic.
func resolveTokenAuthMethod(explicit string, advertised []string) string {
	if explicit != "" {
		return explicit
	}
	has := map[string]bool{}
	for _, m := range advertised {
		has[m] = true
	}
	if has[probe.AuthClientSecretPost] {
		return probe.AuthClientSecretPost
	}
	if has[probe.AuthClientSecretBasic] {
		return probe.AuthClientSecretBasic
	}
	return probe.AuthClientSecretPost
}

// ResolveOptions carries the explicit (CLI) inputs to resolution.
type ResolveOptions struct {
	ClientID          string
	ClientSecret      string
	TokenAuthMethod   string   // explicit --token-auth-method
	RegistrationToken string   // --registration-token (RFC 7591 initial access token)
	Scopes            []string // explicit --scope
	RedirectURIs      []string // for DCR; the auth-code callback URI when known
}

// Resolve computes the AuthPlan once, after discovery. Field selection is pure;
// the only side effect is DCR (when no client is supplied and a
// registration_endpoint is advertised). DCR failure is non-fatal: the plan is
// returned without a client and client-dependent checks will skip.
func Resolve(ctx context.Context, client *http.Client, d Discovered, opts ResolveOptions) (AuthPlan, error) {
	if client == nil {
		client = http.DefaultClient
	}
	plan := AuthPlan{
		ClientID:        opts.ClientID,
		ClientSecret:    opts.ClientSecret,
		TokenAuthMethod: resolveTokenAuthMethod(opts.TokenAuthMethod, d.TokenEndpointAuthMethodsSupported),
		Scopes:          EffectiveScopes(opts.Scopes, d.PRMScopesSupported),
		UsePAR:          d.RequirePushedAuthorizationRequests,
		PAREndpoint:     d.PushedAuthorizationRequestEndpoint,
	}

	// only register a client when none was supplied and the AS advertises a
	// registration endpoint.
	if plan.ClientID == "" && d.RegistrationEndpoint != "" {
		res, err := probe.Register(ctx, client, probe.RegisterInput{
			RegistrationEndpoint:    d.RegistrationEndpoint,
			RedirectURIs:            opts.RedirectURIs,
			GrantTypes:              []string{"client_credentials", "authorization_code"},
			TokenEndpointAuthMethod: plan.TokenAuthMethod,
			Scope:                   strings.Join(plan.Scopes, " "),
			InitialAccessToken:      opts.RegistrationToken,
		})
		if err != nil {
			return plan, nil // non-fatal: continue without a client
		}
		plan.ClientID = res.ClientID
		plan.ClientSecret = res.ClientSecret
		plan.Registered = true
		plan.RegistrationAccessToken = res.RegistrationAccessToken
		plan.RegistrationClientURI = res.RegistrationClientURI
	}
	return plan, nil
}
