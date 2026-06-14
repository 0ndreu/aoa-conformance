package probe

import "net/url"

const GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"

// ExchangeInput describes an RFC 8693 token-exchange request to build. Leaving
// ActorToken empty produces an impersonation request; setting it produces a
// delegation request.
type ExchangeInput struct {
	SubjectToken       string
	SubjectTokenType   string // short form; expanded to the urn:...:token-type:* URI
	ActorToken         string
	ActorTokenType     string
	Audience           []string
	Resource           []string
	Scope              []string
	RequestedTokenType string
}

func tokenTypeURI(short string) string {
	if short == "" {
		return ""
	}
	return "urn:ietf:params:oauth:token-type:" + short
}

// ExchangeForm builds the form body for the token-exchange request.
func ExchangeForm(in ExchangeInput) url.Values {
	v := url.Values{}
	v.Set("grant_type", GrantTokenExchange)
	v.Set("subject_token", in.SubjectToken)
	if t := tokenTypeURI(in.SubjectTokenType); t != "" {
		v.Set("subject_token_type", t)
	}
	if in.ActorToken != "" {
		v.Set("actor_token", in.ActorToken)
		if t := tokenTypeURI(in.ActorTokenType); t != "" {
			v.Set("actor_token_type", t)
		}
	}
	for _, a := range in.Audience {
		v.Add("audience", a)
	}
	for _, r := range in.Resource {
		v.Add("resource", r)
	}
	if len(in.Scope) > 0 {
		v.Set("scope", joinSpace(in.Scope))
	}
	if t := tokenTypeURI(in.RequestedTokenType); t != "" {
		v.Set("requested_token_type", t)
	}
	return v
}

func joinSpace(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}
