// Package probe performs the raw HTTP + JOSE work the conformance checks need,
// including deliberately malformed requests. It depends on jwx directly so it
// can craft adversarial tokens and proofs; aoa is not used here.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Response is an HTTP response captured for inspection + offline evidence.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Evidence   []byte // human-readable "METHOD url\n\nstatus\nheaders\n\nbody"
	json       map[string]any
}

// JSON lazily parses the body as a JSON object (empty map on failure).
func (r *Response) JSON() map[string]any {
	if r.json == nil {
		r.json = map[string]any{}
		_ = json.Unmarshal(r.Body, &r.json)
	}
	return r.json
}

// PostForm posts a form body and captures the response. extraHeaders may carry
// e.g. a DPoP proof or an Authorization header.
func PostForm(ctx context.Context, c *http.Client, endpoint string, form url.Values, extraHeaders http.Header) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, vs := range extraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return do(c, req, fmt.Sprintf("POST %s\nform: %s", endpoint, form.Encode()))
}

// Get fetches a URL (used for metadata documents).
func Get(ctx context.Context, c *http.Client, u string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return do(c, req, "GET "+u)
}

// GetWithHeaders fetches a URL with extra headers (e.g. an Authorization bearer
// header for the --present smoke check).
func GetWithHeaders(ctx context.Context, c *http.Client, u string, extraHeaders http.Header) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for k, vs := range extraHeaders {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return do(c, req, "GET "+u)
}

func do(c *http.Client, req *http.Request, reqLine string) (*Response, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap

	var ev bytes.Buffer
	fmt.Fprintf(&ev, "%s\n\nHTTP %d\n", reqLine, resp.StatusCode)
	for k, v := range resp.Header {
		fmt.Fprintf(&ev, "%s: %s\n", k, strings.Join(v, ", "))
	}
	fmt.Fprintf(&ev, "\n%s\n", body)

	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		Evidence:   ev.Bytes(),
	}, nil
}

// FormString is a convenience for building url.Values one-liners in checks.
func FormString(pairs ...string) url.Values {
	v := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		v.Set(pairs[i], pairs[i+1])
	}
	return v
}
