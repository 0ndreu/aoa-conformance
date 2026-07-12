package conformance

import "testing"

func TestResolveLabel(t *testing.T) {
	if got, ok := resolveLabel("rfc-9728"); !ok || got != "RFC 9728" {
		t.Fatalf("resolveLabel(rfc-9728) = %q,%v; want RFC 9728,true", got, ok)
	}
	if got, ok := resolveLabel("rfc-7636"); !ok || got != "RFC 7636 (PKCE)" {
		t.Fatalf("resolveLabel(rfc-7636) = %q,%v; want RFC 7636 (PKCE),true", got, ok)
	}
	if _, ok := resolveLabel("nope"); ok {
		t.Fatalf("resolveLabel(nope) should be !ok")
	}
}

func TestKnownLabels(t *testing.T) {
	known := KnownLabels(DefaultRegistry())
	if !known["RFC 9728"] {
		t.Fatalf("KnownLabels missing RFC 9728")
	}
}

const validYAML = `
version: 1
data_date: "2026-07-06"
surfaces:
  - name: s1
    vendor: V
    display: D
    requires:
      - id: rfc-9728
        criticality: mandatory
        rationale: r
        source: https://example/1
        rank: primary
      - any_of: [rfc-7636, rfc-8414]
        criticality: optional
        rationale: r
        source: https://example/2
        rank: secondary
`

func testKnown() map[string]bool {
	return map[string]bool{"RFC 9728": true, "RFC 7636 (PKCE)": true, "RFC 8414": true}
}

func TestLoadProfiles_Valid(t *testing.T) {
	p, err := LoadProfiles([]byte(validYAML), testKnown())
	if err != nil {
		t.Fatalf("valid YAML errored: %v", err)
	}
	if p.DataDate != "2026-07-06" || len(p.Surfaces) != 1 || len(p.Surfaces[0].Requires) != 2 {
		t.Fatalf("parsed shape wrong: %+v", p)
	}
}

func TestLoadProfiles_Errors(t *testing.T) {
	cases := map[string]string{
		"unknown slug": `
surfaces: [{name: s, vendor: v, display: d, requires: [{id: rfc-9999, criticality: mandatory, rationale: r, source: x, rank: primary}]}]`,
		"slug resolves to unregistered label": `
surfaces: [{name: s, vendor: v, display: d, requires: [{id: sep-837, criticality: mandatory, rationale: r, source: x, rank: primary}]}]`,
		"both id and any_of": `
surfaces: [{name: s, vendor: v, display: d, requires: [{id: rfc-9728, any_of: [rfc-7636], criticality: mandatory, rationale: r, source: x, rank: primary}]}]`,
		"neither id nor any_of": `
surfaces: [{name: s, vendor: v, display: d, requires: [{criticality: mandatory, rationale: r, source: x, rank: primary}]}]`,
		"bad criticality": `
surfaces: [{name: s, vendor: v, display: d, requires: [{id: rfc-9728, criticality: nope, rationale: r, source: x, rank: primary}]}]`,
		"bad rank": `
surfaces: [{name: s, vendor: v, display: d, requires: [{id: rfc-9728, criticality: mandatory, rationale: r, source: x, rank: nope}]}]`,
		"empty name": `
surfaces: [{vendor: v, display: d, requires: []}]`,
		"duplicate name": `
surfaces:
  - {name: dup, vendor: v, display: d, requires: []}
  - {name: dup, vendor: v, display: d, requires: []}`,
	}
	for name, y := range cases {
		if _, err := LoadProfiles([]byte(y), testKnown()); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
