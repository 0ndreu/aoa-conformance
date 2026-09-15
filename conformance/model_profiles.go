package conformance

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ModelSurface is one client surface (e.g. claude.ai) whose known auth
// requirements are mapped onto the conformance checks.
type ModelSurface struct {
	Name       string             `yaml:"name" json:"name"`
	Vendor     string             `yaml:"vendor" json:"vendor"`
	Display    string             `yaml:"display" json:"display"`
	Note       string             `yaml:"note,omitempty" json:"note,omitempty"`
	Unscorable bool               `yaml:"unscorable,omitempty" json:"unscorable,omitempty"`
	Requires   []ModelRequirement `yaml:"requires" json:"requires"`
}

// ModelRequirement is either a single slug (ID) or an any-of group (AnyOf);
// exactly one must be set. Slugs resolve to a Check.RFC label via labelAlias.
type ModelRequirement struct {
	ID          string   `yaml:"id,omitempty" json:"id,omitempty"`
	AnyOf       []string `yaml:"any_of,omitempty" json:"any_of,omitempty"`
	Criticality string   `yaml:"criticality" json:"criticality"`
	Rationale   string   `yaml:"rationale" json:"rationale"`
	Source      string   `yaml:"source" json:"source"`
	SourceRank  string   `yaml:"rank" json:"rank"`
}

// Profiles is the parsed model_profiles.yaml corpus.
type Profiles struct {
	Version  int            `yaml:"version"`
	DataDate string         `yaml:"data_date"`
	Surfaces []ModelSurface `yaml:"surfaces"`
}

// labelAlias binds each requirement slug to the exact Check.RFC label it joins
// on. It defines the slug vocabulary; the guard test asserts every value is a
// label DefaultRegistry() actually emits.
var labelAlias = map[string]string{
	"oauth-2.1": "OAuth 2.1",
	"rfc-7636":  "RFC 7636 (PKCE)",
	"rfc-8414":  "RFC 8414",
	"rfc-8707":  "RFC 8707",
	"rfc-9728":  "RFC 9728",
	"cimd":      "CIMD",
	"sep-837":   "SEP-837",
}

func resolveLabel(slug string) (string, bool) {
	l, ok := labelAlias[slug]
	return l, ok
}

// KnownLabels returns the set of non-empty Check.RFC labels a registry emits.
func KnownLabels(reg *Registry) map[string]bool {
	known := map[string]bool{}
	for _, c := range reg.Checks() {
		if c.RFC != "" {
			known[c.RFC] = true
		}
	}
	return known
}

// LoadProfiles parses the model-profiles YAML and validates every surface and
// requirement. known is the set of Check.RFC labels the active registry emits.
func LoadProfiles(data []byte, known map[string]bool) (*Profiles, error) {
	var p Profiles
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse model profiles: %w", err)
	}
	seen := map[string]bool{}
	for i := range p.Surfaces {
		s := &p.Surfaces[i]
		if s.Name == "" {
			return nil, fmt.Errorf("surface %d: name is empty", i)
		}
		if seen[s.Name] {
			return nil, fmt.Errorf("surface %q: duplicate name", s.Name)
		}
		seen[s.Name] = true
		for _, r := range s.Requires {
			if err := validateRequirement(r, s.Name, known); err != nil {
				return nil, err
			}
		}
	}
	return &p, nil
}

func validateRequirement(r ModelRequirement, surface string, known map[string]bool) error {
	hasID := r.ID != ""
	hasAny := len(r.AnyOf) > 0
	if hasID == hasAny {
		return fmt.Errorf("surface %q: requirement must set exactly one of id / any_of", surface)
	}
	slugs := r.AnyOf
	if hasID {
		slugs = []string{r.ID}
	}
	for _, slug := range slugs {
		label, ok := resolveLabel(slug)
		if !ok {
			return fmt.Errorf("surface %q: unknown requirement slug %q", surface, slug)
		}
		if !known[label] {
			return fmt.Errorf("surface %q: slug %q resolves to label %q which no registered check emits", surface, slug, label)
		}
	}
	switch r.Criticality {
	case "mandatory", "optional":
	default:
		return fmt.Errorf("surface %q: requirement %q has invalid criticality %q", surface, reqName(r), r.Criticality)
	}
	switch r.SourceRank {
	case "primary", "secondary", "observed":
	default:
		return fmt.Errorf("surface %q: requirement %q has invalid rank %q", surface, reqName(r), r.SourceRank)
	}
	return nil
}

//go:embed model_profiles.yaml
var defaultProfilesYAML []byte

// reqName renders a requirement's slug identity for messages and terse output.
func reqName(r ModelRequirement) string {
	if r.ID != "" {
		return r.ID
	}
	return "any_of[" + strings.Join(r.AnyOf, ",") + "]"
}

// DefaultProfiles parses the embedded corpus against the labels the default
// registry emits.
func DefaultProfiles() (*Profiles, error) {
	return LoadProfiles(defaultProfilesYAML, KnownLabels(DefaultRegistry()))
}

// SelectSurfaces resolves a list of surface names (or the single token "all") to
// surfaces from p. An unknown name is an error that names it and lists the
// available surfaces.
func SelectSurfaces(p *Profiles, names []string) ([]ModelSurface, error) {
	if len(names) == 1 && names[0] == "all" {
		return p.Surfaces, nil
	}
	byName := map[string]ModelSurface{}
	avail := make([]string, 0, len(p.Surfaces))
	for _, s := range p.Surfaces {
		byName[s.Name] = s
		avail = append(avail, s.Name)
	}
	out := make([]ModelSurface, 0, len(names))
	for _, n := range names {
		s, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("unknown --model %q; available: %s", n, strings.Join(avail, ", "))
		}
		out = append(out, s)
	}
	return out, nil
}
