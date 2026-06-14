package conformance

// Registry is an ordered collection of checks.
type Registry struct {
	checks []Check
}

func (r *Registry) Add(c ...Check) { r.checks = append(r.checks, c...) }

func (r *Registry) Checks() []Check { return r.checks }

// FilterProfiles returns a registry limited to the given profiles (nil = all).
func (r *Registry) FilterProfiles(profiles ...Profile) *Registry {
	if len(profiles) == 0 {
		return r
	}
	want := map[Profile]bool{}
	for _, p := range profiles {
		want[p] = true
	}
	out := &Registry{}
	for _, c := range r.checks {
		if want[c.Profile] {
			out.Add(c)
		}
	}
	return out
}

// DefaultRegistry is assembled from each checks_*.go file's register func.
// Each Task 14-21 appends its register call here.
func DefaultRegistry() *Registry {
	r := &Registry{}
	registerRFC9728(r)
	registerRFC8414(r)
	registerPKCE(r)
	registerRFC8707(r)
	registerOAuth21(r)
	registerRFC8693(r)
	registerDPoP(r)
	registerSmoke(r)
	return r
}
