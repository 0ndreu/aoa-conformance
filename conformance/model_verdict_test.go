package conformance

import "testing"

func entry(id, rfc string, st Status) Entry {
	return Entry{Check: Check{ID: CheckID(id), RFC: rfc, Severity: SeverityMUST}, Result: Result{Status: st}}
}

// advisoryEntry is a check whose severity is SHOULD: a shortfall there is a
// caveat, not an incompatibility.
func advisoryEntry(id, rfc string, st Status) Entry {
	return Entry{Check: Check{ID: CheckID(id), RFC: rfc, Severity: SeveritySHOULD}, Result: Result{Status: st}}
}

func skipEntry(id, rfc string, sev Severity, kind SkipKind) Entry {
	return Entry{Check: Check{ID: CheckID(id), RFC: rfc, Severity: sev},
		Result: Result{Status: StatusSkip, SkipKind: kind, Message: "why"}}
}

func mandatory(id string) ModelRequirement {
	return ModelRequirement{ID: id, Criticality: "mandatory", SourceRank: "primary"}
}

func TestEvaluateModels(t *testing.T) {
	// all mandatory pass => aligned
	rep := Report{Entries: []Entry{entry("a", "RFC 9728", StatusPass), entry("b", "RFC 8707", StatusPass)}}
	surf := ModelSurface{Name: "s", Requires: []ModelRequirement{mandatory("rfc-9728"), mandatory("rfc-8707")}}
	if v := EvaluateModels(rep, "2026-09-05", []ModelSurface{surf})[0]; v.Verdict != "aligned" {
		t.Fatalf("all-pass: got %q, reasons %+v", v.Verdict, v.Reasons)
	}

	// a mandatory MUST fail => not-aligned, reason names the requirement
	repFail := Report{Entries: []Entry{entry("a", "RFC 9728", StatusFail)}}
	surf1 := ModelSurface{Name: "s", Requires: []ModelRequirement{mandatory("rfc-9728")}}
	v := EvaluateModels(repFail, "2026-09-05", []ModelSurface{surf1})[0]
	if v.Verdict != "not-aligned" || len(v.Reasons) != 1 || v.Reasons[0].Requirement.ID != "rfc-9728" {
		t.Fatalf("mandatory-fail: got %q, reasons %+v", v.Verdict, v.Reasons)
	}
	if v.DataDate != "2026-09-05" {
		t.Fatalf("DataDate not stamped: %q", v.DataDate)
	}

	// mandatory only skipped for want of a credential => inconclusive
	repSkip := Report{Entries: []Entry{skipEntry("a", "RFC 9728", SeverityMUST, SkipUntested)}}
	if got := EvaluateModels(repSkip, "d", []ModelSurface{surf1})[0].Verdict; got != "inconclusive" {
		t.Fatalf("only-untested: got %q", got)
	}

	// mandatory not run at all => inconclusive
	if got := EvaluateModels(Report{}, "d", []ModelSurface{surf1})[0].Verdict; got != "inconclusive" {
		t.Fatalf("not-run: got %q", got)
	}

	// any_of met when one member passes though the other is absent
	repAny := Report{Entries: []Entry{entry("c", "SEP-837", StatusPass)}}
	surfAny := ModelSurface{Name: "s", Requires: []ModelRequirement{{AnyOf: []string{"cimd", "sep-837"}, Criticality: "mandatory", SourceRank: "primary"}}}
	if got := EvaluateModels(repAny, "d", []ModelSurface{surfAny})[0].Verdict; got != "aligned" {
		t.Fatalf("any_of one-pass: got %q", got)
	}

	// any_of unmet only when all members fail
	repAllFail := Report{Entries: []Entry{entry("c", "CIMD", StatusFail), entry("d", "SEP-837", StatusFail)}}
	if got := EvaluateModels(repAllFail, "d", []ModelSurface{surfAny})[0].Verdict; got != "not-aligned" {
		t.Fatalf("any_of all-fail: got %q", got)
	}

	// optional fail => aligned with an inline caveat
	surfOpt := ModelSurface{Name: "s", Requires: []ModelRequirement{{ID: "rfc-8707", Criticality: "optional", SourceRank: "secondary"}}}
	vOpt := EvaluateModels(Report{Entries: []Entry{entry("a", "RFC 8707", StatusFail)}}, "d", []ModelSurface{surfOpt})[0]
	if vOpt.Verdict != "aligned" || len(vOpt.Caveats) != 1 {
		t.Fatalf("optional-fail: got %q, caveats %+v", vOpt.Verdict, vOpt.Caveats)
	}

	// unscorable => n/a
	if got := EvaluateModels(Report{}, "d", []ModelSurface{{Name: "s", Unscorable: true}})[0].Verdict; got != "n/a" {
		t.Fatalf("unscorable: got %q", got)
	}

	// empty requires => aligned
	if got := EvaluateModels(Report{}, "d", []ModelSurface{{Name: "s"}})[0].Verdict; got != "aligned" {
		t.Fatalf("empty-requires: got %q", got)
	}
}

// TestSHOULDFailureIsCaveatNotIncompatibility is the Linear case: a shipping
// connector was called not-aligned for three agents because one SHOULD-level
// RFC 8414 check (jwks_uri missing) failed alongside passing MUST checks.
func TestSHOULDFailureIsCaveatNotIncompatibility(t *testing.T) {
	rep := Report{Entries: []Entry{
		entry("rfc8414.metadata.fetchable", "RFC 8414", StatusPass),
		advisoryEntry("rfc8414.metadata.jwks_uri", "RFC 8414", StatusFail),
	}}
	surf := ModelSurface{Name: "claude-web", Requires: []ModelRequirement{mandatory("rfc-8414")}}
	v := EvaluateModels(rep, "d", []ModelSurface{surf})[0]
	if v.Verdict != "aligned" {
		t.Fatalf("SHOULD-level shortfall sank the verdict: got %q, reasons %+v", v.Verdict, v.Reasons)
	}
	if len(v.Caveats) != 1 || !v.Caveats[0].Advisory {
		t.Fatalf("expected one advisory caveat, got %+v", v.Caveats)
	}
	if got := verdictSummary(v); got != "(rfc-8414 met with a SHOULD/MAY shortfall)" {
		t.Fatalf("caveat rendering: %q", got)
	}
}

// TestSkipKindSeparatesUnmetFromInconclusive: a capability the server does not
// offer is an answer; a check we could not drive for want of a credential is
// not, and must never produce not-aligned.
func TestSkipKindSeparatesUnmetFromInconclusive(t *testing.T) {
	surf := ModelSurface{Name: "s", Requires: []ModelRequirement{mandatory("rfc-9728")}}

	unsupported := Report{Entries: []Entry{skipEntry("rfc9728.prm.fetchable", "RFC 9728", SeverityMUST, SkipUnsupported)}}
	v := EvaluateModels(unsupported, "d", []ModelSurface{surf})[0]
	if v.Verdict != "not-aligned" {
		t.Fatalf("absent MUST capability: got %q", v.Verdict)
	}
	if want := "rfc9728.prm.fetchable=skip:unsupported"; v.Reasons[0].Detail != want {
		t.Fatalf("detail should carry the skip kind: got %q, want %q", v.Reasons[0].Detail, want)
	}

	untested := Report{Entries: []Entry{skipEntry("rfc9728.prm.fetchable", "RFC 9728", SeverityMUST, SkipUntested)}}
	if got := EvaluateModels(untested, "d", []ModelSurface{surf})[0].Verdict; got != "inconclusive" {
		t.Fatalf("withheld credential must never be not-aligned: got %q", got)
	}
}

// TestAdvisoryCapabilityAbsenceDoesNotSinkVerdict: the RFC 8707 probes mint
// their own client_credentials token. An AS that does not offer that grant
// tells us nothing about resource indicators, so the run stays inconclusive.
func TestAdvisoryCapabilityAbsenceDoesNotSinkVerdict(t *testing.T) {
	rep := Report{Entries: []Entry{
		skipEntry("rfc8707.token.accepts_resource", "RFC 8707", SeveritySHOULD, SkipUntested),
		skipEntry("rfc8707.token.multiple_resources", "RFC 8707", SeverityMAY, SkipUntested),
	}}
	surf := ModelSurface{Name: "chatgpt", Requires: []ModelRequirement{mandatory("rfc-8707")}}
	if got := EvaluateModels(rep, "d", []ModelSurface{surf})[0].Verdict; got != "inconclusive" {
		t.Fatalf("undrivable probe: got %q", got)
	}
}
