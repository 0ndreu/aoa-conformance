package conformance

import "testing"

func entry(id, rfc string, st Status) Entry {
	return Entry{Check: Check{ID: CheckID(id), RFC: rfc}, Result: Result{Status: st}}
}

func mandatory(id string) ModelRequirement {
	return ModelRequirement{ID: id, Criticality: "mandatory", SourceRank: "primary"}
}

func TestEvaluateModels(t *testing.T) {
	// all mandatory pass => aligned
	rep := Report{Entries: []Entry{entry("a", "RFC 9728", StatusPass), entry("b", "RFC 8707", StatusPass)}}
	surf := ModelSurface{Name: "s", Requires: []ModelRequirement{mandatory("rfc-9728"), mandatory("rfc-8707")}}
	if v := EvaluateModels(rep, "2026-07-06", []ModelSurface{surf})[0]; v.Verdict != "aligned" {
		t.Fatalf("all-pass: got %q, reasons %+v", v.Verdict, v.Reasons)
	}

	// a mandatory fail => not-aligned, reason names the requirement
	repFail := Report{Entries: []Entry{entry("a", "RFC 9728", StatusFail)}}
	surf1 := ModelSurface{Name: "s", Requires: []ModelRequirement{mandatory("rfc-9728")}}
	v := EvaluateModels(repFail, "2026-07-06", []ModelSurface{surf1})[0]
	if v.Verdict != "not-aligned" || len(v.Reasons) != 1 || v.Reasons[0].Requirement.ID != "rfc-9728" {
		t.Fatalf("mandatory-fail: got %q, reasons %+v", v.Verdict, v.Reasons)
	}
	if v.DataDate != "2026-07-06" {
		t.Fatalf("DataDate not stamped: %q", v.DataDate)
	}

	// mandatory only skipped => inconclusive
	repSkip := Report{Entries: []Entry{entry("a", "RFC 9728", StatusSkip)}}
	if got := EvaluateModels(repSkip, "d", []ModelSurface{surf1})[0].Verdict; got != "inconclusive" {
		t.Fatalf("only-skip: got %q", got)
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
