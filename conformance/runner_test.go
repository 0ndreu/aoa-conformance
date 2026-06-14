package conformance

import (
	"testing"
	"time"
)

func TestRunnerRunsAllChecksAndTimesThem(t *testing.T) {
	reg := &Registry{}
	reg.Add(Check{ID: "x.pass", Profile: ProfileCore, RFC: "RFC X",
		Run: func(*Target) Result { return Result{Status: StatusPass} }})
	reg.Add(Check{ID: "x.skip", Profile: ProfileCore, RFC: "RFC X",
		Precondition: func(*Target) bool { return false },
		Run:          func(*Target) Result { return Result{Status: StatusPass} }})

	tgt := &Target{Issuer: "https://issuer.example"}
	rep := (&Runner{Registry: reg, SkipDiscovery: true}).Run(tgt)

	if len(rep.Entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(rep.Entries))
	}
	if rep.Target != "https://issuer.example" {
		t.Fatalf("target not recorded: %q", rep.Target)
	}
	s := rep.Summarize()
	if s.Pass != 1 || s.Skip != 1 {
		t.Fatalf("want 1 pass 1 skip, got %+v", s)
	}
}

func TestRunnerRecoversFromPanicAsError(t *testing.T) {
	reg := &Registry{}
	reg.Add(Check{ID: "x.panics", Profile: ProfileCore, RFC: "RFC X",
		Run: func(*Target) Result { panic("kaboom") }})
	rep := (&Runner{Registry: reg, SkipDiscovery: true}).Run(&Target{Issuer: "i"})
	if rep.Entries[0].Result.Status != StatusError {
		t.Fatalf("panic should become StatusError, got %s", rep.Entries[0].Result.Status)
	}
}

func TestRunnerStampsDuration(t *testing.T) {
	reg := &Registry{}
	reg.Add(Check{ID: "x.slow", Profile: ProfileCore, RFC: "RFC X",
		Run: func(*Target) Result { time.Sleep(time.Millisecond); return Result{Status: StatusPass} }})
	rep := (&Runner{Registry: reg, SkipDiscovery: true}).Run(&Target{Issuer: "i"})
	if rep.Entries[0].Result.Duration <= 0 {
		t.Fatal("duration not stamped")
	}
}
