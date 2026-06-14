package conformance

import "testing"

func TestCheckSkipsWhenPreconditionFalse(t *testing.T) {
	c := Check{
		ID:           "test.always_skip",
		Precondition: func(*Target) bool { return false },
		Run:          func(_ *Target) Result { return Result{Status: StatusPass} },
	}
	if got := c.Evaluate(&Target{}); got.Status != StatusSkip {
		t.Fatalf("want skip when precondition false, got %s", got.Status)
	}
}

func TestCheckRunsWhenPreconditionTrue(t *testing.T) {
	c := Check{
		ID:           "test.runs",
		Precondition: func(*Target) bool { return true },
		Run:          func(_ *Target) Result { return Result{Status: StatusFail, Message: "boom"} },
	}
	if got := c.Evaluate(&Target{}); got.Status != StatusFail || got.Message != "boom" {
		t.Fatalf("want fail/boom, got %s/%s", got.Status, got.Message)
	}
}

func TestCheckNilPreconditionAlwaysRuns(t *testing.T) {
	c := Check{ID: "test.no_precond", Run: func(*Target) Result { return Result{Status: StatusPass} }}
	if got := c.Evaluate(&Target{}); got.Status != StatusPass {
		t.Fatalf("nil precondition should run; got %s", got.Status)
	}
}
