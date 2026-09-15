package probe

import "context"

// StepUpResult is the granted scope of each round of a step-up flow.
type StepUpResult struct {
	FirstScope  string
	SecondScope string
}

// RunStepUp runs two interactive authorization rounds against the same client.
// The first requests baseScopes; the second requests baseScopes plus addedScopes
// (the step-up). It returns each round's granted scope so the caller can assert
// the second token accumulated the added scope. Each round binds its own
// callback listener.
func RunStepUp(ctx context.Context, cfg AuthCodeConfig, baseScopes, addedScopes []string) (StepUpResult, error) {
	first := cfg
	first.Scopes = baseScopes
	first.Listener = nil
	r1, err := RunAuthCode(ctx, first)
	if err != nil {
		return StepUpResult{}, err
	}
	second := cfg
	second.Scopes = append(append([]string{}, baseScopes...), addedScopes...)
	second.Listener = nil
	r2, err := RunAuthCode(ctx, second)
	if err != nil {
		return StepUpResult{}, err
	}
	return StepUpResult{FirstScope: r1.GrantedScope, SecondScope: r2.GrantedScope}, nil
}
