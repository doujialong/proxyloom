package healthstore

import (
	"testing"
	"time"
)

func TestApplyTransitionFailureAndRecoverySchedule(t *testing.T) {
	now := time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)
	state := Transition{State: StateUnchecked}
	failure := ProbeResult{
		Class: ResultConnectTimeout, NodeAttributable: true,
		ExecutorID: "sing-box", ExecutorVersion: "1.12.25", Total: time.Second,
	}
	wantDelays := []time.Duration{time.Minute, 5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 30 * time.Minute, time.Hour}
	for index, delay := range wantDelays {
		state = ApplyTransition(TransitionInput{
			State: state.State, ConsecutiveSuccesses: state.ConsecutiveSuccesses,
			ConsecutiveFailures: state.ConsecutiveFailures, RecoveryStep: state.RecoveryStep,
			Result: failure, Now: now,
		})
		if state.NextCheckAt == nil || !state.NextCheckAt.Equal(now.Add(delay)) {
			t.Fatalf("failure %d next = %v, want %v", index+1, state.NextCheckAt, now.Add(delay))
		}
		if index < 2 && state.State != StateDegraded || index >= 2 && state.State != StateUnhealthy {
			t.Fatalf("failure %d state = %s", index+1, state.State)
		}
	}
	success := ProbeResult{
		Class: ResultSuccess, Success: true,
		ExecutorID: "sing-box", ExecutorVersion: "1.12.25", Total: time.Second,
	}
	state = ApplyTransition(TransitionInput{
		State: state.State, ConsecutiveFailures: state.ConsecutiveFailures,
		Result: success, Now: now,
	})
	if state.State != StateDegraded || state.RecoveryStep != 1 || state.NextCheckAt == nil || !state.NextCheckAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("first recovery = %+v", state)
	}
	state = ApplyTransition(TransitionInput{
		State: state.State, ConsecutiveSuccesses: state.ConsecutiveSuccesses,
		RecoveryStep: state.RecoveryStep, Result: success, Now: now.Add(2 * time.Minute),
	})
	if state.State != StateHealthy || state.RecoveryStep != 0 || state.NextCheckAt == nil || !state.NextCheckAt.Equal(now.Add(32*time.Minute)) {
		t.Fatalf("confirmed recovery = %+v", state)
	}
}

func TestApplyTransitionInfrastructureAndUnsupported(t *testing.T) {
	now := time.Date(2026, 7, 18, 8, 0, 0, 0, time.UTC)
	infrastructure := ApplyTransition(TransitionInput{
		State: StateHealthy, ConsecutiveSuccesses: 4,
		Result: ProbeResult{
			Class: ResultExecutorCrash, ExecutorID: "sing-box",
			ExecutorVersion: "1.12.25", Total: time.Second,
		},
		Now: now,
	})
	if infrastructure.State != StateHealthy || infrastructure.ConsecutiveFailures != 0 || infrastructure.NextCheckAt == nil || !infrastructure.NextCheckAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("infrastructure transition = %+v", infrastructure)
	}
	unsupported := ApplyTransition(TransitionInput{
		State: StateUnchecked,
		Result: ProbeResult{
			Class: ResultUnsupported, ExecutorID: "sing-box",
			ExecutorVersion: "1.12.25", Total: 0,
		},
		Now: now,
	})
	if unsupported.State != StateUnsupported || unsupported.NextCheckAt != nil {
		t.Fatalf("unsupported transition = %+v", unsupported)
	}
}
