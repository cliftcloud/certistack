// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// A run a signal stopped names the signal (not only "context canceled"),
// stays a cancellation for every caller, and keeps what the run was doing.
func TestWithInterruption(t *testing.T) {
	stopping := &InterruptedError{Signal: "SIGTERM", NodeStopping: true}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.Canceled, "interrupted: the node began shutting down (SIGTERM from systemd)"},
		{fmt.Errorf("recovery tier 1 (web) failed: %w", context.Canceled), "interrupted: the node began shutting down (SIGTERM from systemd); the run was at: recovery tier 1 (web) failed"},
	} {
		got := withInterruption(tc.err, stopping)
		if got.Error() != tc.want || !errors.Is(got, context.Canceled) {
			t.Errorf("%v: got %q (is canceled: %v), want %q", tc.err, got, errors.Is(got, context.Canceled), tc.want)
		}
		if again := withInterruption(got, stopping); again.Error() != got.Error() {
			t.Errorf("rewritten twice: %q", again)
		}
	}
	other := errors.New("probe failed")
	if got := withInterruption(other, stopping); got != other {
		t.Errorf("a failure that is not a cancellation was rewritten: %v", got)
	}
	if got := (&InterruptedError{Signal: "SIGINT"}).Error(); got != "interrupted by SIGINT" {
		t.Errorf("operator interrupt = %q", got)
	}
}

// Without a signal, a run's context reports no interruption, and stopping
// it twice is harmless.
func TestInterruptContextWithoutASignal(t *testing.T) {
	ctx, stop, interrupted := interruptContext(context.Background())
	if ctx.Err() != nil {
		t.Fatal("canceled at once")
	}
	if got := interrupted(); got != nil {
		t.Fatalf("interrupted = %v", got)
	}
	stop()
	if ctx.Err() == nil {
		t.Fatal("stop did not cancel the context")
	}
}
