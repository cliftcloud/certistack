// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package probe

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Expired is what a probe checks before accepting a success.
func TestExpired(t *testing.T) {
	if err := Expired(context.Background()); err != nil {
		t.Fatalf("live context: %v", err)
	}
	live, cancelLive := context.WithTimeout(context.Background(), time.Hour)
	defer cancelLive()
	if err := Expired(live); err != nil {
		t.Fatalf("context with an hour left: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Expired(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}

	// A deadline that has passed counts even before the context's own
	// timer has marked it done.
	past := deadlineOnly{deadline: time.Now().Add(-time.Millisecond)}
	if err := Expired(past); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("passed deadline: %v", err)
	}
}

// deadlineOnly is a context whose deadline has passed but which does not
// report itself done, as a real one can for a moment.
type deadlineOnly struct {
	context.Context
	deadline time.Time
}

func (d deadlineOnly) Deadline() (time.Time, bool) { return d.deadline, true }
func (d deadlineOnly) Err() error                  { return nil }
