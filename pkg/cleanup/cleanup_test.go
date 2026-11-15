// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package cleanup

import (
	"errors"
	"sync/atomic"
	"testing"
)

func TestStack_LIFOOrder(t *testing.T) {
	s := New()
	var executed []string

	s.Push("step1", func() error {
		executed = append(executed, "step1")
		return nil
	})
	s.Push("step2", func() error {
		executed = append(executed, "step2")
		return nil
	})
	s.Push("step3", func() error {
		executed = append(executed, "step3")
		return nil
	})

	if s.Len() != 3 {
		t.Fatalf("expected length 3, got %d", s.Len())
	}

	if errs := s.Unwind(); len(errs) != 0 {
		t.Fatalf("unexpected cleanup errors: %v", errs)
	}

	if len(executed) != 3 {
		t.Fatalf("expected 3 executed steps, got %d", len(executed))
	}
	if executed[0] != "step3" || executed[1] != "step2" || executed[2] != "step1" {
		t.Errorf("expected reverse order [step3, step2, step1], got %v", executed)
	}

	if s.Len() != 0 {
		t.Errorf("expected stack length 0 after unwind, got %d", s.Len())
	}
}

func TestStack_ErrorContinuation(t *testing.T) {
	s := New()
	var executed []string

	s.Push("step1", func() error {
		executed = append(executed, "step1")
		return nil
	})
	s.Push("step_fail", func() error {
		executed = append(executed, "step_fail")
		return errors.New("something broke")
	})
	s.Push("step2", func() error {
		executed = append(executed, "step2")
		return nil
	})

	errs := s.Unwind()
	if len(errs) != 1 || errs[0].Step != "step_fail" {
		t.Fatalf("expected recorded failure for step_fail, got: %v", errs)
	}

	if len(executed) != 3 {
		t.Fatalf("expected all 3 steps to run despite error, got %d", len(executed))
	}
	if executed[0] != "step2" || executed[1] != "step_fail" || executed[2] != "step1" {
		t.Errorf("expected [step2, step_fail, step1], got %v", executed)
	}
}

func TestStack_Idempotent(t *testing.T) {
	s := New()
	var count int32

	s.Push("step1", func() error {
		atomic.AddInt32(&count, 1)
		return nil
	})

	s.Unwind()
	if errs := s.Unwind(); len(errs) != 0 {
		t.Fatalf("expected no errors from an already-drained stack, got: %v", errs)
	}

	if atomic.LoadInt32(&count) != 1 {
		t.Errorf("expected step to run exactly once, got %d", count)
	}
}

func TestStack_PanicRecovery(t *testing.T) {
	s := New()
	var executed []string

	s.Push("step1", func() error {
		executed = append(executed, "step1")
		return nil
	})
	s.Push("step_panic", func() error {
		executed = append(executed, "step_panic")
		panic("catastrophic failure during cleanup")
	})
	s.Push("step2", func() error {
		executed = append(executed, "step2")
		return nil
	})

	errs := s.Unwind()
	if len(errs) != 1 || errs[0].Step != "step_panic" {
		t.Fatalf("expected recorded panic for step_panic, got: %v", errs)
	}

	if len(executed) != 3 {
		t.Fatalf("expected all 3 steps to execute despite panic, got %d: %v", len(executed), executed)
	}
	if executed[0] != "step2" || executed[1] != "step_panic" || executed[2] != "step1" {
		t.Errorf("expected [step2, step_panic, step1], got %v", executed)
	}
}

func TestStack_NoDeadlockOnCallbackInteraction(t *testing.T) {
	s := New()
	var ran bool

	s.Push("nested", func() error {
		// Pushing or checking Len() while unwind is executing must not deadlock
		if s.Len() != 0 {
			t.Errorf("expected 0 remaining steps during last callback, got %d", s.Len())
		}
		s.Push("new_deferred", func() error { return nil })
		ran = true
		return nil
	})

	s.Unwind()

	if !ran {
		t.Fatalf("callback did not execute")
	}
	if s.Len() != 1 {
		t.Errorf("expected newly pushed step to exist, got length %d", s.Len())
	}
	// Second unwind drains the new step
	s.Unwind()
	if s.Len() != 0 {
		t.Errorf("expected 0 steps after second unwind, got %d", s.Len())
	}
}
