// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package cleanup provides a stack of teardown steps for the resources a run
// creates.
package cleanup

import (
	"fmt"
	"log/slog"
	"sync"
)

// Stack holds the cleanup functions of ephemeral resources (loopback devices,
// COW files, VMs, SDN objects). They run in reverse order of registration, so
// a resource is torn down before what it depends on.
type Stack struct {
	mu    sync.Mutex
	steps []step
}

type step struct {
	name string
	fn   func() error
}

// StepError records a teardown failure without preventing later cleanup steps.
type StepError struct {
	Step string
	Err  error
}

// New creates an empty cleanup stack.
func New() *Stack {
	return &Stack{
		steps: make([]step, 0),
	}
}

// Push registers an idempotent teardown closure with a descriptive name. Push
// is safe to call from multiple goroutines.
func (s *Stack) Push(name string, fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, step{name: name, fn: fn})
}

// Unwind runs every registered cleanup function, the last registered first.
// Each function runs whether or not the earlier ones returned an error or
// panicked. The mutex is released while a function runs, so a function may use
// the stack. Unwind is safe to call repeatedly; each call drains the steps
// queued at that moment.
func (s *Stack) Unwind() []StepError {
	s.mu.Lock()
	steps := s.steps
	s.steps = nil
	s.mu.Unlock()

	totalSteps := len(steps)
	if totalSteps == 0 {
		return nil
	}
	var errs []StepError

	for i := totalSteps - 1; i >= 0; i-- {
		st := steps[i]
		slog.Info("cleanup: unwinding", "step", st.name, "index", i)
		func() {
			defer func() {
				if r := recover(); r != nil {
					err := fmt.Errorf("cleanup step panicked: %v", r)
					slog.Error("cleanup: step panicked", "step", st.name, "panic", r)
					errs = append(errs, StepError{Step: st.name, Err: err})
				}
			}()
			if err := st.fn(); err != nil {
				slog.Error("cleanup: step failed", "step", st.name, "error", err)
				errs = append(errs, StepError{Step: st.name, Err: err})
			}
		}()
	}

	slog.Info("cleanup: unwind complete", "steps", totalSteps, "failures", len(errs))
	return errs
}

// Len returns the current number of registered cleanup functions.
func (s *Stack) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.steps)
}
