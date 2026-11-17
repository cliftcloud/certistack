// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package cleanup provides a LIFO stack for fail-safe resource teardown.
package cleanup

import (
	"fmt"
	"log/slog"
	"sync"
)

// Stack manages a LIFO stack of cleanup functions that execute in reverse
// order of registration. It provides fail-safe resource teardown for
// ephemeral resources (loopback devices, COW files, VMs, SDN objects).
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

// Push registers an idempotent teardown closure with a descriptive name.
// The closure is pushed onto the stack and will execute during Unwind()
// in LIFO order. Push is safe to call from multiple goroutines.
func (s *Stack) Push(name string, fn func() error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.steps = append(s.steps, step{name: name, fn: fn})
}

// Unwind executes all registered cleanup functions in LIFO order.
// Each function is called regardless of whether previous functions
// returned errors or panicked. The mutex is released during callback
// execution to prevent deadlocks if a callback interacts with the stack.
// Unwind is safe to call repeatedly; each call drains whatever steps are currently queued.
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
