// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cliftcloud/certistack/internal/process"
)

// InterruptedError is a run stopped by a signal: an operator's interrupt,
// or the node shutting down. It is a context.Canceled, so every caller that
// treats a cancellation as an interruption still does.
type InterruptedError struct {
	Signal string
	// NodeStopping is true when systemd was shutting the node down.
	NodeStopping bool
}

func (e *InterruptedError) Error() string {
	if e.NodeStopping {
		return fmt.Sprintf("interrupted: the node began shutting down (%s from systemd)", e.Signal)
	}
	return fmt.Sprintf("interrupted by %s", e.Signal)
}

func (e *InterruptedError) Unwrap() error { return context.Canceled }

// interruptContext is ctx, cancelled on SIGINT, SIGHUP or SIGTERM.
// interrupted says which signal stopped the run, and whether the node was
// shutting down, or nil, so a report says more than "context canceled". The CLI's own handler can cancel the parent for
// the same signal first, so the signal is kept apart from the context's
// cause, and read for a moment after the parent is cancelled.
func interruptContext(parent context.Context) (ctx context.Context, stop func(), interrupted func() *InterruptedError) {
	ctx, cancel := context.WithCancelCause(parent)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	done := make(chan struct{})
	finished := make(chan struct{})
	var got *InterruptedError
	record := func(sig os.Signal) *InterruptedError {
		got = &InterruptedError{Signal: signalName(sig), NodeStopping: sig == syscall.SIGTERM && nodeStopping()}
		return got
	}
	go func() {
		defer close(finished)
		select {
		case sig := <-signals:
			cancel(record(sig))
		case <-done:
		case <-ctx.Done():
			select {
			case sig := <-signals: // already delivered: taken first
				record(sig)
				return
			default:
			}
			select {
			case sig := <-signals:
				record(sig)
			case <-done:
			case <-time.After(200 * time.Millisecond):
			}
		}
	}()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		signal.Stop(signals)
		close(done)
		<-finished
		cancel(nil)
	}
	interrupted = func() *InterruptedError {
		stop()
		return got
	}
	return ctx, stop, interrupted
}

func signalName(sig os.Signal) string {
	switch sig {
	case os.Interrupt:
		return "SIGINT"
	case syscall.SIGHUP:
		return "SIGHUP"
	case syscall.SIGTERM:
		return "SIGTERM"
	}
	return sig.String()
}

// nodeStopping reports whether systemd is shutting this host down.
func nodeStopping() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// is-system-running exits non-zero in every state but "running", and
	// still prints the state.
	// Through the process package so that the child gets the minimal environment: the worker's own holds the PVE token.
	out, _ := process.CommandContext(ctx, "systemctl", []string{"is-system-running"}, false).Output()
	return strings.TrimSpace(string(out)) == "stopping"
}

// withInterruption rewrites a cancellation that an InterruptedError caused
// to name it. Other errors are returned unchanged.
func withInterruption(err error, interrupted *InterruptedError) error {
	if err == nil || interrupted == nil || !errors.Is(err, context.Canceled) {
		return err
	}
	var already *InterruptedError
	if errors.As(err, &already) {
		return err
	}
	detail := strings.TrimSuffix(strings.TrimSuffix(err.Error(), context.Canceled.Error()), ": ")
	if detail == "" {
		return interrupted
	}
	return fmt.Errorf("%w; the run was at: %s", interrupted, detail)
}
