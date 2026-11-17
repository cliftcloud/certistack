// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/recoverhint"
)

// The root handler cancels the command context on the first interrupt and the
// cleanup context on the second, and recover passes both to the recovery. These
// tests drive the handler and the command.

// The first interrupt reaches the recovery as its command context, the second
// as its abandon context, and the command ends as an interrupted one (exit 130)
// that says so.
func TestRecoverReceivesBothInterrupts(t *testing.T) {
	signals := make(chan os.Signal, 2)
	var notices bytes.Buffer
	ctx, cleanupCtx, stop := newSignalContexts(signals, &notices)
	defer stop()
	t.Cleanup(func() { activeCommand.Store("") })

	entered := make(chan struct{})
	previous := recoverState
	t.Cleanup(func() { recoverState = previous })
	var gotCtx, gotAbandon context.Context
	recoverState = func(c, a context.Context, _ string) error {
		gotCtx, gotAbandon = c, a
		close(entered)
		<-c.Done()
		select {
		case <-a.Done():
		case <-time.After(5 * time.Second):
			return errors.New("the second interrupt never reached recovery's abandon context")
		}
		return fmt.Errorf("recovery was interrupted: %w", c.Err())
	}

	root := newRootCmd(cleanupCtx)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"recover", "--state-dir", t.TempDir()})
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("recover never ran the recovery")
	}
	if gotCtx.Err() != nil || gotAbandon.Err() != nil {
		t.Fatal("recovery was given a context that was already cancelled")
	}
	signals <- os.Interrupt
	select {
	case <-gotCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the first interrupt never reached recovery's command context")
	}
	if gotAbandon.Err() != nil {
		t.Fatal("the first interrupt cancelled the abandon context")
	}
	signals <- os.Interrupt

	var err error
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("recover did not end after the interrupts")
	}
	if !errors.Is(err, context.Canceled) || exitCodeForError(err) != exitCodeInterrupted {
		t.Fatalf("recover = %v (exit %d), want an interrupted outcome, exit %d", err, exitCodeForError(err), exitCodeInterrupted)
	}
	if !strings.Contains(out.String(), "Crash recovery was interrupted") || strings.Contains(out.String(), "Crash recovery failed") || !strings.Contains(out.String(), recoverhint.Again) {
		t.Fatalf("recover said %q, want it to say it was interrupted and what to do", out.String())
	}
}

// A recovery that fails for another reason is still reported as failed, and a
// normal one still completes: the interrupted wording is for interrupts only.
func TestRecoverWithoutAnInterruptIsUnchanged(t *testing.T) {
	previous := recoverState
	t.Cleanup(func() { recoverState = previous })
	var gotCtx, gotAbandon context.Context
	recoverState = func(c, a context.Context, _ string) error { gotCtx, gotAbandon = c, a; return nil }
	var out bytes.Buffer
	if err := runRoot(t, &out, "recover", "--state-dir", t.TempDir()); err != nil {
		t.Fatalf("recover = %v\n%s", err, out.String())
	}
	if gotCtx == nil || gotAbandon == nil || gotCtx.Err() != nil || gotAbandon.Err() != nil {
		t.Fatalf("recovery was given contexts %v and %v, want live ones", gotCtx, gotAbandon)
	}
	if !strings.Contains(out.String(), "Crash recovery completed successfully") {
		t.Fatalf("recover said %q", out.String())
	}

	recoverState = func(context.Context, context.Context, string) error { return errors.New("PVE refused") }
	out.Reset()
	err := runRoot(t, &out, "recover", "--state-dir", t.TempDir())
	if err == nil || exitCodeForError(err) == exitCodeInterrupted || !strings.Contains(out.String(), "Crash recovery failed") || strings.Contains(out.String(), "interrupted") {
		t.Fatalf("recover = %v (exit %d), output %q; want a failure that is not an interrupted one", err, exitCodeForError(err), out.String())
	}
}

// What the handler tells the operator of recover is what recovery does: it is
// not told to wait for cleanup or to retain a worker workspace, and the second
// interrupt does not promise to abandon what it cannot.
func TestRecoverInterruptWording(t *testing.T) {
	first, second := interruptedOutput(t, "recover", os.Interrupt)
	for _, want := range []string{
		"Interrupt received; stopping recovery",
		"starts no further step",
		"stops waiting on PVE and on a loop detach",
		"runs to its own end",
		"its journal stays unresolved: " + recoverhint.Again,
		"Press Ctrl-C again to cut short the kernel commands of a probe address's removal",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("first interrupt printed %q, want it to say %q", first, want)
		}
	}
	for _, unwanted := range []string{"waiting for CertiStack cleanup", "abandon cleanup", "workspace", "run recover manually", "certistack recover"} {
		if strings.Contains(first, unwanted) || strings.Contains(second, unwanted) {
			t.Errorf("recover was told %q / %q, which is not true of it (%q)", first, second, unwanted)
		}
	}
	for _, want := range []string{
		"Second interrupt received; cutting short the kernel commands of a probe address's removal",
		"already issued go on and are not undone",
		"The journal stays unresolved",
	} {
		if !strings.Contains(second, want) {
			t.Errorf("second interrupt printed %q, want it to say %q", second, want)
		}
	}
	if strings.Contains(second, "abandoning automatic cleanup") {
		t.Errorf("the second interrupt promised to abandon cleanup: %q", second)
	}

	stopped, _ := interruptedOutput(t, "recover", syscall.SIGTERM)
	if !strings.Contains(stopped, "Stop signal received (terminated); stopping recovery") || strings.Contains(stopped, "cleaning up CertiStack's temporary resources") || !strings.Contains(stopped, "A second signal will cut short") {
		t.Errorf("a stop signal printed %q", stopped)
	}
}
