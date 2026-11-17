// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The published CLI contract says read-only commands such as inspect end at
// once on an interrupt, so inspect hands the command's context to the QMP and
// QGA helpers rather than waiting out their own three-second budgets, and a
// late normal result does not end as a success. These tests give the command's
// context and watch it.

// silentSocket listens on a unix socket, accepts every connection and never says
// a word: a QMP socket that sends no greeting, a guest agent that never answers
// the sync.
func silentSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "silent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn) // reads, never answers
			}(conn)
		}
	}()
	return path
}

func runInspectContext(t *testing.T, ctx context.Context, args ...string) (string, error) {
	t.Helper()
	cmd := inspectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(ctx)
	return out.String(), err
}

// An interrupt ends the wait for a QMP greeting that never comes at once, not
// after the socket's three seconds, and the command is an interrupted one.
func TestInspectEndsTheQMPWaitWhenInterrupted(t *testing.T) {
	ctx, interrupt := context.WithCancel(context.Background())
	defer interrupt()
	time.AfterFunc(200*time.Millisecond, interrupt)
	start := time.Now()
	out, err := runInspectContext(t, ctx, "123", "--qmp", silentSocket(t), "--qga", filepath.Join(t.TempDir(), "missing.qga"))
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("inspect took %s to end after the interrupt:\n%s", took, out)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("inspect = %v, want an interrupted outcome:\n%s", err, out)
	}
	if got := exitCodeForError(err); got != exitCodeInterrupted {
		t.Fatalf("exit code = %d, want %d", got, exitCodeInterrupted)
	}
}

// The same for a guest agent that never answers the sync, after a QMP that did.
func TestInspectEndsTheQGAWaitWhenInterrupted(t *testing.T) {
	ctx, interrupt := context.WithCancel(context.Background())
	defer interrupt()
	time.AfterFunc(300*time.Millisecond, interrupt)
	start := time.Now()
	out, err := runInspectContext(t, ctx, "123", "--qmp", fakeQMPSocket(t), "--qga", silentSocket(t))
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("inspect took %s to end after the interrupt:\n%s", took, out)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("inspect = %v, want an interrupted outcome:\n%s", err, out)
	}
}

// A VM that answered, inspected after the command was interrupted, is not a
// success: the root handler told the operator the command was stopping.
func TestInspectAfterAnInterruptIsNotALateSuccess(t *testing.T) {
	ctx, interrupt := context.WithCancel(context.Background())
	interrupt()
	out, err := runInspectContext(t, ctx, "123", "--qmp", fakeQMPSocket(t), "--qga", filepath.Join(t.TempDir(), "missing.qga"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("inspect = %v, want an interrupted outcome, not a late success:\n%s", err, out)
	}
	if got := exitCodeForError(err); got != exitCodeInterrupted {
		t.Fatalf("exit code = %d, want %d", got, exitCodeInterrupted)
	}
}

// The control: with a live context the same inspection is what it was.
func TestInspectWithALiveContextIsUnchanged(t *testing.T) {
	out, err := runInspectContext(t, context.Background(), "123", "--qmp", fakeQMPSocket(t), "--qga", filepath.Join(t.TempDir(), "missing.qga"))
	if err != nil {
		t.Fatalf("inspect = %v:\n%s", err, out)
	}
	for _, want := range []string{"Inspecting VM 123", "Status: running", "UNAVAILABLE"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
