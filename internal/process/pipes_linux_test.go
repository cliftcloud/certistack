//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package process

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// holdsItsPipes is a shell command line that starts a program of its own which
// keeps the command's stdout and stderr open until the file named by $1
// exists (as a descendant that outlives its parent does), and writes the file
// named by $2 once it is running. The rest of the script follows.
const holdsItsPipes = `/bin/sh -c 'while [ ! -e "$1" ] && [ -d "${1%/*}" ]; do /bin/sleep 0.05; done' sh "$1" &
: > "$2"
`

// pipeHolder is a script that leaves a holder behind and then runs tail. The
// holder ends only when the test lets it go, whatever the test does.
func pipeHolder(t *testing.T, tail string) (script []string, started, release string) {
	t.Helper()
	dir := t.TempDir()
	started, release = filepath.Join(dir, "started"), filepath.Join(dir, "release")
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })
	return []string{"-c", holdsItsPipes + tail, "sh", release, started}, started, release
}

func shortPipeWait(t *testing.T) {
	t.Helper()
	saved := PipeWaitDelay
	PipeWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { PipeWaitDelay = saved })
}

// outcome runs f and says whether it returned within the time the test allows
// it. A call that waits for the holder does not: the test then lets the holder
// go, so that nothing is left behind, and fails.
func outcome(t *testing.T, release string, what string, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		_ = os.WriteFile(release, nil, 0o600)
		<-done
		t.Fatalf("%s waited for a program that holds the command's pipes", what)
		return nil
	}
}

// A command that writes past its limit is killed, but a program it started
// keeps its pipe open, so reading the pipe to its end did not return: the call
// that was to stop a runaway client waited for as long as the descendant lived.
func TestCombinedOutputLimitedReturnsWhileADescendantHoldsThePipe(t *testing.T) {
	shortPipeWait(t)
	args, _, release := pipeHolder(t, "while :; do printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'; done\n")
	var out []byte
	err := outcome(t, release, "CombinedOutputLimited", func() error {
		var err error
		out, err = CombinedOutputLimited(CommandContext(context.Background(), "/bin/sh", args, false), 4096)
		return err
	})
	if !errors.Is(err, ErrOutputLimit) || len(out) != 4096 {
		t.Fatalf("output %d bytes, %v; want the first 4096 and ErrOutputLimit", len(out), err)
	}
}

// A command stopped by its deadline while a program it started holds its
// pipe returns, with the deadline's error, within the pipe wait.
func TestCombinedOutputLimitedTimesOutWhileADescendantHoldsThePipe(t *testing.T) {
	shortPipeWait(t)
	args, started, release := pipeHolder(t, "exec /bin/sleep 60\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			if _, err := os.Stat(started); err == nil {
				cancel()
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	err := outcome(t, release, "CombinedOutputLimited", func() error {
		_, err := CombinedOutputLimited(CommandContext(ctx, "/bin/sh", args, false), 4096)
		return err
	})
	if err == nil {
		t.Fatal("a command that was stopped reported success")
	}
}

// A command that ended on its own while a program it started holds its pipe
// has an output that may be cut short by the pipe being closed under it: that
// is an error that says so, never a success with whatever was read.
func TestCombinedOutputLimitedReportsAPipeThatWasHeldAfterTheCommandEnded(t *testing.T) {
	shortPipeWait(t)
	args, _, release := pipeHolder(t, "printf mapped; exit 0\n")
	var out []byte
	err := outcome(t, release, "CombinedOutputLimited", func() error {
		var err error
		out, err = CombinedOutputLimited(CommandContext(context.Background(), "/bin/sh", args, false), 4096)
		return err
	})
	if !errors.Is(err, ErrPipeHeld) || !strings.Contains(err.Error(), "may be incomplete") {
		t.Fatalf("err = %v, want ErrPipeHeld saying the output may be incomplete", err)
	}
	if string(out) != "mapped" {
		t.Fatalf("output = %q, want what was read kept", out)
	}
}

// The other helpers share the rule: Run and CombinedOutput return, with the
// same explicit error, for a command that ended with a descendant holding its
// pipe.
func TestRunAndCombinedOutputReportAPipeThatWasHeldAfterTheCommandEnded(t *testing.T) {
	shortPipeWait(t)
	for name, call := range map[string]func(args []string) error{
		"Run": func(args []string) error {
			cmd := CommandContext(context.Background(), "/bin/sh", args, false)
			cmd.Stdout = &strings.Builder{}
			return Run(cmd)
		},
		"CombinedOutput": func(args []string) error {
			_, err := CombinedOutput(CommandContext(context.Background(), "/bin/sh", args, false))
			return err
		},
	} {
		args, _, release := pipeHolder(t, "printf done; exit 0\n")
		err := outcome(t, release, name, func() error { return call(args) })
		if !errors.Is(err, ErrPipeHeld) {
			t.Errorf("%s: err = %v, want ErrPipeHeld", name, err)
		}
		_ = os.WriteFile(release, nil, 0o600)
	}
}

// The controls: a command whose pipes close with it is unaffected, whatever
// it writes and however it ends.
func TestAPipeThatClosesWithTheCommandIsNotAnError(t *testing.T) {
	shortPipeWait(t)
	out, err := CombinedOutputLimited(CommandContext(context.Background(), "/bin/sh", []string{"-c", "printf ok; printf fine >&2"}, false), 4096)
	if err != nil || string(out) != "okfine" {
		t.Fatalf("output %q, %v", out, err)
	}
	if _, err := CombinedOutputLimited(CommandContext(context.Background(), "/bin/sh", []string{"-c", "printf bad >&2; exit 3"}, false), 4096); err == nil || errors.Is(err, ErrPipeHeld) {
		t.Fatalf("a failing command: %v", err)
	}
}

// The process's own WaitDelay is set on every command the package builds.
func TestCommandContextBoundsTheWaitForItsPipes(t *testing.T) {
	if cmd := CommandContext(context.Background(), "true", nil, false); cmd.WaitDelay != PipeWaitDelay || PipeWaitDelay <= 0 {
		t.Fatalf("WaitDelay = %v, want the package's pipe wait %v", cmd.WaitDelay, PipeWaitDelay)
	}
}
