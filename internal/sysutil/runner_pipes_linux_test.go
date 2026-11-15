//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/process"
)

// holder is a shell script that leaves a program behind holding the command's
// stdout and stderr until release exists, and then runs tail.
func holder(t *testing.T, tail string) (args []string, release string) {
	t.Helper()
	dir := t.TempDir()
	release = filepath.Join(dir, "release")
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })
	script := `/bin/sh -c 'while [ ! -e "$1" ] && [ -d "${1%/*}" ]; do /bin/sleep 0.05; done' sh "$1" &
` + tail
	return []string{"-c", script, "sh", release}, release
}

func returnsWithin(t *testing.T, release, what string, f func() error) error {
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

// A command that runs past its time limit is killed, but a program it started
// holds its stdout and stderr, and the runner, which reads them to their end,
// waited for that program: the node worker's preflight and recovery then ran
// past the limit they were given, for as long as the descendant lived.
func TestRunReturnsAtItsTimeoutWhileADescendantHoldsThePipes(t *testing.T) {
	saved := process.PipeWaitDelay
	process.PipeWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { process.PipeWaitDelay = saved })
	args, release := holder(t, "exec /bin/sleep 60\n")
	var res *Result
	err := returnsWithin(t, release, "Run", func() error {
		var err error
		res, err = Run(context.Background(), 300*time.Millisecond, "/bin/sh", args...)
		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) || res == nil {
		t.Fatalf("Run = %+v, %v; want the timeout", res, err)
	}
}

// One that ended on its own while a program it started holds its pipes is an
// error that says its output may be incomplete, not a result.
func TestRunReportsAPipeHeldAfterTheCommandEnded(t *testing.T) {
	saved := process.PipeWaitDelay
	process.PipeWaitDelay = 200 * time.Millisecond
	t.Cleanup(func() { process.PipeWaitDelay = saved })
	args, release := holder(t, "printf done; exit 0\n")
	err := returnsWithin(t, release, "Run", func() error {
		_, err := Run(context.Background(), 30*time.Second, "/bin/sh", args...)
		return err
	})
	if !errors.Is(err, process.ErrPipeHeld) {
		t.Fatalf("Run = %v; want ErrPipeHeld", err)
	}
}
