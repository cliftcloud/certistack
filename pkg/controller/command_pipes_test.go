//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// holdsItsPipes is a shell command line that starts a program of its own
// which keeps the command's stdout and stderr open until the file named by
// $1 exists (what an ssh connection-sharing master does), writes the file
// named by $2 once that program is running, and then runs the rest of the
// script it is given.
const holdsItsPipes = `/bin/sh -c 'while [ ! -e "$1" ] && [ -d "${1%/*}" ]; do /bin/sleep 0.05; done' sh "$1" &
: > "$2"
`

// pipeHolder starts runCommand on a command that leaves a program behind
// holding its pipes. The program ends only when the test lets it go, after
// runCommand has returned or has been given as long as the slowest test of
// this package may need: nothing here depends on how fast the machine is. A
// runCommand that waits for the pipes returns only when the test lets the
// holder go, and the test fails with that.
func pipeHolder(t *testing.T, ctx context.Context, tail string) (started, release string, done <-chan error) {
	t.Helper()
	dir := t.TempDir()
	started, release = filepath.Join(dir, "started"), filepath.Join(dir, "release")
	// Whatever the test does next, the holder does not outlive it.
	t.Cleanup(func() { _ = os.WriteFile(release, nil, 0o600) })
	result := make(chan error, 1)
	go func() {
		_, err := runCommand(ctx, "/bin/sh", []string{"-c", holdsItsPipes + tail, "sh", release, started}, nil)
		result <- err
	}()
	return started, release, result
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was never written", filepath.Base(path))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A program the command started and left holding its pipes must not hold the
// controller after the command has been stopped. cmd.WaitDelay is what ends the
// wait for the pipes; without it, Wait reads them to the end, and the
// controller could not reach its worker-stop and journal recovery until the
// program let them go, which for a connection- sharing master is never. The
// holder is let go only by the test, after runCommand has returned, so a
// runCommand that waits for it cannot pass.
func TestStoppedCommandReturnsWhileAProgramItStartedHoldsItsPipes(t *testing.T) {
	saved := commandPipeDelay
	commandPipeDelay = 200 * time.Millisecond
	t.Cleanup(func() { commandPipeDelay = saved })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, release, done := pipeHolder(t, ctx, "exec /bin/sleep 60\n")
	waitForFile(t, started)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runCommand reported a command that was stopped as a success")
		}
	case <-time.After(30 * time.Second):
		_ = os.WriteFile(release, nil, 0o600)
		<-done
		t.Fatal("runCommand waited for a program that holds the command's pipes after the command was stopped")
	}
}

// The same for a command that ended on its own. It returns, with an error,
// because what it wrote may be cut short by the pipes being closed under it; it
// does not wait for the holder.
func TestEndedCommandReturnsWhileAProgramItStartedHoldsItsPipes(t *testing.T) {
	saved := commandPipeDelay
	commandPipeDelay = 200 * time.Millisecond
	t.Cleanup(func() { commandPipeDelay = saved })
	_, release, done := pipeHolder(t, context.Background(), "exit 0\n")
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("runCommand reported success although the pipes were closed under the command")
		}
	case <-time.After(30 * time.Second):
		_ = os.WriteFile(release, nil, 0o600)
		<-done
		t.Fatal("runCommand waited for a program that holds the command's pipes after the command ended")
	}
}
