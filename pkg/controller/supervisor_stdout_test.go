//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startWithOutput runs script with the given stdout and stderr, which stand
// for the controller's ssh session, and returns a function that waits for its
// exit status. ignoreSIGPIPE starts it as systemd starts a service.
func startWithOutput(t *testing.T, script string, stdout, stderr *os.File, ignoreSIGPIPE bool) func() int {
	t.Helper()
	if ignoreSIGPIPE {
		script = "trap '' PIPE\n" + script
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script, "certistack-test")
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return func() int {
		err := cmd.Wait()
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	}
}

// The controller's session has ended when the lease expires, and
// the supervisor's stdout and stderr, which belong to it, have no reader. The
// lease-expiry branch treated a failed write of the result as an unreadable
// result, kept the workspace and exited 124 with a false note, where it used
// to remove the workspace; with SIGPIPE at its default a write to the closed
// stderr ended the shell before the credentials were scrubbed. What the
// supervisor writes to a stdout nobody reads changes neither the workspace
// nor its status.
func TestLeaseExpiryOutcomeDoesNotDependOnTheControllersOutput(t *testing.T) {
	saved := abandonedResultWriteSeconds
	abandonedResultWriteSeconds = 1
	defer func() { abandonedResultWriteSeconds = saved }()

	small := `trap 'printf "{\"error\":\"interrupted by SIGTERM\"}"; exit 130' TERM; while :; do /bin/sleep 0.01; done`
	large := `trap 'head -c 300000 /dev/zero | tr "\0" x; exit 130' TERM; while :; do /bin/sleep 0.01; done`
	for _, tc := range []struct {
		name          string
		worker        string
		output        string // open, closed or blocked
		ignoreSIGPIPE bool
	}{
		{"stdout and stderr open", small, "open", true},
		{"closed, SIGPIPE ignored as systemd ignores it", small, "closed", true},
		{"closed, SIGPIPE at its default", small, "closed", false},
		{"open and never read", large, "blocked", true},
		{"open and never read, SIGPIPE at its default", large, "blocked", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSupervisorHarness(t, tc.worker, 0)
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer write.Close()
			var collected chan string
			switch tc.output {
			case "closed":
				read.Close()
			case "open":
				collected = make(chan string, 1)
				go func() {
					data := make([]byte, 0, 1024)
					buf := make([]byte, 4096)
					for {
						n, err := read.Read(buf)
						data = append(data, buf[:n]...)
						if err != nil {
							collected <- string(data)
							return
						}
					}
				}()
			case "blocked":
				defer read.Close() // open, and never read
			}
			wait := startWithOutput(t, h.supervisor(t), write, write, tc.ignoreSIGPIPE)
			write.Close() // the parent's copy: the child's own stays open
			h.waitTicks(t, 2)
			h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
			started := time.Now()
			status := wait()
			if time.Since(started) > 20*time.Second {
				t.Fatalf("the supervisor took %v", time.Since(started))
			}
			if status != 130 {
				t.Fatalf("status = %d, want the worker's 130", status)
			}
			if !exists(h.recovered) {
				t.Error("the run's journal was not recovered")
			}
			if exists(h.workspace) {
				t.Error("the workspace was kept")
			}
			if note := filepath.Join(h.workspace, "credentials-removed.txt"); exists(note) {
				t.Errorf("a credentials-removed note was written: %s", note)
			}
			if kept, err := os.ReadFile(filepath.Join(h.stateDir, "logs", filepath.Base(h.workspace)+".log")); err != nil || !strings.Contains(string(kept), "recovery ran") {
				t.Errorf("the recovery log was not kept: %q, %v", kept, err)
			}
			if tc.output == "open" {
				if got := <-collected; !strings.Contains(got, `{"error":"interrupted by SIGTERM"}`) {
					t.Errorf("the connected controller got %q", got)
				}
			}
		})
	}
}

// A result the supervisor cannot read is still a failure of the
// lease-expiry branch, and is told apart from a stdout nobody reads: the
// credentials go and the workspace stays.
func TestLeaseExpiryWithAnUnreadableResultKeepsTheWorkspace(t *testing.T) {
	h := newSupervisorHarness(t, `trap 'exit 130' TERM; while :; do /bin/sleep 0.01; done`, 0)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	read.Close()
	defer write.Close()
	wait := startWithOutput(t, h.supervisor(t), write, write, true)
	write.Close()
	h.waitTicks(t, 2)
	// The result goes before the lease expires, as a disk fault would take it.
	if err := os.Remove(h.result); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(h.result, 0o700); err != nil {
		t.Fatal(err)
	}
	h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
	if status := wait(); status != supervisorResultUnreadableStatus {
		t.Fatalf("status = %d, want %d", status, supervisorResultUnreadableStatus)
	}
	if !exists(h.workspace) || exists(h.env) || exists(h.worker) {
		t.Fatalf("workspace kept %v, environment kept %v: want the workspace kept and its credentials gone", exists(h.workspace), exists(h.env))
	}
	if note, err := os.ReadFile(filepath.Join(h.workspace, "credentials-removed.txt")); err != nil || !strings.Contains(string(note), "result could not be read") {
		t.Fatalf("note = %q, %v", note, err)
	}
}
