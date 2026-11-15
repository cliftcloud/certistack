// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux

package repocontract

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// signalStub stands in for `certistack run` the way the real one takes a
// signal: it handles SIGINT, SIGTERM and SIGHUP even when its parent started it
// with SIGINT ignored (a non-interactive shell's background job), as Go's
// signal.Notify does. It logs each signal, waits a second for a second one
// (which would abandon the real cleanup), and exits 130. With STUB_MODE=marker
// it prints a report it could not save between the markers instead, and exits 2.
const signalStub = `#!/usr/bin/env python3
import os, signal, sys, time
if sys.argv[1] != "run":
    sys.exit(99)
if os.environ.get("STUB_MODE") == "marker":
    print("-----BEGIN CERTISTACK REPORT-----")
    print('{"report_id":"unsaved"}')
    print("-----END CERTISTACK REPORT-----")
    sys.exit(2)
got = []
def handle(sig, frame):
    with open(os.environ["STUB_SIGNALS"], "a") as log:
        log.write(signal.Signals(sig).name + "\n")
    got.append(sig)
for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, handle)
open(os.environ["STUB_STARTED"], "w").close()
deadline = time.time() + 30
while not got and time.time() < deadline:
    time.sleep(0.05)
time.sleep(1)
sys.exit(130)
`

// The wrapper passes a stop request on so that `certistack run` cleans up the
// node, and a second signal abandons that cleanup. So certistack must get each
// stop exactly once: Ctrl-C and a hangup reach it from the terminal itself (the
// whole foreground process group gets them), and a SIGTERM sent to the wrapper
// alone (systemctl stop, with KillMode=mixed) is forwarded once. A report that
// run could not save, printed between the markers, is kept on standard error.
func TestAutomationWrapperStopSignals(t *testing.T) {
	needTools(t, "flock", "jq", "sed", "python3")

	dir := t.TempDir()
	wrapper := repoFile("scripts", "certistack-validate")
	plan := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(plan, []byte("version: v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "certistack"), []byte(signalStub), 0o755); err != nil {
		t.Fatal(err)
	}

	start := func(t *testing.T, mode string) (*exec.Cmd, *strings.Builder, string, string) {
		signals := filepath.Join(t.TempDir(), "signals")
		started := filepath.Join(t.TempDir(), "started")
		cmd := exec.Command("bash", wrapper, plan)
		cmd.Env = append(os.Environ(),
			"CERTISTACK_ENV_FILE="+filepath.Join(dir, "env_file"),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"STUB_SIGNALS="+signals, "STUB_STARTED="+started, "STUB_MODE="+mode)
		// Its own process group, as a job at a terminal has.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		output := &strings.Builder{}
		cmd.Stdout, cmd.Stderr = output, output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd, output, signals, started
	}
	exitCode := func(t *testing.T, cmd *exec.Cmd, output *strings.Builder) int {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return exit.ExitCode()
			}
			if err != nil {
				t.Fatal(err)
			}
			return 0
		case <-time.After(60 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			t.Fatalf("the wrapper did not exit; output:\n%s", output)
		}
		return -1
	}

	for _, tc := range []struct {
		name  string
		group bool // the whole process group, as a terminal signals it
		sig   syscall.Signal
		want  string
	}{
		{"Ctrl-C at a terminal", true, syscall.SIGINT, "SIGINT\n"},
		{"a hangup of the terminal", true, syscall.SIGHUP, "SIGHUP\n"},
		{"a stop request to the wrapper alone (systemctl stop)", false, syscall.SIGTERM, "SIGTERM\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd, output, signals, started := start(t, "")
			deadline := time.Now().Add(60 * time.Second)
			for {
				if _, err := os.Stat(started); err == nil {
					break
				}
				if time.Now().After(deadline) {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
					t.Fatalf("the stand-in run never started; output:\n%s", output)
				}
				time.Sleep(20 * time.Millisecond)
			}
			target := cmd.Process.Pid
			if tc.group {
				target = -target
			}
			if err := syscall.Kill(target, tc.sig); err != nil {
				t.Fatal(err)
			}
			if got := exitCode(t, cmd, output); got != 130 {
				t.Errorf("exit status %d, want 130; output:\n%s", got, output)
			}
			got, err := os.ReadFile(signals)
			if err != nil {
				t.Fatalf("the stand-in run got no signal: %v; output:\n%s", err, output)
			}
			if string(got) != tc.want {
				t.Errorf("the stand-in run got %q, want %q: a second signal abandons the cleanup", got, tc.want)
			}
		})
	}

	t.Run("a report run could not save is kept", func(t *testing.T) {
		cmd, output, _, _ := start(t, "marker")
		if got := exitCode(t, cmd, output); got != 2 {
			t.Errorf("exit status %d, want 2; output:\n%s", got, output)
		}
		if !strings.Contains(output.String(), `{"report_id":"unsaved"}`) {
			t.Errorf("the report printed between the markers was lost; output:\n%s", output)
		}
	})
}
