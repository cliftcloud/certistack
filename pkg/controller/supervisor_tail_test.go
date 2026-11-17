//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A supervisor that cannot identify its progress tail does not signal it, and
// must not wait for it for ever, leaving the controller at "streaming node
// phases". The tail is waited for only once it is known to be the one the
// supervisor started; a service's control group ends whatever else is left
// when the service ends.
func TestSupervisorEndsWhenItCannotIdentifyItsProgressTail(t *testing.T) {
	h := newSupervisorHarness(t, `printf '{"report":{}}'; exit 0`, 0)
	script := h.supervisor(t)
	const identify = "proc_start \"$tail_pid\"\ntail_ticks=$ticks\n"
	if !strings.Contains(script, identify) {
		t.Fatal("the supervisor no longer identifies its tail where this test expects it")
	}
	cmd := exec.Command("/bin/sh", "-c", strings.Replace(script, identify, "tail_ticks=\n", 1), "certistack-test")
	// The tail it leaves behind ends with the test, as the service's control
	// group ends it on a node.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// The tail holds the supervisor's pipes open, so Wait would not return for
	// it: the supervisor has ended when its process has, which is what a
	// service's end is.
	cmd.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, exec.ErrWaitDelay) || cmd.ProcessState.ExitCode() != 0 || stdout.String() != `{"report":{}}` {
			t.Fatalf("supervisor: %v, stdout %q, stderr %q", err, stdout.String(), stderr.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the supervisor is still waiting for a progress tail it could not identify")
	}
}
