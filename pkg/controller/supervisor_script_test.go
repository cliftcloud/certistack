//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// After a worker was killed, the supervisor's recovery released a
// leaked PBS map, but nothing it said reached the controller or survived the
// workspace. Its progress must stream to the controller and stay in the
// node's state directory.
func TestSupervisorStreamsAndKeepsRecoveryAfterTheWorkerIsKilled(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	workspaceRoot := filepath.Join(stateDir, "workers")
	id := uuid.NewString()
	workspace := filepath.Join(workspaceRoot, id)
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	worker := filepath.Join(workspace, "certistack-node")
	fake := "#!/bin/sh\n" +
		"if [ \"$1\" = recover ]; then\n" +
		"  printf '%s{\"level\":\"INFO\",\"stage\":\"Recovery\",\"message\":\"Destroyed sandbox VM 9001 on pve1.\"}\\n' 'CERTISTACK_PROGRESS ' >&2\n" +
		"  exit 0\n" +
		"fi\n" +
		"sleep 0.5\n" +
		"kill -9 $$\n"
	if err := os.WriteFile(worker, []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	lease := filepath.Join(workspace, "controller.lease")
	if err := os.WriteFile(lease, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	progress := filepath.Join(workspace, "worker-progress.log")
	command := (&Executor{}).supervisedWorkerCommand(SSHConfig{}, "certistack-test", workspaceRoot, workspace,
		filepath.Join(workspace, "worker.pid"), lease, stateDir, filepath.Join(workspace, "runtime.env"),
		filepath.Join(workspace, "worker-result.json"), progress, []string{worker, "node-run"})
	if len(command) == 0 {
		t.Fatal("no supervisor command")
	}
	script := launchedScript(t, command)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var stream bytes.Buffer
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	cmd.Stderr = &stream
	err := cmd.Run()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 137 {
		t.Fatalf("supervisor exit = %v, want the worker's 137", err)
	}
	for _, want := range []string{
		`"message":"The node worker ended by signal 9 before it finished; recovering its journal."`,
		`"message":"Destroyed sandbox VM 9001 on pve1."`,
	} {
		if !strings.Contains(stream.String(), want) {
			t.Errorf("the controller's stream lacks %s:\n%s", want, stream.String())
		}
	}
	kept, err := os.ReadFile(filepath.Join(stateDir, "logs", id+".log"))
	if err != nil || !strings.Contains(string(kept), "Destroyed sandbox VM 9001") {
		t.Fatalf("kept log = %q, %v", kept, err)
	}
}

// A node cut off from the controller stops the run itself once the lease
// expires, then removes the workspace. What the worker did in its teardown must
// stay in the node's state directory.
func TestSupervisorKeepsTheTeardownLogWhenTheLeaseExpires(t *testing.T) {
	h := newSupervisorHarness(t, "", 0)
	fake := "#!/bin/sh\n" +
		"if [ \"$1\" = recover ]; then\n" +
		"  echo 'recorded run is already marked cleaned' >&2\n" +
		"  exit 0\n" +
		"fi\n" +
		"trap 'printf \"%s{\\\"level\\\":\\\"INFO\\\",\\\"stage\\\":\\\"Teardown\\\",\\\"message\\\":\\\"Destroyed sandbox VM 9001.\\\"}\\n\" \"CERTISTACK_PROGRESS \" >&2; exit 143' TERM\n" +
		"while :; do sleep 0.1; done\n"
	h.write(t, h.worker, fake)
	wait := h.start(t, h.supervisor(t))
	h.waitTicks(t, 2)
	// The lease has not been renewed for longer than it lasts.
	h.setUptime(t, 1000+2*workerLeaseDurationSeconds)
	if status, _, _ := wait(); status != 143 {
		t.Fatalf("supervisor exit = %d, want the worker's 143", status)
	}
	if _, err := os.Stat(h.workspace); !os.IsNotExist(err) {
		t.Fatalf("workspace after a lease-expiry teardown: %v, want it removed", err)
	}
	kept, err := os.ReadFile(filepath.Join(h.stateDir, "logs", filepath.Base(h.workspace)+".log"))
	if err != nil {
		t.Fatalf("no kept log: %v", err)
	}
	for _, want := range []string{"controller lease expired; starting worker cleanup", "Destroyed sandbox VM 9001.", "recorded run is already marked cleaned"} {
		if !strings.Contains(string(kept), want) {
			t.Errorf("kept log lacks %q:\n%s", want, kept)
		}
	}
}
