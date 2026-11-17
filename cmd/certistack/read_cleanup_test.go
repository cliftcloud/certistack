// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/runner"
)

func resetInterruptState(t *testing.T) {
	t.Helper()
	reset := func() {
		activeCommand.Store("")
		remoteWorkerStaged.Store(false)
		remoteInspectionStaged.Store(false)
		localInspection.Store(false)
	}
	reset()
	t.Cleanup(reset)
}

// The workspace of plan, check and init's discovery is read-only: it keeps no
// journal, so there is nothing for `recover` to find, and it has a lease watch
// on the node that removes it once the controller stops renewing the lease.
// The notices of an interrupt say what an abandoned cleanup really leaves, not,
// as for a run, that a second Ctrl-C retains the protected worker workspace
// and that recover is to be run manually.
func TestInterruptWordingOfAReadOnlyRemoteWorker(t *testing.T) {
	lease := fmt.Sprintf("about %d seconds", controller.ReadWorkspaceLeaseSeconds)
	for _, command := range []string{"plan", "check", "init"} {
		t.Run(command, func(t *testing.T) {
			resetInterruptState(t)
			remoteWorkerStaged.Store(true)
			first, second := interruptedOutput(t, command, os.Interrupt)
			if !strings.Contains(first, "waiting for CertiStack cleanup") || !strings.Contains(first, "Press Ctrl-C again to abandon cleanup") {
				t.Errorf("first interrupt printed %q; want the wait for cleanup and the offer to abandon it", first)
			}
			for _, notice := range []string{first, second} {
				if !strings.Contains(notice, "removes the temporary worker workspace itself") || !strings.Contains(notice, lease) || !strings.Contains(notice, "nothing to recover manually") {
					t.Errorf("notice %q; want what an abandoned cleanup leaves: the node removes the workspace itself %s after the lease, and nothing to recover", notice, lease)
				}
				if strings.Contains(notice, "retain the protected worker workspace") || strings.Contains(notice, "run recover manually") || strings.Contains(notice, "for manual recovery") {
					t.Errorf("notice %q tells the operator of a read-only workspace to keep it or to recover it", notice)
				}
			}
			if !strings.Contains(second, "Second interrupt received; abandoning automatic cleanup") {
				t.Errorf("second interrupt printed %q", second)
			}
		})
	}
}

// The inspection of init --inspect (a journaled worker, here or on the node)
// and the commands with a run's cleanup keep the recover instruction.
func TestInterruptWordingKeepsRecoverForJournaledWorkers(t *testing.T) {
	cases := map[string]func(){
		"run": func() {},
		// recover is not here: it is itself the recovery, so it has no worker
		// workspace to retain and no recover to run manually, and its second
		// interrupt says what it does (TestRecoverInterruptWording).
		"init, remote inspection":  func() { remoteWorkerStaged.Store(true); remoteInspectionStaged.Store(true) },
		"init, local inspection":   func() { localInspection.Store(true) },
		"plan, nothing staged yet": func() {},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			resetInterruptState(t)
			command, _, _ := strings.Cut(name, ",")
			setup()
			_, second := interruptedOutput(t, command, os.Interrupt)
			switch name {
			case "plan, nothing staged yet":
				if strings.Contains(second, "recover manually") || !strings.Contains(second, "Second interrupt received") {
					t.Errorf("a command with nothing to clean up said %q", second)
				}
			default:
				if !strings.Contains(second, "Retain the protected worker workspace, and "+recoverhint.Recover) {
					t.Errorf("second interrupt printed %q; want the journaled worker's recover instruction", second)
				}
			}
		})
	}
}

// The second interrupt cancels the cleanup context newSignalContexts makes, and
// the commands that stage a read-only worker hand that context to the
// controller: the removal of the workspace is what it abandons.
func TestReadOnlyRemoteCommandsHandTheCleanupContextToTheController(t *testing.T) {
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_NODE", "CERTISTACK_OVERLAY_STORAGE", "PBS_NAMESPACE"} {
		t.Setenv(name, "")
	}
	resetInterruptState(t)
	cleanup, abandon := context.WithCancel(context.Background())
	defer abandon()
	run := func(args ...string) error {
		root := newRootCmd(cleanup)
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs(args)
		return root.ExecuteContext(context.Background())
	}
	stop := errors.New("stop here")

	t.Run("plan", func(t *testing.T) {
		previous := remotePlan
		t.Cleanup(func() { remotePlan = previous })
		var got context.Context
		remotePlan = func(_ context.Context, opts controller.RunOptions) ([]byte, error) {
			got = opts.CleanupContext
			return nil, stop
		}
		planPath := planWithScratch(t, t.TempDir(), "")
		if err := run("plan", planPath, "--ssh-host", "pve1.example", "--node", "pve1", "--state-dir", t.TempDir(), "--ssh-known-hosts", filepath.Join(t.TempDir(), "known_hosts")); err == nil || !strings.Contains(err.Error(), "stop here") {
			t.Fatalf("plan: %v", err)
		}
		if got != cleanup {
			t.Errorf("plan gave the controller cleanup context %v; want the one the second interrupt cancels", got)
		}
	})
	t.Run("init discovery", func(t *testing.T) {
		previous := remoteDiscover
		t.Cleanup(func() { remoteDiscover = previous })
		var got context.Context
		remoteDiscover = func(_ context.Context, opts controller.RunOptions, _ initplan.Request) ([]byte, error) {
			got = opts.CleanupContext
			return nil, stop
		}
		dir := t.TempDir()
		if err := run("init", "--node", "pve1", "--vm", "100", "--ssh-host", "pve1.example", "--ssh-known-hosts", filepath.Join(dir, "known_hosts"), "--output", filepath.Join(dir, "a.yaml")); err == nil || !strings.Contains(err.Error(), "stop here") {
			t.Fatalf("init: %v", err)
		}
		if got != cleanup {
			t.Errorf("init's discovery gave the controller cleanup context %v; want the one the second interrupt cancels", got)
		}
	})
	t.Run("check", func(t *testing.T) {
		c := readyController(t)
		stub := &nodeStub{stagingError: stop}
		withNode(t, stub)
		if err := run("check", "--env-file", c.env); err == nil {
			t.Fatal("check passed with a failing node")
		}
		if len(stub.staged) != 1 {
			t.Fatalf("the node's layers were run %d times", len(stub.staged))
		}
		if stub.staged[0].CleanupContext != cleanup {
			t.Errorf("check gave the controller cleanup context %v; want the one the second interrupt cancels", stub.staged[0].CleanupContext)
		}
	})
}

// init --inspect's remote inspection is a journaled worker, as a run's is: from
// the moment it is staged, an interrupt says what a run's says.
func TestRemoteInitInspectionIsMarkedAsAJournaledWorker(t *testing.T) {
	resetInterruptState(t)
	previous := remoteInspect
	t.Cleanup(func() { remoteInspect = previous })
	var marked bool
	remoteInspect = func(context.Context, controller.RunOptions, initplan.InspectRequest) ([]byte, error) {
		marked = remoteInspectionStaged.Load()
		return nil, errors.New("stop here")
	}
	remote := &controller.RunOptions{NodeName: "pve1"}
	_, _ = inspectForInit(context.Background(), io.Discard, initplan.InspectRequest{Node: "pve1"}, remote, runner.InspectOptions{})
	if !marked {
		t.Error("a remote inspection was not marked as a journaled worker before it was staged")
	}
}
