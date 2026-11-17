// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// The wording of an interrupt follows the command: only a command with a
// cleanup says CertiStack is waiting for it and offers to abandon it,
// retaining a worker workspace. validate, doctor, verify-report and the others
// only read: they end at once and have no workspace.

// interruptedOutput runs the signal handler for the named command and returns
// what it printed for an interrupt, the second interrupt and a stop signal.
func interruptedOutput(t *testing.T, command string, signal os.Signal) (first, second string) {
	t.Helper()
	activeCommand.Store(command)
	t.Cleanup(func() { activeCommand.Store(""); remoteWorkerStaged.Store(false) })
	signals := make(chan os.Signal, 2)
	var output bytes.Buffer
	ctx, cleanupCtx, stop := newSignalContexts(signals, &output)
	defer stop()
	signals <- signal
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatalf("%s: the signal did not cancel the command's context", command)
	}
	first = output.String()
	if signal != os.Interrupt {
		return first, ""
	}
	signals <- os.Interrupt
	select {
	case <-cleanupCtx.Done():
	case <-time.After(time.Second):
		t.Fatalf("%s: the second interrupt did not cancel the cleanup context", command)
	}
	return first, output.String()[len(first):]
}

func TestInterruptWordingFollowsWhetherTheCommandHasCleanup(t *testing.T) {
	const cleanupFirst = "Interrupt received; waiting for CertiStack cleanup. Press Ctrl-C again to abandon cleanup"
	const cleanupSecond = "Second interrupt received; abandoning automatic cleanup"
	for _, tc := range []struct {
		command    string
		hasCleanup bool
	}{
		{"run", true}, {"node-run", true}, {"node-inspect", true}, {"recover", true},
		{"", true}, {"a-command-added-later", true},
		{"version", false}, {"validate", false}, {"doctor", false}, {"verify-report", false},
		{"inspect", false}, {"node-plan", false}, {"node-discover", false},
		{"report", false}, {"show", false}, {"schema", false},
		{"setup", false}, {"trust-node", false}, {"pve-ca", false}, {"rbac", false}, {"node-check", false},
		{"plan", false}, {"init", false}, {"check", false}, // locally; remotely they stage a worker (below)
	} {
		t.Run(tc.command, func(t *testing.T) {
			if tc.command == "recover" {
				// recover is itself the cleanup: there is no worker workspace for
				// an interrupt to retain, and the contexts reach the recovery.
				// Its wording is checked by TestRecoverInterruptWording.
				return
			}
			first, second := interruptedOutput(t, tc.command, os.Interrupt)
			if got := strings.Contains(first, cleanupFirst); got != tc.hasCleanup {
				t.Errorf("first interrupt printed %q; offers cleanup = %v, want %v", first, got, tc.hasCleanup)
			}
			if got := strings.Contains(second, cleanupSecond); got != tc.hasCleanup {
				t.Errorf("second interrupt printed %q; abandons cleanup = %v, want %v", second, got, tc.hasCleanup)
			}
			if !tc.hasCleanup {
				if strings.Contains(first, "workspace") || strings.Contains(first, "waiting for CertiStack cleanup") || !strings.Contains(first, "Interrupt received; stopping") {
					t.Errorf("a command with nothing to clean up said %q", first)
				}
				if strings.Contains(second, "recover manually") || !strings.Contains(second, "Second interrupt received") {
					t.Errorf("a command with nothing to clean up said %q at the second interrupt", second)
				}
			}
			stopped, _ := interruptedOutput(t, tc.command, syscall.SIGTERM)
			if got := strings.Contains(stopped, "cleaning up CertiStack's temporary resources"); got != tc.hasCleanup {
				t.Errorf("a stop signal printed %q; cleaning up = %v, want %v", stopped, got, tc.hasCleanup)
			}
			if !tc.hasCleanup && !strings.Contains(stopped, "stopping") {
				t.Errorf("a stop signal printed %q", stopped)
			}
		})
	}
}

// Every command the root registers has its wording decided here, so a command
// added later is classified on purpose and not by the default.
func TestEveryCommandHasItsInterruptWordingDecided(t *testing.T) {
	decided := map[string]bool{ // true: has cleanup to wait for
		"version": false, "init": false, "node-discover": false, "validate": false, "doctor": false, "plan": false,
		"node-plan": false, "keygen": false, "verify-report": false, "inspect": false, "telemetry": false,
		"report": false, "schema": false, "setup": false, "check": false, "node-check": false,
		"recover": true, "run": true, "node-run": true, "node-inspect": true,
	}
	for _, command := range newRootCmd(nil).Commands() {
		want, known := decided[command.Name()]
		if !known {
			if command.Name() == "help" || command.Name() == "completion" {
				continue
			}
			t.Errorf("command %q has no decided interrupt wording: add it here, and to interruptHasCleanup if it only reads", command.Name())
			continue
		}
		activeCommand.Store(command.Name())
		if got := interruptHasCleanup(); got != want {
			t.Errorf("command %q: interruptHasCleanup = %v, want %v", command.Name(), got, want)
		}
	}
	t.Cleanup(func() { activeCommand.Store(""); remoteWorkerStaged.Store(false) })
}

// The command's own name reaches the handler through the root command, and a
// plan or init that stages a worker on a node has cleanup to wait for.
func TestInterruptWordingKnowsTheRunningCommandAndRemoteWorkers(t *testing.T) {
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_NODE", "CERTISTACK_OVERLAY_STORAGE", "PBS_NAMESPACE"} {
		t.Setenv(name, "")
	}
	t.Cleanup(func() { activeCommand.Store(""); remoteWorkerStaged.Store(false) })

	activeCommand.Store("")
	if err := runRoot(t, io.Discard, "version"); err != nil {
		t.Fatal(err)
	}
	if got, _ := activeCommand.Load().(string); got != "version" {
		t.Fatalf("the active command is %q after `version`", got)
	}
	if interruptHasCleanup() {
		t.Error("`version` was said to have cleanup")
	}

	// plan on a node: the controller stages a temporary worker there.
	previousPlan := remotePlan
	t.Cleanup(func() { remotePlan = previousPlan })
	var stagedAtCall bool
	remotePlan = func(context.Context, controller.RunOptions) ([]byte, error) {
		stagedAtCall = interruptHasCleanup()
		return nil, errors.New("stop here")
	}
	planPath := planWithScratch(t, t.TempDir(), "")
	remoteWorkerStaged.Store(false)
	if err := runRoot(t, io.Discard, "plan", planPath, "--ssh-host", "pve1.example", "--node", "pve1", "--state-dir", t.TempDir(), "--ssh-known-hosts", filepath.Join(t.TempDir(), "known_hosts")); err == nil || !strings.Contains(err.Error(), "stop here") {
		t.Fatalf("plan: %v", err)
	}
	if !stagedAtCall {
		t.Error("`plan --ssh-host` did not say it stages a worker before it did: an interrupt would call it a command with nothing to clean up")
	}

	// init on a node, likewise; locally it stages nothing.
	previousDiscover, previousLocal := remoteDiscover, runnerDiscover
	t.Cleanup(func() { remoteDiscover, runnerDiscover = previousDiscover, previousLocal })
	stagedAtCall = false
	remoteDiscover = func(context.Context, controller.RunOptions, initplan.Request) ([]byte, error) {
		stagedAtCall = interruptHasCleanup()
		return nil, errors.New("stop here")
	}
	runnerDiscover = func(context.Context, initplan.Request, string) (*initplan.Discovery, error) {
		return nil, errors.New("stop here too")
	}
	dir := t.TempDir()
	remoteWorkerStaged.Store(false)
	if err := runRoot(t, io.Discard, "init", "--node", "pve1", "--vm", "100", "--ssh-host", "pve1.example", "--ssh-known-hosts", filepath.Join(dir, "known_hosts"), "--output", filepath.Join(dir, "a.yaml")); err == nil || !strings.Contains(err.Error(), "stop here") {
		t.Fatalf("remote init: %v", err)
	}
	if !stagedAtCall {
		t.Error("`init --ssh-host` did not say it stages a worker before it did")
	}
	remoteWorkerStaged.Store(false)
	if err := runRoot(t, io.Discard, "init", "--node", "pve1", "--vm", "100", "--output", filepath.Join(dir, "b.yaml")); err == nil || !strings.Contains(err.Error(), "stop here too") {
		t.Fatalf("local init: %v", err)
	}
	if interruptHasCleanup() {
		t.Error("a local `init` was said to have cleanup")
	}
}

// A notice written to a terminal or pipe that blocks must not hold up what the
// signal asks for: the first signal still cancels the run, and the second still
// abandons the cleanup.
type blockedWriter struct{ release chan struct{} }

func (w blockedWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

func TestASignalNoticeThatBlocksDoesNotHoldUpCancellation(t *testing.T) {
	old := noticeWait
	noticeWait = 100 * time.Millisecond
	t.Cleanup(func() { noticeWait = old })
	activeCommand.Store("run")
	t.Cleanup(func() { activeCommand.Store("") })
	release := make(chan struct{})
	defer close(release)
	signals := make(chan os.Signal, 2)
	ctx, cleanupCtx, stop := newSignalContexts(signals, blockedWriter{release})
	defer stop()

	signals <- os.Interrupt
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the first signal did not cancel the run while its notice was blocked")
	}
	signals <- os.Interrupt
	select {
	case <-cleanupCtx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the second signal did not abandon the cleanup while its notice was blocked")
	}
}
