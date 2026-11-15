// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// inspectOptions are the options of an inspection through a fake SSH runner,
// with the environment a controller stages.
func inspectOptions(t *testing.T) RunOptions {
	t.Helper()
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "audit@pve!token")
	t.Setenv("PVE_TOKEN_SECRET", "audit-pve-secret")
	t.Setenv("PBS_REPOSITORY", "audit@pbs!token@pbs.example:8007:store")
	t.Setenv("PBS_PASSWORD", "audit-pbs-secret")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return RunOptions{NodeName: "pve1", StateDir: "/var/lib/certistack", SSH: SSHConfig{Host: "pve.example", User: "root", Port: 22, KnownHostsFile: knownHosts}}
}

var inspectReq = initplan.InspectRequest{Node: "pve1", Namespace: "prod", Targets: []initplan.InspectTarget{
	{SourceVMID: 100, Snapshot: "vm/100/2026-10-01T02:00:00Z"},
	{SourceVMID: 101, Snapshot: "vm/101/2026-10-01T02:00:00Z"},
}}

// answering is a fake node whose node-inspect worker answers with in, or
// fails with err.
func answering(in initplan.Inspection, err error) *fakeCommandRunner {
	fake := &fakeCommandRunner{}
	fake.hook = func(name, joined string) ([]byte, error, bool) {
		if name != "ssh" || !strings.Contains(joined, "node-inspect") {
			return nil, nil, false
		}
		if err != nil {
			return nil, err, true
		}
		data, _ := json.Marshal(in)
		return data, nil, true
	}
	return fake
}

func commands(fake *fakeCommandRunner) string {
	var all []string
	for _, call := range fake.calls {
		all = append(all, call.name+" "+strings.Join(call.args, " "))
	}
	return strings.Join(all, "\n")
}

// The worker that maps backups is staged and supervised as a run's worker
// is: a lease, a transient systemd unit and its supervisor, the command line
// with every target, and afterwards the node's journal verified as a run's
// is, before the workspace goes. No credential is on a command line.
func TestInspectSupervisesTheWorkerAndVerifiesItsJournal(t *testing.T) {
	opts := inspectOptions(t)
	fake := answering(initplan.Inspection{Journaled: true, CleanupVerified: true, VMs: []initplan.InspectedVM{{SourceVMID: 100, Snapshot: "vm/100/2026-10-01T02:00:00Z"}}}, nil)
	fake.journalPhase = "cleaned"
	var progress bytes.Buffer
	opts.Writer = &progress
	out, err := (&Executor{runner: fake}).Inspect(context.Background(), opts, inspectReq)
	if err != nil {
		t.Fatal(err)
	}
	var in initplan.Inspection
	if json.Unmarshal(out, &in) != nil || len(in.VMs) != 1 {
		t.Fatalf("answer %s", out)
	}
	all := commands(fake)
	for _, want := range []string{
		"'/usr/bin/install' '-m' '0600' '/dev/null' '/var/lib/certistack/workers/", // the lease
		"/usr/bin/systemd-run",
		"'\"'\"'node-inspect'\"'\"'",
		"'\"'\"'--target'\"'\"' '\"'\"'100=vm/100/2026-10-01T02:00:00Z'\"'\"'",
		"'\"'\"'--namespace'\"'\"' '\"'\"'prod'\"'\"'",
		"'\"'\"'--run-id'\"'\"' '\"'\"'run-",
		"active.json",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("commands lack %s:\n%s", want, all)
		}
	}
	if fake.workspaceRemoveCalls != 1 {
		t.Errorf("workspace removals %d, want 1", fake.workspaceRemoveCalls)
	}
	for _, secret := range []string{"audit-pve-secret", "audit-pbs-secret"} {
		if strings.Contains(all, secret) {
			t.Fatalf("a command carries %s", secret)
		}
	}
	if !strings.Contains(progress.String(), "Journal verified") {
		t.Errorf("progress %s", progress.String())
	}
}

// A worker that ended without an answer is stopped and its journal
// recovered, as an interrupted run's is, before the workspace is removed.
func TestInspectRecoversAWorkerThatGaveNoAnswer(t *testing.T) {
	opts := inspectOptions(t)
	fake := answering(initplan.Inspection{}, errors.New("exit status 2: the worker panicked"))
	fake.journalPhase = "running"
	_, err := (&Executor{runner: fake}).Inspect(context.Background(), opts, inspectReq)
	if err == nil || errors.Is(err, ErrInspectionCleanupUnverified) {
		t.Fatalf("Inspect = %v, want the worker's failure, its journal recovered", err)
	}
	all := commands(fake)
	if !strings.Contains(all, "kill -TERM") || fake.recoverCalls == 0 || fake.workspaceRemoveCalls != 1 {
		t.Fatalf("stop %v, recover calls %d, removals %d:\n%s", strings.Contains(all, "kill -TERM"), fake.recoverCalls, fake.workspaceRemoveCalls, all)
	}
}

// When the journal cannot be shown clean, the workspace is kept for its
// recovery, and the error says so: init writes its plan and fails.
func TestInspectKeepsTheWorkspaceWhenCleanupCannotBeVerified(t *testing.T) {
	opts := inspectOptions(t)
	fake := answering(initplan.Inspection{Journaled: true, VMs: []initplan.InspectedVM{{SourceVMID: 100, Snapshot: "vm/100/2026-10-01T02:00:00Z"}}}, nil)
	fake.journalPhase = "cleanup_failed"
	fake.workerRecoveryError = errors.New("exit status 1: PBS loop device /dev/loop7 remains mapped")
	var progress bytes.Buffer
	opts.Writer = &progress
	out, err := (&Executor{runner: fake}).Inspect(context.Background(), opts, inspectReq)
	if !errors.Is(err, ErrInspectionCleanupUnverified) || len(out) == 0 {
		t.Fatalf("Inspect = %q, %v; want the answer and the unverified cleanup", out, err)
	}
	if fake.workspaceRemoveCalls != 0 {
		t.Fatal("the workspace was removed although the inspection's journal is not clean")
	}
	if !strings.Contains(progress.String(), "recover") {
		t.Errorf("progress does not say how to recover: %s", progress.String())
	}
}

// A node that refused (its lock was held) made no journal of the inspection:
// with no record of it, there is nothing to recover, and the workspace goes.
func TestInspectAcceptsNoJournalFromAWorkerThatMappedNothing(t *testing.T) {
	opts := inspectOptions(t)
	fake := answering(initplan.Inspection{Refused: "another CertiStack operation holds the node's host lock"}, nil)
	fake.journalReads = []string{"run-someone-else running"}
	if _, err := (&Executor{runner: fake}).Inspect(context.Background(), opts, inspectReq); err != nil {
		t.Fatal(err)
	}
	if fake.recoverCalls != 0 {
		t.Fatalf("recovery ran %d times over another operation's journal", fake.recoverCalls)
	}
}

// What reaches the node is checked first: another node, a request that is
// not valid.
func TestInspectRefusesBadRequests(t *testing.T) {
	opts := inspectOptions(t)
	fake := &fakeCommandRunner{}
	bad := inspectReq
	bad.Node = "pve2"
	if _, err := (&Executor{runner: fake}).Inspect(context.Background(), opts, bad); err == nil {
		t.Error("an inspection for another node was accepted")
	}
	bad = initplan.InspectRequest{Node: "pve1", Targets: []initplan.InspectTarget{{SourceVMID: 100, Snapshot: "vm/100/x; rm -rf /"}}}
	if _, err := (&Executor{runner: fake}).Inspect(context.Background(), opts, bad); err == nil {
		t.Error("a target that is not a snapshot was accepted")
	}
	if len(fake.calls) != 0 {
		t.Fatalf("a refused request reached the node: %s", commands(fake))
	}
}
