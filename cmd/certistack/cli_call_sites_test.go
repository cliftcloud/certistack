// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/spf13/cobra"
)

// This file tests the call sites the earlier tests left open: each fix was
// guarded at its ends or at one command, and reverting it at another command
// left every test green.

// planWithScratch is the repository's valid plan with storage.scratch_dir set
// to dir (or left as it is when dir is empty).
func planWithScratch(t *testing.T, root, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if dir != "" {
		withScratch := strings.Replace(text, "storage:", "storage:\n  scratch_dir: "+dir, 1)
		if withScratch == text {
			withScratch = text + "\nstorage:\n  scratch_dir: " + dir + "\n"
		}
		text = withScratch
	}
	path := filepath.Join(root, "plan.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Node-local `plan` replaced an empty --scratch with the global
// default and never asked the plan, so it worked out a different directory
// than a run would use. Doctor and the shared resolver were guarded; this is
// the plan command's own call, which could be reverted with every test green.
func TestPlanCommandResolvesTheScratchDirectoryAsARunDoes(t *testing.T) {
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_OVERLAY_STORAGE", "CERTISTACK_NODE"} {
		t.Setenv(name, "")
	}
	previous := computeNodePlan
	t.Cleanup(func() { computeNodePlan = previous })
	var got string
	computeNodePlan = func(_ *cobra.Command, plan *config.Plan, node, scratchDir, stateDir, overlayStorage, own string) (*orchestrator.RunPlan, error) {
		got = scratchDir
		return &orchestrator.RunPlan{PlanID: plan.PlanID, Node: node, Mode: "release"}, nil
	}
	root := t.TempDir()
	planScratch := filepath.Join(root, "plan-scratch")
	flagScratch := filepath.Join(root, "flag-scratch")
	envScratch := filepath.Join(root, "env-scratch")
	withPlanScratch := planWithScratch(t, t.TempDir(), planScratch)
	withoutPlanScratch := planWithScratch(t, t.TempDir(), "")
	run := func(args ...string) string {
		t.Helper()
		got = "(computePlan was not called)"
		if err := runRoot(t, io.Discard, append([]string{"plan", "--node", "pve1", "--state-dir", t.TempDir()}, args...)...); err != nil {
			t.Fatalf("plan %v: %v", args, err)
		}
		return got
	}

	if scratch := run(withPlanScratch); scratch != planScratch {
		t.Errorf("the plan's storage.scratch_dir was not the one planned with: %q, want %q", scratch, planScratch)
	}
	if scratch := run(withoutPlanScratch); scratch != sysutil.DefaultScratchDir {
		t.Errorf("a plan without a scratch directory planned with %q, want the default %q", scratch, sysutil.DefaultScratchDir)
	}
	t.Setenv("CERTISTACK_SCRATCH_DIR", envScratch)
	if scratch := run(withPlanScratch); scratch != envScratch {
		t.Errorf("CERTISTACK_SCRATCH_DIR did not beat the plan: %q, want %q", scratch, envScratch)
	}
	if scratch := run(withPlanScratch, "--scratch", flagScratch); scratch != flagScratch {
		t.Errorf("--scratch did not beat the environment and the plan: %q, want %q", scratch, flagScratch)
	}
}

// The commands whose result goes to standard output through their
// own checked writer, one by one. Each answered as the first run of the
// earlier table did when the write failed, and kept its own exit status when
// it had one; reverting any of these call sites to `return nil` left the
// earlier suite green.
func TestEveryCommandsOwnResultIsCheckedWhereItIsWritten(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PVE_URL", "")
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_NODE", "CERTISTACK_OVERLAY_STORAGE", "PBS_NAMESPACE"} {
		t.Setenv(name, "")
	}
	planPath := planWithScratch(t, root, "")
	qmpSocket := fakeQMPSocket(t)

	var plan *orchestrator.RunPlan
	previousPlan, previousPreflight, previousDiscover := computeNodePlan, runPreflight, runnerDiscover
	t.Cleanup(func() {
		computeNodePlan, runPreflight, runnerDiscover = previousPlan, previousPreflight, previousDiscover
	})
	computeNodePlan = func(*cobra.Command, *config.Plan, string, string, string, string, string) (*orchestrator.RunPlan, error) {
		return plan, nil
	}
	runPreflight = func(context.Context, *config.Plan, preflight.Options) preflight.Result {
		return preflight.Result{Ready: true, Checks: []preflight.CheckItem{{Name: "kvm", Status: "passed", Detail: "/dev/kvm is accessible"}}}
	}
	runnerDiscover = func(context.Context, initplan.Request, string) (*initplan.Discovery, error) {
		return &initplan.Discovery{Node: "pve1", Backups: []pbs.VMBackups{{VMID: 100, Comment: "web-01", Time: time.Date(2026, 9, 27, 3, 0, 0, 0, time.UTC), Count: 3}}}, nil
	}
	cleanPlan := &orchestrator.RunPlan{PlanID: "p1", Node: "pve1", Mode: "release", Steps: []orchestrator.PlanStep{{Phase: "teardown", Action: orchestrator.PlanDelete, Kind: "pve-vm", Target: "VM 9001"}}}
	refusedPlan := &orchestrator.RunPlan{PlanID: "p1", Node: "pve1", Mode: "release", Refusals: []string{"VM 9001 already exists in the PVE cluster"}}

	for _, tc := range []struct {
		name string
		plan *orchestrator.RunPlan
		args []string
		// controlExit is the exit status with a working stdout; zero is success.
		controlExit int
		// encoderError says the command's JSON mode returns the encoder's own
		// error for a write that failed, as verify-report's does.
		encoderError bool
	}{
		{"plan, text", cleanPlan, []string{"plan", planPath, "--node", "pve1", "--state-dir", root}, 0, false},
		{"plan, JSON", cleanPlan, []string{"plan", planPath, "--node", "pve1", "--state-dir", root, "--json"}, 0, false},
		{"plan a run would refuse, text", refusedPlan, []string{"plan", planPath, "--node", "pve1", "--state-dir", root}, exitCodeValidationFailed, false},
		{"plan a run would refuse, JSON", refusedPlan, []string{"plan", planPath, "--node", "pve1", "--state-dir", root, "--json"}, exitCodeValidationFailed, false},
		{"inspect a VM", nil, []string{"inspect", "9001", "--qmp", qmpSocket, "--qga", filepath.Join(root, "absent.qga")}, 0, false},
		{"doctor on a ready host, text", nil, []string{"doctor", "--scratch", filepath.Join(root, "scratch"), "--state-dir", root}, 0, false},
		{"doctor on a ready host, JSON", nil, []string{"doctor", "--json", "--scratch", filepath.Join(root, "scratch"), "--state-dir", root}, 0, true},
		{"init listing the backups", nil, []string{"init", "--node", "pve1"}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan = tc.plan
			var out bytes.Buffer
			err := runRoot(t, &out, tc.args...)
			if tc.controlExit == 0 && err != nil || tc.controlExit != 0 && exitCodeForError(err) != tc.controlExit {
				t.Fatalf("with a working stdout: err = %v (exit %d), want exit %d\n%s", err, exitCodeForError(err), tc.controlExit, out.String())
			}
			if out.Len() == 0 {
				t.Fatal("the command wrote nothing")
			}
			wantExit := tc.controlExit
			if wantExit == 0 {
				wantExit = exitCodeInfrastructure
			}
			for name, writer := range map[string]io.Writer{
				"stdout full from the start": &fullDiskWriter{},
				"stdout fills part way":      &fullDiskWriter{budget: 24},
				"stdout takes half a write":  shortWriter{},
			} {
				err := runRoot(t, writer, tc.args...)
				// A JSON document is written by the encoder, whose error is
				// the write's own (verify-report's JSON mode does the same);
				// every other result says what could not be written.
				named := err != nil && strings.Contains(err.Error(), "could not be written to standard output")
				if err == nil || !named && !(tc.encoderError && (errors.Is(err, errNoSpace) || errors.Is(err, io.ErrShortWrite))) {
					t.Errorf("%s: err = %v, want the write failure named", name, err)
					continue
				}
				if name != "stdout takes half a write" && !errors.Is(err, errNoSpace) {
					t.Errorf("%s: the write error is not kept: %v", name, err)
				}
				if exitCodeForError(err) != wantExit {
					t.Errorf("%s: exit %d, want %d: %v", name, exitCodeForError(err), wantExit, err)
				}
			}
		})
	}
}

// The scratch directory of `init` reached the node through several
// hops (the flag, the controller's command, the worker's command, the
// runner, the read of the backups); the ends were tested and the middle was
// not, so a hop that dropped it again was invisible. These are the command
// hops: what `init` and the worker's `node-discover` hand to discovery.
func TestInitCommandsHandTheirScratchDirectoryToDiscovery(t *testing.T) {
	// node-discover loads a worker environment file, which unsets every name
	// the worker allows; t.Setenv puts them back when the test ends.
	for name := range workerEnvironmentNames {
		t.Setenv(name, "")
	}
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_NODE", "PBS_NAMESPACE", "CERTISTACK_OVERLAY_STORAGE"} {
		t.Setenv(name, "")
	}
	previous := runnerDiscover
	t.Cleanup(func() { runnerDiscover = previous })
	var calls int
	var gotScratch string
	runnerDiscover = func(_ context.Context, _ initplan.Request, scratchDir string) (*initplan.Discovery, error) {
		calls++
		gotScratch = scratchDir
		return nil, errors.New("stop here: only the scratch directory is looked at")
	}
	dir := t.TempDir()
	envFile := filepath.Join(dir, "worker.env")
	if err := os.WriteFile(envFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		env  string
		want string
	}{
		{"init --scratch", []string{"init", "--node", "pve1", "--vm", "100", "--scratch", "/srv/certistack/flag", "--output", filepath.Join(dir, "a.yaml")}, "", "/srv/certistack/flag"},
		{"init, CERTISTACK_SCRATCH_DIR", []string{"init", "--node", "pve1", "--vm", "100", "--output", filepath.Join(dir, "b.yaml")}, "/srv/certistack/env", "/srv/certistack/env"},
		{"init, nothing chosen", []string{"init", "--node", "pve1", "--vm", "100", "--output", filepath.Join(dir, "c.yaml")}, "", ""},
		{"node-discover --scratch", []string{"node-discover", "--node", "pve1", "--vm", "100", "--scratch", "/srv/certistack/worker", "--env-file", envFile}, "", "/srv/certistack/worker"},
		{"node-discover, nothing chosen", []string{"node-discover", "--node", "pve1", "--vm", "100", "--env-file", envFile}, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CERTISTACK_SCRATCH_DIR", tc.env)
			before := calls
			gotScratch = "(discovery was not called)"
			if err := runRoot(t, io.Discard, tc.args...); err == nil || !strings.Contains(err.Error(), "stop here") {
				t.Fatalf("%v: %v", tc.args, err)
			}
			if calls != before+1 || gotScratch != tc.want {
				t.Fatalf("%v: discovery was handed scratch %q (calls %d), want %q", tc.args, gotScratch, calls-before, tc.want)
			}
		})
	}
}

// `plan --json` printed the plan and nothing else of what happened: a
// cleanup of the temporary worker that did not complete was only in the
// command's error, on standard error, where a program reading the document
// does not look. The document now carries it as a warning.
func TestPlanJSONCarriesTheWorkersCleanupFailure(t *testing.T) {
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_NODE", "CERTISTACK_OVERLAY_STORAGE"} {
		t.Setenv(name, "")
	}
	previous := remotePlan
	t.Cleanup(func() { remotePlan = previous })
	cleanup := errors.New("remove temporary node workspace /var/lib/certistack/workers/1234: exit status 1\nremove temporary SSH staging directory: connection reset")
	var cleanupErr error
	remotePlan = func(context.Context, controller.RunOptions) ([]byte, error) {
		return []byte(`{"plan_id":"p1","node":"pve1","mode":"release","steps":[],"warnings":["VM 9001's backup is crash-consistent"]}`), cleanupErr
	}
	planPath := planWithScratch(t, t.TempDir(), "")
	args := []string{"plan", planPath, "--ssh-host", "pve1.example", "--node", "pve1", "--state-dir", t.TempDir(), "--ssh-known-hosts", filepath.Join(t.TempDir(), "known_hosts")}

	// Without a cleanup problem the document is the node's, untouched.
	var out bytes.Buffer
	if err := runRoot(t, &out, append(args, "--json")...); err != nil {
		t.Fatalf("a clean plan: %v", err)
	}
	var clean orchestrator.RunPlan
	if err := json.Unmarshal(out.Bytes(), &clean); err != nil || len(clean.Warnings) != 1 {
		t.Fatalf("the document without a cleanup problem: %v, warnings %q", err, clean.Warnings)
	}

	cleanupErr = cleanup
	// JSON: the document carries the failure, and the command still fails.
	out.Reset()
	err := runRoot(t, &out, append(append([]string{}, args...), "--json")...)
	if err == nil || !strings.Contains(err.Error(), "remove temporary node workspace") || exitCodeForError(err) != exitCodeInfrastructure {
		t.Fatalf("the cleanup failure is not the command's error: %v (exit %d)", err, exitCodeForError(err))
	}
	var document orchestrator.RunPlan
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatalf("the document does not parse: %v\n%s", err, out.String())
	}
	joined := strings.Join(document.Warnings, "\n")
	for _, want := range []string{"VM 9001's backup is crash-consistent", "cleanup on the node did not complete", "remove temporary node workspace /var/lib/certistack/workers/1234", "remove temporary SSH staging directory: connection reset"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the document's warnings %q lack %q", document.Warnings, want)
		}
	}
	if len(document.Warnings) != 2 {
		t.Errorf("warnings = %q, want the node's own and one for the cleanup, each a single line", document.Warnings)
	}
	// Text: the same warning is in the warnings section.
	out.Reset()
	if err := runRoot(t, &out, args...); err == nil || exitCodeForError(err) != exitCodeInfrastructure {
		t.Fatalf("text: %v", err)
	}
	if !strings.Contains(out.String(), "cleanup on the node did not complete") {
		t.Errorf("the text plan lacks the cleanup warning:\n%s", out.String())
	}
}
