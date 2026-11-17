// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// A command that is given --env-file applies it for the length of the command
// and puts the process environment back as it was found.
// TestCommandEnvironmentRestoresUnsetAndEmptyValues tests the function, and
// nothing tested that each command calls it: `defer restoreEnvironment` could
// be removed from any one of the nine call sites with the whole package green,
// and a command that forgot it leaks the file's values into every later command
// of the process. This runs each of the nine through the real root command,
// with an environment file whose values differ from what the process holds (a
// set value, an empty one, and one that is unset), and compares os.Environ
// before and after. Where a command's seam shows what it saw, the test requires
// the file's value there too, so that "unchanged afterwards" is not "never
// applied".
func TestEveryCommandPutsTheProcessEnvironmentBackWhenItEnds(t *testing.T) {
	// A process with nothing of the allowlists set but the three names the file
	// will change: one inherited, one inherited empty, one absent.
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "")
	}
	for name := range workerEnvironmentNames {
		t.Setenv(name, "")
	}
	t.Setenv("PVE_URL", "https://inherited.example:8006")
	t.Setenv("PVE_TOKEN_ID", "")
	t.Setenv("PBS_NAMESPACE", "")
	if err := os.Unsetenv("PBS_NAMESPACE"); err != nil {
		t.Fatal(err)
	}
	const sentinel = "seam11-namespace"
	envFile := writeEnvFile(t, "PVE_URL=https://file.example:8006\nPVE_TOKEN_ID=file@pve!seam11\nPBS_NAMESPACE="+sentinel+"\n")

	root := t.TempDir()
	plan := writeValidationFixture(t, root, "plan.yaml")
	state, scratch := filepath.Join(root, "state"), filepath.Join(root, "scratch")
	for _, dir := range []string{state, scratch} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	var seen string
	previousPlan, previousPreflight, previousDiscover, previousRecover, previousInspect := computeNodePlan, runPreflight, runnerDiscover, recoverState, nodeInspect
	t.Cleanup(func() {
		computeNodePlan, runPreflight, runnerDiscover, recoverState, nodeInspect = previousPlan, previousPreflight, previousDiscover, previousRecover, previousInspect
	})
	nodeInspect = func(context.Context, initplan.InspectRequest, runner.InspectOptions) initplan.Inspection {
		seen = os.Getenv("PBS_NAMESPACE")
		return initplan.Inspection{}
	}
	computeNodePlan = func(*cobra.Command, *config.Plan, string, string, string, string, string) (*orchestrator.RunPlan, error) {
		seen = os.Getenv("PBS_NAMESPACE")
		return &orchestrator.RunPlan{PlanID: "p1", Node: "pve1", Mode: "release"}, nil
	}
	runPreflight = func(context.Context, *config.Plan, preflight.Options) preflight.Result {
		seen = os.Getenv("PBS_NAMESPACE")
		return preflight.Result{Ready: true, Checks: []preflight.CheckItem{{Name: "kvm", Status: "passed", Detail: "/dev/kvm is accessible"}}}
	}
	runnerDiscover = func(context.Context, initplan.Request, string) (*initplan.Discovery, error) {
		seen = os.Getenv("PBS_NAMESPACE")
		return &initplan.Discovery{Node: "pve1"}, nil
	}
	recoverState = func(context.Context, context.Context, string) error {
		seen = os.Getenv("PBS_NAMESPACE")
		return nil
	}

	for _, tc := range []struct {
		name string
		args []string
		// observed says the command's seam sees the file's value; otherwise the
		// command is asked to fail after it has applied the file.
		observed bool
		wantErr  string
	}{
		{"validate", []string{"validate", plan, "--env-file", envFile}, false, ""},
		{"doctor", []string{"doctor", "--scratch", scratch, "--state-dir", state, "--env-file", envFile}, true, ""},
		{"init", []string{"init", "--node", "pve1", "--env-file", envFile}, true, ""},
		{"plan", []string{"plan", plan, "--node", "pve1", "--state-dir", state, "--env-file", envFile}, true, ""},
		{"run", []string{"run", plan, "--skip-integrity", "--env-file", envFile}, false, "--skip-integrity is test-only"},
		{"recover", []string{"recover", "--state-dir", state, "--env-file", envFile}, true, ""},
		{"node-discover", []string{"node-discover", "--node", "pve1", "--env-file", envFile}, true, ""},
		{"node-inspect", []string{"node-inspect", "--node", "pve1", "--target", "100=vm/100/2026-10-05T02:00:00Z", "--state-dir", state, "--scratch", scratch, "--env-file", envFile}, true, ""},
		{"node-plan", []string{"node-plan", "--plan", plan, "--node", "pve1", "--state-dir", state, "--scratch", scratch, "--env-file", envFile}, true, ""},
		{"node-run", []string{"node-run", "--plan", plan, "--node", "pve1", "--state-dir", state, "--scratch", scratch, "--skip-integrity", "--env-file", envFile}, false, "CERTISTACK_ALLOW_TEST_MODE=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen = ""
			before := os.Environ()
			slices.Sort(before)

			err := runRoot(t, io.Discard, tc.args...)

			if tc.wantErr == "" && err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("%s: err = %v, want the failure that comes after the environment file is applied (%q)", tc.name, err, tc.wantErr)
			}
			if tc.observed && seen != sentinel {
				t.Fatalf("%s did not apply its --env-file: it saw PBS_NAMESPACE=%q, want %q", tc.name, seen, sentinel)
			}
			after := os.Environ()
			slices.Sort(after)
			if !slices.Equal(before, after) {
				t.Errorf("%s left the process environment changed:%s", tc.name, environmentDifference(before, after))
			}
		})
	}
}

// environmentDifference lists what differs between two sorted environments.
func environmentDifference(before, after []string) string {
	var out strings.Builder
	for _, entry := range after {
		if !slices.Contains(before, entry) {
			name, _, _ := strings.Cut(entry, "=")
			out.WriteString("\n  now set: " + name)
		}
	}
	for _, entry := range before {
		if !slices.Contains(after, entry) {
			name, _, _ := strings.Cut(entry, "=")
			out.WriteString("\n  lost or changed: " + name)
		}
	}
	return out.String()
}

// The other half of the call sites: the node worker's commands read the
// worker's allowlist, and the controller's commands the controller's, so a
// node-run does not take SSH settings from the file the controller uploads. A
// name only a controller reads is refused in the file of each command that runs
// on the node, and accepted by each that runs on the controller.
func TestCommandsReadTheEnvironmentAllowlistOfTheirRole(t *testing.T) {
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "")
	}
	// A name that sets nothing the commands act on (no SSH host: a controller
	// command that accepted the file would otherwise try to reach one).
	envFile := writeEnvFile(t, "CERTISTACK_SSH_USER=seam11\n")
	root := t.TempDir()
	plan := writeValidationFixture(t, root, "plan.yaml")
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	previousPlan, previousDiscover, previousRecover := computeNodePlan, runnerDiscover, recoverState
	t.Cleanup(func() {
		computeNodePlan, runnerDiscover, recoverState = previousPlan, previousDiscover, previousRecover
	})
	computeNodePlan = func(*cobra.Command, *config.Plan, string, string, string, string, string) (*orchestrator.RunPlan, error) {
		return &orchestrator.RunPlan{PlanID: "p1", Node: "pve1", Mode: "release"}, nil
	}
	runnerDiscover = func(context.Context, initplan.Request, string) (*initplan.Discovery, error) {
		return &initplan.Discovery{Node: "pve1"}, nil
	}
	recoverState = func(context.Context, context.Context, string) error { return nil }

	for _, tc := range []struct {
		name   string
		args   []string
		worker bool
	}{
		{"node-run", []string{"node-run", "--plan", plan, "--node", "pve1", "--state-dir", state, "--scratch", filepath.Join(root, "scratch"), "--env-file", envFile}, true},
		{"node-plan", []string{"node-plan", "--plan", plan, "--node", "pve1", "--state-dir", state, "--env-file", envFile}, true},
		{"node-discover", []string{"node-discover", "--node", "pve1", "--env-file", envFile}, true},
		{"node-inspect", []string{"node-inspect", "--node", "pve1", "--target", "100=vm/100/2026-10-05T02:00:00Z", "--state-dir", state, "--env-file", envFile}, true},
		{"recover", []string{"recover", "--state-dir", state, "--env-file", envFile}, true},
		{"validate", []string{"validate", plan, "--env-file", envFile}, false},
		{"run", []string{"run", plan, "--skip-integrity", "--env-file", envFile}, false},
		{"plan", []string{"plan", plan, "--node", "pve1", "--state-dir", state, "--env-file", envFile}, false},
		{"init", []string{"init", "--node", "pve1", "--env-file", envFile}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runRoot(t, io.Discard, tc.args...)
			refused := err != nil && strings.Contains(err.Error(), "CERTISTACK_SSH_USER")
			if tc.worker && !refused {
				t.Errorf("%s accepted a controller-only name in its environment file: %v", tc.name, err)
			}
			if !tc.worker && refused {
				t.Errorf("%s refused a controller's own name in its environment file: %v", tc.name, err)
			}
		})
	}
}
