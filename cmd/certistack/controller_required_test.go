// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// onHost makes the commands see a host that is, or is not, a PVE node. The
// tests of this package run on hosts that are no PVE node, and TestMain has
// the check stand aside for them; a test that wants the check says what the
// host is.
func onHost(t *testing.T, isPVENode bool) {
	t.Helper()
	previous := hostIsPVENode
	t.Cleanup(func() { hostIsPVENode = previous })
	hostIsPVENode = func() bool { return isPVENode }
}

const controllerRequiredMessage = "pass --env-file FILE to work from the controller; without it this command runs on the PVE node itself and must be run there"

func clearSSHEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_NODE", "CERTISTACK_OVERLAY_STORAGE", "PBS_NAMESPACE"} {
		t.Setenv(name, "")
	}
}

// plan and init without --env-file and without an SSH host work on the node
// itself. On a host that is not a PVE node (a controller, where a newcomer who
// forgot the flag is) they stop before calling PVE and say what to do, rather
// than retrying PVE and failing on a missing proxmox-backup-client with the
// controller's own host name shown as the node.
func TestPlanAndInitOnAControllerWithoutEnvFileSayToPassOne(t *testing.T) {
	clearSSHEnvironment(t)
	onHost(t, false)
	spy := spyOnNode(t)
	planPath := planWithScratch(t, t.TempDir(), "")
	for name, args := range map[string][]string{
		"plan":         {"plan", planPath},
		"plan --json":  {"plan", planPath, "--json"},
		"init":         {"init"},
		"init --vm":    {"init", "--vm", "100", "-o", filepath.Join(t.TempDir(), "plan.yaml")},
		"plan --node":  {"plan", planPath, "--node", "pve-node-01"},
		"init --node ": {"init", "--node", "pve-node-01"},
	} {
		t.Run(name, func(t *testing.T) {
			started := time.Now()
			var out bytes.Buffer
			err := runRoot(t, &out, args...)
			if err == nil || !strings.Contains(err.Error(), controllerRequiredMessage) {
				t.Fatalf("err = %v, want the message %q", err, controllerRequiredMessage)
			}
			if !strings.Contains(err.Error(), "/etc/pve") {
				t.Errorf("the message does not say why this host is not a node: %v", err)
			}
			if spy.planned || spy.discovered || out.Len() != 0 || time.Since(started) > 2*time.Second {
				t.Errorf("the command went on past the refusal: planned %v, discovered %v, output %q", spy.planned, spy.discovered, out.String())
			}
		})
	}
}

// An environment file without an SSH host is still the node-local use, and a
// controller is told the variable that makes it a controller's.
func TestPlanAndInitOnAControllerWithAnEnvFileWithoutAnSSHHostNameTheVariable(t *testing.T) {
	clearSSHEnvironment(t)
	onHost(t, false)
	spyOnNode(t)
	planPath := planWithScratch(t, t.TempDir(), "")
	for name, args := range map[string][]string{
		"plan": {"plan", planPath},
		"init": {"init"},
	} {
		t.Run(name, func(t *testing.T) {
			envFile := writeEnvFile(t, "PVE_URL=https://pve.example:8006\n")
			err := runRoot(t, new(bytes.Buffer), append(args, "--env-file", envFile)...)
			if err == nil || !strings.Contains(err.Error(), "CERTISTACK_SSH_HOST") || strings.Contains(err.Error(), controllerRequiredMessage) {
				t.Fatalf("err = %v, want the missing CERTISTACK_SSH_HOST named, and not the advice to pass the file it was given", err)
			}
		})
	}
}

// An SSH host makes it the controller's command wherever it runs, and a real
// PVE node keeps its node-local use: the check refuses neither.
func TestPlanAndInitKeepTheControllerAndTheNodeLocalUse(t *testing.T) {
	clearSSHEnvironment(t)
	planPath := planWithScratch(t, t.TempDir(), "")

	t.Run("an SSH host on a controller", func(t *testing.T) {
		onHost(t, false)
		previousPlan, previousDiscover := remotePlan, remoteDiscover
		t.Cleanup(func() { remotePlan, remoteDiscover = previousPlan, previousDiscover })
		var planned, discovered bool
		remotePlan = func(context.Context, controller.RunOptions) ([]byte, error) {
			planned = true
			return []byte(`{"plan_id":"p1","node":"pve1","mode":"release","steps":[]}`), nil
		}
		remoteDiscover = func(context.Context, controller.RunOptions, initplan.Request) ([]byte, error) {
			discovered = true
			return []byte(`{"node":"pve1"}`), nil
		}
		known := filepath.Join(t.TempDir(), "known_hosts")
		if err := runRoot(t, new(bytes.Buffer), "plan", planPath, "--ssh-host", "pve1.example", "--node", "pve1", "--ssh-known-hosts", known); err != nil && strings.Contains(err.Error(), controllerRequiredMessage) {
			t.Fatalf("plan with an SSH host was refused: %v", err)
		}
		if err := runRoot(t, new(bytes.Buffer), "init", "--ssh-host", "pve1.example", "--node", "pve1", "--ssh-known-hosts", known); err != nil && strings.Contains(err.Error(), controllerRequiredMessage) {
			t.Fatalf("init with an SSH host was refused: %v", err)
		}
		if !planned || !discovered {
			t.Errorf("the controller's path was not taken: plan %v, init %v", planned, discovered)
		}
	})

	t.Run("a PVE node, without an environment file", func(t *testing.T) {
		onHost(t, true)
		spy := spyOnNode(t)
		if err := runRoot(t, new(bytes.Buffer), "plan", planPath); err != nil && strings.Contains(err.Error(), controllerRequiredMessage) {
			t.Fatalf("plan as root on the node was refused: %v", err)
		}
		if err := runRoot(t, new(bytes.Buffer), "init"); err != nil && strings.Contains(err.Error(), controllerRequiredMessage) {
			t.Fatalf("init as root on the node was refused: %v", err)
		}
		if !spy.planned || !spy.discovered {
			t.Errorf("the node-local path was not taken: plan %v, init %v", spy.planned, spy.discovered)
		}
	})
}

// The node-side workers and doctor are not the controller's commands: they run
// on the node whatever it looks like to this check.
func TestNodeSideCommandsAreNotAskedForAnEnvFileToWorkFromTheController(t *testing.T) {
	clearSSHEnvironment(t)
	onHost(t, false)
	spyOnNode(t)
	dir := t.TempDir()
	planFile := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(planFile, []byte("not a plan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runRoot(t, new(bytes.Buffer), "node-plan", "--plan", planFile, "--node", "pve1", "--env-file", writeEnvFile(t, "PVE_URL=https://pve.example:8006\n"))
	if err != nil && strings.Contains(err.Error(), controllerRequiredMessage) {
		t.Fatalf("node-plan was asked for the controller's environment file: %v", err)
	}
}
