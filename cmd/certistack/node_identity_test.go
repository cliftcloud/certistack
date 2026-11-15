// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/nodecheck"
	"github.com/cliftcloud/certistack/internal/nodeidentity"
	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// onPVENode makes the node-side commands run on the PVE node named local. The
// tests of this package run on hosts that are no PVE node, and TestMain has
// the check stand aside for them; a test that wants the check puts it back.
func onPVENode(t *testing.T, local string) {
	t.Helper()
	previous := verifyNodeIdentity
	t.Cleanup(func() { verifyNodeIdentity = previous })
	verifyNodeIdentity = func(named string) error { return nodeidentity.Compare(local, named) }
}

const foreignNodeMessage = "this host is PVE node pve-real, but the node name given (CERTISTACK_NODE or --node) is pve-other: set CERTISTACK_NODE=pve-real, or point CERTISTACK_SSH_HOST at node pve-other."

// nodeSpy records which of the calls that reach the node (its host lock, its
// PBS and PVE, its journal and directories) a command made.
type nodeSpy struct {
	lockTaken, discovered, probed, preflighted, planned, inspected bool
}

func spyOnNode(t *testing.T) *nodeSpy {
	t.Helper()
	spy := &nodeSpy{}
	previousLock, previousDiscover, previousProbes, previousPreflight, previousPlan, previousInspect := acquireHostLock, runnerDiscover, nodeCheckProbes, runPreflight, computeNodePlan, nodeInspect
	t.Cleanup(func() {
		acquireHostLock, runnerDiscover, nodeCheckProbes, runPreflight, computeNodePlan, nodeInspect = previousLock, previousDiscover, previousProbes, previousPreflight, previousPlan, previousInspect
	})
	acquireHostLock = func() (*os.File, error) { spy.lockTaken = true; return nil, errors.New("test: no host lock") }
	runnerDiscover = func(context.Context, initplan.Request, string) (*initplan.Discovery, error) {
		spy.discovered = true
		return nil, errors.New("test: discovery reached")
	}
	nodeCheckProbes = nodecheck.Probes{
		LookPath: func(name string) (string, error) { spy.probed = true; return "/usr/bin/" + name, nil },
		PVEVersion: func(context.Context, nodecheck.Settings) (string, error) {
			spy.probed = true
			return "", errors.New("test")
		},
		PBSBackups: func(context.Context, nodecheck.Settings) ([]pbs.VMBackups, error) { spy.probed = true; return nil, nil },
	}
	runPreflight = func(context.Context, *config.Plan, preflight.Options) preflight.Result {
		spy.preflighted = true
		return preflight.Result{Ready: true}
	}
	computeNodePlan = func(*cobra.Command, *config.Plan, string, string, string, string, string) (*orchestrator.RunPlan, error) {
		spy.planned = true
		return nil, errors.New("test: plan reached")
	}
	nodeInspect = func(context.Context, initplan.InspectRequest, runner.InspectOptions) initplan.Inspection {
		spy.inspected = true
		return initplan.Inspection{}
	}
	return spy
}

// nodeSideCommand is a command that runs on a PVE node, with the arguments
// that give it a node name and the effects it must not have had when the name
// is refused.
type nodeSideCommand struct {
	name string
	// args are the command's arguments for node; dir is a private directory.
	args func(t *testing.T, dir, node string) []string
	// reached reports an effect on the node, which a refused name must not have.
	reached func(spy *nodeSpy, dir string) bool
}

func nodeSideCommands() []nodeSideCommand {
	worker := func(t *testing.T) string {
		return writeEnvFile(t, "PVE_URL=https://pve.example:8006\n")
	}
	plan := func(t *testing.T, dir string) string {
		path := filepath.Join(dir, "plan.yaml")
		if err := os.WriteFile(path, []byte("not a plan\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return []nodeSideCommand{
		{"node-run", func(t *testing.T, dir, node string) []string {
			return []string{"node-run", "--plan", plan(t, dir), "--node", node, "--env-file", worker(t), "--state-dir", filepath.Join(dir, "state"), "--scratch", filepath.Join(dir, "scratch")}
		}, func(spy *nodeSpy, dir string) bool {
			_, err := os.Stat(filepath.Join(dir, "state"))
			return spy.lockTaken || err == nil
		}},
		{"node-plan", func(t *testing.T, dir, node string) []string {
			return []string{"node-plan", "--plan", plan(t, dir), "--node", node, "--env-file", worker(t)}
		}, func(spy *nodeSpy, _ string) bool { return spy.planned }},
		{"node-inspect", func(t *testing.T, dir, node string) []string {
			return []string{"node-inspect", "--node", node, "--env-file", worker(t), "--state-dir", filepath.Join(dir, "state"), "--scratch", filepath.Join(dir, "scratch"), "--target", "100=vm/100/2026-10-01T00:00:00Z"}
		}, func(spy *nodeSpy, dir string) bool {
			_, err := os.Stat(filepath.Join(dir, "state"))
			return spy.inspected || spy.lockTaken || err == nil
		}},
		{"node-discover", func(t *testing.T, _, node string) []string {
			return []string{"node-discover", "--node", node, "--env-file", worker(t)}
		}, func(spy *nodeSpy, _ string) bool { return spy.discovered }},
		{"node-check", func(t *testing.T, _, node string) []string {
			return []string{"node-check", "--node", node, "--env-file", worker(t)}
		}, func(spy *nodeSpy, _ string) bool { return spy.probed }},
		{"doctor with CERTISTACK_NODE", func(t *testing.T, dir, node string) []string {
			return []string{"doctor", "--env-file", writeEnvFile(t, "CERTISTACK_NODE="+node+"\n"), "--state-dir", filepath.Join(dir, "state"), "--scratch", filepath.Join(dir, "scratch")}
		}, func(spy *nodeSpy, _ string) bool { return spy.preflighted }},
		{"init --node on the node", func(t *testing.T, _, node string) []string {
			return []string{"init", "--node", node, "--env-file", writeEnvFile(t, "")}
		}, func(spy *nodeSpy, _ string) bool { return spy.discovered }},
		{"init with CERTISTACK_NODE on the node", func(t *testing.T, _, node string) []string {
			return []string{"init", "--env-file", writeEnvFile(t, "CERTISTACK_NODE="+node+"\n")}
		}, func(spy *nodeSpy, _ string) bool { return spy.discovered }},
		{"plan --node on the node", func(t *testing.T, dir, node string) []string {
			return []string{"plan", plan(t, dir), "--node", node}
		}, func(spy *nodeSpy, _ string) bool { return spy.planned }},
		{"plan with CERTISTACK_NODE on the node", func(t *testing.T, dir, node string) []string {
			return []string{"plan", plan(t, dir), "--env-file", writeEnvFile(t, "CERTISTACK_NODE="+node+"\n")}
		}, func(spy *nodeSpy, _ string) bool { return spy.planned }},
	}
}

func TestNodeSideCommandsRefuseANodeNameThatIsNotTheHosts(t *testing.T) {
	for _, command := range nodeSideCommands() {
		t.Run(command.name, func(t *testing.T) {
			onPVENode(t, "pve-real")
			spy := spyOnNode(t)
			dir := t.TempDir()
			_, err := runRootWithInput(t, "", command.args(t, dir, "pve-other")...)
			if err == nil || !strings.Contains(err.Error(), foreignNodeMessage) {
				t.Fatalf("err = %v, want the refusal %q", err, foreignNodeMessage)
			}
			if command.reached(spy, dir) {
				t.Error("the command went on past the check: it called the node, or changed it, before it refused")
			}
		})
	}
}

func TestNodeSideCommandsGoOnWhenTheNodeNameIsTheHosts(t *testing.T) {
	for _, command := range nodeSideCommands() {
		t.Run(command.name, func(t *testing.T) {
			onPVENode(t, "pve-real")
			spyOnNode(t)
			_, err := runRootWithInput(t, "", command.args(t, t.TempDir(), "pve-real")...)
			if err != nil && strings.Contains(err.Error(), "this host is PVE node") {
				t.Fatalf("the host's own name was refused: %v", err)
			}
		})
	}
}
