// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// The worker's side of check reads the runtime environment the controller
// staged, runs the node's layers with it, and prints the report as the only
// thing on standard output. A failed layer is a report, not a failed command.
func TestNodeCheckPrintsTheReportAndExitsZeroWhenALayerFails(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "runtime.env")
	body := strings.Join([]string{
		"PVE_URL=https://pve.example:8006",
		"PVE_TOKEN_ID=certistack-svc@pve!automation",
		"PVE_TOKEN_SECRET=worker-secret",
		"PBS_REPOSITORY=ro@pbs!t@pbs.example:8007:ds",
		"PBS_PASSWORD=pbs-secret",
		"PBS_NAMESPACE=prod",
		"CERTISTACK_PVE_CA_SOURCE=" + filepath.Join(dir, "pve-ca.pem"),
		"CERTISTACK_PROGRESS_EVENTS=1",
	}, "\n") + "\n"
	if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := nodeCheckProbes
	t.Cleanup(func() { nodeCheckProbes = previous })
	var seen nodecheck.Settings
	nodeCheckProbes = nodecheck.Probes{
		LookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		PVEVersion: func(_ context.Context, s nodecheck.Settings) (string, error) {
			seen = s
			return "", errors.New("configure PVE API client: boom")
		},
		PBSBackups: func(context.Context, nodecheck.Settings) ([]pbs.VMBackups, error) {
			t.Error("PBS was asked after the PVE layer failed")
			return nil, nil
		},
	}

	out, err := runRootWithInput(t, "", "node-check", "--env-file", env)
	if err != nil {
		t.Fatalf("node-check: %v", err)
	}
	var report nodecheck.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("standard output is not the report: %v\n%q", err, out)
	}
	failed := report.Failed()
	if failed == nil || failed.Name != nodecheck.LayerPVE || failed.Code != nodecheck.CodePVEConfig || len(report.Layers) != 2 {
		t.Fatalf("report = %+v", report)
	}
	if seen.PVEURL != "https://pve.example:8006" || seen.PVETokenID != "certistack-svc@pve!automation" || seen.PVETokenSecret != "worker-secret" ||
		seen.PBSNamespace != "prod" || seen.PVECAFile != filepath.Join(dir, "pve-ca.pem") {
		t.Errorf("the layers did not get the runtime environment: %+v", seen)
	}
	if strings.Contains(out, "worker-secret") || strings.Contains(out, "pbs-secret") {
		t.Errorf("the report holds a secret: %s", out)
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Errorf("standard output is more than the one report line:\n%s", out)
	}
}

func TestNodeCheckIsHiddenAndNeedsItsEnvironmentFile(t *testing.T) {
	for _, command := range newRootCmd(nil).Commands() {
		if command.Name() == "node-check" && !command.Hidden {
			t.Error("node-check is not hidden")
		}
	}
	if _, err := runRootWithInput(t, "", "node-check"); err == nil || !strings.Contains(err.Error(), "env-file") {
		t.Errorf("no --env-file: %v", err)
	}
	// The controller's own variables are not the worker's.
	env := filepath.Join(t.TempDir(), "runtime.env")
	if err := os.WriteFile(env, []byte("CERTISTACK_SSH_HOST=pve\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runRootWithInput(t, "", "node-check", "--env-file", env); err == nil || !strings.Contains(err.Error(), "unsupported node worker environment variable") {
		t.Errorf("a controller-only variable: %v", err)
	}
}

// --through has the worker stop after a layer, so that a controller that has
// no token yet learns about the node's tools and PVE is never asked.
func TestNodeCheckThroughStopsAfterTheLayer(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "runtime.env")
	body := strings.Join([]string{
		"PVE_URL=https://pve.example:8006",
		"PVE_TOKEN_ID=not-set@pve!placeholder",
		"PVE_TOKEN_SECRET=placeholder",
		"PBS_REPOSITORY=ro@pbs!t@pbs.example:8007:ds",
		"PBS_PASSWORD=pbs-secret",
	}, "\n") + "\n"
	if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := nodeCheckProbes
	t.Cleanup(func() { nodeCheckProbes = previous })
	nodeCheckProbes = nodecheck.Probes{
		LookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		PVEVersion: func(context.Context, nodecheck.Settings) (string, error) {
			t.Error("PVE was asked although the check stops after the tools")
			return "", nil
		},
		PBSBackups: func(context.Context, nodecheck.Settings) ([]pbs.VMBackups, error) {
			t.Error("PBS was asked although the check stops after the tools")
			return nil, nil
		},
	}
	out, err := runRootWithInput(t, "", "node-check", "--env-file", env, "--through", "node_tools")
	if err != nil {
		t.Fatal(err)
	}
	var report nodecheck.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil || len(report.Layers) != 1 || report.Layers[0].Name != nodecheck.LayerTools {
		t.Fatalf("report = %+v, %v", report, err)
	}
}

// With the plan's sandbox network on the command line, the worker's last layer
// judges it against this node; without, there is no such layer.
func TestNodeCheckJudgesThePlansSandboxNetwork(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "runtime.env")
	body := strings.Join([]string{
		"PVE_URL=https://10.42.20.5:8006",
		"PVE_TOKEN_ID=certistack-svc@pve!automation",
		"PVE_TOKEN_SECRET=worker-secret",
		"PBS_REPOSITORY=ro@pbs!t@10.42.10.5:8007:ds",
		"PBS_PASSWORD=pbs-secret",
	}, "\n") + "\n"
	if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := nodeCheckProbes
	t.Cleanup(func() { nodeCheckProbes = previous })
	var read int
	nodeCheckProbes = nodecheck.Probes{
		LookPath:   func(name string) (string, error) { return "/usr/bin/" + name, nil },
		PVEVersion: func(context.Context, nodecheck.Settings) (string, error) { return "9.0.3", nil },
		PBSBackups: func(context.Context, nodecheck.Settings) ([]pbs.VMBackups, error) { return nil, nil },
		NodeNetworks: func() (preflight.NodeNetworks, error) {
			read++
			return preflight.NodeNetworks{Routes: []preflight.NodeRoute{{Destination: netip.MustParsePrefix("10.42.15.0/24"), Interface: "vmbr4"}}}, nil
		},
	}
	layers := func(args ...string) nodecheck.Report {
		t.Helper()
		out, err := runRootWithInput(t, "", append([]string{"node-check", "--env-file", env}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		var report nodecheck.Report
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return report
	}

	if report := layers(); len(report.Layers) != 3 || read != 0 {
		t.Fatalf("without a plan's network: %d layers, %d reads", len(report.Layers), read)
	}
	clean := layers("--sandbox-range", "192.0.2.0/24", "--sandbox-probe", "192.0.2.1", "--sandbox-vnet", "csVnet1")
	if len(clean.Layers) != 4 || clean.Failed() != nil || clean.Layers[3].Name != nodecheck.LayerSandbox {
		t.Fatalf("a clean range: %+v", clean)
	}
	over := layers("--sandbox-range", "10.42.15.0/24", "--sandbox-probe", "10.42.15.250", "--sandbox-vnet", "csVnet1", "--sandbox-lifecycle", "ephemeral")
	failed := over.Failed()
	if failed == nil || failed.Name != nodecheck.LayerSandbox || failed.Code != nodecheck.CodeSandboxNetwork || !strings.Contains(failed.Detail, "10.42.15.0/24 (on interface vmbr4)") {
		t.Fatalf("an overlapping range: %+v", over)
	}
	held := layers("--sandbox-range", "10.42.20.0/24", "--sandbox-probe", "10.42.20.250", "--sandbox-vnet", "csVnet1")
	if failed := held.Failed(); failed == nil || failed.Code != nodecheck.CodeSandboxRange {
		t.Fatalf("a range holding PVE: %+v", held)
	}
	// The network goes together: a range with no probe address is not a network.
	if _, err := runRootWithInput(t, "", "node-check", "--env-file", env, "--sandbox-range", "192.0.2.0/24"); err == nil || !strings.Contains(err.Error(), "--sandbox-probe") {
		t.Errorf("a range alone: %v", err)
	}
}

// With --no-wire-probes (the controller's word that the plan has none) the
// worker does not require nft; without it, it does.
func TestNodeCheckNoWireProbesMakesNftOptional(t *testing.T) {
	env := filepath.Join(t.TempDir(), "runtime.env")
	body := strings.Join([]string{
		"PVE_URL=https://pve.example:8006",
		"PVE_TOKEN_ID=not-set@pve!placeholder",
		"PVE_TOKEN_SECRET=placeholder",
		"PBS_REPOSITORY=ro@pbs!t@pbs.example:8007:ds",
		"PBS_PASSWORD=pbs-secret",
	}, "\n") + "\n"
	if err := os.WriteFile(env, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := nodeCheckProbes
	t.Cleanup(func() { nodeCheckProbes = previous })
	nodeCheckProbes = nodecheck.Probes{
		LookPath: func(name string) (string, error) {
			if name == "nft" {
				return "", errors.New("not found")
			}
			return "/usr/bin/" + name, nil
		},
	}
	tools := func(args ...string) nodecheck.Layer {
		t.Helper()
		out, err := runRootWithInput(t, "", append([]string{"node-check", "--env-file", env, "--through", "node_tools"}, args...)...)
		if err != nil {
			t.Fatal(err)
		}
		var report nodecheck.Report
		if err := json.Unmarshal([]byte(out), &report); err != nil || len(report.Layers) != 1 {
			t.Fatalf("report = %+v, %v", report, err)
		}
		return report.Layers[0]
	}
	if layer := tools(); layer.Status != nodecheck.StatusFailed || len(layer.Missing) != 1 || layer.Missing[0].Name != "nft" {
		t.Errorf("a node without nft passed the tools layer: %+v", layer)
	}
	if layer := tools("--no-wire-probes"); layer.Status != nodecheck.StatusPassed {
		t.Errorf("--no-wire-probes still required nft: %+v", layer)
	}
}
