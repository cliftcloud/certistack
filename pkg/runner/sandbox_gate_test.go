// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// gatedPlan is a plan with a sandbox range, enough for run to reach the checks.
func gatedPlan() *config.Plan {
	return &config.Plan{
		PlanID:           "sandbox-gate",
		Compliance:       config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
		Network:          config.Network{Mode: "simple", ZoneID: "csGate1", VNetID: "csGateV1", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers:            []config.Tier{{Level: 1, VMs: []config.VM{{VMID: 9001, Name: "vm"}}}},
	}
}

// withSandboxChecks gives run and PlanRun the checks, and fails the test if the
// run goes on to read PBS (prepareRun) when reached is false.
func withSandboxChecks(t *testing.T, checks *orchestrator.SandboxChecks, prepared *bool) {
	t.Helper()
	previousChecks, previousPrepare := sandboxChecksFor, prepareRunFn
	t.Cleanup(func() { sandboxChecksFor, prepareRunFn = previousChecks, previousPrepare })
	sandboxChecksFor = func(*config.Plan, Options) *orchestrator.SandboxChecks { return checks }
	prepareRunFn = func(context.Context, *config.Plan, Options, string) (*pve.Client, *pbs.Client, error) {
		*prepared = true
		return nil, nil, errors.New("stop here: prepareRun was reached")
	}
}

// A run starts with the checks. One that refuses stops it before the run reads
// PBS, makes its directories, or opens its journal: nothing of the run exists.
func TestRunRefusesAnUnsafeSandboxBeforeAnythingExists(t *testing.T) {
	for _, tc := range []struct {
		name   string
		checks *orchestrator.SandboxChecks
		want   string
	}{
		{"a server inside the range", &orchestrator.SandboxChecks{
			Range: func(context.Context) error {
				return errors.New("network.ip_range 10.100.0.0/24 contains the PBS server (10.100.0.5)")
			},
			Network: func(context.Context) (string, error) { return "", nil },
		}, "contains the PBS server"},
		{"a real network of the node", &orchestrator.SandboxChecks{
			Range: func(context.Context) error { return nil },
			Network: func(context.Context) (string, error) {
				return "", errors.New("network.ip_range 10.100.0.0/24 overlaps the node's real network 10.100.0.0/24 (on interface vmbr4)")
			},
		}, "overlaps the node's real network"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared := false
			withSandboxChecks(t, tc.checks, &prepared)
			root := t.TempDir()
			opts := Options{NodeName: "pve1", StateDir: filepath.Join(root, "state"), ScratchDir: filepath.Join(root, "scratch"), OutputDir: filepath.Join(root, "reports"), Writer: io.Discard}
			report, err := run(context.Background(), gatedPlan(), opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run = %v, want a refusal containing %q", err, tc.want)
			}
			if report != nil {
				t.Errorf("a refused run returned a report: %+v", report)
			}
			if prepared {
				t.Error("the run went on to read PBS after the refusal")
			}
			for _, made := range []string{opts.StateDir, opts.ScratchDir, opts.OutputDir, filepath.Join(opts.StateDir, "active.json")} {
				if _, err := os.Stat(made); err == nil {
					t.Errorf("%s exists: the refusal came after the run began", made)
				}
			}
		})
	}
}

// Routes the node would not give: a run that could not compare the range with
// the node's networks does not go ahead (`plan` and `check` show
// the same condition as a warning, since they change nothing). The refusal names
// the cause and how to retry, and comes before anything of the run exists.
func TestRunRefusesWhenTheNodesRoutesCannotBeRead(t *testing.T) {
	const warning = "could not check the node's routes (open /proc/net/route: permission denied): network.ip_range 10.100.0.0/24 was not compared with the networks the node really uses. Before you run, list them with `ip -4 route` on the node and confirm that none overlaps 10.100.0.0/24."
	prepared := false
	withSandboxChecks(t, &orchestrator.SandboxChecks{
		Range:   func(context.Context) error { return nil },
		Network: func(context.Context) (string, error) { return warning, nil },
	}, &prepared)
	root := t.TempDir()
	opts := Options{NodeName: "pve1", StateDir: filepath.Join(root, "state"), ScratchDir: filepath.Join(root, "scratch"), OutputDir: filepath.Join(root, "reports"), Writer: io.Discard}
	report, err := run(context.Background(), gatedPlan(), opts)
	if err == nil {
		t.Fatal("run went ahead although the node's routes could not be read")
	}
	for _, want := range []string{"could not check the node's routes", "permission denied", "10.100.0.0/24", "was not started", "run again", "/proc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %v", want, err)
		}
	}
	if report != nil {
		t.Errorf("a refused run returned a report: %+v", report)
	}
	if prepared {
		t.Error("the run went on to read PBS after the refusal")
	}
	for _, made := range []string{opts.StateDir, opts.ScratchDir, opts.OutputDir, filepath.Join(opts.StateDir, "active.json")} {
		if _, err := os.Stat(made); err == nil {
			t.Errorf("%s exists: the refusal came after the run began", made)
		}
	}
}

// With no checks (a caller with no node to judge against) the run is as it was.
func TestRunWithoutSandboxChecksGoesStraightOn(t *testing.T) {
	prepared := false
	withSandboxChecks(t, nil, &prepared)
	root := t.TempDir()
	_, err := run(context.Background(), gatedPlan(), Options{NodeName: "pve1", StateDir: filepath.Join(root, "state"), ScratchDir: filepath.Join(root, "scratch"), OutputDir: filepath.Join(root, "reports"), Writer: io.Discard})
	if !prepared || err == nil || !strings.Contains(err.Error(), "prepareRun was reached") {
		t.Fatalf("run = %v, prepared = %v", err, prepared)
	}
}

// PlanRun gives the plan the checks, so `certistack plan` lists them first and
// stops there: the same refusal a run gives, as a failed step.
func TestPlanRunListsTheSandboxChecks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(server.Close)
	previousChecks, previousPrepare := sandboxChecksFor, prepareRunFn
	t.Cleanup(func() { sandboxChecksFor, prepareRunFn = previousChecks, previousPrepare })
	const refusal = "network.ip_range 10.100.0.0/24 overlaps the node's real network 10.100.0.0/24 (on interface vmbr4)"
	sandboxChecksFor = func(*config.Plan, Options) *orchestrator.SandboxChecks {
		return &orchestrator.SandboxChecks{
			Range:   func(context.Context) error { return nil },
			Network: func(context.Context) (string, error) { return "", errors.New(refusal) },
		}
	}
	prepareRunFn = func(context.Context, *config.Plan, Options, string) (*pve.Client, *pbs.Client, error) {
		return pve.NewClient(pve.Config{BaseURL: server.URL}), pbs.New(pbs.Config{}), nil
	}
	runPlan, err := PlanRun(context.Background(), gatedPlan(), Options{NodeName: "pve1", ScratchDir: t.TempDir(), StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(runPlan.Steps) < 2 || runPlan.Steps[0].Kind != "sandbox-range" || runPlan.Steps[0].Status != orchestrator.StatusOK ||
		runPlan.Steps[1].Kind != "sandbox-network" || runPlan.Steps[1].Status != orchestrator.StatusFailed || !strings.Contains(runPlan.Steps[1].Detail, refusal) {
		t.Fatalf("first steps = %+v", runPlan.Steps[:min(2, len(runPlan.Steps))])
	}
	if len(runPlan.Refusals) == 0 || runPlan.Refusals[0] != refusal {
		t.Errorf("refusals = %v, want the node's networks first", runPlan.Refusals)
	}
}

// The real checks, with a node whose networks are given: what they refuse and
// what they leave alone.
func TestDefaultSandboxChecks(t *testing.T) {
	node := preflight.NodeNetworks{
		Routes: []preflight.NodeRoute{
			{Destination: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("10.42.20.1"), Interface: "vmbr0"},
			{Destination: netip.MustParsePrefix("10.42.20.0/24"), Interface: "vmbr0"},
			{Destination: netip.MustParsePrefix("10.100.0.0/24"), Interface: "csGateV1"},
		},
		Addresses: []preflight.NodeAddress{
			{Prefix: netip.MustParsePrefix("10.42.20.36/24"), Interface: "vmbr0"},
			{Prefix: netip.MustParsePrefix("10.100.0.1/24"), Interface: "csGateV1"},
		},
	}
	previous := readNodeNetworks
	t.Cleanup(func() { readNodeNetworks = previous })
	readNodeNetworks = func() (preflight.NodeNetworks, error) { return node, nil }
	t.Setenv("PVE_URL", "https://10.42.20.5:8006")
	t.Setenv("PBS_REPOSITORY", "")

	networkOf := func(plan *config.Plan, opts Options) (string, error) {
		return defaultSandboxChecks(plan, opts).Network(context.Background())
	}

	// The range the node carries on the plan's own VNet is a leftover for an
	// ephemeral sandbox, and the sandbox itself for a pre-provisioned one.
	if _, err := networkOf(gatedPlan(), Options{}); err == nil || !strings.Contains(err.Error(), "csGateV1") {
		t.Errorf("an ephemeral sandbox found already on the node: %v, want a refusal naming interface csGateV1", err)
	}
	pre := gatedPlan()
	pre.Network.Lifecycle = "preprovisioned"
	if warning, err := networkOf(pre, Options{}); err != nil || warning != "" {
		t.Errorf("a pre-provisioned sandbox on its own VNet: warning %q, error %v", warning, err)
	}
	// A recovery that removes the plan's VNet first leaves nothing of it to find.
	if warning, err := networkOf(gatedPlan(), Options{Recovered: orchestrator.Recovered{SDNVNetIDs: []string{"csGateV1"}}}); err != nil || warning != "" {
		t.Errorf("a leftover VNet that recovery removes first: warning %q, error %v", warning, err)
	}
	// A range over the management network is refused whatever the lifecycle.
	over := gatedPlan()
	over.Network.IPRange, over.Network.ProbeIP = "10.42.20.0/24", "10.42.20.250"
	if _, err := networkOf(over, Options{}); err == nil || !strings.Contains(err.Error(), "10.42.20.0/24") {
		t.Errorf("a range over the management network: %v", err)
	}
	// Unreadable routes warn.
	readNodeNetworks = func() (preflight.NodeNetworks, error) {
		return preflight.NodeNetworks{}, errors.New("permission denied")
	}
	if warning, err := networkOf(gatedPlan(), Options{}); err != nil || !strings.Contains(warning, "could not check the node's routes") {
		t.Errorf("unreadable routes: warning %q, error %v", warning, err)
	}

	// The PVE API and the PBS server of the run, from the environment, else the plan.
	rangeOf := func(plan *config.Plan) error {
		return defaultSandboxChecks(plan, Options{}).Range(context.Background())
	}
	holds := gatedPlan()
	holds.Network.IPRange, holds.Network.ProbeIP = "10.42.20.0/24", "10.42.20.250"
	if err := rangeOf(holds); err == nil || !strings.Contains(err.Error(), "the PVE API") {
		t.Errorf("a range holding PVE_URL's host: %v", err)
	}
	t.Setenv("PVE_URL", "https://192.0.2.5:8006")
	if err := rangeOf(holds); err != nil {
		t.Errorf("a range beside the servers was refused: %v", err)
	}
	t.Setenv("PBS_REPOSITORY", "u@pbs!t@10.42.20.7:store")
	if err := rangeOf(holds); err == nil || !strings.Contains(err.Error(), "the PBS server") {
		t.Errorf("a range holding PBS_REPOSITORY's host: %v", err)
	}
	t.Setenv("PBS_REPOSITORY", "")
	holds.Storage.PBSRepository = "u@pbs!t@10.42.20.8:store"
	if err := rangeOf(holds); err == nil || !strings.Contains(err.Error(), "the PBS server") {
		t.Errorf("a range holding the plan's pbs_repository host: %v", err)
	}
	if defaultSandboxChecks(nil, Options{}) != nil {
		t.Error("a nil plan has checks")
	}
}
