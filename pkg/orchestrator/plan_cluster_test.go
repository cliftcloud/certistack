// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// overlayStepOf plans with overlay storage on the cluster database's disk, and
// returns the overlay-storage step the plan shows.
func overlayStepOf(t *testing.T, configure func(*Orchestrator)) PlanStep {
	t.Helper()
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	o.opts.OverlayStorage = "certistack-scratch"
	o.validateOverlayStorageFn = func(context.Context) error { return nil }
	o.overlayVolumePathFn = func(_ context.Context, volume string) (string, error) {
		_, rest, _ := strings.Cut(volume, ":")
		return "/var/lib/vz/images/" + rest, nil
	}
	o.sharedDisksFn = func(context.Context, string, string) ([]string, error) { return []string{"sda"}, nil }
	configure(o)
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range p.Steps {
		if step.Kind == "overlay-storage" {
			return step
		}
	}
	t.Fatal("no overlay-storage step")
	return PlanStep{}
}

// The warning that overlay storage shares the cluster database's disk talks of
// corosync and the node's cluster membership. A standalone node has no cluster:
// it is told what is true there, that the disk is shared with the node's own
// services. A node whose cluster could not be told gets the cluster's wording.
func TestOverlayDiskWarningSpeaksOfTheClusterOnlyOnAClusterNode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*Orchestrator)
		want      []string
		notWant   []string
	}{
		{"a cluster of three", func(o *Orchestrator) { inCluster(o, 3) },
			[]string{"same disk (sda) as the cluster's configuration database", "delay corosync and cost this node its cluster membership"}, nil},
		{"a node whose cluster is not known", func(o *Orchestrator) {
			o.clusterNodesFn = func(context.Context) (int, bool) { return 0, false }
		}, []string{"cost this node its cluster membership"}, nil},
		{"a standalone node", func(o *Orchestrator) { o.clusterNodesFn = func(context.Context) (int, bool) { return 0, true } },
			[]string{"same disk (sda) as the node's configuration database", "slow everything else on that disk, the node's own services included", "Put overlay storage on a disk of its own"},
			[]string{"corosync", "cluster membership", "the cluster's"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step := overlayStepOf(t, tc.configure)
			if step.Status != StatusWarning {
				t.Fatalf("overlay storage check = %+v", step)
			}
			for _, want := range tc.want {
				if !strings.Contains(step.Detail, want) {
					t.Errorf("the warning lacks %q: %s", want, step.Detail)
				}
			}
			for _, not := range tc.notWant {
				if strings.Contains(step.Detail, not) {
					t.Errorf("the warning says %q on a node that has no cluster: %s", not, step.Detail)
				}
			}
		})
	}
}

// Where the disks could not be told apart, the same: the standalone node hears
// nothing of corosync.
func TestUnknownOverlayDiskWarningSpeaksOfTheClusterOnlyOnAClusterNode(t *testing.T) {
	for name, tc := range map[string]struct {
		standalone bool
		want       string
	}{
		"standalone": {true, "shares a disk with the node's configuration database"},
		"cluster":    {false, "can delay corosync"},
	} {
		o := &Orchestrator{sharedDisksFn: func(context.Context, string, string) ([]string, error) {
			return nil, errors.New("no sysfs here")
		}}
		o.opts.OverlayStorage = "certistack-scratch"
		o.clusterNodesFn = func(context.Context) (int, bool) { return map[bool]int{true: 0, false: 3}[tc.standalone], true }
		warning, err := o.overlayClusterDiskWarning(context.Background(), "/var/lib/vz")
		if err != nil || !strings.Contains(warning, tc.want) {
			t.Errorf("%s: warning %q, err %v, want it to say %q", name, warning, err, tc.want)
		}
		if tc.standalone && strings.Contains(warning, "corosync") {
			t.Errorf("%s: a standalone node is told of corosync: %s", name, warning)
		}
	}
}

// The copy decision speaks the same way.
func TestCopyDecisionSpeaksOfTheClusterOnlyOnAClusterNode(t *testing.T) {
	in := copyInputs{mode: "always", vmBytes: 10 << 30, freeBytes: 500 << 30, sharedDisk: true}
	if _, warning, err := decideCopy(in); err != nil || !strings.Contains(warning, "delay corosync") {
		t.Errorf("a cluster node: %q, %v", warning, err)
	}
	in.standalone = true
	if _, warning, err := decideCopy(in); err != nil || strings.Contains(warning, "corosync") || !strings.Contains(warning, "node's own services") {
		t.Errorf("a standalone node: %q, %v", warning, err)
	}
	auto := copyInputs{vmBytes: 48 << 30, budgetKnown: true, budget: 35 << 30, freeBytes: 500 << 30, sharedDisk: true, standalone: true}
	if _, warning, err := decideCopy(auto); err != nil || strings.Contains(warning, "corosync") || !strings.Contains(warning, "node's configuration database") {
		t.Errorf("auto on a standalone node: %q, %v", warning, err)
	}
}

// readClusterNodes counts the nodes PVE lists, and reads a node with a corosync
// configuration as clustered even when PVE lists one.
func TestReadClusterNodes(t *testing.T) {
	dir := t.TempDir()
	corosync := filepath.Join(dir, "corosync.conf")
	if err := os.WriteFile(corosync, []byte("totem {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "none")
	for _, tc := range []struct {
		name      string
		list      string // PVE's /nodes answer; "fail" is an error
		corosync  string
		wantNodes int
		wantKnown bool
	}{
		{"three nodes", `[{"node":"a"},{"node":"b"},{"node":"c"}]`, missing, 3, true},
		{"a standalone node", `[{"node":"a"}]`, missing, 0, true},
		{"a cluster of one", `[{"node":"a"}]`, corosync, 1, true},
		{"a list PVE would not give", "fail", missing, 0, false},
		{"no list but a corosync configuration", "fail", corosync, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := clusterNodesPVE(t, tc.list)
			nodes, known := readClusterNodes(context.Background(), client, tc.corosync)
			if nodes != tc.wantNodes || known != tc.wantKnown {
				t.Fatalf("readClusterNodes = %d, %v; want %d, %v", nodes, known, tc.wantNodes, tc.wantKnown)
			}
		})
	}
}

// On a cluster node the plan says that every run reloads the network on all of
// its nodes, twice, and what avoids it. It says nothing on a standalone node,
// where only that node reloads, or of a cluster it could not read.
func TestPlanSaysAClusterReloadsItsNetworkOnEveryRun(t *testing.T) {
	const note = "This node is in a cluster of 3 nodes: every run applies SDN twice, at its start and at its end, and PVE reloads the network on all 3 nodes each time. network.lifecycle: preprovisioned avoids it"
	for _, tc := range []struct {
		name      string
		configure func(*Orchestrator)
		want      bool
	}{
		{"a cluster of three", func(o *Orchestrator) { inCluster(o, 3) }, true},
		{"a cluster of one", func(o *Orchestrator) { inCluster(o, 1) }, false},
		{"a standalone node", func(o *Orchestrator) { inCluster(o, 0) }, false},
		{"a node whose cluster is not known", func(o *Orchestrator) { o.clusterNodesFn = func(context.Context) (int, bool) { return 0, false } }, false},
		{"a pre-provisioned sandbox in a cluster", func(o *Orchestrator) {
			inCluster(o, 3)
			o.plan.Network.Lifecycle = "preprovisioned"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
			tc.configure(o)
			p, err := o.Plan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			warned := strings.Contains(strings.Join(p.Warnings, "\n"), note)
			var onStep bool
			for _, step := range p.Steps {
				if step.Kind == "sdn-reload" && step.Status == StatusWarning && strings.Contains(step.Detail, note) {
					onStep = true
				}
			}
			if warned != tc.want || onStep != tc.want {
				t.Fatalf("the cluster note: in the warnings %v, on the sdn-reload step %v; want %v\nwarnings: %v", warned, onStep, tc.want, p.Warnings)
			}
			if tc.want && !strings.Contains(strings.Join(p.Warnings, "\n"), "docs/plan-reference.md") {
				t.Errorf("the note names no page to read: %v", p.Warnings)
			}
		})
	}
}

// clusterNodesPVE answers the list of nodes with list, or an error for "fail".
func clusterNodesPVE(t *testing.T, list string) *pve.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api2/json/nodes" {
			http.NotFound(w, r)
			return
		}
		if list == "fail" {
			http.Error(w, `{"data":null,"message":"no nodes"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"data":` + list + `}`))
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}
