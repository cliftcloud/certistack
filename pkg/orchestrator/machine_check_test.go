// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// pve84Machines are the machine IDs of a PVE 8.4 node with QEMU 9.2 (the facts
// of a real PVE 8.4 node): nothing newer than 9.2, plus the unversioned
// aliases.
var pve84Machines = []string{
	"q35", "pc", "pc-q35-9.2+pve1", "pc-q35-9.2", "pc-q35-9.1", "pc-q35-9.0", "pc-q35-8.1", "pc-q35-7.2",
	"pc-i440fx-9.2+pve1", "pc-i440fx-9.2", "pc-i440fx-9.1", "pc-i440fx-8.1", "pc-i440fx-5.1",
}

// machineNode is a fake PVE node that lists QEMU machines and records every
// request it is sent.
type machineNode struct {
	mu       sync.Mutex
	requests []string
	ids      []string
	fail     bool
}

func newMachineNode(t *testing.T, ids ...string) (*machineNode, *pve.Client) {
	t.Helper()
	node := &machineNode{ids: ids}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node.mu.Lock()
		node.requests = append(node.requests, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/api2/json/"))
		fail, ids := node.fail, node.ids
		node.mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/pve1/capabilities/qemu/machines" {
			if fail {
				http.Error(w, `{"data":null,"message":"synthetic machine list failure"}`, http.StatusInternalServerError)
				return
			}
			type machine struct {
				ID string `json:"id"`
			}
			list := make([]machine, 0, len(ids))
			for _, id := range ids {
				list = append(list, machine{ID: id})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": list})
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(server.Close)
	return node, pve.NewClient(pve.Config{BaseURL: server.URL})
}

func (n *machineNode) seen() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.requests...)
}

func (n *machineNode) machineReads() int {
	reads := 0
	for _, request := range n.seen() {
		if request == "GET nodes/pve1/capabilities/qemu/machines" {
			reads++
		}
	}
	return reads
}

// machinePlan is a one-tier plan whose VMs have the given machines, VM IDs
// 9001, 9002, ... in order.
func machinePlan(machines ...string) *config.Plan {
	plan := planTestPlan()
	base := plan.Tiers[0].VMs[0]
	plan.Tiers[0].VMs = nil
	for i, machine := range machines {
		vm := withOwnTarget(base, 10+i)
		vm.VMID, vm.Name, vm.Machine = 9001+i, "vm"+string(rune('a'+i)), machine
		vm.MAC = "02:AA:BB:CC:DD:0" + string(rune('1'+i))
		plan.Tiers[0].VMs = append(plan.Tiers[0].VMs, vm)
	}
	return plan
}

func machineOrchestrator(t *testing.T, plan *config.Plan, client *pve.Client) *Orchestrator {
	t.Helper()
	return New(plan, Options{NodeName: "pve1", ScratchDir: t.TempDir(), StateDir: t.TempDir(), RunID: "run-machines"}, pbs.New(pbs.Config{}), client)
}

// q35, pc, i440fx and no setting are unversioned and never refused; only a
// versioned type is compared, whatever options follow it.
func TestVersionedMachineReadsOnlyVersionedTypes(t *testing.T) {
	for _, tc := range []struct {
		setting, machine, family, base string
		ok                             bool
	}{
		{"pc-q35-11.0+pve2", "pc-q35-11.0+pve2", "q35", "11.0", true},
		{"pc-q35-9.0", "pc-q35-9.0", "q35", "9.0", true},
		{"pc-i440fx-8.1", "pc-i440fx-8.1", "i440fx", "8.1", true},
		{"pc-i440fx-9.2+pve1,viommu=intel", "pc-i440fx-9.2+pve1", "i440fx", "9.2", true},
		{"type=pc-q35-9.2+pve1", "pc-q35-9.2+pve1", "q35", "9.2", true},
		{"q35", "", "", "", false},
		{"pc", "", "", "", false},
		{"i440fx", "", "", "", false},
		{"", "", "", "", false},
		{"q35,viommu=virtio", "", "", "", false},
		{"pc-q35-9", "", "", "", false},
		{"pc-q35-9.0+pvex", "", "", "", false},
		{"virt-9.0", "", "", "", false},
		{"microvm", "", "", "", false},
	} {
		machine, family, base, ok := versionedMachine(tc.setting)
		if machine != tc.machine || family != tc.family || base != tc.base || ok != tc.ok {
			t.Errorf("versionedMachine(%q) = %q, %q, %q, %v; want %q, %q, %q, %v", tc.setting, machine, family, base, ok, tc.machine, tc.family, tc.base, tc.ok)
		}
	}
}

// The live fact (PVE 8.4, QEMU 9.2): a VM created with pc-q35-11.0+pve2 only
// fails when it starts. The check refuses it first, naming the VM, the machine
// and what the node offers, and refuses nothing the node can run.
func TestCheckNodeMachinesRefusesAMachineTheNodeCannotRun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		machines []string
		offered  []string // the node's list; nil is pve84Machines
		want     []string // in the refusal
		warn     string   // in the warning
		reads    int
	}{
		{name: "newer than the node's QEMU", machines: []string{"pc-q35-11.0+pve2"}, want: []string{"VM 9001 (vma)", "pc-q35-11.0+pve2", "newer than node pve1's QEMU can run", "pc-q35-9.2, pc-q35-9.1, pc-q35-9.0", "set machine for that VM in the plan to an unversioned type", "as new as the one that made the backup"}, reads: 1},
		{name: "unversioned q35 reads nothing", machines: []string{"q35"}, reads: 0},
		{name: "unversioned pc and none read nothing", machines: []string{"pc", ""}, reads: 0},
		{name: "an older version", machines: []string{"pc-q35-9.0"}, reads: 1},
		{name: "the newest version", machines: []string{"pc-q35-9.2+pve1"}, reads: 1},
		{name: "another revision of an offered version", machines: []string{"pc-q35-9.2+pve2"}, reads: 1},
		{name: "options after the type", machines: []string{"pc-q35-8.1,viommu=intel"}, reads: 1},
		{name: "a version the node no longer offers", machines: []string{"pc-q35-2.4"}, want: []string{"VM 9001", "pc-q35-2.4", "does not offer", "pc-q35-9.2, pc-q35-9.1, pc-q35-9.0"}, reads: 1},
		{name: "i440fx too new", machines: []string{"pc-i440fx-10.0"}, want: []string{"pc-i440fx-10.0", "newer than", "pc-i440fx-9.2, pc-i440fx-9.1, pc-i440fx-8.1"}, reads: 1},
		{name: "one list read for several VMs", machines: []string{"pc-q35-11.0+pve2", "pc-q35-9.0", "pc-i440fx-10.0", "q35"}, want: []string{"VM 9001 (vma) is pinned to machine pc-q35-11.0+pve2", "VM 9003 (vmc) is pinned to machine pc-i440fx-10.0"}, reads: 1},
		{name: "a family the node lists none of is not judged", machines: []string{"pc-i440fx-9.0"}, offered: []string{"pc-q35-9.2"}, warn: "lists no QEMU machine versions to check VM 9001 (pc-i440fx-9.0)", reads: 1},
		{name: "an empty list is not judged", machines: []string{"pc-q35-11.0+pve2"}, offered: []string{}, warn: "lists no QEMU machine versions to check VM 9001 (pc-q35-11.0+pve2)", reads: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			offered := tc.offered
			if offered == nil {
				offered = pve84Machines
			}
			node, client := newMachineNode(t, offered...)
			o := machineOrchestrator(t, machinePlan(tc.machines...), client)
			warning, err := o.checkNodeMachines(context.Background())
			if len(tc.want) == 0 && err != nil {
				t.Fatalf("a machine the node can run was refused: %v", err)
			}
			if len(tc.want) > 0 && err == nil {
				t.Fatalf("a machine the node cannot run was accepted")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q lacks %q", err, want)
				}
			}
			if tc.warn == "" && warning != "" {
				t.Errorf("unexpected warning %q", warning)
			}
			if !strings.Contains(warning, tc.warn) {
				t.Errorf("warning %q lacks %q", warning, tc.warn)
			}
			if got := node.machineReads(); got != tc.reads {
				t.Errorf("the machine list was read %d times, want %d (requests %v)", got, tc.reads, node.seen())
			}
			if len(node.seen()) != node.machineReads() {
				t.Errorf("the check asked PVE for more than the machine list: %v", node.seen())
			}
			if len(tc.want) == 1 && strings.Count(err.Error(), "is pinned to machine") != 1 {
				t.Errorf("the refusal names %d VMs, want one: %v", strings.Count(err.Error(), "is pinned to machine"), err)
			}
		})
	}
}

// A machine list that cannot be read is a warning and the run goes on, as the
// pin of an unversioned Windows machine does: the check never refuses on what
// it could not see. The warning is one, naming every VM it could not check.
func TestCheckNodeMachinesWarnsOnceWhenTheListCannotBeRead(t *testing.T) {
	node, client := newMachineNode(t, pve84Machines...)
	node.fail = true
	o := machineOrchestrator(t, machinePlan("pc-q35-11.0+pve2", "pc-q35-10.1"), client)
	warning, err := o.checkNodeMachines(context.Background())
	if err != nil {
		t.Fatalf("an unreadable list refused the run: %v", err)
	}
	for _, want := range []string{"Could not read node pve1's QEMU machine versions", "VM 9001 (pc-q35-11.0+pve2), VM 9002 (pc-q35-10.1)", "synthetic machine list failure"} {
		if !strings.Contains(warning, want) {
			t.Errorf("warning %q lacks %q", warning, want)
		}
	}
	if got := node.machineReads(); got != 1 {
		t.Errorf("the failing list was read %d times, want once", got)
	}
}

// Run refuses before it prepares any guest: no sandbox network, no VM boot (the
// restore, overlay and PBS map all happen inside it), and nothing written to
// PVE. The only request is the one read of the machine list.
func TestRunRefusesANewerMachineBeforeAnyGuestPreparation(t *testing.T) {
	node, client := newMachineNode(t, pve84Machines...)
	o := machineOrchestrator(t, machinePlan("pc-q35-11.0+pve2"), client)
	booted := 0
	o.bootVMFn = func(context.Context, config.VM, int, *attest.PhaseTimings) (*probe.VMValidationRecord, error) {
		booted++
		return &probe.VMValidationRecord{}, nil
	}
	result, err := o.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pc-q35-11.0+pve2") || !strings.Contains(err.Error(), "VM 9001") {
		t.Fatalf("run = %v, want the machine refusal naming VM 9001", err)
	}
	if result == nil || result.AllPassed || len(result.VMRecords) != 0 {
		t.Errorf("result = %+v, want a failed run with no VM records", result)
	}
	if booted != 0 {
		t.Errorf("%d VM(s) were prepared before the refusal", booted)
	}
	for _, request := range node.seen() {
		if request != "GET nodes/pve1/capabilities/qemu/machines" {
			t.Errorf("a refused run sent PVE %q; only the machine list is read before the refusal", request)
		}
	}
	if node.machineReads() != 1 {
		t.Errorf("the machine list was read %d times, want once; requests %v", node.machineReads(), node.seen())
	}
}

// plan shows the same refusal as a failed check, and the steps after it as not
// reached; a plan whose machines the node can run has no such refusal.
func TestPlanShowsTheMachineRefusal(t *testing.T) {
	plannedMachines = `[{"id":"pc-q35-9.2+pve1"},{"id":"pc-q35-9.2"},{"id":"pc-q35-9.0"}]`
	t.Cleanup(func() { plannedMachines = "" })

	plan := planTestPlan()
	plan.Tiers[0].VMs[0].Machine = "pc-q35-11.0+pve2"
	p, err := planOrchestrator(t, plan, planPVE(t, "")).Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refusals) != 1 || !strings.Contains(p.Refusals[0], "VM 9001 (web01) is pinned to machine pc-q35-11.0+pve2") || !strings.Contains(p.Refusals[0], "pc-q35-9.2, pc-q35-9.0") {
		t.Fatalf("refusals = %q", p.Refusals)
	}
	var shown, later bool
	for _, step := range p.Steps {
		if step.Kind == "machine-versions" {
			shown = step.Status == StatusFailed
		}
		if step.Kind == "pve-vm" && step.Status == StatusNotReached {
			later = true
		}
	}
	if !shown || !later {
		t.Errorf("failed machine check shown %v, later steps not reached %v:\n%+v", shown, later, p.Steps)
	}

	plan = planTestPlan()
	plan.Tiers[0].VMs[0].Machine = "pc-q35-9.0"
	p, err = planOrchestrator(t, plan, planPVE(t, "")).Plan(context.Background())
	if err != nil || len(p.Refusals) != 0 {
		t.Fatalf("a machine the node offers: err %v, refusals %v", err, p.Refusals)
	}
	var passed bool
	for _, step := range p.Steps {
		passed = passed || (step.Kind == "machine-versions" && step.Status == StatusOK)
	}
	if !passed {
		t.Errorf("the plan does not show the passed machine check:\n%+v", p.Steps)
	}

	// No versioned machine, no check step and no list read.
	p, err = planOrchestrator(t, planTestPlan(), planPVE(t, "")).Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range p.Steps {
		if step.Kind == "machine-versions" {
			t.Errorf("a plan with no versioned machine shows %+v", step)
		}
	}
}

// An unreadable machine list is a plan warning, not a refusal.
func TestPlanWarnsWhenTheMachineListCannotBeRead(t *testing.T) {
	plannedMachines = "fail"
	t.Cleanup(func() { plannedMachines = "" })
	plan := planTestPlan()
	plan.Tiers[0].VMs[0].Machine = "pc-q35-11.0+pve2"
	p, err := planOrchestrator(t, plan, planPVE(t, "")).Plan(context.Background())
	if err != nil || len(p.Refusals) != 0 {
		t.Fatalf("an unreadable list refused the plan: err %v, refusals %v", err, p.Refusals)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "Could not read node pve1's QEMU machine versions") {
		t.Errorf("warnings = %q", p.Warnings)
	}
}
