// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// withOwnTarget copies a planned VM and gives the copy its own wire-probe
// address, 10.100.0.<last>: a plan names each wire target on one VM only, so a
// peer made by copying a planned VM needs an address of its own.
func withOwnTarget(vm config.VM, last int) config.VM {
	probes := make([]config.Probe, len(vm.Probes))
	copy(probes, vm.Probes)
	for i := range probes {
		if config.IsWireProbe(probes[i].Type) {
			probes[i].TargetIP = fmt.Sprintf("10.100.0.%d", last)
		}
	}
	vm.Probes = probes
	return vm
}

// countingListener accepts connections on a loopback port and counts them.
func countingListener(t *testing.T) (host string, port int, accepted *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted = new(atomic.Int32)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err = strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port, accepted
}

func preservedVM(vmid int, name, target string, port int) config.VM {
	return config.VM{
		VMID: vmid, Name: name,
		NetworkRecovery: config.NetworkRecovery{Mode: "preserve"},
		Probes:          []config.Probe{{Type: "tcp", TargetIP: target, Port: port, TimeoutSec: 1, Description: name + " service"}},
	}
}

// Two VMs whose probes name one listener must not both pass and be signed as
// that listener's two verified services. The probes of a VM whose target
// another VM of the plan names are not run, so the listener is never asked on
// either one's behalf; the probes of a VM that owns its target are unaffected.
func TestRunProbesRefusesATargetAnotherVMNames(t *testing.T) {
	host, port, accepted := countingListener(t)
	first := preservedVM(9200, "preserved-first", host, port)
	second := preservedVM(9201, "preserved-second", host, port)
	orch := &Orchestrator{plan: &config.Plan{Tiers: []config.Tier{{Level: 1, VMs: []config.VM{first, second}}}}}

	for _, vm := range []config.VM{first, second} {
		results, passed, err := orch.runProbes(context.Background(), vm)
		if err == nil || passed || len(results) != 0 {
			t.Fatalf("VM %d: results %v, passed %v, err %v; want a refusal and no result", vm.VMID, results, passed, err)
		}
		for _, want := range []string{fmt.Sprintf("VM %d", vm.VMID), "9200, 9201", host, "exactly one VM"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("VM %d: error %q does not mention %q", vm.VMID, err, want)
			}
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the listener took %d connection(s) for VMs whose target another VM names", n)
	}

	// The control: the second VM has an address of its own, and the first VM's
	// probe reaches the listener once.
	second = preservedVM(9201, "preserved-second", "10.100.0.11", port)
	orch.plan = &config.Plan{Tiers: []config.Tier{{Level: 1, VMs: []config.VM{first, second}}}}
	results, passed, err := orch.runProbes(context.Background(), first)
	if err != nil || !passed || len(results) != 1 {
		t.Fatalf("a VM that owns its target: results %v, passed %v, err %v", results, passed, err)
	}
	for deadline := time.Now().Add(2 * time.Second); accepted.Load() < 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := accepted.Load(); n != 1 {
		t.Fatalf("the listener took %d connection(s) for the one VM that owns its target, want 1", n)
	}
}

// A VM the plan does not list is still not run on a target a listed VM names.
func TestRunProbesRefusesATargetOfAVMOutsideThePlan(t *testing.T) {
	host, port, accepted := countingListener(t)
	owner := preservedVM(9200, "owner", host, port)
	stranger := preservedVM(9299, "stranger", host, port)
	orch := &Orchestrator{plan: &config.Plan{Tiers: []config.Tier{{Level: 1, VMs: []config.VM{owner}}}}}
	if _, passed, err := orch.runProbes(context.Background(), stranger); err == nil || passed || !strings.Contains(err.Error(), "9200, 9299") {
		t.Fatalf("passed %v, err %v", passed, err)
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the listener took %d connection(s)", n)
	}
}

// The resolved plan is checked before the run creates anything: a target two
// VMs name, in preserve mode as in any other, and a MAC two NICs hold, as the
// plan's resolved backups can leave them.
func TestRunRefusesAPlanWhoseVMsShareATargetOrAMACBeforeCreatingAnything(t *testing.T) {
	cases := map[string]struct {
		mutate func(plan *config.Plan)
		want   []string
	}{
		"one target on two preserve-mode VMs": {
			mutate: func(plan *config.Plan) {
				plan.Tiers[0].VMs[1].Probes[0].TargetIP = plan.Tiers[0].VMs[0].Probes[0].TargetIP
			},
			want: []string{"10.100.0.10", "9100, 9101", "exactly one VM"},
		},
		"one MAC on two VMs": {
			mutate: func(plan *config.Plan) {
				plan.Tiers[0].VMs[0].MAC, plan.Tiers[0].VMs[1].MAC = "02:AA:BB:CC:DD:EE", "02-aa-bb-cc-dd-ee"
			},
			want: []string{"VM 9101 net0 and VM 9100 net0 both use 02:AA:BB:CC:DD:EE"},
		},
		"net0's MAC again on net1": {
			mutate: func(plan *config.Plan) {
				plan.Tiers[0].VMs[0].MAC = "02:AA:BB:CC:DD:EE"
				plan.Tiers[0].VMs[0].AdditionalNICs = []config.SourceNIC{{Slot: "net1", Model: "virtio", MAC: "02:AA:BB:CC:DD:EE"}}
			},
			want: []string{"VM 9100 net1 and VM 9100 net0 both use 02:AA:BB:CC:DD:EE"},
		},
		"a multicast MAC": {
			mutate: func(plan *config.Plan) { plan.Tiers[0].VMs[1].MAC = "01:00:5E:00:00:01" },
			want:   []string{"tiers[0].vms[1].mac", "VM 9101 net0", "multicast"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
			}))
			defer server.Close()
			plan := networkOnlyPlan()
			plan.Tiers = []config.Tier{{Level: 1, VMs: []config.VM{
				preservedVM(9100, "web", "10.100.0.10", 443),
				preservedVM(9101, "app", "10.100.0.11", 443),
			}}}
			tc.mutate(plan)
			hostAddresses := &fakeHostAddressManager{}
			orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
			orch.hostAddresses = hostAddresses

			res, err := orch.Run(context.Background())
			if err == nil || res.AllPassed {
				t.Fatalf("Run = passed %v, err %v; want a refusal", res.AllPassed, err)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
			if requests != 0 || len(hostAddresses.added) != 0 {
				t.Fatalf("run created resources before refusing: %d PVE request(s), host addresses %v", requests, hostAddresses.added)
			}
			if len(res.VMRecords) != 0 {
				t.Fatalf("VM records before the refusal: %v", res.VMRecords)
			}
		})
	}
}

// The plan lists the same check, so a refusal shows before a run is tried.
func TestPlanRefusesAPlanWhoseVMsShareATargetOrAMAC(t *testing.T) {
	plan := planTestPlan()
	second := plan.Tiers[0].VMs[0] // the same target
	second.VMID, second.Name = 9002, "web02"
	plan.Tiers[0].VMs = append(plan.Tiers[0].VMs, second)
	o := planOrchestrator(t, plan, planPVE(t, ""))
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refusals) == 0 || !strings.Contains(strings.Join(p.Refusals, "\n"), "9001, 9002") {
		t.Fatalf("refusals = %v", p.Refusals)
	}
	var shown bool
	for _, step := range p.Steps {
		shown = shown || (step.Kind == "vm-identities" && step.Status == StatusFailed)
	}
	if !shown {
		t.Fatal("the plan does not show the failed identity check")
	}

	// With own addresses and distinct MACs the same plan has no such refusal.
	plan = planTestPlan()
	second = withOwnTarget(plan.Tiers[0].VMs[0], 11)
	second.VMID, second.Name = 9002, "web02"
	plan.Tiers[0].VMs[0].MAC, second.MAC = "02:AA:BB:CC:DD:01", "02:AA:BB:CC:DD:02"
	plan.Tiers[0].VMs = append(plan.Tiers[0].VMs, second)
	p, err = planOrchestrator(t, plan, planPVE(t, "")).Plan(context.Background())
	if err != nil || len(p.Refusals) != 0 {
		t.Fatalf("distinct plan: err %v, refusals %v", err, p.Refusals)
	}
}

// sandboxVMConfig and CreateParams refuse NICs that share a MAC: one VM's NICs
// cannot share an address at the request, and the plan refuses a pair across
// VMs before any request is built.
func TestRequestsRefuseDuplicateMACs(t *testing.T) {
	const duplicateMAC = "02:AA:BB:CC:DD:EE"
	plan := &config.Plan{Network: config.Network{VNetID: "csVn202"}}
	orch := &Orchestrator{plan: plan}
	first := config.VM{
		VMID: 9900, Name: "duplicate-one", MAC: duplicateMAC, NICModel: "virtio",
		AdditionalNICs: []config.SourceNIC{{Slot: "net1", Model: "virtio", MAC: duplicateMAC}},
	}
	second := config.VM{VMID: 9901, Name: "duplicate-two", MAC: duplicateMAC, NICModel: "virtio"}
	disk := []pve.DiskOverlay{{Slot: "scsi0", Path: "/tmp/audit-duplicate.qcow2"}}
	if _, err := orch.sandboxVMConfig(first, disk, "scsi0", nil).CreateParams(); err == nil || !strings.Contains(err.Error(), "net1 and net0 both use MAC address "+duplicateMAC) {
		t.Fatalf("net0 and net1 of one VM: %v", err)
	}
	first.AdditionalNICs = nil
	if _, err := orch.sandboxVMConfig(first, disk, "scsi0", nil).CreateParams(); err != nil {
		t.Fatalf("one VM alone: %v", err)
	}
	plan.Tiers = []config.Tier{{VMs: []config.VM{first, second}}}
	if err := orch.checkResolvedInputs(); err == nil || !strings.Contains(err.Error(), "VM 9901 net0 and VM 9900 net0 both use "+duplicateMAC) {
		t.Fatalf("net0 of two VMs: %v", err)
	}
}

// The plan shows each sandbox VM's NIC identities as the run will send
// them, in PVE's spelling, so an operator reads the resolved inventory (the
// MACs a backup contributed included) before a run.
func TestPlanShowsEachVMsNICIdentities(t *testing.T) {
	plan := planTestPlan()
	vm := &plan.Tiers[0].VMs[0]
	vm.MAC, vm.NICModel = "bc-24-11-00-00-01", "virtio"
	vm.AdditionalNICs = []config.SourceNIC{{Slot: "net1", Model: "e1000", MAC: "bc:24:11:00:00:02"}}
	p, err := planOrchestrator(t, plan, planPVE(t, "")).Plan(context.Background())
	if err != nil || len(p.Refusals) != 0 {
		t.Fatalf("err %v, refusals %v", err, p.Refusals)
	}
	for _, step := range p.Steps {
		if step.Action == PlanCreate && step.Kind == "pve-vm" {
			if step.Params["net0"] != "virtio=BC:24:11:00:00:01,bridge=csVn01,firewall=1" || step.Params["net1"] != "e1000=BC:24:11:00:00:02,bridge=csVn01,firewall=1" {
				t.Fatalf("NIC parameters: net0=%q net1=%q", step.Params["net0"], step.Params["net1"])
			}
			return
		}
	}
	t.Fatal("the plan has no sandbox VM step")
}
