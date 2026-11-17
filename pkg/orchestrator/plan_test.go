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

	"github.com/cliftcloud/certistack/internal/recoverhint"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// pendingSDN, when set, is a zone with unapplied changes planPVE lists.
var pendingSDN string

// plannedZones and plannedVNets, when set, are the entries of PVE's zone and
// VNet lists planPVE answers with (JSON objects, comma-separated).
var plannedZones, plannedVNets string

// plannedMachines, when set, is the body of PVE's QEMU machine list planPVE
// answers with (a JSON array); "fail" makes the read fail.
var plannedMachines string

// plannedVMConfig, when set, is the body of VM 9001's configuration planPVE
// answers with (a JSON object); "refused" and "missing" make the read fail,
// the second in PVE's own words for a VM that does not exist on the node.
var plannedVMConfig string

// planPVE answers a planner's reads: no sandbox SDN exists yet, and the
// VMIDs in inUse are taken. Every request that is not a GET fails the test:
// planning must never change anything.
func planPVE(t *testing.T, inUse string) *pve.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("planning sent %s %s", r.Method, r.URL.Path)
			http.Error(w, "planning must not write", http.StatusForbidden)
			return
		}
		switch {
		case r.URL.Path == "/api2/json/nodes/pve1/capabilities/qemu/machines" && plannedMachines == "fail":
			http.Error(w, `{"data":null,"message":"synthetic machine list failure"}`, http.StatusInternalServerError)
		case r.URL.Path == "/api2/json/nodes/pve1/capabilities/qemu/machines" && plannedMachines != "":
			_, _ = w.Write([]byte(`{"data":` + plannedMachines + `}`))
		case r.URL.Path == "/api2/json/nodes/pve1/qemu/9001/config" && plannedVMConfig == "refused":
			http.Error(w, `{"data":null,"message":"permission check failed"}`, http.StatusForbidden)
		case r.URL.Path == "/api2/json/nodes/pve1/qemu/9001/config" && plannedVMConfig == "missing":
			http.Error(w, `{"data":null,"message":"Configuration file 'nodes/pve1/qemu-server/9001.conf' does not exist"}`, http.StatusInternalServerError)
		case r.URL.Path == "/api2/json/nodes/pve1/qemu/9001/config" && plannedVMConfig != "":
			_, _ = w.Write([]byte(`{"data":` + plannedVMConfig + `}`))
		case r.URL.Path == "/api2/json/cluster/sdn/zones" && r.URL.Query().Get("pending") == "1" && pendingSDN != "":
			_, _ = w.Write([]byte(`{"data":[` + pendingSDN + `]}`))
		case r.URL.Path == "/api2/json/cluster/sdn/zones" && plannedZones != "":
			_, _ = w.Write([]byte(`{"data":[` + plannedZones + `]}`))
		case r.URL.Path == "/api2/json/cluster/sdn/vnets" && plannedVNets != "":
			_, _ = w.Write([]byte(`{"data":[` + plannedVNets + `]}`))
		case r.URL.Path == "/api2/json/cluster/sdn/zones" || r.URL.Path == "/api2/json/cluster/sdn/vnets" || r.URL.Path == "/api2/json/cluster/sdn/controllers":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case strings.HasPrefix(r.URL.Path, "/api2/json/cluster/sdn/"):
			// As PVE answers a read of a missing zone or VNet.
			http.Error(w, `{"data":null,"message":"sdn zone 'csSb01' does not exist\n"}`, http.StatusInternalServerError)
		case r.URL.Path == "/api2/json/cluster/resources":
			_, _ = w.Write([]byte(`{"data":[` + inUse + `]}`))
		case r.URL.Path == "/api2/json/access/permissions":
			// The documented CertiStackRole, granted on /.
			path := r.URL.Query().Get("path")
			_, _ = w.Write([]byte(`{"data":{"` + path + `":{"VM.Allocate":1,"VM.Audit":1,"VM.PowerMgmt":1,"VM.Console":1,"VM.Config.Disk":1,"VM.Config.CPU":1,"VM.Config.Memory":1,"VM.Config.Network":1,"VM.Config.Options":1,"VM.Config.HWType":1,"VM.Config.CDROM":1,"SDN.Allocate":1,"SDN.Audit":1,"SDN.Use":1,"Sys.Audit":1,"Datastore.AllocateSpace":1,"Datastore.Audit":1}}}`))
		default:
			_, _ = w.Write([]byte(`{"data":null}`))
		}
	}))
	t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

func planTestPlan() *config.Plan {
	return &config.Plan{
		PlanID:           "plan-preview",
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 100, MaxHostIOWaitPercent: 100, DeferRetryIntervalSec: 1, MaxDeferRetries: 1},
		Network:          config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers: []config.Tier{{Level: 1, Name: "web", StartupGracePeriodSec: 30, VMs: []config.VM{{
			VMID: 9001, Name: "web01", SourceVMID: 100,
			SourcePBS:         config.SourcePBS{Snapshot: "vm/100/2026-09-27T03:00:00Z", Drives: []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0.img.fidx"}, {Slot: "scsi1", Archive: "drive-scsi1.img.fidx"}}},
			SourceDiskBytes:   map[string]int64{"scsi0": 10 << 30, "scsi1": 2 << 30},
			SourceConsistency: pbs.ConsistencyQuiesced,
			NetworkRecovery:   config.NetworkRecovery{Mode: "preserve"},
			Probes:            []config.Probe{{Type: "tcp", TargetIP: "10.100.0.10", Port: 22, TimeoutSec: 30, Description: "ssh"}},
		}}}},
	}
}

func planOrchestrator(t *testing.T, plan *config.Plan, client *pve.Client) *Orchestrator {
	t.Helper()
	o := New(plan, Options{NodeName: "pve1", ScratchDir: t.TempDir(), StateDir: t.TempDir(), RunID: "run-planned"}, nil, client)
	o.admission = nil // host memory is not under test
	o.cacheMemoryFn = func() (float64, error) { return 100 * 1024, nil }
	o.freeBytesFn = func(string) (int64, error) { return 500 << 30, nil }
	o.sharedDisksFn = func(context.Context, string, string) ([]string, error) { return nil, nil }
	// A standalone node, whatever machine the test runs on.
	o.clusterNodesFn = func(context.Context) (int, bool) { return 0, true }
	return o
}

// inCluster makes the planner's node one of nodes nodes of a cluster.
func inCluster(o *Orchestrator, nodes int) {
	o.clusterNodesFn = func(context.Context) (int, bool) { return nodes, true }
}

// The plan lists what a run creates, in the run's order, with the sandbox
// VM's exact PVE parameters, and teardown undoing it in reverse. It sends
// PVE nothing but reads.
func TestPlanListsARunStepByStep(t *testing.T) {
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refusals) > 0 {
		t.Fatalf("refusals: %v", p.Refusals)
	}
	var got []string
	var vm *PlanStep
	for i, step := range p.Steps {
		got = append(got, step.Action+" "+step.Kind+" "+step.Target)
		if step.Action == PlanCreate && step.Kind == "pve-vm" {
			vm = &p.Steps[i]
		}
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"create sdn-zone csSb01\ncreate sdn-vnet csVn01\ncreate sdn-subnet 10.100.0.0/24\nrun sdn-reload cluster SDN\nrun bridge-forwarding csVn01\ncreate host-address 10.100.0.1/24\ncreate nft-table inet csiso_",
		"read pbs-snapshot vm/100/2026-09-27T03:00:00Z\nread pbs-map vm/100/2026-09-27T03:00:00Z/drive-scsi0.img.fidx\ncreate overlay ",
		"read integrity-scan scsi0\nread integrity-scan scsi1\ncreate pve-vm VM 9001\nstart pve-vm VM 9001\nrun wait 30 s\nrun probe VM 9001 tcp",
		"delete pve-vm VM 9001\ndelete overlay ",
		"delete pbs-map vm/100/2026-09-27T03:00:00Z/drive-scsi0.img.fidx\ndelete nft-table inet csiso_",
		"delete host-address 10.100.0.1/24\nrun sdn-lock cluster SDN\ndelete sdn-vnet csVn01\ndelete sdn-zone csSb01\nrun sdn-reload cluster SDN\nkeep report",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan lacks, in order:\n%s\nplan:\n%s", want, joined)
		}
	}
	if vm == nil {
		t.Fatal("no sandbox VM in the plan")
	}
	for key, want := range map[string]string{"net0": "bridge=csVn01,firewall=1", "scsi0": "cache=unsafe", "scsi1": "backup=0", "tags": "certistack", "boot": "order=scsi0"} {
		if !strings.Contains(vm.Params[key], want) {
			t.Errorf("VM param %s = %q, want it to contain %q", key, vm.Params[key], want)
		}
	}
	for _, step := range p.Steps {
		if step.Kind == "integrity-scan" && step.Target == "scsi0" && !strings.Contains(step.Detail, "10 GiB") {
			t.Errorf("scan of scsi0 says %q, want its size", step.Detail)
		}
	}
}

// The preview names a VNet tag only where the VNet request carries one:
// a vxlan network's VNI. A simple network's VNet has no tag, whatever the
// plan's field says.
func TestPlanNamesTheVNetTagOnlyWhenTheRequestSendsOne(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network config.Network
		wantTag bool
	}{
		{"simple", config.Network{Mode: "simple"}, false},
		{"simple with a tag set", config.Network{Mode: "simple", Tag: 4242}, false},
		{"vxlan", config.Network{Mode: "vxlan", Tag: 4242, Peers: "10.0.0.1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := planTestPlan()
			plan.Network.Mode, plan.Network.Tag, plan.Network.Peers = tc.network.Mode, tc.network.Tag, tc.network.Peers
			p, err := planOrchestrator(t, plan, planPVE(t, "")).Plan(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range p.Steps {
				if step.Kind != "sdn-vnet" || step.Action != PlanCreate {
					continue
				}
				if got := strings.Contains(step.Detail, "tag"); got != tc.wantTag {
					t.Fatalf("preview %q names a tag: %v; the request carries one: %v", step.Detail, got, tc.wantTag)
				}
				if tc.wantTag && !strings.Contains(step.Detail, "tag 4242") {
					t.Fatalf("preview %q lacks the VNI", step.Detail)
				}
				return
			}
			t.Fatal("no VNet step in the plan")
		})
	}
}

// A run's refusals are listed, and planning goes on past each one.
func TestPlanListsEveryRefusal(t *testing.T) {
	plan := planTestPlan()
	vm := &plan.Tiers[0].VMs[0]
	vm.SourceConsistency, vm.SourceConsistencyDetail = pbs.ConsistencyCrash, "fsfreeze failed"
	vm.RequireQuiescedBackup = true
	vm.CopyBeforeBoot = config.CopyBeforeBootAlways
	o := planOrchestrator(t, plan, planPVE(t, `{"vmid":9001,"type":"qemu"}`))
	o.freeBytesFn = func(string) (int64, error) { return 1 << 30, nil }
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(p.Refusals, "\n")
	for _, want := range []string{"VM 9001 already exists", "requires a quiesced backup", "copy_before_boot: always needs"} {
		if !strings.Contains(joined, want) {
			t.Errorf("refusals lack %q:\n%s", want, joined)
		}
	}
	if last := p.Steps[len(p.Steps)-1]; last.Action != PlanKeep {
		t.Errorf("planning stopped at a refusal: last step %+v", last)
	}
}

func stepsByStatus(p *RunPlan) map[string][]string {
	out := map[string][]string{}
	for _, step := range p.Steps {
		out[step.Status] = append(out[step.Status], step.Phase+": "+step.Action+" "+step.Kind+" "+step.Target)
	}
	return out
}

// A refusal before anything is created stops the whole run: every later step
// is not reached, and teardown has nothing to delete.
func TestPlanMarksEverythingAfterAGlobalRefusalNotReached(t *testing.T) {
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	o.validateOverlayStorageFn = func(context.Context) error { return errors.New(`overlay storage "x" is type "lvmthin"`) }
	o.opts.OverlayStorage = "x"
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byStatus := stepsByStatus(p)
	if failed := byStatus[StatusFailed]; len(failed) != 1 || !strings.Contains(failed[0], "check overlay-storage x") {
		t.Fatalf("failed steps = %v", failed)
	}
	for _, reached := range byStatus[""] {
		if !strings.HasPrefix(reached, "teardown: keep") {
			t.Errorf("reached after the refusal: %s", reached)
		}
	}
	if len(byStatus[StatusNotReached]) < 10 {
		t.Errorf("not-reached steps = %v", byStatus[StatusNotReached])
	}
}

// A VM's refusal stops that VM and the later tiers, not its tier peer, and
// teardown undoes only what was reached.
func TestPlanScopesAVMRefusal(t *testing.T) {
	plan := planTestPlan()
	peer := withOwnTarget(plan.Tiers[0].VMs[0], 11)
	peer.VMID, peer.Name = 9002, "web02"
	plan.Tiers[0].VMs = append(plan.Tiers[0].VMs, peer)
	later := withOwnTarget(peer, 12)
	later.VMID, later.Name = 9003, "app01"
	plan.Tiers = append(plan.Tiers, config.Tier{Level: 2, Name: "app", VMs: []config.VM{later}})
	o := planOrchestrator(t, plan, planPVE(t, `{"vmid":9001,"type":"qemu"}`))
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byStatus := stepsByStatus(p)
	joinedFailed := strings.Join(byStatus[StatusFailed], "\n")
	if !strings.Contains(joinedFailed, "VM 9001 (web01): check vmid-free VM 9001") || len(byStatus[StatusFailed]) != 1 {
		t.Fatalf("failed steps = %v", byStatus[StatusFailed])
	}
	reached := strings.Join(byStatus[""], "\n")
	notReached := strings.Join(byStatus[StatusNotReached], "\n")
	for _, want := range []string{"VM 9002 (web02): create pve-vm VM 9002", "tier 1: run probe VM 9002 tcp", "teardown: delete pve-vm VM 9002", "teardown: delete sdn-zone csSb01"} {
		if !strings.Contains(reached, want) {
			t.Errorf("reached steps lack %q", want)
		}
	}
	for _, want := range []string{"VM 9001 (web01): create pve-vm VM 9001", "tier 1: run probe VM 9001 tcp", "VM 9003 (app01): create pve-vm VM 9003", "tier 2: run probe VM 9003 tcp"} {
		if !strings.Contains(notReached, want) {
			t.Errorf("not-reached steps lack %q", want)
		}
	}
	if strings.Contains(reached, "teardown: delete pve-vm VM 9001") || strings.Contains(reached, "teardown: delete pve-vm VM 9003") {
		t.Errorf("teardown deletes what was never created:\n%s", reached)
	}
}

// The run warns when overlay storage shares the cluster database's disk; the
// plan shows the same warning on its overlay storage check, not a plain pass
// (plan fidelity, 7011).
func TestPlanWarnsOfOverlayStorageOnTheClusterDisk(t *testing.T) {
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	inCluster(o, 1)
	o.opts.OverlayStorage = "certistack-scratch"
	o.validateOverlayStorageFn = func(context.Context) error { return nil }
	o.overlayVolumePathFn = func(_ context.Context, volume string) (string, error) {
		_, rest, _ := strings.Cut(volume, ":")
		return "/var/lib/vz/images/" + rest, nil
	}
	o.sharedDisksFn = func(_ context.Context, dir, _ string) ([]string, error) {
		if dir = filepath.ToSlash(dir); dir != "/var/lib/vz" && !strings.HasPrefix(dir, "/var/lib/vz/") {
			t.Errorf("compared %q", dir)
		}
		return []string{"sda"}, nil
	}
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range p.Steps {
		if step.Kind == "overlay-storage" {
			if step.Status != StatusWarning || !strings.Contains(step.Detail, "same disk (sda) as the cluster's configuration database") {
				t.Fatalf("overlay storage check = %+v", step)
			}
			if !strings.Contains(strings.Join(p.Warnings, "\n"), "same disk (sda)") {
				t.Fatalf("plan warnings lack the shared disk: %v", p.Warnings)
			}
			return
		}
	}
	t.Fatal("no overlay-storage step")
}

// Copy-before-boot's decision is a check: a warning when auto can't copy.
func TestPlanShowsTheCopyDecision(t *testing.T) {
	plan := planTestPlan()
	plan.Tiers[0].VMs[0].SourceDiskBytes = map[string]int64{"scsi0": 90 << 30, "scsi1": 10 << 30}
	o := planOrchestrator(t, plan, planPVE(t, ""))
	inCluster(o, 1)
	o.sharedDisksFn = func(context.Context, string, string) ([]string, error) { return []string{"sda"}, nil }
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range p.Steps {
		if step.Kind == "copy-before-boot" {
			if step.Status != StatusWarning || !strings.Contains(step.Detail, "shares the cluster database's disk") {
				t.Fatalf("copy decision = %+v", step)
			}
			return
		}
	}
	t.Fatal("no copy-before-boot step")
}

// The sandbox VM's image directory does not exist until the run makes it, so
// plan measures the free space of the storage the directory will be on, less
// the copies of the VMs before it, and applies storage.max_copy_gib as the run
// does: a copy_before_boot: always is not refused for an unknown free space.
func TestPlanDecidesCopiesOnTheStorageTheRunUses(t *testing.T) {
	storage := t.TempDir()
	if err := os.MkdirAll(filepath.Join(storage, "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan := planTestPlan()
	plan.Storage.MaxCopyGiB = 60
	vm := &plan.Tiers[0].VMs[0]
	vm.SourceDiskBytes = map[string]int64{"scsi0": 40 << 30, "scsi1": 8 << 30}
	vm.CopyBeforeBoot = config.CopyBeforeBootAlways
	second := withOwnTarget(*vm, 11)
	second.VMID, second.Name = 9002, "web02"
	plan.Tiers[0].VMs = append(plan.Tiers[0].VMs, second)
	o := planOrchestrator(t, plan, planPVE(t, ""))
	o.opts.OverlayStorage = "certistack-scratch"
	o.validateOverlayStorageFn = func(context.Context) error { return nil }
	o.overlayVolumePathFn = func(_ context.Context, volume string) (string, error) {
		_, rest, _ := strings.Cut(volume, ":")
		return filepath.Join(storage, "images", filepath.FromSlash(rest)), nil
	}
	var measured []string
	o.freeBytesFn = func(dir string) (int64, error) {
		if _, err := os.Stat(dir); err != nil {
			return 0, err // as statfs fails on a directory the run has not made
		}
		measured = append(measured, dir)
		return 100 << 30, nil
	}
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var copies []PlanStep
	for _, step := range p.Steps {
		if step.Kind == "copy-before-boot" {
			copies = append(copies, step)
		}
	}
	if len(copies) != 2 || copies[0].Status != StatusOK || !strings.Contains(copies[0].Detail, "copies the disks") {
		t.Fatalf("copy steps = %+v", copies)
	}
	// 48 GiB copied of 100 leaves 52, under the 53 the second needs; and
	// 96 GiB would be over the 60 GiB cap. The free space comes first.
	if copies[1].Status != StatusFailed || !strings.Contains(copies[1].Detail, "needs 53 GiB free") {
		t.Fatalf("second VM's copy = %+v", copies[1])
	}
	for _, dir := range measured {
		if filepath.Base(dir) != "images" {
			t.Errorf("measured %s, want the storage's images directory", dir)
		}
	}
}

func TestPlannedDirClimbsAtMostToTheStorage(t *testing.T) {
	exists := func(dirs ...string) func(string) bool {
		return func(d string) bool {
			for _, e := range dirs {
				if filepath.ToSlash(d) == e {
					return true
				}
			}
			return false
		}
	}
	for _, tc := range []struct {
		existing []string
		want     string
	}{
		{[]string{"/mnt/s/images/9001"}, "/mnt/s/images/9001"},
		{[]string{"/mnt/s/images"}, "/mnt/s/images"},
		{[]string{"/mnt/s"}, "/mnt/s"},
		// An unmounted storage is never measured on the root file system.
		{[]string{"/mnt", "/"}, "/mnt/s/images/9001"},
	} {
		if got := filepath.ToSlash(plannedDir(filepath.FromSlash("/mnt/s/images/9001"), exists(tc.existing...))); got != tc.want {
			t.Errorf("existing %v: planned %s, want %s", tc.existing, got, tc.want)
		}
	}
}

// An unfinished run's sandbox still holds the plan's VMID. The run recovers it
// first and goes on, and plan says so rather than that the run would refuse.
// Recovery destroys the VM because its markers say it is that run's: the
// journal names the run and the node, and PVE shows the markers
// (plannedVMConfig).
func TestPlanCountsWhatRecoveryDeletes(t *testing.T) {
	defer func() { plannedVMConfig = "" }()
	plannedVMConfig = `{"tags":"certistack;run-old","description":"owner=certistack; run_id=run-old"}`
	o := planOrchestrator(t, planTestPlan(), planPVE(t, `{"vmid":9001,"type":"qemu"}`))
	o.opts.Recovered = Recovered{VMIDs: []int{9001}, SDNIDs: []string{"csSb01"}, RunID: "run-old", VMNodes: map[int]string{9001: "pve1"}}
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Refusals) > 0 {
		t.Fatalf("refusals: %v", p.Refusals)
	}
	for _, step := range p.Steps {
		if step.Kind == "vmid-free" && (step.Status != StatusOK || !strings.Contains(step.Detail, "recovery destroys that VM first")) {
			t.Errorf("vmid check = %+v", step)
		}
	}
	// Without the recovery, the same VMID is refused.
	o = planOrchestrator(t, planTestPlan(), planPVE(t, `{"vmid":9001,"type":"qemu"}`))
	if p, _ := o.Plan(context.Background()); len(p.Refusals) != 1 || !strings.Contains(p.Refusals[0], "already exists") {
		t.Fatalf("refusals without recovery: %v", p.Refusals)
	}
}

// Plan says "recovery deletes it first" only where recovery would: the
// unfinished run's VNet carries the journaled marker. A replacement VNet of the
// same name (and its zone) stays, and the run would meet it; a journal that
// names no marker has recovery delete nothing PVE lists.
func TestPlanPromisesRecoveryOnlyWhereRecoveryWouldDeleteIt(t *testing.T) {
	const marker = "certistack run-old"
	defer func() { plannedZones, plannedVNets = "", "" }()
	plannedZones = `{"zone":"csSb01","type":"simple"}`
	sandbox := func(recovered Recovered) (*RunPlan, PlanStep) {
		t.Helper()
		o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
		o.opts.Recovered = recovered
		p, err := o.Plan(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range p.Steps {
			if step.Kind == "sdn-available" {
				return p, step
			}
		}
		t.Fatal("no sdn-available step in the plan")
		return nil, PlanStep{}
	}
	owned := Recovered{SDNIDs: []string{"csSb01", "csVn01"}, SDNZoneIDs: []string{"csSb01"}, SDNVNetIDs: []string{"csVn01"}, SDNOwner: marker}

	plannedVNets = `{"vnet":"csVn01","zone":"csSb01","alias":"` + marker + `"}`
	if p, step := sandbox(owned); len(p.Refusals) != 0 || !strings.Contains(step.Detail, "recovery deletes it first") {
		t.Errorf("the run's own VNet: refusals %v, step %+v; want the promise kept", p.Refusals, step)
	}

	plannedVNets = `{"vnet":"csVn01","zone":"csSb01","alias":"an administrator's VNet"}`
	p, step := sandbox(owned)
	refused := strings.Join(p.Refusals, "\n")
	if step.Status != StatusFailed || strings.Contains(step.Detail, "recovery deletes it first") ||
		!strings.Contains(refused, "already exists") || !strings.Contains(refused, "recovery would not delete it first") {
		t.Errorf("a replacement VNet: step %+v, refusals %q; want the run refused, and why recovery does not help", step, refused)
	}

	legacy := Recovered{}
	if p, step := sandbox(legacy); step.Status != StatusFailed || len(p.Refusals) != 1 {
		t.Errorf("a journal that names no marker: step %+v, refusals %v; want the run refused, nothing promised", step, p.Refusals)
	}
}

// A run applies its sandbox network under PVE's SDN lock, which PVE
// refuses while an administrator's changes are pending: plan says so first.
func TestPlanRefusesOverPendingSDNChanges(t *testing.T) {
	pendingSDN = `{"zone":"prodZ","type":"evpn","state":"changed"}`
	defer func() { pendingSDN = "" }()
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	refused := strings.Join(p.Refusals, "\n")
	if !strings.Contains(refused, "zone prodZ (changed)") || !strings.Contains(refused, "a run would be refused") {
		t.Fatalf("refusals = %q, want the pending SDN change named", refused)
	}
	// The change is someone else's: the plan says to ask them, not to apply it.
	if !strings.Contains(refused, "Ask whoever changed SDN to apply or discard the change") || !strings.Contains(refused, "Do not apply someone else's change yourself") {
		t.Fatalf("refusals = %q, want the advice to ask whoever changed SDN", refused)
	}
	for _, step := range p.Steps {
		if step.Action == PlanCreate && step.Kind == "sdn-zone" {
			t.Fatalf("plan still lists the zone a refused run would not create: %+v", step)
		}
	}
}

// The plan says what a run does when PVE's SDN lock cannot be taken for the
// teardown: it deletes nothing, leaves the zone and VNet for certistack recover,
// and does not report clean. It must not promise "made but not applied", which
// the execution never does.
func TestPlanTeardownLockWordingMatchesWhatExecutionDoes(t *testing.T) {
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, step := range p.Steps {
		if step.Kind == "sdn-lock" && strings.Contains(step.Detail, "removals") {
			found = true
			if strings.Contains(step.Detail, "made but not applied") || !strings.Contains(step.Detail, "nothing is deleted") || !strings.Contains(step.Detail, recoverhint.Recovery) {
				t.Fatalf("the teardown lock step says %q", step.Detail)
			}
		}
	}
	if !found {
		t.Fatal("the plan has no teardown SDN lock step")
	}
}

// The Community Edition writes its report unsigned, and the plan's teardown
// line does not promise a "signed JSON report".
func TestPlanSaysTheKeptReportIsUnsignedJSON(t *testing.T) {
	o := planOrchestrator(t, planTestPlan(), planPVE(t, ""))
	p, err := o.Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range p.Steps {
		if step.Kind != "report" {
			continue
		}
		if strings.Contains(step.Target, "signed JSON") && !strings.Contains(step.Target, "unsigned") {
			t.Errorf("the report line promises a signature: %+v", step)
		}
		if want := "JSON report (unsigned in the Community Edition)"; step.Target != want {
			t.Errorf("report line target = %q, want %q", step.Target, want)
		}
		return
	}
	t.Fatal("no report step in the plan")
}
