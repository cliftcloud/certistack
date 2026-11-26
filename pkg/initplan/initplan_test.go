// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

type fakeBackups struct {
	list     []pbs.VMBackups
	profiles map[string]pbs.VMProfile
	errs     map[string]error
	mu       sync.Mutex // profiles are read concurrently
	read     []string
}

func (f *fakeBackups) ListVMBackups(context.Context) ([]pbs.VMBackups, error) { return f.list, nil }

func (f *fakeBackups) LoadVMProfile(_ context.Context, snapshot, _ string) (pbs.VMProfile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.read = append(f.read, snapshot)
	if err := f.errs[snapshot]; err != nil {
		return pbs.VMProfile{}, err
	}
	return f.profiles[snapshot], nil
}

type fakeCluster struct {
	used     map[int]bool
	storages []pve.NodeStorage
	taken    map[string]bool
	calls    int
}

func (f *fakeCluster) UsedVMIDs(context.Context) (map[int]bool, error) {
	f.calls++
	used := map[int]bool{}
	for id := range f.used {
		used[id] = true
	}
	return used, nil
}

func (f *fakeCluster) ListNodeStorages(context.Context, string) ([]pve.NodeStorage, error) {
	f.calls++
	return f.storages, nil
}

func (f *fakeCluster) UsedSDNIDs(context.Context) (map[string]bool, error) {
	f.calls++
	used := map[string]bool{}
	for id := range f.taken {
		used[strings.ToLower(id)] = true
	}
	return used, nil
}

var backupTime = time.Date(2026, 9, 27, 3, 0, 0, 0, time.UTC)

func backupsOf(ids ...int) []pbs.VMBackups {
	var list []pbs.VMBackups
	for _, id := range ids {
		list = append(list, pbs.VMBackups{VMID: id, Latest: fmt.Sprintf("vm/%d/2026-09-27T03:00:00Z", id), Time: backupTime, Count: 3})
	}
	return list
}

func storage(name, typ, content string, active, shared int, availGiB int64) pve.NodeStorage {
	return pve.NodeStorage{Storage: name, NodeStorageStatus: pve.NodeStorageStatus{Type: typ, Content: content, Active: active, Enabled: 1, Shared: shared, Avail: availGiB << 30}}
}

// Without VMs, init only lists what has backups, and asks PVE nothing.
// The same lookalike, in the refusal of an invalid node name.
func TestValidateRequestShowsALookalikeNodeNameEscaped(t *testing.T) {
	err := ValidateRequest(Request{Node: "pv\u0435" + "1"})
	if err == nil {
		t.Fatal("a lookalike node name was accepted")
	}
	if !strings.Contains(err.Error(), "pv\\u04351") || strings.ContainsRune(err.Error(), '\u0435') {
		t.Errorf("the refusal does not show the lookalike escaped: %v", err)
	}
}

func TestDiscoverListsBackups(t *testing.T) {
	backups := &fakeBackups{list: backupsOf(100, 101)}
	cluster := &fakeCluster{}
	d, err := Discover(context.Background(), backups, cluster, Request{Node: "pve1"}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Backups) != 2 || len(d.VMs) != 0 || cluster.calls != 0 || len(backups.read) != 0 {
		t.Fatalf("listing read %v and asked PVE %d times: %+v", backups.read, cluster.calls, d)
	}
}

func TestDiscoverRefusesAVMWithoutABackup(t *testing.T) {
	_, err := Discover(context.Background(), &fakeBackups{list: backupsOf(100)}, &fakeCluster{}, Request{Node: "pve1", Namespace: "prod", VMIDs: []int{100, 105, 106}}, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no complete backup of VM 105, 106 in namespace \"prod\"") {
		t.Fatalf("err = %v", err)
	}
}

// Discover reads each backup as a run does, and picks sandbox VM IDs and
// SDN IDs that PVE, other plans and existing backups do not use.
func TestDiscoverChoosesFreeIDsAndUsableStorage(t *testing.T) {
	backups := &fakeBackups{
		list: backupsOf(100, 101, 9101),
		profiles: map[string]pbs.VMProfile{
			"vm/100/2026-09-27T03:00:00Z":  {Name: "web-01", OSType: "l26", MAC: "BC:24:11:00:00:01", Agent: true, MemoryMB: 4096, DiskBytes: map[string]int64{"scsi0": 32 << 30, "scsi1": 8 << 30}},
			"vm/9101/2026-09-27T03:00:00Z": {Name: "db-01", OSType: "l26", MAC: "BC:24:11:00:00:02", Agent: true},
		},
		errs: map[string]error{"vm/101/2026-09-27T03:00:00Z": errors.New("the backup is encrypted and no key was given")},
	}
	cluster := &fakeCluster{
		used: map[int]bool{9100: true},
		storages: []pve.NodeStorage{
			storage("scratch", "dir", "images,iso", 1, 0, 400),
			storage("local-lvm", "lvmthin", "images,rootdir", 1, 0, 900),
			storage("local", "dir", "iso,vztmpl,backup", 1, 0, 90),
			storage("nfs-old", "nfs", "images", 0, 1, 900),
		},
		taken: map[string]bool{"csZone1": true},
	}
	d, err := Discover(context.Background(), backups, cluster, Request{Node: "pve1", VMIDs: []int{101, 100, 9101}, AvoidVMIDs: []int{9102}, AvoidSDNIDs: []string{"csvnet2"}}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.VMs) != 3 || d.VMs[0].SourceVMID != 100 || d.VMs[1].SourceVMID != 101 {
		t.Fatalf("VMs = %+v", d.VMs)
	}
	if vm := d.VMs[0]; vm.Name != "web-01" || !vm.Agent || !vm.HasNIC || vm.DiskBytes != 40<<30 || vm.MemoryMB != 4096 || vm.Error != "" {
		t.Errorf("VM 100 = %+v", vm)
	}
	if !strings.Contains(d.VMs[1].Error, "encrypted") {
		t.Errorf("VM 101 = %+v", d.VMs[1])
	}
	// 9100 is in use, 9101 names a backup, 9102 is another plan's. VM 101's
	// backup could not be read, so the plan leaves it out and it takes no ID.
	if fmt.Sprint(d.SandboxVMIDs) != "[9103 9104]" {
		t.Errorf("sandbox VM IDs = %v", d.SandboxVMIDs)
	}
	if len(d.Storages) != 1 || d.Storages[0].Storage != "scratch" {
		t.Errorf("storages = %+v", d.Storages)
	}
	// csZone1 exists, csVnet2 is another plan's (compared without case).
	if d.ZoneID != "csZone3" || d.VNetID != "csVnet3" {
		t.Errorf("SDN = %s/%s", d.ZoneID, d.VNetID)
	}
}

func discovered() *Discovery {
	vm := func(id int, name, ostype, bios string, agent, nic bool) VM {
		return VM{SourceVMID: id, Snapshot: fmt.Sprintf("vm/%d/2026-09-27T03:00:00Z", id), BackupTime: backupTime, Name: name, OSType: ostype, BIOS: bios, Agent: agent, HasNIC: nic, DiskBytes: 32 << 30}
	}
	return &Discovery{
		Node: "pve1",
		VMs: []VM{
			vm(100, "web-01", "l26", "seabios", true, true),
			vm(101, "dc-01", "win11", "ovmf", true, true),
			vm(102, "", "win10", "seabios", false, true),
			vm(103, "fw", "other", "seabios", true, true),
			vm(104, "batch", "l26", "seabios", false, false),
			{SourceVMID: 105, Snapshot: "vm/105/2026-09-27T03:00:00Z", Error: "the backup is encrypted and no key was given"},
			vm(106, strings.Repeat("a", 70), "l26", "seabios", false, true),
		},
		Storages:     []pve.NodeStorage{storage("nfs-big", "nfs", "images", 1, 1, 2000), storage("scratch", "dir", "images", 1, 0, 400)},
		SandboxVMIDs: []int{9100, 9101, 9102, 9103, 9104, 9105, 9106},
		ZoneID:       "csZone1",
		VNetID:       "csVnet1",
	}
}

// Init writes the label for "no standard", NONE, with a comment that says what
// the labels are: the plan is valid as written, maps to no framework only by
// that explicit choice, and the operator replaces NONE only to name a
// standard.
func TestComposedPlanIsValidAsWritten(t *testing.T) {
	res, err := Compose(discovered(), Options{Written: backupTime})
	if err != nil {
		t.Fatal(err)
	}
	text := string(res.YAML)
	if strings.Contains(text, "frameworks: []") || strings.Contains(text, "frameworks: [CHANGE]") {
		t.Fatalf("the composed plan still needs its frameworks set:\n%s", text)
	}
	const block = "compliance:\n  # The standards the report is labeled with: DORA, SOC2, HIPAA, ISO27001,\n  # CIS_V8 (a label, not a certification). NONE names none and stands alone;\n  # replace it to name one or more. It is valid as it stands.\n  frameworks: [NONE]\n"
	if !strings.Contains(text, block) {
		t.Fatalf("the plan lacks the frameworks line and the comment that explains it:\n%s", text)
	}
	if strings.Contains(text, "not valid until") || strings.Contains(text, "set compliance.frameworks") {
		t.Fatalf("the plan still says it needs the frameworks set:\n%s", text)
	}
	plan, err := config.LoadFromReader(bytes.NewReader(res.YAML))
	if err != nil || len(plan.Compliance.Frameworks) != 1 || plan.Compliance.Frameworks[0] != "NONE" {
		t.Fatalf("loading the composed plan as written: frameworks %v, err %v", plan, err)
	}
	// The probes keep their CHANGE marker: each is a first check, not the VM's service.
	if !strings.Contains(text, "# CHANGE: check the service this VM is for") {
		t.Fatalf("the probes lost their CHANGE marker:\n%s", text)
	}
}

// The Community Edition writes its reports unsigned, so init asks for no signing
// key and writes no sign_key_path (nor a pointer to a keygen command): the plan it
// writes is valid as written, and a Community user never meets a
// signing step.
func TestComposedPlanNeedsNoSigningKeyAndNamesNone(t *testing.T) {
	res, err := Compose(discovered(), Options{Written: backupTime})
	if err != nil {
		t.Fatalf("init refused to write a plan without a signing key: %v", err)
	}
	text := string(res.YAML)
	for _, forbidden := range []string{"sign_key_path", "keygen", "signing key"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the composed plan mentions %q:\n%s", forbidden, text)
		}
	}
	if _, err := config.LoadFromReader(bytes.NewReader(res.YAML)); err != nil {
		t.Fatalf("the plan is not valid as written: %v", err)
	}
}

// Init writes a positive retention, and a plan that omits the key or
// sets it to zero is refused.
func TestComposedPlanWithoutRetentionIsRefused(t *testing.T) {
	res, err := Compose(discovered(), Options{Written: backupTime})
	if err != nil {
		t.Fatal(err)
	}
	filled := string(res.YAML)
	const line = "  retention_days: 90\n"
	if !strings.Contains(filled, line) || !strings.Contains(filled, "# Your choice: the retention period in days") || strings.Contains(filled, "CHANGE: the retention period") {
		t.Fatalf("the composed plan lacks a marked retention_days:\n%s", filled)
	}
	for name, edited := range map[string]string{
		"omitted":       strings.Replace(filled, line, "", 1),
		"explicit zero": strings.Replace(filled, line, "  retention_days: 0\n", 1),
	} {
		_, err := config.LoadFromReader(strings.NewReader(edited))
		if err == nil || !strings.Contains(err.Error(), "compliance.retention_days") {
			t.Errorf("%s: err %v, want retention_days refused", name, err)
		}
	}
	if _, err := config.LoadFromReader(strings.NewReader(filled)); err != nil {
		t.Errorf("the plan with its retention does not load: %v", err)
	}
}

// The composed plan validates, and each VM's probe fits what its backup
// says: Linux with a NIC on SSH at its sandbox address, and a guest with
// the agent through the agent. A guest with neither is left out with the
// reason: a QMP probe would certify nothing about it.
func TestComposeWritesAValidPlan(t *testing.T) {
	res, err := Compose(discovered(), Options{Written: backupTime})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.LoadFromReader(bytes.NewReader(res.YAML))
	if err != nil {
		t.Fatalf("composed plan does not load: %v\n%s", err, res.YAML)
	}
	if plan.PlanID != "recovery-pve1" || plan.Storage.OverlayStorage != "scratch" || plan.Network.ZoneID != "csZone1" || !plan.UseBackupConfig {
		t.Errorf("plan = %s %q %q", plan.PlanID, plan.Storage.OverlayStorage, plan.Network.ZoneID)
	}
	vms := plan.Tiers[0].VMs
	if len(vms) != 4 || res.VMs != 4 {
		t.Fatalf("%d VMs in the plan, want 4 (102, 104 and 105 left out)", len(vms))
	}
	type want struct {
		sandbox, source int
		probe, target   string
		preserve        bool
	}
	for i, w := range []want{
		{9100, 100, "tcp", "192.0.2.10", false},
		{9101, 101, "qga", "", true},
		{9102, 103, "qga", "", true},
		{9103, 106, "tcp", "192.0.2.11", false},
	} {
		vm := vms[i]
		if vm.VMID != w.sandbox || vm.SourceVMID != w.source || vm.Probes[0].Type != w.probe || vm.Probes[0].TargetIP != w.target || (vm.NetworkRecovery.Mode == "preserve") != w.preserve {
			t.Errorf("VM %d = sandbox %d, probe %s %s, recovery %q", w.source, vm.VMID, vm.Probes[0].Type, vm.Probes[0].TargetIP, vm.NetworkRecovery.Mode)
		}
		if len(vm.Probes) != 1 || !config.IsGuestLevelProbe(vm.Probes[0].Type) || (vm.Probes[0].Type == "qga" && !vm.Probes[0].RequireQGA) {
			t.Errorf("VM %d's probes %+v are not sure to assert something in the guest", w.source, vm.Probes)
		}
	}
	if vms[1].Probes[0].Command != "sc query EventLog" || vms[2].Probes[0].Command != "ping" {
		t.Errorf("guest agent probes = %q, %q", vms[1].Probes[0].Command, vms[2].Probes[0].Command)
	}
	if len(vms[3].Name) > 63 || !strings.HasPrefix(vms[3].Name, "cs-aaa") {
		t.Errorf("name %q", vms[3].Name)
	}
	text := string(res.YAML)
	for _, want := range []string{"# Not in this plan:", "VM 105: the backup is encrypted", "also possible: nfs-big", "CHANGE"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q:\n%s", want, text)
		}
	}
	notes := strings.Join(res.Notes, "\n")
	for _, want := range []string{"Not in the plan: VM 105", "SSH (port 22)", "100 (web-01)"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
}

// A guest with no agent enabled in its backup and no address the sandbox can
// give it (Windows or another OS, or Linux without a NIC) could only get a
// QMP-only probe, which passes for a guest in a boot loop or at a kernel
// panic. Such a VM is left out, in the plan and in the notes, with what to do;
// the plan never certifies a guest by QMP, and its header does not claim the
// run "checks that the guest comes up".
func TestComposeLeavesOutAGuestItCouldOnlyCheckByQMP(t *testing.T) {
	res, err := Compose(discovered(), Options{Written: backupTime})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.LoadFromReader(bytes.NewReader(res.YAML))
	if err != nil {
		t.Fatalf("plan does not load: %v\n%s", err, res.YAML)
	}
	for _, vm := range plan.Tiers[0].VMs {
		if vm.SourceVMID == 102 || vm.SourceVMID == 104 {
			t.Errorf("source VM %d is in the plan with probes %+v; it has no agent and no address to probe", vm.SourceVMID, vm.Probes)
		}
		for _, p := range vm.Probes {
			if p.Type == "qmp" || p.Type == "screendump" {
				t.Errorf("VM %d has a %s probe, which asserts nothing in the guest", vm.SourceVMID, p.Type)
			}
		}
	}
	text, notes := string(res.YAML), strings.Join(res.Notes, "\n")
	for _, want := range []string{"VM 102: its backup has no guest agent enabled", "VM 104 (batch): its backup has no guest agent enabled", "nothing about the guest", "Enable the guest agent in the VM"} {
		if !strings.Contains(text, want) || !strings.Contains(notes, want) {
			t.Errorf("plan or notes lack %q:\n%s\n%s", want, text, notes)
		}
	}
	if strings.Contains(text, "checks that the guest comes up") || strings.Contains(notes, "only boot is checked") || strings.Contains(text, `type: "qmp"`) {
		t.Errorf("the plan still claims a boot check:\n%s\n%s", text, notes)
	}
	if !strings.Contains(text, "# A VM counts as verified only when a probe that asserts something in the\n# guest passed.") {
		t.Errorf("the header does not say what verifies a VM:\n%s", text)
	}

	// Only such VMs: nothing can be written, and the error says why for each.
	d := discovered()
	d.VMs = d.VMs[2:3]
	d.VMs = append(d.VMs, discovered().VMs[4])
	_, err = Compose(d, Options{})
	if err == nil || !strings.Contains(err.Error(), "VM 102") || !strings.Contains(err.Error(), "VM 104") || !strings.Contains(err.Error(), "guest agent") {
		t.Errorf("no VM can be probed: %v", err)
	}
}

// Without storage for overlays, a UEFI VM is left out with the reason, and
// the rest is planned on the scratch directory.
func TestComposeWithoutOverlayStorage(t *testing.T) {
	d := discovered()
	d.Storages = nil
	res, err := Compose(d, Options{})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := config.LoadFromReader(bytes.NewReader(res.YAML))
	if plan.Storage.OverlayStorage != "" || len(plan.Tiers[0].VMs) != 3 {
		t.Fatalf("overlay storage %q, %d VMs", plan.Storage.OverlayStorage, len(plan.Tiers[0].VMs))
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "VM 101 (dc-01): it boots with UEFI") {
		t.Errorf("notes = %v", res.Notes)
	}
}

func TestComposeRefusals(t *testing.T) {
	// (A missing signing key is not a refusal: see
	// TestComposedPlanNeedsNoSigningKeyAndNamesNone.)
	if _, err := Compose(discovered(), Options{OverlayStorage: "local-lvm"}); err == nil || !strings.Contains(err.Error(), "these can: nfs-big, scratch") {
		t.Errorf("unusable storage: %v", err)
	}
	res, err := Compose(discovered(), Options{OverlayStorage: "nfs-big", PlanID: "nightly", Name: "Nightly"})
	if err != nil {
		t.Fatal(err)
	}
	if plan, _ := config.LoadFromReader(bytes.NewReader(res.YAML)); plan.Storage.OverlayStorage != "nfs-big" || plan.PlanID != "nightly" {
		t.Errorf("requested storage and ID not used: %+v", plan.Storage)
	}
	d := discovered()
	d.VMs = d.VMs[5:6] // only the unreadable backup
	if _, err := Compose(d, Options{}); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("nothing restorable: %v", err)
	}
}

// A source named "cs-…" gets the sandbox name "cs-sandbox-…", not "cs-cs-…";
// Windows is described by its versions, not its bare ostype; a multi-NIC VM's
// description names the NICs the sandbox leaves out.
func TestComposeNamesDescriptionsAndOtherNICs(t *testing.T) {
	d := discovered()
	d.VMs = []VM{
		{SourceVMID: 7011, Name: "cs-http-rocky-01", OSType: "l26", HasNIC: true, Agent: true, BackupTime: backupTime},
		{SourceVMID: 7214, Name: "win2016-iis", OSType: "win10", HasNIC: true, Agent: true, BackupTime: backupTime},
		{SourceVMID: 7505, Name: "multinic", OSType: "l26", HasNIC: true, OtherNICs: []string{"net1", "net2"}, BackupTime: backupTime},
	}
	res, err := Compose(d, Options{})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := config.LoadFromReader(bytes.NewReader(res.YAML))
	if name := plan.Tiers[0].VMs[0].Name; name != "cs-sandbox-http-rocky-01" {
		t.Errorf("sandbox name = %q", name)
	}
	text := string(res.YAML)
	for _, want := range []string{"Windows 10/2016/2019 (ostype win10)", "The backup also has net1, net2; the sandbox attaches only net0", "attach_all_nics: true"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q", want)
		}
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "more NICs than net0, which the sandbox leaves out: 7505 (multinic)") {
		t.Errorf("notes = %v", res.Notes)
	}
	if plan.Tiers[0].VMs[2].NetworkRecovery.AttachAllNICs {
		t.Error("attach_all_nics was set; it is only suggested")
	}
}

// A namespace is carried to the plan and to every VM's source.
func TestComposeCarriesTheNamespace(t *testing.T) {
	d := discovered()
	d.Namespace = "prod/site-a"
	res, err := Compose(d, Options{})
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := config.LoadFromReader(bytes.NewReader(res.YAML))
	if plan.Storage.PBSNamespace != "prod/site-a" || plan.Tiers[0].VMs[0].SourcePBS.Namespace != "prod/site-a" {
		t.Errorf("namespace: %q, %q", plan.Storage.PBSNamespace, plan.Tiers[0].VMs[0].SourcePBS.Namespace)
	}
}

// A VM the plan will leave out (an unreadable backup, a UEFI VM without
// overlay storage) takes no sandbox ID, so with few IDs left discovery does
// not fail for a plan that needs only the rest.
func TestDiscoverSpendsNoSandboxIDOnAVMThePlanLeavesOut(t *testing.T) {
	const last = 999999999
	readable := pbs.VMProfile{Name: "web-01", OSType: "l26", MAC: "BC:24:11:00:00:01"}
	// Two VMs of one plan hold two addresses.
	readableToo := pbs.VMProfile{Name: "web-02", OSType: "l26", MAC: "BC:24:11:00:00:02"}
	for _, tc := range []struct {
		name     string
		profiles map[string]pbs.VMProfile
		errs     map[string]error
		storages []pve.NodeStorage
		first    int
		ids      []int
		note     string
	}{
		{"an unreadable backup",
			map[string]pbs.VMProfile{"vm/7011/2026-09-27T03:00:00Z": readable},
			map[string]error{"vm/7012/2026-09-27T03:00:00Z": errors.New("audit unreadable backup")},
			nil, last, []int{last}, "VM 7012"},
		{"a UEFI VM without overlay storage",
			map[string]pbs.VMProfile{"vm/7011/2026-09-27T03:00:00Z": readable, "vm/7012/2026-09-27T03:00:00Z": {Name: "dc", OSType: "win11", BIOS: "ovmf", MAC: "BC:24:11:00:00:02"}},
			nil, nil, last, []int{last}, "it boots with UEFI"},
		// The guests Compose leaves out for want of anything to probe: only Compose
		// knew of them, so discovery still reserved an ID for each, and failed at the
		// top of the ID range.
		{"a Windows guest without the guest agent",
			map[string]pbs.VMProfile{"vm/7011/2026-09-27T03:00:00Z": readable, "vm/7012/2026-09-27T03:00:00Z": {Name: "file", OSType: "win11", MAC: "BC:24:11:00:00:02"}},
			nil, nil, last, []int{last}, "no guest agent enabled"},
		{"another OS without the guest agent",
			map[string]pbs.VMProfile{"vm/7011/2026-09-27T03:00:00Z": readable, "vm/7012/2026-09-27T03:00:00Z": {Name: "fw", OSType: "other", MAC: "BC:24:11:00:00:02"}},
			nil, nil, last, []int{last}, "no guest agent enabled"},
		{"a Linux guest with neither the agent nor a NIC",
			map[string]pbs.VMProfile{"vm/7011/2026-09-27T03:00:00Z": readable, "vm/7012/2026-09-27T03:00:00Z": {Name: "batch", OSType: "l26"}},
			nil, nil, last, []int{last}, "no guest agent enabled"},
		{"the positive control: both fit",
			map[string]pbs.VMProfile{"vm/7011/2026-09-27T03:00:00Z": readable, "vm/7012/2026-09-27T03:00:00Z": readableToo},
			nil, nil, last - 1, []int{last - 1, last}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backups := &fakeBackups{list: backupsOf(7011, 7012), profiles: tc.profiles, errs: tc.errs}
			d, err := Discover(context.Background(), backups, &fakeCluster{storages: tc.storages}, Request{Node: "pve1", VMIDs: []int{7011, 7012}, FirstVMID: tc.first}, t.TempDir())
			if err != nil {
				t.Fatalf("discovery failed although the plan needs %d ID(s): %v", len(tc.ids), err)
			}
			if fmt.Sprint(d.SandboxVMIDs) != fmt.Sprint(tc.ids) {
				t.Fatalf("sandbox IDs = %v, want %v", d.SandboxVMIDs, tc.ids)
			}
			res, err := Compose(d, Options{Written: backupTime})
			if err != nil {
				t.Fatalf("compose: %v", err)
			}
			plan, err := config.LoadFromReader(bytes.NewReader(res.YAML))
			if err != nil {
				t.Fatalf("the composed plan does not load: %v\n%s", err, res.YAML)
			}
			if got := len(plan.Tiers[0].VMs); got != len(tc.ids) || plan.Tiers[0].VMs[0].VMID != tc.ids[0] {
				t.Fatalf("plan has %d VM(s), first %d; want %v", got, plan.Tiers[0].VMs[0].VMID, tc.ids)
			}
			if tc.note != "" && !strings.Contains(strings.Join(res.Notes, "\n"), tc.note) {
				t.Errorf("notes lack %q: %v", tc.note, res.Notes)
			}
		})
	}
	// With two VMs to restore and one ID left, discovery still fails.
	backups := &fakeBackups{list: backupsOf(7011, 7012), profiles: map[string]pbs.VMProfile{
		"vm/7011/2026-09-27T03:00:00Z": readable, "vm/7012/2026-09-27T03:00:00Z": readableToo}}
	if _, err := Discover(context.Background(), backups, &fakeCluster{}, Request{Node: "pve1", VMIDs: []int{7011, 7012}, FirstVMID: last}, t.TempDir()); err == nil || !strings.Contains(err.Error(), "no free VM IDs") {
		t.Errorf("two restorable VMs, one ID: %v", err)
	}
	// Every VM excluded: compose says why, not that IDs ran out.
	d := &Discovery{Node: "pve1", ZoneID: "csZone1", VNetID: "csVnet1", VMs: []VM{{SourceVMID: 7012, Error: "audit unreadable backup"}}}
	if _, err := Compose(d, Options{}); err == nil || !strings.Contains(err.Error(), "audit unreadable backup") {
		t.Errorf("every VM excluded: %v", err)
	}
}

// dirRecordingBackups records the directory each configuration is read into.
type dirRecordingBackups struct {
	fakeBackups
	dirs []string
	seen []bool
}

func (f *dirRecordingBackups) LoadVMProfile(ctx context.Context, snapshot, dir string) (pbs.VMProfile, error) {
	f.mu.Lock()
	f.dirs = append(f.dirs, dir)
	info, err := os.Stat(dir)
	f.seen = append(f.seen, err == nil && info.IsDir())
	f.mu.Unlock()
	return f.fakeBackups.LoadVMProfile(ctx, snapshot, dir)
}

// Each backup's configuration is read into a private directory
// beneath the scratch directory discovery is given, and that directory is
// removed afterwards.
func TestDiscoverReadsConfigurationsBeneathTheScratchDirectory(t *testing.T) {
	scratch := t.TempDir()
	backups := &dirRecordingBackups{fakeBackups: fakeBackups{list: backupsOf(7011, 7012), profiles: map[string]pbs.VMProfile{
		"vm/7011/2026-09-27T03:00:00Z": {Name: "a", OSType: "l26", MAC: "BC:24:11:00:00:01"},
		"vm/7012/2026-09-27T03:00:00Z": {Name: "b", OSType: "l26", MAC: "BC:24:11:00:00:02"},
	}}}
	if _, err := Discover(context.Background(), backups, &fakeCluster{}, Request{Node: "pve1", VMIDs: []int{7011, 7012}}, scratch); err != nil {
		t.Fatal(err)
	}
	if len(backups.dirs) != 2 {
		t.Fatalf("configurations read into %v", backups.dirs)
	}
	for i, dir := range backups.dirs {
		if filepath.Dir(dir) != scratch || !strings.HasPrefix(filepath.Base(dir), "certistack-init-") || !backups.seen[i] {
			t.Errorf("configuration read into %s (existed %v), want a certistack-init- directory beneath %s", dir, backups.seen[i], scratch)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("%s was not removed: %v", dir, err)
		}
	}
	if entries, _ := os.ReadDir(scratch); len(entries) != 0 {
		t.Errorf("the scratch directory was left holding %d entries", len(entries))
	}
}

// The IDs discovery reserves are exactly the VMs Compose keeps, for
// every reason a VM is left out (an unreadable backup, a UEFI VM without
// storage, a guest with nothing to probe), because both ask leftOut: no
// reason to leave a VM out is known to Compose alone.
func TestSandboxIDsNeededIsExactlyWhatComposeKeeps(t *testing.T) {
	noStorage := discovered()
	noStorage.Storages = nil
	mostlyLeftOut := discovered()
	mostlyLeftOut.VMs = []VM{mostlyLeftOut.VMs[2], mostlyLeftOut.VMs[4], mostlyLeftOut.VMs[5], mostlyLeftOut.VMs[0]}
	for name, d := range map[string]*Discovery{"the usual mix": discovered(), "no storage for overlays": noStorage, "mostly left out": mostlyLeftOut} {
		res, err := Compose(d, Options{Written: backupTime})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if needed := d.sandboxIDsNeeded(""); needed != res.VMs {
			t.Errorf("%s: discovery reserves IDs for %d VM(s), the plan keeps %d", name, needed, res.VMs)
		}
	}
}

func TestLeftOutGivesTheReasonOrNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		vm      VM
		storage string
		want    string // a fragment of the reason, "" when the VM is kept
	}{
		"a Linux guest with a NIC":               {VM{SourceVMID: 1, OSType: "l26", HasNIC: true}, "scratch", ""},
		"a guest with the agent":                 {VM{SourceVMID: 2, OSType: "win11", Agent: true}, "scratch", ""},
		"an unreadable backup":                   {VM{SourceVMID: 3, Error: "the backup is encrypted"}, "scratch", "the backup is encrypted"},
		"a UEFI guest with storage":              {VM{SourceVMID: 4, OSType: "l26", HasNIC: true, BIOS: "ovmf"}, "scratch", ""},
		"a UEFI guest without storage":           {VM{SourceVMID: 4, OSType: "l26", HasNIC: true, BIOS: "ovmf"}, "", "needs overlay storage"},
		"Windows without the agent":              {VM{SourceVMID: 5, OSType: "win10", HasNIC: true}, "scratch", "no guest agent enabled"},
		"Linux without a NIC or the agent":       {VM{SourceVMID: 6, OSType: "l26"}, "scratch", "no guest agent enabled"},
		"another OS with a NIC and no agent":     {VM{SourceVMID: 7, OSType: "other", HasNIC: true}, "scratch", "no guest agent enabled"},
		"an unreadable backup that is also UEFI": {VM{SourceVMID: 8, BIOS: "ovmf", Error: "unreadable"}, "", "unreadable"},
	} {
		got := leftOut(tc.vm, tc.storage)
		if (got == "") != (tc.want == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: leftOut = %q, want %q", name, got, tc.want)
		}
	}
}

// Init writes plans that inherit each backup's net0 MAC, so two backups
// that carry one MAC (VMs cloned from one another) made a plan the run refuses,
// at its plan or run, with nothing in the plan to explain it. The later VM is
// left out with the reason, takes no sandbox ID, and the plan loads.
func TestComposeLeavesOutAVMWhoseBackupRepeatsAnotherMAC(t *testing.T) {
	linux := func(name, mac string) pbs.VMProfile {
		return pbs.VMProfile{Name: name, OSType: "l26", MAC: mac, Agent: true}
	}
	backups := &fakeBackups{list: backupsOf(7011, 7012, 7013), profiles: map[string]pbs.VMProfile{
		"vm/7011/2026-09-27T03:00:00Z": linux("web-01", "BC:24:11:00:00:01"),
		"vm/7012/2026-09-27T03:00:00Z": linux("web-02-clone", "bc:24:11:00:00:01"), // the same address, another case
		"vm/7013/2026-09-27T03:00:00Z": linux("db-01", "BC:24:11:00:00:03"),
	}}
	d, err := Discover(context.Background(), backups, &fakeCluster{}, Request{Node: "pve1", VMIDs: []int{7011, 7012, 7013}, FirstVMID: 999999998}, t.TempDir())
	if err != nil {
		t.Fatalf("discovery needed an ID for the clone: %v", err)
	}
	if got := d.sandboxIDsNeeded(""); got != 2 {
		t.Fatalf("sandbox IDs needed = %d, want 2", got)
	}
	res, err := Compose(d, Options{Written: backupTime})
	if err != nil {
		t.Fatal(err)
	}
	if res.VMs != 2 {
		t.Fatalf("plan restores %d VM(s), want 2:\n%s", res.VMs, res.YAML)
	}
	notes := strings.Join(res.Notes, "\n")
	for _, want := range []string{"VM 7012 (web-02-clone)", "net0 MAC bc:24:11:00:00:01 is also the MAC of VM 7011 (web-01)", "separate plans"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	plan, err := config.LoadFromReader(bytes.NewReader(res.YAML))
	if err != nil {
		t.Fatalf("the composed plan does not load: %v", err)
	}
	if got := plan.Tiers[0].VMs; len(got) != 2 || got[0].SourceVMID != 7011 || got[1].SourceVMID != 7013 {
		t.Fatalf("plan VMs = %+v", got)
	}
	// A VM that is left out for another reason holds no address.
	d.VMs[0].Error = "unreadable"
	if got := d.sandboxIDsNeeded(""); got != 2 {
		t.Fatalf("with the first VM unreadable, the clone is kept: needed = %d, want 2", got)
	}
}

// The header of the plan init writes says what a run produces, and for this
// edition that is an unsigned JSON report; it never says a run "signs a
// report", which the Community Edition does not do.
func TestComposedPlanHeaderSaysTheReportIsJSONAndUnsigned(t *testing.T) {
	res, err := Compose(discovered(), Options{Written: backupTime})
	if err != nil {
		t.Fatal(err)
	}
	var header []string
	scanner := bufio.NewScanner(bytes.NewReader(res.YAML))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			break
		}
		header = append(header, strings.TrimPrefix(line, "#"))
	}
	text := strings.Join(strings.Fields(strings.Join(header, " ")), " ")
	if text == "" {
		t.Fatal("the plan has no header")
	}
	// "unsigned" is the point; "sign", "signs" and "signed" as words are not.
	if word := regexp.MustCompile(`\bsign(s|ed|ing)?\b`).FindString(text); word != "" {
		t.Errorf("the header says %q, which this edition does not do:\n%s", word, text)
	}
	if want := "writes a JSON report (unsigned in the Community Edition)"; !strings.Contains(text, want) {
		t.Errorf("the header lacks %q:\n%s", want, text)
	}
}
