// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

const (
	macSnapshot = "vm/7011/2026-09-16T00:00:00Z"
	macSource   = "00:11:22:33:44:55"
	macOther    = "02:AA:BB:CC:DD:EE"
)

func sourceProfile(mac, model string) pbs.VMProfile {
	return pbs.VMProfile{MAC: mac, NICModel: model, Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}}
}

func preservePlan(useBackupConfig bool, mac, model string) *config.Plan {
	vm := config.VM{
		VMID: 9900, Name: "preserve-mac", MAC: mac, NICModel: model,
		NetworkRecovery: config.NetworkRecovery{Mode: "preserve"},
		SourcePBS:       config.SourcePBS{Snapshot: macSnapshot},
	}
	if !useBackupConfig {
		vm.SourcePBS.Drives = []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}
	}
	return &config.Plan{
		UseBackupConfig: useBackupConfig,
		Network:         config.Network{IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers:           []config.Tier{{VMs: []config.VM{vm}}},
	}
}

// resolve runs the steps prepareRun runs for the plan's mode.
func resolve(plan *config.Plan, resolver fakeBackupProfileResolver) error {
	if plan.UseBackupConfig {
		return applyBackupConfig(context.Background(), plan, resolver, "/tmp")
	}
	if err := applyBackupNetworkIdentity(context.Background(), plan, resolver, "/tmp"); err != nil {
		return err
	}
	return applyBackupLayout(context.Background(), plan, resolver, "/tmp")
}

func oneSource(mac, model string) fakeBackupProfileResolver {
	return fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{macSnapshot: sourceProfile(mac, model)}}
}

// The first reported case: a use_backup_config plan in preserve mode
// with an explicit replacement MAC resolved to the replacement while the
// backup's net0 had another, and the guest, left as backed up, would not find
// its NIC. It is refused now, naming both addresses and the way out.
func TestPreserveRefusesAReplacementMAC(t *testing.T) {
	err := resolve(preservePlan(true, macOther, ""), oneSource(macSource, "e1000"))
	if err == nil {
		t.Fatal("a preserve plan replaced the backup's net0 MAC")
	}
	for _, want := range []string{"VM 9900", "preserve", macOther, macSource, "Remove mac"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	// The same refusal without the backup's configuration being inherited.
	if err := resolve(preservePlan(false, macOther, ""), oneSource(macSource, "e1000")); err == nil || !strings.Contains(err.Error(), macSource) {
		t.Errorf("a replacement MAC without use_backup_config: %v", err)
	}
	// And the model: the guest's driver and adapter binding follow it.
	for _, useBackupConfig := range []bool{true, false} {
		err := resolve(preservePlan(useBackupConfig, "", "virtio"), oneSource(macSource, "e1000"))
		if err == nil || !strings.Contains(err.Error(), "nic_model virtio") || !strings.Contains(err.Error(), "e1000") {
			t.Errorf("use_backup_config=%t: a replacement NIC model: %v", useBackupConfig, err)
		}
	}
}

// The second reported case: with the backup's configuration not
// inherited, a preserve plan skipped the source net0 altogether, and PVE was
// left to choose a MAC and the default model. The source's identity is kept.
func TestPreserveKeepsTheBackupsIdentityWithOrWithoutBackupConfig(t *testing.T) {
	for _, useBackupConfig := range []bool{true, false} {
		plan := preservePlan(useBackupConfig, "", "")
		if err := resolve(plan, oneSource(macSource, "e1000")); err != nil {
			t.Fatalf("use_backup_config=%t: %v", useBackupConfig, err)
		}
		if vm := plan.Tiers[0].VMs[0]; vm.MAC != macSource || vm.NICModel != "e1000" {
			t.Errorf("use_backup_config=%t: MAC %q model %q, want the backup's %s e1000", useBackupConfig, vm.MAC, vm.NICModel, macSource)
		}
		if drives := plan.Tiers[0].VMs[0].SourcePBS.RestoreDrives(); len(drives) != 1 || drives[0].Slot != "scsi0" {
			t.Errorf("use_backup_config=%t: the source layout was not applied: %+v", useBackupConfig, drives)
		}
	}
}

// The compatible choices stay open: the backup's own MAC and model, written
// out (in any spelling), and every other mode, which rewrites the guest's
// network profile to the new identity in its disposable overlay.
func TestCompatibleIdentitiesAreAccepted(t *testing.T) {
	for _, useBackupConfig := range []bool{true, false} {
		for _, mac := range []string{macSource, "00-11-22-33-44-55", "0011.2233.4455"} {
			plan := preservePlan(useBackupConfig, mac, "e1000")
			if err := resolve(plan, oneSource(macSource, "e1000")); err != nil {
				t.Errorf("use_backup_config=%t: the backup's own identity %q: %v", useBackupConfig, mac, err)
			}
			if got := plan.Tiers[0].VMs[0].MAC; got != mac {
				t.Errorf("use_backup_config=%t: the plan's MAC %q was rewritten to %q", useBackupConfig, mac, got)
			}
		}
		// A source with no net0 has nothing to keep: the plan's identity stands.
		if err := resolve(preservePlan(useBackupConfig, macOther, "virtio"), oneSource("", "")); err != nil {
			t.Errorf("use_backup_config=%t: a source without net0: %v", useBackupConfig, err)
		}
	}
	plan := preservePlan(true, macOther, "virtio")
	plan.Tiers[0].VMs[0].NetworkRecovery = config.NetworkRecovery{Mode: "auto", SandboxIP: "10.100.0.10"}
	if err := resolve(plan, oneSource(macSource, "e1000")); err != nil {
		t.Fatalf("auto mode with a new identity: %v", err)
	}
	if vm := plan.Tiers[0].VMs[0]; vm.MAC != macOther || vm.NICModel != "virtio" {
		t.Errorf("auto mode lost the plan's identity: MAC %q model %q", vm.MAC, vm.NICModel)
	}
}

// The reported case: two source profiles with one primary MAC, the
// first with a net1 of that address attached by attach_all_nics, all resolved
// without complaint, and the same MAC went on three NICs of one VNet. The
// resolution is refused now, with every collision named.
func TestResolutionRefusesOneMACOnSeveralNICs(t *testing.T) {
	const (
		first  = "vm/7001/2026-09-16T00:00:00Z"
		second = "vm/7002/2026-09-16T00:00:00Z"
	)
	build := func() (*config.Plan, fakeBackupProfileResolver) {
		plan := &config.Plan{
			UseBackupConfig: true,
			Tiers: []config.Tier{{VMs: []config.VM{
				{VMID: 9900, Name: "duplicate-one", SourcePBS: config.SourcePBS{Snapshot: first}, NetworkRecovery: config.NetworkRecovery{AttachAllNICs: true}},
				{VMID: 9901, Name: "duplicate-two", SourcePBS: config.SourcePBS{Snapshot: second}},
			}}},
		}
		resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
			first: {
				MAC: macOther, NICModel: "virtio", Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}},
				NICs: []pbs.SourceNIC{{Slot: "net1", Model: "virtio", MAC: macOther}},
			},
			second: {MAC: macOther, NICModel: "virtio", Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}},
		}}
		return plan, resolver
	}
	plan, resolver := build()
	err := applyBackupConfig(context.Background(), plan, resolver, t.TempDir())
	if err == nil {
		t.Fatal("resolution accepted one MAC on net0 and net1 of a VM and on net0 of another")
	}
	for _, want := range []string{"VM 9900 net1 and VM 9900 net0", "VM 9901 net0 and VM 9900 net0", macOther} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// The control: distinct addresses resolve.
	plan, resolver = build()
	resolver.profiles[first] = pbs.VMProfile{MAC: "02:AA:BB:CC:DD:01", NICModel: "virtio", Drives: resolver.profiles[first].Drives,
		NICs: []pbs.SourceNIC{{Slot: "net1", Model: "virtio", MAC: "02:AA:BB:CC:DD:02"}}}
	resolver.profiles[second] = pbs.VMProfile{MAC: "02:AA:BB:CC:DD:03", NICModel: "virtio", Drives: resolver.profiles[second].Drives}
	if err := applyBackupConfig(context.Background(), plan, resolver, t.TempDir()); err != nil {
		t.Fatalf("distinct addresses refused: %v", err)
	}
}

// The same check closes the path that does not inherit the backup's
// configuration, where net0 comes from the identity step and the other NICs
// from the layout step: clone-derived backups restored together in preserve
// mode share an address, and an explicit mac that repeats a backup's does too.
func TestResolutionWithoutBackupConfigRefusesOneMAC(t *testing.T) {
	const (
		first  = "vm/7001/2026-09-16T00:00:00Z"
		second = "vm/7002/2026-09-16T00:00:00Z"
	)
	drive := []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}
	plan := &config.Plan{
		Network: config.Network{IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers: []config.Tier{{VMs: []config.VM{
			{VMID: 9900, Name: "clone-one", SourcePBS: config.SourcePBS{Snapshot: first, Drives: drive}, NetworkRecovery: config.NetworkRecovery{Mode: "preserve"}},
			{VMID: 9901, Name: "clone-two", SourcePBS: config.SourcePBS{Snapshot: second, Drives: drive}, NetworkRecovery: config.NetworkRecovery{Mode: "preserve"}},
		}}},
	}
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		first:  sourceProfile(macSource, "virtio"),
		second: sourceProfile(macSource, "virtio"),
	}}
	err := resolve(plan, resolver)
	if err == nil || !strings.Contains(err.Error(), "VM 9901 net0 and VM 9900 net0 both use 00:11:22:33:44:55") {
		t.Fatalf("clone-derived backups with one MAC: %v", err)
	}

	// An explicit mac that repeats the other VM's backed-up one, in auto mode
	// (where a new identity is allowed), collides all the same.
	auto := &config.Plan{
		Network: config.Network{IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers: []config.Tier{{VMs: []config.VM{
			{VMID: 9900, Name: "one", SourcePBS: config.SourcePBS{Snapshot: first, Drives: drive}, NetworkRecovery: config.NetworkRecovery{Mode: "auto", SandboxIP: "10.100.0.10"}, Probes: []config.Probe{{Type: "tcp", TargetIP: "10.100.0.10"}}},
			{VMID: 9901, Name: "two", MAC: "00-11-22-33-44-55", NICModel: "virtio", SourcePBS: config.SourcePBS{Snapshot: second, Drives: drive}, NetworkRecovery: config.NetworkRecovery{Mode: "auto", SandboxIP: "10.100.0.11"}, Probes: []config.Probe{{Type: "tcp", TargetIP: "10.100.0.11"}}},
		}}},
	}
	resolver.profiles[second] = sourceProfile("02:AA:BB:CC:DD:03", "virtio")
	if err := resolve(auto, resolver); err == nil || !strings.Contains(err.Error(), "00:11:22:33:44:55") {
		t.Fatalf("an explicit mac repeating a backup's: %v", err)
	}
}
