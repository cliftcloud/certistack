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

// doctor reports, per VM, what a run would find in each backup, and one VM's
// refusal does not hide the next one's.
func TestCheckSourcesReportsEachVMAsARunWould(t *testing.T) {
	plan := &config.Plan{Network: config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}, Tiers: []config.Tier{{VMs: []config.VM{
		{VMID: 1, Name: "web", SourceVMID: 101, SourcePBS: config.SourcePBS{Snapshot: "latest", Drive: "drive-scsi0.img.fidx"}},
		{VMID: 2, Name: "gone", SourceVMID: 102, SourcePBS: config.SourcePBS{Snapshot: "latest", Drive: "drive-scsi0.img.fidx"}},
		{VMID: 3, Name: "uefi", SourceVMID: 103, SourcePBS: config.SourcePBS{Snapshot: "latest", Drive: "drive-scsi0.img.fidx"}},
		{VMID: 4, Name: "db", SourceVMID: 104, SourcePBS: config.SourcePBS{Snapshot: "latest", Drive: "drive-scsi0.img.fidx"}},
	}}}}
	snapshots := &fakeSnapshotResolver{resolved: map[string]string{
		"latest:101": "vm/101/2026-09-27T03:00:00Z",
		"latest:103": "vm/103/2026-09-27T03:00:00Z",
		"latest:104": "vm/104/2026-09-27T03:00:00Z",
	}}
	backups := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/101/2026-09-27T03:00:00Z": {Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0.img.fidx"}}, CryptMode: pbs.CryptModeEncrypt,
			Consistency: pbs.BackupConsistency{State: pbs.ConsistencyQuiesced}},
		"vm/103/2026-09-27T03:00:00Z": {Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0.img.fidx"}}, BIOS: "ovmf",
			Firmware: []pbs.FirmwareImage{{Slot: "efidisk0", Archive: "drive-efidisk0.img.fidx"}}},
		"vm/104/2026-09-27T03:00:00Z": {Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0.img.fidx"}},
			Consistency: pbs.BackupConsistency{State: pbs.ConsistencyCrash, Detail: "the guest agent could not freeze the file systems: Permission denied"}},
	}}
	checks := checkSources(context.Background(), plan, snapshots, backups, t.TempDir(), "")
	want := []struct {
		status, detail string
	}{
		{SourcePassed, "encrypted (key configured); backup quiesced"},
		{SourceFailed, "resolve PBS snapshot for target VM 2"},
		{SourceFailed, "overlay_storage"},
		{SourceWarning, "backup crash-consistent: the guest agent could not freeze"},
	}
	if len(checks) != len(want) {
		t.Fatalf("checks = %+v", checks)
	}
	for i, w := range want {
		if checks[i].Status != w.status || !strings.Contains(checks[i].Detail, w.detail) {
			t.Errorf("VM %d: %s %q, want %s containing %q", checks[i].VMID, checks[i].Status, checks[i].Detail, w.status, w.detail)
		}
	}
	// With overlay storage, the UEFI VM passes and names its firmware state.
	checks = checkSources(context.Background(), plan, snapshots, backups, t.TempDir(), "certistack-scratch")
	if checks[2].Status != SourcePassed || !strings.Contains(checks[2].Detail, "UEFI + efidisk0") {
		t.Errorf("UEFI VM with overlay storage: %+v", checks[2])
	}
	// The plan itself is never changed.
	if plan.Tiers[0].VMs[0].SourcePBS.Snapshot != "latest" || plan.Tiers[0].VMs[2].BIOS != "" {
		t.Errorf("checkSources changed the plan: %+v", plan.Tiers[0].VMs)
	}
}

// A VM whose plan requires a quiesced backup fails doctor on a
// crash-consistent one, and passes on a quiesced one.
func TestCheckSourcesFailsAnUnquiescedBackupTheVMRequires(t *testing.T) {
	plan := &config.Plan{Network: config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}, Tiers: []config.Tier{{VMs: []config.VM{
		{VMID: 1, Name: "db", SourceVMID: 101, RequireQuiescedBackup: true, SourcePBS: config.SourcePBS{Snapshot: "latest", Drive: "drive-scsi0.img.fidx"}},
		{VMID: 2, Name: "db2", SourceVMID: 102, RequireQuiescedBackup: true, SourcePBS: config.SourcePBS{Snapshot: "latest", Drive: "drive-scsi0.img.fidx"}},
	}}}}
	snapshots := &fakeSnapshotResolver{resolved: map[string]string{
		"latest:101": "vm/101/2026-09-27T03:00:00Z",
		"latest:102": "vm/102/2026-09-27T03:00:00Z",
	}}
	backups := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/101/2026-09-27T03:00:00Z": {Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0.img.fidx"}},
			Consistency: pbs.BackupConsistency{State: pbs.ConsistencyCrash, Detail: "fsfreeze failed"}},
		"vm/102/2026-09-27T03:00:00Z": {Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0.img.fidx"}},
			Consistency: pbs.BackupConsistency{State: pbs.ConsistencyQuiesced}},
	}}
	checks := checkSources(context.Background(), plan, snapshots, backups, t.TempDir(), "")
	if checks[0].Status != SourceFailed || !strings.Contains(checks[0].Detail, "require_quiesced_backup") || !strings.Contains(checks[0].Detail, "crash-consistent: fsfreeze failed") {
		t.Errorf("crash-consistent backup of a VM that requires quiesced: %+v", checks[0])
	}
	if checks[1].Status != SourcePassed {
		t.Errorf("quiesced backup of a VM that requires it: %+v", checks[1])
	}
}
