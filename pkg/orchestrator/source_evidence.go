// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// newVMRecord is a VM's validation record as it is at the start of its restore:
// everything the plan and the run's resolved inputs already say about the
// backup it restores, before anything can go wrong. A restore that stops at
// the first guard, on a lost map, or on a failed overlay returns this record,
// and it is what the failure report holds, so two failures of different
// backups (another snapshot, another disk layout, another crypt mode, other
// tags) never carry the same evidence. Each later step adds only what
// it establishes. Nothing in bootAndVerifyVM sets these fields afterwards: a
// test (TestTheSourceIdentityIsSeededOnceAtTheStart) keeps it that way.
func newVMRecord(vmCfg config.VM) *probe.VMValidationRecord {
	return &probe.VMValidationRecord{
		VMID:               vmCfg.VMID,
		SourceVMID:         vmCfg.SourceVMID,
		Name:               vmCfg.Name,
		VerificationStatus: "pending",
		AllPassed:          true,
		// Known before anything is restored, so even a VM that never boots
		// says how consistent its backup was.
		SourceConsistency:       vmCfg.SourceConsistency,
		SourceConsistencyDetail: vmCfg.SourceConsistencyDetail,
		// The resolved snapshot (a "latest" selector is already an exact
		// path), and how the backup is protected and what it leaves out.
		SourceSnapshot:          vmCfg.SourcePBS.Snapshot,
		SourceCryptMode:         vmCfg.SourceCryptMode,
		SourceSignatureVerified: vmCfg.SourceSignatureVerified,
		ExcludedSourceDisks:     append([]string(nil), vmCfg.ExcludedDisks...),
		OmittedSourceDisks:      append([]string(nil), vmCfg.OmittedDisks...),
		SourceTags:              append([]string(nil), vmCfg.SourceTags...),
		SourceDisks:             requestedSourceDisks(vmCfg),
	}
}

// requestedSourceDisks lists the disks a restore of vmCfg is asked for, none of
// them attempted yet: the data disks the plan restores, in the order they are
// mapped, then the firmware state of a UEFI VM. A disk's status only moves
// forward from here, so a run that fails part way still says which disks it
// verified and which it did not reach.
func requestedSourceDisks(vmCfg config.VM) []probe.SourceDiskEvidence {
	drives := vmCfg.SourcePBS.RestoreDrives()
	disks := make([]probe.SourceDiskEvidence, 0, len(drives)+len(vmCfg.FirmwareDisks))
	for _, drive := range drives {
		disks = append(disks, probe.SourceDiskEvidence{
			Slot:              drive.Slot,
			Archive:           drive.Archive,
			ManifestReference: manifestReference(drive.Archive),
			IntegrityStatus:   probe.DiskNotAttempted,
		})
	}
	for _, disk := range vmCfg.FirmwareDisks {
		disks = append(disks, probe.SourceDiskEvidence{
			Slot:              disk.Slot,
			Archive:           disk.Archive,
			ManifestReference: manifestReference(disk.Archive),
			IntegrityStatus:   probe.DiskNotAttempted,
		})
	}
	if len(disks) == 0 {
		return nil
	}
	return disks
}

// diskStatusRank orders the integrity_status values by how far a restore got:
// nothing yet, the map made, and an outcome. An outcome (verified, skipped in
// test mode, or a failure) is final.
func diskStatusRank(status string) int {
	switch status {
	case probe.DiskNotAttempted:
		return 0
	case probe.DiskMapped:
		return 1
	}
	return 2
}

// setSourceDisk records what is now known of one disk, replacing the entry of
// its slot or, for a disk the request did not list, adding one. A disk that
// already has an outcome keeps it: progress never moves backwards or sideways,
// so a later failure keeps what the earlier steps established.
func setSourceDisk(record *probe.VMValidationRecord, disk probe.SourceDiskEvidence) {
	if record == nil {
		return
	}
	for i := range record.SourceDisks {
		if record.SourceDisks[i].Slot != disk.Slot {
			continue
		}
		if diskStatusRank(disk.IntegrityStatus) > diskStatusRank(record.SourceDisks[i].IntegrityStatus) {
			record.SourceDisks[i] = disk
		}
		return
	}
	record.SourceDisks = append(record.SourceDisks, disk)
}

// setSourceDiskStatus moves a requested disk to status, keeping what else the
// record knows of it, under the same rule as setSourceDisk.
func setSourceDiskStatus(record *probe.VMValidationRecord, slot, status string) {
	if record == nil {
		return
	}
	for i := range record.SourceDisks {
		if record.SourceDisks[i].Slot == slot {
			if diskStatusRank(status) > diskStatusRank(record.SourceDisks[i].IntegrityStatus) {
				record.SourceDisks[i].IntegrityStatus = status
			}
			return
		}
	}
}
