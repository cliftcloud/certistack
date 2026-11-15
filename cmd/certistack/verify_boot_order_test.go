// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// restored_hardware.boot_order lists only disks the report has integrity
// evidence for, and leads with the disk it says booted. A report that predates
// the field (no boot_order) is judged as before.
func TestReportAcceptanceBootOrder(t *testing.T) {
	plan := mustLoadFixturePlan()
	vm := &plan.Tiers[0].VMs[0]
	vm.SourcePBS.Drives = append(vm.SourcePBS.Drives, config.SourceDrive{Slot: "scsi1", Archive: "drive-scsi1"})
	exp := fixtureExpectations(plan, accept.OutcomePass)
	report := passReport(plan)
	report.VMRecords[0].SourceDisks = append(report.VMRecords[0].SourceDisks, probe.SourceDiskEvidence{
		Slot: "scsi1", Archive: "drive-scsi1", ManifestReference: "drive-scsi1.img.fidx", IntegrityStatus: "verified", ImageDigest: fixtureDigest(9001, "scsi1"),
	})

	report.VMRecords[0].RestoredHardware = &probe.RestoredHardware{BootDisk: "scsi0"}
	expectAccepted(t, "a report with no boot order", report, exp)
	report.VMRecords[0].RestoredHardware.BootOrder = []string{"scsi0", "scsi1"}
	expectAccepted(t, "both disks in the boot order", report, exp)
	report.VMRecords[0].RestoredHardware = &probe.RestoredHardware{BootDisk: "scsi1", BootOrder: []string{"scsi1", "scsi0"}}
	expectAccepted(t, "the second disk first", report, exp)

	report.VMRecords[0].RestoredHardware = &probe.RestoredHardware{BootDisk: "scsi0", BootOrder: []string{"scsi0", "scsi9"}}
	expectRejected(t, "a boot order disk with no evidence", report, exp, `boot order names disk "scsi9", which has no integrity evidence`)
	report.VMRecords[0].RestoredHardware = &probe.RestoredHardware{BootDisk: "scsi0", BootOrder: []string{"net0", "scsi0"}}
	expectRejected(t, "a network entry in the boot order", report, exp, `boot order names disk "net0", which has no integrity evidence`)
	report.VMRecords[0].RestoredHardware = &probe.RestoredHardware{BootDisk: "scsi0", BootOrder: []string{"scsi1", "scsi0"}}
	expectRejected(t, "a boot order that does not lead with the boot disk", report, exp, `booted disk "scsi0", but its boot order starts with "scsi1"`)
}
