// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/google/uuid"
)

// workerReportFor is the report an honest worker returns for a passing run of
// opts' plan on opts' node, in opts' mode: one record per planned VM, one
// passing result per planned probe, integrity evidence for each disk, and a
// clean teardown, in a run that began a moment ago. It names no run: the
// fake worker fills in the run the controller started.
func workerReportFor(t *testing.T, opts RunOptions) *attest.Report {
	t.Helper()
	plan, err := config.LoadFromFile(opts.PlanPath)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := config.CanonicalWorkerPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	mode, status := attest.ValidationModeFullIntegrity, "verified"
	if opts.SkipIntegrity {
		mode, status = attest.ValidationModeTestSkipIntegrity, "skipped_test_mode"
	}
	report := &attest.Report{
		ReportSchemaVersion: attest.CurrentReportSchemaVersion,
		ReportID:            uuid.NewString(),
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		PlanID:              plan.PlanID,
		ValidatedPlanSHA256: digest,
		ResolvedPlanSHA256:  digest,
		PlanDigestFormat:    config.WorkerPlanDigestFormat,
		PlanName:            plan.Name,
		NodeFQDN:            opts.NodeName,
		ValidationMode:      mode,
		Frameworks:          append([]string(nil), plan.Compliance.Frameworks...),
		RetentionDays:       plan.Compliance.RetentionDays,
		AllPassed:           true,
		TeardownEvidence:    &attest.TeardownEvidence{AllCleaned: true, OrphanSweepClean: true},
		RTOTargetSeconds:    attest.RTOObjective(plan),
		Admission:           grantedAdmission(plan),
	}
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			record := probe.VMValidationRecord{
				VMID: vm.VMID, SourceVMID: vm.SourceVMID, Name: vm.Name,
				AllPassed: true, VerificationStatus: "verified", PBSVerifyStatus: "passed",
				SourceSnapshot: resolvedSnapshot(vm),
			}
			drives := vm.SourcePBS.RestoreDrives()
			if len(drives) == 0 {
				drives = []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}
			}
			for _, drive := range drives {
				record.SourceDisks = append(record.SourceDisks, probe.SourceDiskEvidence{
					Slot: drive.Slot, Archive: drive.Archive, ManifestReference: "vm/" + vm.Name + "/index.json.blob",
					IntegrityStatus: status, ImageDigest: strings.Repeat("ab", 32),
				})
			}
			for _, p := range vm.Probes {
				target, _ := attest.ExpectedProbeTarget(p)
				result := probe.Result{Type: p.Type, Target: target, Description: p.Description, Passed: true,
					// The policy the worker's prober ran under, as the plan sets it.
					TimeoutSec: p.TimeoutSec, Retries: max(p.Retries, 0)}
				switch {
				case p.Type == "qga":
					result.RequireQGA = p.RequireQGA
				case p.Type == "http" || p.Type == "mssql":
					result.ServerName = p.ServerName
				}
				if config.IsWireProbe(p.Type) {
					result.SourceInterface, result.SourceAddress = plan.Network.VNetID, strings.TrimSpace(plan.Network.ProbeIP)
				}
				record.ProbeResults = append(record.ProbeResults, result)
			}
			if tier.SoakTimeSec > 0 {
				record.Soak = honestSoak(record, vm, tier.SoakTimeSec)
			}
			report.VMRecords = append(report.VMRecords, record)
		}
	}
	return report
}

// resolvedSnapshot is the snapshot a worker records for a planned VM: the one
// the plan pins, or, for a selector, the latest of the source VM's group as the
// worker resolved it.
func resolvedSnapshot(vm config.VM) string {
	pinned := strings.TrimSpace(vm.SourcePBS.Snapshot)
	if parts := strings.Split(pinned, "/"); len(parts) == 3 && parts[0] == "vm" {
		if _, err := time.Parse(time.RFC3339, parts[2]); err == nil {
			return pinned
		}
	}
	return fmt.Sprintf("vm/%d/2026-09-27T03:12:59Z", attest.ExpectedSourceVMID(vm))
}

// honestSoak is the summary an honest worker records for a VM whose tier held
// it for soakSec seconds: a service check every 30 s and one at the end, all
// of them passed, the soak having ended a moment ago.
func honestSoak(record probe.VMValidationRecord, vm config.VM, soakSec int) *probe.SoakEvidence {
	end := time.Now().Add(-2 * time.Second)
	start := end.Add(-time.Duration(soakSec) * time.Second)
	samples := soakSec/30 + 1
	soak := &probe.SoakEvidence{
		ConfiguredSec: soakSec, IntervalSec: 30, Samples: samples, StatusReads: samples + 1,
		StartedAt: start.UTC().Format(time.RFC3339), FirstSampleAt: start.Add(time.Duration(min(30, soakSec)) * time.Second).UTC().Format(time.RFC3339),
		LastSampleAt: end.UTC().Format(time.RFC3339),
	}
	for index, p := range vm.Probes {
		if config.IsGuestLevelProbe(p.Type) {
			soak.Probes = append(soak.Probes, probe.SoakProbeEvidence{
				Probe: index + 1, Type: record.ProbeResults[index].Type, Description: record.ProbeResults[index].Description,
				Passed: samples, WorstDuration: 3 * time.Millisecond,
			})
		}
	}
	return soak
}
