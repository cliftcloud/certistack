// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// Source check statuses, as doctor reports them.
const (
	SourcePassed  = "passed"
	SourceWarning = "warning"
	SourceFailed  = "failed"
)

// SourceCheck is one plan VM's backup as a run would find it.
type SourceCheck struct {
	VMID   int
	Name   string
	Status string
	Detail string
}

// CheckSources does, for each VM of plan, what a run does with its backup
// before it creates the first sandbox resource: resolve the snapshot, check
// the configured key against it, read its configuration and layout, apply
// the plan to them, and check that firmware state has overlay storage. So
// doctor can report, VM by VM, every refusal a run would give for a backup:
// an encrypted backup without its key, the wrong key, a UEFI VM without
// overlay storage, a plan disk the backup lacks. A crash-consistent backup
// is a warning. Nothing is created: PBS is only read, and each backup's
// configuration is restored into a private temporary directory that is
// removed afterwards.
func CheckSources(ctx context.Context, plan *config.Plan, opts Options) ([]SourceCheck, error) {
	if plan == nil {
		return nil, errors.New("plan is required")
	}
	opts = normalizeOptions(plan, opts)
	scratch, err := os.MkdirTemp("", "certistack-doctor-")
	if err != nil {
		return nil, fmt.Errorf("create private scratch directory: %w", err)
	}
	defer os.RemoveAll(scratch)
	client, err := pbsClientFor(plan)
	if err != nil {
		return nil, err
	}
	return checkSources(ctx, plan, client, newSourceCache(client), scratch, opts.OverlayStorage), nil
}

// checkSources runs a run's own source steps on a one-VM copy of plan for
// each VM, so one VM's refusal does not hide the next one's.
func checkSources(ctx context.Context, plan *config.Plan, snapshots snapshotResolver, backups backupProfileResolver, scratch, overlayStorage string) []SourceCheck {
	var checks []SourceCheck
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			single := *plan
			one := tier
			one.VMs = []config.VM{vm}
			single.Tiers = []config.Tier{one}
			checks = append(checks, checkSource(ctx, &single, snapshots, backups, scratch, overlayStorage))
		}
	}
	return checks
}

func checkSource(ctx context.Context, plan *config.Plan, snapshots snapshotResolver, backups backupProfileResolver, scratch, overlayStorage string) SourceCheck {
	vm := &plan.Tiers[0].VMs[0]
	check := SourceCheck{VMID: vm.VMID, Name: vm.Name}
	err := resolveLatestSnapshots(ctx, plan, snapshots)
	if err == nil && plan.UseBackupConfig {
		err = applyBackupConfig(ctx, plan, backups, scratch)
	} else if err == nil {
		if err = applyBackupNetworkIdentity(ctx, plan, backups, scratch); err == nil {
			err = applyBackupLayout(ctx, plan, backups, scratch)
		}
	}
	if err == nil {
		err = requireFirmwareStorage(plan, overlayStorage)
	}
	if err != nil {
		check.Status, check.Detail = SourceFailed, SafeFailureReason(err)
		return check
	}
	check.Status, check.Detail = SourcePassed, describeSource(vm)
	if vm.RequireQuiescedBackup {
		if reason := pbs.QuiescedRequirementUnmet(vm.SourceConsistency, vm.SourceConsistencyDetail); reason != "" {
			check.Status, check.Detail = SourceFailed, reason
			return check
		}
	}
	if vm.SourceConsistency == pbs.ConsistencyCrash {
		check.Status = SourceWarning
	}
	return check
}

// describeSource summarizes what a run would restore for vm.
func describeSource(vm *config.VM) string {
	parts := []string{vm.SourcePBS.Snapshot}
	firmware := "BIOS"
	if vm.BIOS == "ovmf" {
		firmware = "UEFI"
		for _, disk := range vm.FirmwareDisks {
			firmware += " + " + disk.Slot
		}
	}
	parts = append(parts, firmware)
	disks := len(vm.SourcePBS.RestoreDrives())
	parts = append(parts, fmt.Sprintf("%d disk(s) restored", disks))
	if len(vm.OmittedDisks) > 0 {
		parts = append(parts, "left out: "+strings.Join(vm.OmittedDisks, ", "))
	}
	switch vm.SourceCryptMode {
	case pbs.CryptModeEncrypt:
		parts = append(parts, "encrypted (key configured)")
	case pbs.CryptModeSignOnly:
		parts = append(parts, "signed (key configured)")
	default:
		parts = append(parts, "not encrypted")
	}
	switch vm.SourceConsistency {
	case "":
	case pbs.ConsistencyCrash, pbs.ConsistencyUnknown:
		parts = append(parts, "backup "+vm.SourceConsistency+": "+vm.SourceConsistencyDetail)
	default:
		parts = append(parts, "backup "+vm.SourceConsistency)
	}
	return strings.Join(parts, "; ")
}
