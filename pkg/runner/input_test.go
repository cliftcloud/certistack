// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// A plan handed to a run without the validating loader is refused before
// anything is created when a sandbox VM ID is not a Proxmox VM ID or its
// hardware overrides are outside the ranges a backup's configuration is held
// to. A negative override would otherwise suppress the value inherited from the
// backup and fall to a default.
func TestRunRefusesVMIDsAndHardwareOutsideTheirRanges(t *testing.T) {
	const prefix = "tiers[0].vms[0]."
	validPlan := func(vm config.VM) *config.Plan {
		return &config.Plan{
			// Valid compliance metadata, so the only fault in each case is the
			// one named and the refusal must say so.
			Compliance:       config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
			AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
			Tiers:            []config.Tier{{Level: 1, VMs: []config.VM{vm}}},
		}
	}
	// The control: a VM with in-range hardware is not refused, so each case
	// below fails for the one field it changes.
	if err := requirePlanBounds(validPlan(config.VM{VMID: 9101, Name: "vm"})); err != nil {
		t.Fatalf("the unmutated plan is refused: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*config.VM)
		field  string
	}{
		"VM ID below 100":       {func(v *config.VM) { v.VMID = 99 }, "vmid"},
		"VM ID above 999999999": {func(v *config.VM) { v.VMID = 1000000000 }, "vmid"},
		"negative cores":        {func(v *config.VM) { v.HardwareOverrides.Cores = -1 }, "hardware_overrides.cores"},
		"negative sockets":      {func(v *config.VM) { v.HardwareOverrides.Sockets = -2 }, "hardware_overrides.sockets"},
		"negative memory":       {func(v *config.VM) { v.HardwareOverrides.MemoryMB = -3 }, "hardware_overrides.memory_mb"},
		"negative balloon":      {func(v *config.VM) { v.HardwareOverrides.BalloonMB = -4 }, "hardware_overrides.balloon_mb"},
		"negative CPU weight":   {func(v *config.VM) { v.HardwareOverrides.CPUWeight = -5 }, "hardware_overrides.cpu_weight"},
		"cores above 256":       {func(v *config.VM) { v.HardwareOverrides.Cores = 257 }, "hardware_overrides.cores"},
		"CPU weight above max":  {func(v *config.VM) { v.HardwareOverrides.CPUWeight = 262145 }, "hardware_overrides.cpu_weight"},
	} {
		vm := config.VM{VMID: 9101, Name: "vm"}
		tc.mutate(&vm)
		plan := validPlan(vm)
		for entry, call := range map[string]func() error{
			"run":     func() error { _, err := run(guardedContext(t), plan, Options{}); return err },
			"PlanRun": func() error { _, err := PlanRun(guardedContext(t), plan, Options{}); return err },
		} {
			err := call()
			if err == nil || !strings.Contains(err.Error(), "invalid plan") || !strings.Contains(err.Error(), prefix+tc.field+": ") {
				t.Errorf("%s, %s: err %v, want the plan refused for %s%s", name, entry, err, prefix, tc.field)
			}
			if err != nil && strings.Contains(err.Error(), "compliance") {
				t.Errorf("%s, %s: refused for its compliance metadata, not the bound under test: %v", name, entry, err)
			}
		}
	}
}

// A key does not by itself make a run require signed backups: the
// snapshot's own file list decides whether the key is used, so an unsigned
// backup (or a list that says a backup is unsigned) restores as unsigned. A
// VM whose plan sets require_signed_backup is refused, before anything is
// created, unless the key verified its snapshot's manifest, through both
// plan styles and for doctor.
func TestRequireSignedBackupRefusesAnUnverifiedSnapshot(t *testing.T) {
	const snapshot = "vm/7011/2026-09-27T03:00:00Z"
	drives := []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}
	for _, tc := range []struct {
		name     string
		profile  pbs.VMProfile
		required bool
		refused  string
	}{
		{"no requirement, unsigned", pbs.VMProfile{CryptMode: pbs.CryptModeNone, Drives: drives}, false, ""},
		{"no requirement, verified", pbs.VMProfile{CryptMode: pbs.CryptModeSignOnly, SignatureVerified: true, Drives: drives}, false, ""},
		{"required, unsigned", pbs.VMProfile{CryptMode: pbs.CryptModeNone, Drives: drives}, true, "neither signed nor encrypted"},
		{"required, signed but no key verified it", pbs.VMProfile{CryptMode: pbs.CryptModeSignOnly, Drives: drives}, true, "signed, and"},
		{"required, encrypted but no key verified it", pbs.VMProfile{CryptMode: pbs.CryptModeEncrypt, Drives: drives}, true, "encrypted, and"},
		{"required, verified", pbs.VMProfile{CryptMode: pbs.CryptModeSignOnly, SignatureVerified: true, Drives: drives}, true, ""},
		{"required, encrypted and verified", pbs.VMProfile{CryptMode: pbs.CryptModeEncrypt, SignatureVerified: true, Drives: drives}, true, ""},
	} {
		for _, useBackupConfig := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s (use_backup_config %v)", tc.name, useBackupConfig), func(t *testing.T) {
				plan := &config.Plan{UseBackupConfig: useBackupConfig, Tiers: []config.Tier{{VMs: []config.VM{{
					VMID: 9101, Name: "signed", RequireSignedBackup: tc.required,
					SourcePBS: config.SourcePBS{Snapshot: snapshot, Drives: []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}},
				}}}}}
				resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{snapshot: tc.profile}}
				var err error
				if useBackupConfig {
					err = applyBackupConfig(context.Background(), plan, resolver, "/tmp")
				} else {
					err = applyBackupLayout(context.Background(), plan, resolver, "/tmp")
				}
				if tc.refused == "" {
					if err != nil {
						t.Fatalf("refused: %v", err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "require_signed_backup") || !strings.Contains(err.Error(), tc.refused) || !strings.Contains(err.Error(), "VM 9101") {
					t.Fatalf("err = %v, want the requirement named with %q", err, tc.refused)
				}
			})
		}
	}
	// doctor runs the same steps for each VM and reports the refusal.
	plan := &config.Plan{UseBackupConfig: true, Tiers: []config.Tier{{Level: 1, VMs: []config.VM{{
		VMID: 9101, Name: "signed", RequireSignedBackup: true, SourcePBS: config.SourcePBS{Snapshot: snapshot},
	}}}}}
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{snapshot: {CryptMode: pbs.CryptModeNone, Drives: drives}}}
	checks := checkSources(context.Background(), plan, &fakeSnapshotResolver{resolved: map[string]string{snapshot + ":0": snapshot}}, resolver, "/tmp", "")
	if len(checks) != 1 || checks[0].Status != SourceFailed || !strings.Contains(checks[0].Detail, "require_signed_backup") {
		t.Fatalf("doctor checks = %+v", checks)
	}
}

// The worker's discovery prepares the scratch directory it is given,
// private, before it reads anything, and refuses one it cannot use, instead
// of falling back to the temporary directory.
func TestDiscoverPreparesItsScratchDirectory(t *testing.T) {
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("PATH", t.TempDir()) // no proxmox-backup-client: discovery stops after the scratch directory
	base := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(base, 0o700); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(base, "scratch")
	_, err := Discover(context.Background(), initplan.Request{Node: "pve1"}, scratch)
	if err == nil {
		t.Fatal("discovery without PBS succeeded")
	}
	info, statErr := os.Stat(scratch)
	if statErr != nil || !info.IsDir() || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o700) {
		t.Fatalf("the scratch directory was not prepared private: %v, %v", info, statErr)
	}
	for _, bad := range []string{"relative/scratch", "/tmp"} {
		if _, err := Discover(context.Background(), initplan.Request{Node: "pve1"}, bad); err == nil || !strings.Contains(err.Error(), "prepare scratch directory") {
			t.Errorf("scratch %q: %v", bad, err)
		}
	}
}
