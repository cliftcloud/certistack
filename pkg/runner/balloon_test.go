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

const balloonSnapshot = "vm/7011/2026-09-16T00:00:00Z"

func balloonPlan(useBackupConfig bool, hardware config.HardwareOverrides) *config.Plan {
	return &config.Plan{UseBackupConfig: useBackupConfig, Tiers: []config.Tier{{VMs: []config.VM{{
		VMID: 9900, Name: "restore", HardwareOverrides: hardware,
		SourcePBS: config.SourcePBS{Snapshot: balloonSnapshot, Drives: []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}},
	}}}}}
}

func balloonResolver(memoryMB int) fakeBackupProfileResolver {
	return fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		balloonSnapshot: {MemoryMB: memoryMB, Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}},
	}}
}

// validate compares balloon_mb only with a memory_mb the plan sets. A memory the
// plan takes from the backup (or leaves to the default) is known once the backup
// is read, and a balloon target above it is refused there, before anything is
// created, by the plan check and the run alike (both call prepareRun).
func TestBalloonAboveTheMemoryOfTheBackupIsRefused(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		plan    *config.Plan
		apply   func(*config.Plan) error
		wantErr []string // empty: accepted
	}{
		{"memory from the backup, balloon above it",
			balloonPlan(true, config.HardwareOverrides{BalloonMB: 8192}),
			func(p *config.Plan) error { return applyBackupConfig(ctx, p, balloonResolver(4096), "/tmp") },
			[]string{"balloon_mb is 8192 MiB", "memory of 4096 MiB", "its backup's configuration", "at most 4096", "at least 8192"}},
		{"memory from the backup, balloon within it",
			balloonPlan(true, config.HardwareOverrides{BalloonMB: 4096}),
			func(p *config.Plan) error { return applyBackupConfig(ctx, p, balloonResolver(4096), "/tmp") }, nil},
		{"memory the backup does not give, balloon above the default",
			balloonPlan(true, config.HardwareOverrides{BalloonMB: 4096}),
			func(p *config.Plan) error { return applyBackupConfig(ctx, p, balloonResolver(0), "/tmp") },
			[]string{"memory of 2048 MiB", "the default for a VM whose memory is not set"}},
		{"memory the plan sets, balloon above it",
			balloonPlan(true, config.HardwareOverrides{MemoryMB: 1024, BalloonMB: 2048}),
			func(p *config.Plan) error { return applyBackupConfig(ctx, p, balloonResolver(8192), "/tmp") },
			[]string{"memory of 1024 MiB", "the plan's memory_mb"}},
		{"no backup configuration, balloon above the default",
			balloonPlan(false, config.HardwareOverrides{BalloonMB: 4096}),
			func(p *config.Plan) error { return applyBackupLayout(ctx, p, balloonResolver(8192), "/tmp") },
			[]string{"memory of 2048 MiB", "does not use the backup's configuration"}},
		{"no backup configuration, memory set above the balloon",
			balloonPlan(false, config.HardwareOverrides{MemoryMB: 8192, BalloonMB: 4096}),
			func(p *config.Plan) error { return applyBackupLayout(ctx, p, balloonResolver(8192), "/tmp") }, nil},
		{"no balloon target at all",
			balloonPlan(true, config.HardwareOverrides{}),
			func(p *config.Plan) error { return applyBackupConfig(ctx, p, balloonResolver(512), "/tmp") }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.apply(tc.plan)
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("a balloon target above the VM's memory was accepted")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error lacks %q: %v", want, err)
				}
			}
		})
	}
}
