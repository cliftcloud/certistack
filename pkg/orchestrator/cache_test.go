// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// A tier of two Windows VMs with 48 GiB of disks each. The kernel keeps a
// scan's pages on one NUMA node and evicts the first of them once that node is
// full. The run says so when the tier outgrows the smallest node's free memory,
// once per tier.
func TestTierCacheWarnsWhenScannedDisksOutgrowFreeMemory(t *testing.T) {
	o := &Orchestrator{cacheMemoryFn: func() (float64, error) { return 93 * 1024, nil }}
	tier := config.Tier{Level: 1, VMs: []config.VM{
		{VMID: 7214, OSType: "w2k22", HardwareOverrides: config.HardwareOverrides{MemoryMB: 4096}},
		{VMID: 7213, OSType: "w2k22"}, // no memory setting: PVE's default
	}}
	o.beginTierCache(tier)
	if msg := o.noteScannedDisks(7214, 48<<30); msg != "" {
		t.Fatalf("warned after the first VM: %s", msg)
	}
	msg := o.noteScannedDisks(7213, 48<<30)
	for _, want := range []string{"Tier 1's disks scanned so far (96 GiB, through VM 7213)", "(86 GiB of free memory, after the tier's VM memory)", "Issue 19"} {
		if !strings.Contains(msg, want) {
			t.Errorf("warning lacks %q: %q", want, msg)
		}
	}
	if again := o.noteScannedDisks(7215, 1<<30); again != "" {
		t.Errorf("warned twice in one tier: %s", again)
	}

	o.beginTierCache(config.Tier{Level: 2, VMs: []config.VM{{VMID: 7216}}})
	if msg := o.noteScannedDisks(7216, 40<<30); msg != "" {
		t.Errorf("the next tier inherited the first tier's total: %s", msg)
	}
}

func TestTierCacheIsSilentWithoutAMemoryReading(t *testing.T) {
	for name, fn := range map[string]func() (float64, error){
		"error": func() (float64, error) { return 0, errors.New("no /proc/meminfo") },
		"zero":  func() (float64, error) { return 0, nil },
		"nil":   nil,
	} {
		o := &Orchestrator{cacheMemoryFn: fn}
		o.beginTierCache(config.Tier{Level: 1, VMs: []config.VM{{VMID: 1}}})
		if msg := o.noteScannedDisks(1, 1<<40); msg != "" {
			t.Errorf("%s: warned without knowing free memory: %s", name, msg)
		}
	}
	// A scan outside a tier (no beginTierCache) has no budget either.
	if msg := (&Orchestrator{}).noteScannedDisks(1, 1<<40); msg != "" {
		t.Errorf("warned outside a tier: %s", msg)
	}
}

func TestScanCacheMBReadsThisHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("NUMA and MemAvailable are read from Linux /sys and /proc")
	}
	mb, err := scanCacheMB()
	if err != nil || mb <= 0 {
		t.Fatalf("scanCacheMB() = %v, %v; want free memory", mb, err)
	}
}
