// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"fmt"
	"log/slog"
	"slices"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// tierCache tracks how much of the page cache a tier's pre-boot scans have
// filled, against what the node can hold before evicting the first of it.
// Each sandbox boots from the cache its scan filled. The kernel keeps
// a scan's pages on the NUMA node the scan runs on, and that node's kswapd
// evicts the oldest of them once the node is full, even while other nodes
// are free (a test node reclaimed 14 GiB on node 0 with 103 GiB free on
// node 1). The first-scanned disks' reads then go back to PBS at boot.
type tierCache struct {
	level       int
	budgetKnown bool // false until beginTierCache reads the node's memory
	budgetBytes int64
	scanned     int64
	// plannedBytes is the tier's disks all together, from the sizes the
	// backups record; 0 when one of them is unknown. Auto copies every VM of
	// a tier whose disks together outgrow the budget (see decideCopy).
	plannedBytes int64
	warned       bool
	// windows is true when any VM of the tier is a Windows guest: only the
	// wording of the warning depends on it.
	windows bool
}

// scanCacheMB is the page cache a scan can fill before the kernel evicts
// its first pages. With two or more NUMA nodes whose CPUs the worker may use,
// the scan spreads its cache over them (pbs startScanSpread), so it is
// their free and inactive file memory together. Otherwise it is one node's,
// the smallest, since an unspread scan may run on any node. Without NUMA
// information, it is the host's MemAvailable.
func scanCacheMB() (float64, error) {
	nodes, err := sysutil.NUMANodeCacheMB(sysutil.NUMANodeRoot)
	if err != nil || len(nodes) == 0 {
		return admission.AvailableMemoryMB()
	}
	if pbs.ScanSpreadNodes() >= 2 {
		var total float64
		for _, mb := range nodes {
			total += mb
		}
		return total, nil
	}
	return slices.Min(nodes), nil
}

// beginTierCache starts a tier's accounting. The tier's VMs take their
// memory from what is free now, and may take it on any node, so it is not
// available for the cache.
func (o *Orchestrator) beginTierCache(tier config.Tier) {
	o.tierCache = tierCache{level: tier.Level, plannedBytes: tierDiskBytes(tier)}
	for _, vm := range tier.VMs {
		if windowsOSType(vm.OSType) {
			o.tierCache.windows = true
		}
	}
	if o.cacheMemoryFn == nil {
		return
	}
	cacheMB, err := o.cacheMemoryFn()
	if err != nil || cacheMB <= 0 {
		return
	}
	var vmMB int64
	for _, vm := range tier.VMs {
		memory := vm.HardwareOverrides.MemoryMB
		if memory <= 0 {
			memory = admission.DefaultSandboxMemoryMB
		}
		vmMB += int64(memory) + admission.SandboxVMHostOverheadMB
	}
	o.tierCache.budgetBytes = max(0, int64(cacheMB)-vmMB) << 20
	o.tierCache.budgetKnown = true
}

// tierDiskBytes is the tier's disks all together, from the sizes the backups
// record (the snapshot manifest's image size, else the configuration's); 0 when
// any restored disk has no recorded size, so a tier of unknown size decides
// nothing.
func tierDiskBytes(tier config.Tier) int64 {
	var total int64
	for _, vm := range tier.VMs {
		for _, drive := range vm.SourcePBS.RestoreDrives() {
			n, ok := sourceDiskLength(vm, drive.Slot)
			if !ok || n <= 0 {
				return 0
			}
			total += n
		}
	}
	return total
}

// noteScannedDisks adds a VM's scanned disks to its tier's total and warns,
// once per tier, when the total outgrows the tier's cache budget. It
// returns the warning it gave, if any.
func (o *Orchestrator) noteScannedDisks(vmid int, bytes int64) string {
	c := &o.tierCache
	c.scanned += bytes
	if c.warned || !c.budgetKnown || c.scanned <= c.budgetBytes {
		return ""
	}
	c.warned = true
	consequence := "A service can then miss the service manager's start deadline (troubleshooting Issues 26 and 27)."
	if c.windows {
		consequence = "Windows services can then miss their start deadline (troubleshooting Issue 27)."
	}
	msg := fmt.Sprintf("Tier %d's disks scanned so far (%d GiB, through VM %d) are more than this node can keep cached (%d GiB of free memory, after the tier's VM memory). Each sandbox boots from the cache its scan filled; once memory is full, the kernel evicts the first-scanned disks, and those reads go back to PBS at boot. %s Split the tier, run it on a node with more free memory, or let copy_before_boot copy the disks first.",
		c.level, c.scanned>>30, vmid, c.budgetBytes>>30, consequence)
	slog.Warn("tier disks exceed the page cache the node can hold", "tier", c.level, "scanned_bytes", c.scanned, "budget_bytes", c.budgetBytes)
	progress.Warn("Storage", "%s", msg)
	return msg
}
