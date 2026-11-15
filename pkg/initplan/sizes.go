// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"fmt"
	"time"

	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/runphase"
)

const (
	// ScanBytesPerSecond is the speed at which the estimate has a run read and
	// hash a backup's disks: about what the lab's older Xeon E5 v2 nodes do (about
	// three hours per TiB, docs/compatibility.md). A faster node takes less.
	ScanBytesPerSecond = 100_000_000
	// PrepareSecondsPerVM is the guest network preparation of one VM on bare
	// metal, which a run does one VM at a time.
	PrepareSecondsPerVM = 120
	// ConfirmAboveBytes is the total disk size above which init asks again before
	// it writes a plan, at a terminal: a run of that plan reads for about an hour
	// and a half or more.
	ConfirmAboveBytes = 500 << 30
)

// Sizes is what a run of the plan init writes reads and holds: the backups'
// disks it reads in full to check them, the time that takes, and the memory it
// reserves while its VMs run. Only the VMs the plan keeps count.
type Sizes struct {
	// VMs is how many VMs the plan restores.
	VMs int
	// DiskBytes is the size of their disks, from the backups' configurations.
	DiskBytes int64
	// Unsized is how many of the VMs have a backup that gives no disk size; they
	// add nothing to DiskBytes.
	Unsized int
	// ReservedMB is the memory a run holds at its peak: each VM's own, or the
	// sandbox default when its backup gives none, and the host overhead of each.
	ReservedMB int
}

// Estimate is about how long a run takes: reading the disks at ScanBytesPerSecond
// and preparing each VM. The boot and the probes are not in it.
func (s Sizes) Estimate() time.Duration {
	scan := time.Duration(s.DiskBytes/ScanBytesPerSecond) * time.Second
	return scan + time.Duration(s.VMs*PrepareSecondsPerVM)*time.Second
}

// Large reports whether the plan's disks are more than init writes without
// asking again.
func (s Sizes) Large() bool { return s.DiskBytes > ConfirmAboveBytes }

// PlanSizes is the sizes of the plan Compose would write for d, given the
// storage the operator asked for ("" chooses one). It counts the VMs Compose
// keeps and none it leaves out, by the same rule (leftOutVMs). The error is
// Compose's own refusal of the storage.
func (d *Discovery) PlanSizes(requestedStorage string) (Sizes, error) {
	storage, _, err := chooseOverlayStorage(d, requestedStorage)
	if err != nil {
		return Sizes{}, err
	}
	var s Sizes
	for i, reason := range leftOutVMs(d.VMs, storage) {
		if reason != "" {
			continue
		}
		vm := d.VMs[i]
		s.VMs++
		if vm.DiskBytes > 0 {
			s.DiskBytes += vm.DiskBytes
		} else {
			s.Unsized++
		}
		memory := vm.MemoryMB
		if memory <= 0 {
			memory = admission.DefaultSandboxMemoryMB
		}
		s.ReservedMB += memory + admission.SandboxVMHostOverheadMB
	}
	return s, nil
}

// Lines are the sizes as init prints them, one fact to a line, to go under
// "The plan restores N VM(s). A run of it:".
func (s Sizes) Lines() []string {
	lines := []string{
		fmt.Sprintf("reads %s of backup disks, each in full", sizeText(s.DiskBytes)),
		fmt.Sprintf("takes about %s (reading at %d MB/s, a rate measured on older servers, plus %d minutes to prepare each VM; a faster node takes less)", durationText(s.Estimate()), ScanBytesPerSecond/1_000_000, PrepareSecondsPerVM/60),
		fmt.Sprintf("reserves %s of the node's RAM while it runs (each VM's memory plus 256 MiB)", sizeText(int64(s.ReservedMB)<<20)),
	}
	if s.Unsized > 0 {
		lines = append(lines, fmt.Sprintf("(%d VM(s) have no disk size in their backup, so the first two lines leave them out)", s.Unsized))
	}
	return lines
}

// sizeText writes bytes as GiB, or TiB from 1024 GiB: "412 GiB", "1.5 TiB".
func sizeText(n int64) string {
	const gib, tib = int64(1) << 30, int64(1) << 40
	switch {
	case n >= tib:
		return fmt.Sprintf("%.1f TiB", float64(n)/float64(tib))
	case n >= gib && n%gib == 0:
		return fmt.Sprintf("%d GiB", n/gib)
	case n >= gib:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(gib))
	}
	if n <= 0 {
		return "0 MiB"
	}
	return runphase.FormatSize(n)
}

// durationText writes d to the minute: "6 min", "1 h 18 min", "2 h".
func durationText(d time.Duration) string {
	minutes := int((d + 30*time.Second) / time.Minute)
	switch {
	case minutes < 1:
		return "under a minute"
	case minutes < 60:
		return fmt.Sprintf("%d min", minutes)
	case minutes%60 == 0:
		return fmt.Sprintf("%d h", minutes/60)
	}
	return fmt.Sprintf("%d h %d min", minutes/60, minutes%60)
}
