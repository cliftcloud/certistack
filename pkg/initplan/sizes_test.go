// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package initplan

import (
	"strings"
	"testing"
	"time"
)

// The sizes are those of the VMs the plan keeps: a VM it leaves out is read by
// no run, and holds no memory.
func TestPlanSizesCountOnlyTheVMsThePlanKeeps(t *testing.T) {
	d := discovered()
	res, err := Compose(d, Options{Written: backupTime})
	if err != nil {
		t.Fatal(err)
	}
	sizes, err := d.PlanSizes("")
	if err != nil {
		t.Fatal(err)
	}
	if sizes.VMs != res.VMs {
		t.Fatalf("sizes count %d VMs, the plan restores %d", sizes.VMs, res.VMs)
	}
	// Each kept VM has 32 GiB and no memory of its own: 2048 + 256 MiB each.
	if want := int64(sizes.VMs) * (32 << 30); sizes.DiskBytes != want || sizes.Unsized != 0 {
		t.Errorf("disks = %d (%d unsized), want %d", sizes.DiskBytes, sizes.Unsized, want)
	}
	if want := sizes.VMs * (2048 + 256); sizes.ReservedMB != want {
		t.Errorf("reserved = %d MiB, want %d", sizes.ReservedMB, want)
	}
}

func TestPlanSizesUseTheBackupsMemoryAndSayWhichSizesAreMissing(t *testing.T) {
	d := &Discovery{Node: "pve1", ZoneID: "csZone1", VNetID: "csVnet1", SandboxVMIDs: []int{9100, 9101}, VMs: []VM{
		{SourceVMID: 100, Snapshot: "vm/100/2026-09-27T03:00:00Z", BackupTime: backupTime, Name: "a", OSType: "l26", BIOS: "seabios", HasNIC: true, MAC: "BC:24:11:00:00:01", DiskBytes: 100 << 30, MemoryMB: 8192},
		{SourceVMID: 101, Snapshot: "vm/101/2026-09-27T03:00:00Z", BackupTime: backupTime, Name: "b", OSType: "l26", BIOS: "seabios", HasNIC: true, MAC: "BC:24:11:00:00:02"},
	}}
	sizes, err := d.PlanSizes("")
	if err != nil {
		t.Fatal(err)
	}
	if sizes.DiskBytes != 100<<30 || sizes.Unsized != 1 || sizes.ReservedMB != 8192+256+2048+256 {
		t.Fatalf("sizes = %+v", sizes)
	}
	lines := strings.Join(sizes.Lines(), "\n")
	for _, want := range []string{"reads 100 GiB of backup disks, each in full", "reserves 10.5 GiB of the node's RAM", "(1 VM(s) have no disk size in their backup"} {
		if !strings.Contains(lines, want) {
			t.Errorf("the lines lack %q:\n%s", want, lines)
		}
	}
	// A storage the plan cannot use is Compose's refusal, and the sizes' too.
	if _, err := d.PlanSizes("nowhere"); err == nil {
		t.Error("sizes of a plan on a storage the node cannot use")
	}
}

func TestSizesEstimateAndLargeThreshold(t *testing.T) {
	// 1 TiB at 100 MB/s is 10995 s, and each of 2 VMs takes 4 minutes to prepare.
	s := Sizes{VMs: 2, DiskBytes: 1 << 40}
	if got, want := s.Estimate(), 10995*time.Second+8*time.Minute; got != want {
		t.Errorf("estimate = %v, want %v", got, want)
	}
	if !s.Large() || (Sizes{DiskBytes: ConfirmAboveBytes}).Large() || !(Sizes{DiskBytes: ConfirmAboveBytes + 1}).Large() {
		t.Error("a plan is large above 500 GiB, and not at 500 GiB")
	}
	for in, want := range map[time.Duration]string{
		10 * time.Second: "under a minute", 90 * time.Second: "2 min", 17 * time.Minute: "17 min",
		time.Hour: "1 h", 78 * time.Minute: "1 h 18 min", 3*time.Hour + 2*time.Minute: "3 h 2 min",
	} {
		if got := durationText(in); got != want {
			t.Errorf("durationText(%v) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[int64]string{300 << 20: "300 MiB", 12 << 30: "12 GiB", 10<<30 + 512<<20: "10.5 GiB", 3 << 40: "3.0 TiB", 1<<20 + 123: "1.0 MiB", 0: "0 MiB"} {
		if got := sizeText(in); got != want {
			t.Errorf("sizeText(%d) = %q, want %q", in, got, want)
		}
	}
}
