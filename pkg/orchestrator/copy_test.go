// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

const gib = int64(1) << 30

// Copy-before-boot copies exactly the VMs a cache can't carry to their
// boot, where there is room and never onto the cluster database's disk,
// unless the plan says otherwise.
func TestDecideCopy(t *testing.T) {
	roomy := copyInputs{vmBytes: 48 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib}
	for _, tc := range []struct {
		name    string
		in      copyInputs
		copy    bool
		warning string
		err     string
	}{
		{name: "auto, fits in the cache", in: copyInputs{vmBytes: 20 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib}},
		{name: "auto, over the cache, room", in: roomy, copy: true},
		{name: "auto, tier already full", in: copyInputs{vmBytes: 20 * gib, tierScanned: 30 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib}, copy: true},
		// The tier, not the VM, outgrows the cache: a VM that fits on its own is still
		// copied, because the later VMs' disk reads would push its cached blocks out
		// while it runs from the backup map (a four-controller domain went cold fifty
		// minutes after its first controller booted).
		{name: "auto, the tier outgrows the cache and this VM fits", in: copyInputs{vmBytes: 20 * gib, tierBytes: 80 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib}, copy: true},
		{name: "auto, the tier fits the cache", in: copyInputs{vmBytes: 20 * gib, tierBytes: 30 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib}},
		{name: "auto, the tier's size is unknown", in: copyInputs{vmBytes: 20 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib}},
		{name: "auto, the tier outgrows the cache, budget unknown", in: copyInputs{vmBytes: 20 * gib, tierBytes: 80 * gib, freeBytes: 500 * gib}},
		{name: "auto, the tier outgrows the cache, no room", in: copyInputs{vmBytes: 20 * gib, tierBytes: 80 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 20 * gib}, warning: "The tier's disks (80 GiB together) are more than this node can keep cached (35 GiB), and this VM's disks (20 GiB) are not copied to local storage first: overlay storage has 20 GiB free, and the copies need 25 GiB"},
		{name: "auto, the tier outgrows the cache, shared cluster disk", in: copyInputs{vmBytes: 20 * gib, tierBytes: 80 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib, sharedDisk: true}, warning: "The tier's disks (80 GiB together)"},
		{name: "auto, the tier outgrows the cache, over the cap", in: copyInputs{vmBytes: 20 * gib, tierBytes: 80 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib, capBytes: 50 * gib, copied: 40 * gib}, warning: "the run's copies would reach 60 GiB, over storage.max_copy_gib (50 GiB)"},
		{name: "never, the tier outgrows the cache", in: copyInputs{mode: config.CopyBeforeBootNever, vmBytes: 20 * gib, tierBytes: 80 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib}},
		{name: "auto, budget unknown", in: copyInputs{vmBytes: 48 * gib, freeBytes: 500 * gib}},
		{name: "auto, size unknown", in: copyInputs{vmBytes: -1, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib}},
		{name: "auto, shared cluster disk", in: copyInputs{vmBytes: 48 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib, sharedDisk: true}, warning: "shares the cluster database's disk"},
		{name: "auto, no room", in: copyInputs{vmBytes: 48 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 50 * gib}, warning: "has 50 GiB free, and the copies need 53 GiB"},
		{name: "auto, free space unknown", in: copyInputs{vmBytes: 48 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: -1}, warning: "free space where the copies go is unknown"},
		{name: "never, over the cache", in: func() copyInputs { in := roomy; in.mode = config.CopyBeforeBootNever; return in }()},
		{name: "always, fits in the cache", in: copyInputs{mode: config.CopyBeforeBootAlways, vmBytes: 10 * gib, freeBytes: 500 * gib}, copy: true},
		{name: "always, shared disk", in: copyInputs{mode: config.CopyBeforeBootAlways, vmBytes: 10 * gib, freeBytes: 500 * gib, sharedDisk: true}, copy: true, warning: "can delay corosync"},
		{name: "always, no room", in: copyInputs{mode: config.CopyBeforeBootAlways, vmBytes: 48 * gib, freeBytes: 50 * gib}, err: "needs 53 GiB free"},
		{name: "always, free unknown", in: copyInputs{mode: config.CopyBeforeBootAlways, vmBytes: 48 * gib, freeBytes: -1}, err: "free space where the copies go is unknown"},
		{name: "always, size unknown", in: copyInputs{mode: config.CopyBeforeBootAlways, vmBytes: -1, freeBytes: 500 * gib}, err: "size of the VM's disks is unknown"},
		// storage.max_copy_gib: a test cluster's 50 GiB scratch share, where one
		// 48 GiB Windows copy nearly fills it.
		{name: "auto, under the cap", in: func() copyInputs { in := roomy; in.capBytes = 50 * gib; return in }(), copy: true},
		{name: "auto, over the cap with earlier copies", in: func() copyInputs { in := roomy; in.capBytes, in.copied = 50*gib, 10*gib; return in }(), warning: "the run's copies would reach 58 GiB, over storage.max_copy_gib (50 GiB)"},
		{name: "always, over the cap", in: copyInputs{mode: config.CopyBeforeBootAlways, vmBytes: 48 * gib, freeBytes: 500 * gib, capBytes: 40 * gib}, err: "over storage.max_copy_gib (40 GiB)"},
		{name: "always, no cap", in: copyInputs{mode: config.CopyBeforeBootAlways, vmBytes: 48 * gib, freeBytes: 500 * gib, copied: 400 * gib}, copy: true},
	} {
		copyDisks, warning, err := decideCopy(tc.in)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err = %v, want %q", tc.name, err, tc.err)
			}
			continue
		}
		if err != nil || copyDisks != tc.copy || (tc.warning == "") != (warning == "") || !strings.Contains(warning, tc.warning) {
			t.Errorf("%s: copy %v warning %q err %v; want copy %v warning %q", tc.name, copyDisks, warning, err, tc.copy, tc.warning)
		}
	}
}

func TestChooseCopyBeforeBootGathersItsInputs(t *testing.T) {
	o := &Orchestrator{
		deviceBytesFn: func(device string) (int64, error) {
			return map[string]int64{"/dev/loop0": 40 * gib, "/dev/loop1": 8 * gib}[device], nil
		},
		freeBytesFn:   func(string) (int64, error) { return 500 * gib, nil },
		sharedDisksFn: func(context.Context, string, string) ([]string, error) { return nil, nil },
		tierCache:     tierCache{budgetKnown: true, budgetBytes: 35 * gib},
	}
	vm := config.VM{VMID: 7214}
	if copyDisks, err := o.chooseCopyBeforeBoot(context.Background(), vm, []string{"/dev/loop0", "/dev/loop1"}, "/scratch"); err != nil || !copyDisks {
		t.Fatalf("48 GiB against a 35 GiB cache: copy %v, %v", copyDisks, err)
	}
	// A size that can't be read means auto never copies.
	o.deviceBytesFn = func(string) (int64, error) { return 0, errors.New("no sysfs") }
	if copyDisks, err := o.chooseCopyBeforeBoot(context.Background(), vm, []string{"/dev/loop0"}, "/scratch"); err != nil || copyDisks {
		t.Fatalf("unknown size: copy %v, %v", copyDisks, err)
	}
	// Test mode has no scan: auto doesn't copy, always still does.
	o.deviceBytesFn = func(string) (int64, error) { return 48 * gib, nil }
	o.opts.SkipIntegrity = true
	if copyDisks, _ := o.chooseCopyBeforeBoot(context.Background(), vm, []string{"/dev/loop0"}, "/scratch"); copyDisks {
		t.Fatal("auto copied in test mode")
	}
	vm.CopyBeforeBoot = config.CopyBeforeBootAlways
	if copyDisks, err := o.chooseCopyBeforeBoot(context.Background(), vm, []string{"/dev/loop0"}, "/scratch"); err != nil || !copyDisks {
		t.Fatalf("always in test mode: copy %v, %v", copyDisks, err)
	}
}

// The cap counts the run's copies together: a second VM's copy that would
// take them over storage.max_copy_gib is not made.
func TestCopyCapCountsTheRunsCopies(t *testing.T) {
	o := &Orchestrator{
		plan:          &config.Plan{Storage: config.Storage{MaxCopyGiB: 60}},
		deviceBytesFn: func(string) (int64, error) { return 48 * gib, nil },
		freeBytesFn:   func(string) (int64, error) { return 500 * gib, nil },
		sharedDisksFn: func(context.Context, string, string) ([]string, error) { return nil, nil },
		tierCache:     tierCache{budgetKnown: true, budgetBytes: 35 * gib},
	}
	if copyDisks, err := o.chooseCopyBeforeBoot(context.Background(), config.VM{VMID: 1}, []string{"/dev/loop0"}, "/scratch"); err != nil || !copyDisks {
		t.Fatalf("first VM: copy %v, %v", copyDisks, err)
	}
	if copyDisks, err := o.chooseCopyBeforeBoot(context.Background(), config.VM{VMID: 2}, []string{"/dev/loop1"}, "/scratch"); err != nil || copyDisks {
		t.Fatalf("second VM over the 60 GiB cap: copy %v, %v", copyDisks, err)
	}
	if o.copiedBytes != 48*gib {
		t.Fatalf("copied = %d GiB, want 48", o.copiedBytes/gib)
	}
}

// when it cannot be determined whether overlay storage
// shares the cluster database's disk, auto does not copy and says why;
// always still copies, and warns.
func TestDecideCopyTreatsUnknownDiskSharingAsUnsafe(t *testing.T) {
	in := copyInputs{vmBytes: 48 * gib, budgetKnown: true, budget: 35 * gib, freeBytes: 500 * gib, sharedUnknown: "zfs pool unknown"}
	if copyDisks, warning, err := decideCopy(in); copyDisks || err != nil || !strings.Contains(warning, "could not be determined (zfs pool unknown)") {
		t.Fatalf("auto: copy %v, warning %q, err %v", copyDisks, warning, err)
	}
	in.mode = config.CopyBeforeBootAlways
	if copyDisks, warning, err := decideCopy(in); !copyDisks || err != nil || !strings.Contains(warning, "could not be determined") {
		t.Fatalf("always: copy %v, warning %q, err %v", copyDisks, warning, err)
	}
}

// A tier whose disks together outgrow the cache copies every VM, the first
// ones too: four 20 GiB controllers against a 35 GiB cache. Before, only the
// VMs after the cache filled were copied, and the first one, running from the
// backup map, went cold when their reads pushed its cache out.
func TestAutoCopiesEveryVMOfATierThatOutgrowsTheCache(t *testing.T) {
	o := &Orchestrator{
		deviceBytesFn: func(string) (int64, error) { return 20 * gib, nil },
		freeBytesFn:   func(string) (int64, error) { return 500 * gib, nil },
		sharedDisksFn: func(context.Context, string, string) ([]string, error) { return nil, nil },
		tierCache:     tierCache{budgetKnown: true, budgetBytes: 35 * gib, plannedBytes: 80 * gib},
	}
	for vmid := 1; vmid <= 4; vmid++ {
		copyDisks, err := o.chooseCopyBeforeBoot(context.Background(), config.VM{VMID: vmid}, []string{"/dev/loop0"}, "/scratch")
		if err != nil || !copyDisks {
			t.Fatalf("VM %d of 4: copy %v, %v", vmid, copyDisks, err)
		}
	}
	if o.copiedBytes != 80*gib {
		t.Fatalf("copied = %d GiB, want 80", o.copiedBytes/gib)
	}
	// The same four VMs in a tier that fits the cache are not copied.
	o = &Orchestrator{
		deviceBytesFn: func(string) (int64, error) { return 8 * gib, nil },
		freeBytesFn:   func(string) (int64, error) { return 500 * gib, nil },
		sharedDisksFn: func(context.Context, string, string) ([]string, error) { return nil, nil },
		tierCache:     tierCache{budgetKnown: true, budgetBytes: 35 * gib, plannedBytes: 32 * gib},
	}
	for vmid := 1; vmid <= 4; vmid++ {
		o.tierCache.scanned = int64(vmid-1) * 8 * gib
		if copyDisks, err := o.chooseCopyBeforeBoot(context.Background(), config.VM{VMID: vmid}, []string{"/dev/loop0"}, "/scratch"); err != nil || copyDisks {
			t.Fatalf("VM %d of 4 in a tier that fits: copy %v, %v", vmid, copyDisks, err)
		}
	}
}

// A tier's size comes from the sizes the backups record; a disk with none
// makes the whole tier's size unknown, which decides nothing.
func TestBeginTierCacheRecordsTheTiersDiskBytes(t *testing.T) {
	vm := func(vmid int, sizes ...int64) config.VM {
		v := config.VM{VMID: vmid, SourceDiskBytes: map[string]int64{}}
		for i, n := range sizes {
			slot := []string{"scsi0", "scsi1"}[i]
			v.SourcePBS.Drives = append(v.SourcePBS.Drives, config.SourceDrive{Slot: slot, Archive: "drive-" + slot + ".img"})
			if n > 0 {
				v.SourceDiskBytes[slot] = n
			}
		}
		return v
	}
	o := &Orchestrator{cacheMemoryFn: func() (float64, error) { return 100 * 1024, nil }}
	o.beginTierCache(config.Tier{Level: 1, VMs: []config.VM{vm(1, 20*gib, 10*gib), vm(2, 30*gib)}})
	if o.tierCache.plannedBytes != 60*gib {
		t.Fatalf("plannedBytes = %d GiB, want 60", o.tierCache.plannedBytes/gib)
	}
	o.beginTierCache(config.Tier{Level: 1, VMs: []config.VM{vm(1, 20*gib), vm(2, 0)}})
	if o.tierCache.plannedBytes != 0 {
		t.Fatalf("a disk of unknown size: plannedBytes = %d, want 0", o.tierCache.plannedBytes)
	}
}
