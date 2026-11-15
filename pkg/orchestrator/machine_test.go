// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

// The sandbox VM starts a Windows guest on the machine a restore of the
// backup would (qemu-server 9.2.7 get_vm_machine), pinning it only where
// that differs from the node's latest version.
func TestWindowsRestoreMachine(t *testing.T) {
	node := []string{"pc-i440fx-5.1", "pc-q35-5.1", "pc-q35-9.0", "pc-q35-9.1", "pc-q35-10.1", "pc-q35-11.0", "pc-q35-11.0+pve2", "pc-i440fx-11.0"}
	for _, tc := range []struct {
		name, requested, meta string
		want                  string
		pinned                bool
	}{
		{"created on this QEMU", "q35", "creation-qemu=11.0.3,ctime=1", "q35", false},
		{"created on 10.1", "q35", "creation-qemu=10.1.2,ctime=1", "pc-q35-10.1+pve0", true},
		{"created on 9.1", "q35,viommu=virtio", "creation-qemu=9.1.0", "pc-q35-9.1+pve0,viommu=virtio", true},
		{"created before 9.1", "q35", "creation-qemu=8.1.5,ctime=1", "pc-q35-5.1+pve0", true},
		{"no meta", "q35", "", "pc-q35-5.1+pve0", true},
		{"i440fx default", "", "creation-qemu=8.0.2", "pc-i440fx-5.1+pve0", true},
		{"version the node lacks", "q35", "creation-qemu=10.0.1", "q35", false},
		{"created on a newer QEMU", "q35", "creation-qemu=12.0.0", "q35", false},
		{"already versioned", "pc-q35-8.1", "creation-qemu=8.1.5", "pc-q35-8.1", false},
	} {
		got, pinned := windowsRestoreMachine(tc.requested, tc.meta, node)
		if got != tc.want || pinned != tc.pinned {
			t.Errorf("%s: %q, %v; want %q, %v", tc.name, got, pinned, tc.want, tc.pinned)
		}
	}
	if got, pinned := windowsRestoreMachine("q35", "creation-qemu=8.1.5", nil); got != "q35" || pinned {
		t.Errorf("without the node's machine list: %q, %v", got, pinned)
	}
	// 5.1 dropped by the node (QEMU 11.1): the latest version, as PVE does.
	if got, pinned := windowsRestoreMachine("q35", "creation-qemu=8.1.5", []string{"pc-q35-9.1", "pc-q35-11.1"}); got != "q35" || pinned {
		t.Errorf("without 5.1: %q, %v", got, pinned)
	}
}

// The boot disk is scanned last, so it is the freshest in the page cache
// when the guest boots; every disk is scanned exactly once.
func TestScanOrderPutsTheBootDiskLast(t *testing.T) {
	for _, tc := range []struct {
		slots []string
		boot  string
		want  string
	}{
		{[]string{"scsi0", "scsi1", "scsi2"}, "scsi0", "1,2,0"},
		{[]string{"scsi0", "scsi1"}, "scsi1", "0,1"},
		{[]string{"virtio0"}, "virtio0", "0"},
		{[]string{"scsi0", "scsi1"}, "", "0,1"},
	} {
		var got []string
		for _, i := range scanOrder(tc.slots, tc.boot) {
			got = append(got, strconv.Itoa(i))
		}
		if strings.Join(got, ",") != tc.want {
			t.Errorf("scanOrder(%v, %q) = %v, want %s", tc.slots, tc.boot, got, tc.want)
		}
	}
}

// The shared-disk warning is checked once per run, however many
// overlays the run creates.
func TestOverlayClusterDiskWarningIsCheckedOnce(t *testing.T) {
	calls := 0
	o := &Orchestrator{sharedDisksFn: func(_ context.Context, a, b string) ([]string, error) {
		calls++
		if b != "/var/lib/pve-cluster" {
			t.Errorf("compared with %q", b)
		}
		return []string{"sda"}, nil
	}}
	for _, dir := range []string{"/var/lib/vz/images/17011", "/var/lib/vz/images/17012"} {
		if err := o.warnOverlaySharesClusterDisk(context.Background(), dir); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("checked %d times, want once", calls)
	}
}
