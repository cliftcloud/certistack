//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fakeSysfs builds /sys/dev/block links for sda (with partition sda3), sdb,
// and dm-0 (an LVM volume on sda3), as a node with root and local-lvm on
// one disk has.
func fakeSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mk := func(dir string, files map[string]string) {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, body := range files {
			if err := os.WriteFile(filepath.Join(root, dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	link := func(target, name string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, target), filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	mk("devices/pci0/block/sda", map[string]string{"dev": "8:0\n"})
	mk("devices/pci0/block/sda/sda3", map[string]string{"dev": "8:3\n", "partition": "3\n"})
	mk("devices/pci0/block/sdb", map[string]string{"dev": "8:16\n"})
	mk("devices/virtual/block/dm-0/slaves", nil)
	mk("devices/virtual/block/dm-0", map[string]string{"dev": "253:0\n"})
	// sdc holds two ZFS pools on two partitions, sdd a third on one.
	mk("devices/pci0/block/sdc", map[string]string{"dev": "8:32\n"})
	mk("devices/pci0/block/sdc/sdc1", map[string]string{"dev": "8:33\n", "partition": "1\n"})
	mk("devices/pci0/block/sdc/sdc2", map[string]string{"dev": "8:34\n", "partition": "2\n"})
	mk("devices/pci0/block/sdd", map[string]string{"dev": "8:48\n"})
	mk("devices/pci0/block/sdd/sdd1", map[string]string{"dev": "8:49\n", "partition": "1\n"})
	link("devices/pci0/block/sdc", "dev/block/8:32")
	link("devices/pci0/block/sdc/sdc1", "dev/block/8:33")
	link("devices/pci0/block/sdc/sdc2", "dev/block/8:34")
	link("devices/pci0/block/sdd", "dev/block/8:48")
	link("devices/pci0/block/sdd/sdd1", "dev/block/8:49")
	link("devices/pci0/block/sda/sda3", "devices/virtual/block/dm-0/slaves/sda3")
	link("devices/pci0/block/sda", "dev/block/8:0")
	link("devices/pci0/block/sda/sda3", "dev/block/8:3")
	link("devices/pci0/block/sdb", "dev/block/8:16")
	link("devices/virtual/block/dm-0", "dev/block/253:0")
	return root
}

// Overlay storage on the root disk shares it with pmxcfs, and a
// sandbox's write storm then delays corosync.
func TestWalkBlockDeviceFindsThePhysicalDisk(t *testing.T) {
	root := fakeSysfs(t)
	for majmin, want := range map[string]string{
		"8:3":   "sda", // a partition: its disk
		"253:0": "sda", // an LVM volume: the disk under its partition
		"8:16":  "sdb", // a whole disk
	} {
		disks := map[string]bool{}
		if err := walkBlockDevice(root, majmin, disks, 0); err != nil {
			t.Fatal(err)
		}
		var got []string
		for disk := range disks {
			got = append(got, disk)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != want {
			t.Errorf("%s: disks %v, want %q", majmin, got, want)
		}
	}
}

func TestSharedDisksOfTheSamePath(t *testing.T) {
	dir := t.TempDir()
	shared, err := SharedDisks(context.Background(), dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	// On a block-device file system a path shares its own disk; on tmpfs or
	// overlayfs (some CI) it has none. Either way the call must not fail.
	t.Logf("shared disks of %s with itself: %v", dir, shared)
}

// A file system image mounted through a loop device lives on the disk that
// holds the image: overlay storage built that way on the root disk shares it
// with the cluster database.
func TestWalkBlockDeviceFollowsALoopDevicesBackingFile(t *testing.T) {
	root := fakeSysfs(t)
	if err := os.MkdirAll(filepath.Join(root, "devices/virtual/block/loop0/loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "devices/virtual/block/loop0/loop/backing_file"), []byte("/var/lib/scratch.img\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "devices/virtual/block/loop0"), filepath.Join(root, "dev/block/7:0")); err != nil {
		t.Fatal(err)
	}
	orig := deviceOf
	deviceOf = func(path string) (string, error) {
		if path != "/var/lib/scratch.img" {
			t.Errorf("followed %q", path)
		}
		return "253:0", nil // an LVM volume on sda3
	}
	defer func() { deviceOf = orig }()
	disks := map[string]bool{}
	walkBlockDevice(root, "7:0", disks, 0)
	if len(disks) != 1 || !disks["sda"] {
		t.Fatalf("disks = %v, want sda", disks)
	}
}

// file systems without a block device of their own were
// "shared with nothing", so on a ZFS-root node the cluster database and
// overlay storage never looked shared. They are resolved through the mount
// table now, and what cannot be resolved is unknown, never "not shared".
func TestSharedDisksThroughTheMountTable(t *testing.T) {
	root := fakeSysfs(t)
	mountInfo := filepath.Join(t.TempDir(), "mountinfo")
	table := strings.Join([]string{
		"25 1 0:24 / / rw,relatime - zfs rpool/ROOT/pve-1 rw,xattr",
		"40 25 0:45 / /rpool/data rw,relatime - zfs rpool/data rw,xattr",
		"41 25 0:46 / /tank/scratch rw,relatime - zfs tank/scratch rw,xattr",
		"42 25 0:47 / /mnt/pve/nfs rw,relatime - nfs4 nas:/export rw",
		"43 25 0:48 / /mnt/btrfs rw,relatime - btrfs /dev/sdb rw",
		"44 25 0:49 / /mnt/odd rw,relatime - exotic something rw",
		"45 25 8:3 / /var rw,relatime - ext4 /dev/sda3 rw",
		"46 25 0:50 / /mnt/fuse rw,relatime - fuse.encfs /dev/sdb rw",
		"47 25 0:51 / /fast rw,relatime - zfs fast rw,xattr",
		"48 25 0:52 / /lost rw,relatime - zfs lost rw,xattr",
	}, "\n") + "\n"
	if err := os.WriteFile(mountInfo, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	devices := map[string]string{
		"/var/lib/pve-cluster": "0:24", "/var/lib/vz": "0:24", "/rpool/data/x": "0:45", "/tank/scratch/x": "0:46",
		"/mnt/pve/nfs/x": "0:47", "/mnt/btrfs/x": "0:48", "/mnt/odd/x": "0:49", "/var/x": "8:3",
		"/mnt/fuse/x": "0:50", "/fast/x": "0:51", "/lost/x": "0:52",
	}
	// zpool lists each imported pool's devices: rpool on sdc1 with a log
	// device on sdb, fast on sdc2, tank on sdd1 with a failed mirror
	// member that is gone. "lost" is not imported.
	status := map[string]string{
		"rpool": zpoolStatusSample("rpool", "\t    /dev/sdc1  ONLINE       0     0     0\n\tlogs\n\t  /dev/sdb  ONLINE       0     0     0\n"),
		"fast":  zpoolStatusSample("fast", "\t  /dev/sdc2  ONLINE       0     0     0\n"),
		"tank":  zpoolStatusSample("tank", "\t    /dev/sdd1  ONLINE       0     0     0\n\t    /dev/sdz1  UNAVAIL      0     0     0\n"),
	}
	origDev, origMount, origRdev, origStatus := deviceOf, mountInfoPath, rdevOf, zpoolStatus
	t.Cleanup(func() { deviceOf, mountInfoPath, rdevOf, zpoolStatus = origDev, origMount, origRdev, origStatus })
	deviceOf = func(path string) (string, error) { return devices[path], nil }
	mountInfoPath = mountInfo
	zpoolStatus = func(_ context.Context, pool string) ([]byte, error) {
		if out, ok := status[pool]; ok {
			return []byte(out), nil
		}
		return nil, errors.New("cannot open '" + pool + "': no such pool")
	}
	rdevOf = func(path string) (string, error) {
		if id, ok := map[string]string{"/dev/sdb": "8:16", "/dev/sdc1": "8:33", "/dev/sdc2": "8:34", "/dev/sdd1": "8:49"}[path]; ok {
			return id, nil
		}
		return "", os.ErrNotExist
	}
	for _, tc := range []struct {
		a, b    string
		want    string
		unknown bool
	}{
		{"/var/lib/vz", "/var/lib/pve-cluster", "sdb,sdc", false},   // one ZFS dataset
		{"/rpool/data/x", "/var/lib/pve-cluster", "sdb,sdc", false}, // two datasets of one pool
		{"/fast/x", "/var/lib/pve-cluster", "sdc", false},           // two pools on one disk
		{"/tank/scratch/x", "/var/lib/pve-cluster", "", false},      // a pool on another disk
		{"/tank/scratch/x", "/var/x", "", false},                    // a pool and an ext4 disk
		{"/lost/x", "/var/lib/pve-cluster", "", true},               // not an imported pool
		{"/mnt/pve/nfs/x", "/var/lib/pve-cluster", "", false},       // network storage
		{"/mnt/btrfs/x", "/var/x", "", true},                        // mountinfo does not list all btrfs members
		{"/mnt/odd/x", "/var/lib/pve-cluster", "", true},            // cannot tell
		{"/mnt/fuse/x", "/var/lib/pve-cluster", "", true},           // FUSE can have local backing
	} {
		shared, err := sharedDisks(context.Background(), root, tc.a, tc.b)
		if tc.unknown {
			if !errors.Is(err, ErrDisksUnknown) {
				t.Errorf("%s vs %s: shared %v, err %v; want ErrDisksUnknown", tc.a, tc.b, shared, err)
			}
			continue
		}
		if err != nil || strings.Join(shared, ",") != tc.want {
			t.Errorf("%s vs %s: shared %v, err %v; want %q", tc.a, tc.b, shared, err, tc.want)
		}
	}
	// Incomplete membership is unknown, even if the named member is readable.
	if _, err := deviceDisks(context.Background(), root, "0:48"); !errors.Is(err, ErrDisksUnknown) {
		t.Errorf("btrfs topology error = %v", err)
	}
}

func TestDeviceDisksRejectsIncompleteMemberTraversal(t *testing.T) {
	root := fakeSysfs(t)
	// dm-0 already has a healthy member on sda. A second member that cannot
	// be resolved must not turn that partial result into a safety decision.
	member := filepath.Join(root, "devices/virtual/block/dm-0/slaves/missing")
	if err := os.MkdirAll(member, 0755); err != nil {
		t.Fatal(err)
	}
	if disks, err := deviceDisks(context.Background(), root, "253:0"); !errors.Is(err, ErrDisksUnknown) || disks != nil {
		t.Fatalf("partial topology accepted: %v, %v", disks, err)
	}
	if err := walkBlockDevice(root, "0:999", map[string]bool{}, 0); !errors.Is(err, ErrDisksUnknown) {
		t.Fatalf("missing block device accepted: %v", err)
	}
	if err := walkBlockDevice(root, "8:0", map[string]bool{}, 9); !errors.Is(err, ErrDisksUnknown) {
		t.Fatalf("truncated traversal accepted: %v", err)
	}
}

// zpoolStatusSample is `zpool status -P -L` for pool with the given device
// lines.
func zpoolStatusSample(pool, devices string) string {
	return "  pool: " + pool + "\n state: ONLINE\nconfig:\n\n\tNAME        STATE     READ WRITE CKSUM\n\t" + pool +
		"       ONLINE       0     0     0\n\t  mirror-0  ONLINE       0     0     0\n" + devices + "\nerrors: No known data errors\n"
}
