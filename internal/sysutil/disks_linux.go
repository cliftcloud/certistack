//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// ClusterStateDir holds the Proxmox VE cluster file system's database
// (pmxcfs). Starving its disk delays corosync and can cost the node its
// cluster membership.
const ClusterStateDir = "/var/lib/pve-cluster"

// ErrDisksUnknown means the disks under a file system could not be
// determined. Callers must treat that as possibly shared, never as not
// shared.
var ErrDisksUnknown = errors.New("cannot determine which disks hold the file system")

// SharedDisks returns the physical disks that pathA's and pathB's file
// systems both live on, resolving partitions to their disk and
// device-mapper, MD RAID and similar devices to their members. Two paths on
// one file system always share it. A file system without a block device of
// its own is resolved through the mount table: a ZFS dataset to the disks
// under the devices its imported pool lists; known network file systems and tmpfs
// hold no local disk. FUSE and multi-device btrfs need topology the mount
// table does not give. When the disks cannot be determined, the error wraps
// ErrDisksUnknown.
//
// The check ends when ctx does: its ZFS pool listing is a subprocess, which
// is stopped, and the error returned is ctx's, never ErrDisksUnknown, so a
// caller that was canceled is not told the topology is unknown.
func SharedDisks(ctx context.Context, pathA, pathB string) ([]string, error) {
	return sharedDisks(ctx, "/sys", pathA, pathB)
}

func sharedDisks(ctx context.Context, sysRoot, pathA, pathB string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	devA, err := deviceOf(pathA)
	if err != nil {
		return nil, err
	}
	devB, err := deviceOf(pathB)
	if err != nil {
		return nil, err
	}
	if devA == devB {
		// One file system: whatever holds it, both paths share.
		disks, err := deviceDisks(ctx, sysRoot, devA)
		if ctxErr := ctx.Err(); err != nil && ctxErr != nil {
			return nil, ctxErr
		}
		if err != nil || len(disks) == 0 {
			return []string{"file system " + devA}, nil
		}
		return sortedKeys(disks), nil
	}
	disksA, err := deviceDisks(ctx, sysRoot, devA)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pathA, err)
	}
	disksB, err := deviceDisks(ctx, sysRoot, devB)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pathB, err)
	}
	var shared []string
	for disk := range disksA {
		if disksB[disk] {
			shared = append(shared, disk)
		}
	}
	sort.Strings(shared)
	return shared, nil
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// mountInfoPath, zpoolStatus and rdevOf are replaced by tests.
var (
	mountInfoPath = "/proc/self/mountinfo"
	// zpoolStatus is `zpool status -P -L <pool>`: the imported pool's
	// devices, by their real paths. It runs under the caller's context, with
	// its own timeout as well: a suspended pool can hang zpool, and the run
	// must still end when it is told to.
	zpoolStatus = func(ctx context.Context, pool string) ([]byte, error) {
		result, err := Run(ctx, zpoolStatusTimeout, "zpool", "status", "-P", "-L", pool)
		if err != nil {
			return nil, err
		}
		return result.Stdout, nil
	}
	rdevOf = func(path string) (string, error) {
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err != nil {
			return "", err
		}
		dev := uint64(st.Rdev)
		major := (dev >> 8 & 0xfff) | (dev >> 32 & ^uint64(0xfff))
		minor := (dev & 0xff) | (dev >> 12 & ^uint64(0xff))
		return fmt.Sprintf("%d:%d", major, minor), nil
	}
)

// noLocalDisk are file system types that hold no local disk.
var noLocalDisk = map[string]bool{
	"nfs": true, "nfs4": true, "cifs": true, "smb3": true, "ceph": true, "glusterfs": true, "9p": true,
	"tmpfs": true, "ramfs": true, "devtmpfs": true,
}

// deviceDisks is the set of disks under the file system on device majmin. When
// ctx ends while a ZFS pool is being listed, the error is ctx's alone.
func deviceDisks(ctx context.Context, sysRoot, majmin string) (map[string]bool, error) {
	disks := map[string]bool{}
	if _, err := os.Stat(filepath.Join(sysRoot, "dev", "block", majmin)); err == nil {
		if err := walkBlockDevice(sysRoot, majmin, disks, 0); err != nil {
			return nil, err
		}
		if len(disks) == 0 {
			return nil, fmt.Errorf("%w: device %s resolves to no disk", ErrDisksUnknown, majmin)
		}
		return disks, nil
	}
	// No block device of its own (an anonymous device): read the mount.
	fstype, source, ok := mountOfDevice(majmin)
	if !ok {
		return nil, fmt.Errorf("%w: no mount of device %s", ErrDisksUnknown, majmin)
	}
	switch {
	case fstype == "zfs":
		pool, _, _ := strings.Cut(source, "/")
		if err := zfsPoolDisks(ctx, sysRoot, pool, disks); err != nil {
			return nil, err
		}
	case noLocalDisk[fstype]:
	case fstype == "btrfs":
		// mountinfo names just one member, not every disk of the file system.
		return nil, fmt.Errorf("%w: btrfs requires all member devices", ErrDisksUnknown)
	case fstype == "fuse" || strings.HasPrefix(fstype, "fuse."):
		return nil, fmt.Errorf("%w: FUSE may be backed by local storage", ErrDisksUnknown)
	case strings.HasPrefix(source, "/dev/"):
		device, err := rdevOf(source)
		if err != nil {
			return nil, fmt.Errorf("%w: %s file system on %s: %v", ErrDisksUnknown, fstype, source, err)
		}
		if err := walkBlockDevice(sysRoot, device, disks, 0); err != nil {
			return nil, err
		}
		if len(disks) == 0 {
			return nil, fmt.Errorf("%w: %s file system on %s resolves to no disk", ErrDisksUnknown, fstype, source)
		}
	default:
		return nil, fmt.Errorf("%w: %s file system %q", ErrDisksUnknown, fstype, source)
	}
	return disks, nil
}

// zpoolStatusTimeout bounds zpool, which a suspended pool can hang. It is
// the check's own limit, besides the caller's context; tests shorten it.
var zpoolStatusTimeout = 15 * time.Second

var zfsPoolNameExpr = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]*$`)

// zfsPoolDisks adds the disks under the devices the imported ZFS pool
// lists: data, log, cache and spare. A pool's name cannot tell two pools on
// one disk apart, and neither can a disk's ZFS label: a guest's disk can
// hold a pool of any name, such as a TrueNAS guest's boot-pool or a nested
// PVE's rpool. A device that is gone (a failed mirror member) holds nothing.
// A pool zpool cannot list is unknown, unless ctx ended first: then the
// listing was stopped, nothing is known of the pool, and the error is ctx's
// (not the pool's, and not the internal timeout's, which stays "unknown").
func zfsPoolDisks(ctx context.Context, sysRoot, pool string, disks map[string]bool) error {
	if !zfsPoolNameExpr.MatchString(pool) {
		return fmt.Errorf("%w: ZFS pool name %q", ErrDisksUnknown, pool)
	}
	out, err := zpoolStatus(ctx, pool)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("list the devices of ZFS pool %s: %w", pool, ctxErr)
		}
		return fmt.Errorf("%w: list the devices of ZFS pool %s: %v", ErrDisksUnknown, pool, err)
	}
	devices := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "/dev/") {
			continue
		}
		device, err := rdevOf(fields[0])
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: ZFS pool %s device %s: %v", ErrDisksUnknown, pool, fields[0], err)
		}
		if err := walkBlockDevice(sysRoot, device, disks, 0); err != nil {
			return err
		}
		devices++
	}
	if devices == 0 {
		return fmt.Errorf("%w: zpool lists no device of ZFS pool %s", ErrDisksUnknown, pool)
	}
	return nil
}

// mountOfDevice finds the mount of device majmin in the mount table: its
// file system type and source.
func mountOfDevice(majmin string) (fstype, source string, ok bool) {
	data, err := os.ReadFile(mountInfoPath)
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[2] != majmin {
			continue
		}
		for i := 6; i < len(fields)-2; i++ {
			if fields[i] == "-" {
				return fields[i+1], fields[i+2], true
			}
		}
	}
	return "", "", false
}

// deviceOf is the block device ("major:minor") holding path's file system.
// Tests replace it.
var deviceOf = func(path string) (string, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}
	dev := uint64(st.Dev)
	major := (dev >> 8 & 0xfff) | (dev >> 32 & ^uint64(0xfff))
	minor := (dev & 0xff) | (dev >> 12 & ^uint64(0xff))
	return fmt.Sprintf("%d:%d", major, minor), nil
}

// walkBlockDevice adds the physical disks under the block device majmin.
func walkBlockDevice(sysRoot, majmin string, disks map[string]bool, depth int) error {
	if depth > 8 {
		return fmt.Errorf("%w: block device traversal exceeded depth limit", ErrDisksUnknown)
	}
	device, err := filepath.EvalSymlinks(filepath.Join(sysRoot, "dev", "block", majmin))
	if err != nil {
		return fmt.Errorf("%w: resolve block device %s: %v", ErrDisksUnknown, majmin, err)
	}
	// A loop device's file system lives in a file: follow it to the disks
	// that file is on, as for a file system image mounted as overlay storage
	// on the root disk. stat never opens the file.
	if data, err := os.ReadFile(filepath.Join(device, "loop", "backing_file")); err == nil {
		backing := strings.TrimSuffix(strings.TrimSpace(string(data)), " (deleted)")
		id, err := deviceOf(backing)
		if err != nil {
			return fmt.Errorf("%w: resolve loop backing file: %v", ErrDisksUnknown, err)
		}
		return walkBlockDevice(sysRoot, id, disks, depth+1)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: read loop backing file: %v", ErrDisksUnknown, err)
	}
	if slaves, err := os.ReadDir(filepath.Join(device, "slaves")); err == nil && len(slaves) > 0 {
		for _, slave := range slaves {
			id, err := os.ReadFile(filepath.Join(device, "slaves", slave.Name(), "dev"))
			if err != nil {
				return fmt.Errorf("%w: read member device: %v", ErrDisksUnknown, err)
			}
			if err := walkBlockDevice(sysRoot, strings.TrimSpace(string(id)), disks, depth+1); err != nil {
				return err
			}
		}
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: list member devices: %v", ErrDisksUnknown, err)
	}
	if _, err := os.Stat(filepath.Join(device, "partition")); err == nil {
		device = filepath.Dir(device)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: inspect partition: %v", ErrDisksUnknown, err)
	}
	disks[filepath.Base(device)] = true
	return nil
}
