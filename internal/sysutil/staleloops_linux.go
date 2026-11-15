//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// StaleFUSELoop is a read-only loop device whose backing file is on a FUSE
// file system that is no longer mounted anywhere. Nothing can read it any
// more. A PBS map whose daemon died without detaching its loop, and whose
// FUSE mount was then detached, leaves exactly this; the map's
// name is gone with the mount, so nothing ties it to a run.
type StaleFUSELoop struct {
	Device string
	Bytes  int64
	// Stuck is true when reads are in flight on the loop: they wait on a
	// FUSE file whose daemon is gone but whose connection is still open. Every
	// open of the loop hangs until that connection is aborted, so the loop was not
	// opened.
	Stuck bool
	// Holders are the md and device-mapper devices that hold the loop or its
	// partitions open, children first. The host assembles a guest's software RAID
	// and LVM from the partitions of a mapped disk, and a loop that is held cannot
	// be detached: losetup -d only marks it for removal until they are stopped.
	Holders []LoopHolder
}

// OrphanedFUSEConnection is a FUSE connection with requests waiting and no
// mount: nothing will ever answer them.
type OrphanedFUSEConnection struct {
	Minor   string
	Waiting int
}

// staleLoopScan is where StaleFUSELoops looks; tests replace it.
type staleLoopScan struct {
	sysBlock  string // /sys/block
	fuseConns string // /sys/fs/fuse/connections
	mountInfo string // /proc/self/mountinfo
	// backingDevice is the device of a loop's backing file, from
	// LOOP_GET_STATUS64.
	backingDevice func(device string) (major, minor uint32, err error)
}

var hostStaleLoopScan = staleLoopScan{
	sysBlock:      "/sys/block",
	fuseConns:     "/sys/fs/fuse/connections",
	mountInfo:     "/proc/self/mountinfo",
	backingDevice: loopBackingDevice,
}

// StaleFUSELoops lists the stale FUSE loop devices on this host. A loop
// counts only when all of these hold: it is read-only; its backing file
// reads "/" or nothing in sysfs, as a file on a detached single-file mount
// does; and either reads are stuck on it, or its backing file's device has
// a FUSE connection that no mount uses. Only such a loop with no reads in
// flight is opened, for its backing device: a live map's loop, and a wedged
// one, are never opened.
func StaleFUSELoops() []StaleFUSELoop {
	return hostStaleLoopScan.find()
}

// OrphanedFUSEConnections lists the FUSE connections with requests waiting
// and no mount.
func OrphanedFUSEConnections() []OrphanedFUSEConnection {
	return hostStaleLoopScan.orphanedConnections()
}

func (s staleLoopScan) find() []StaleFUSELoop {
	backings, _ := filepath.Glob(filepath.Join(s.sysBlock, "loop*", "loop", "backing_file"))
	var mounted map[string]bool
	var stale []StaleFUSELoop
	for _, backingFile := range backings {
		data, err := os.ReadFile(backingFile)
		if err != nil {
			continue
		}
		if backing := strings.TrimSpace(string(data)); backing != "" && backing != "/" {
			continue
		}
		dir := filepath.Dir(filepath.Dir(backingFile))
		if ro, err := os.ReadFile(filepath.Join(dir, "ro")); err != nil || strings.TrimSpace(string(ro)) != "1" {
			continue
		}
		loop := StaleFUSELoop{Device: "/dev/" + filepath.Base(dir)}
		loop.Holders, _ = holderHost{sysBlock: s.sysBlock}.loopHolders(loop.Device)
		if sectors, err := os.ReadFile(filepath.Join(dir, "size")); err == nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(sectors)), 10, 64); err == nil {
				loop.Bytes = n * 512
			}
		}
		if inFlight(filepath.Join(dir, "inflight")) {
			loop.Stuck = true
			stale = append(stale, loop)
			continue
		}
		major, minor, err := s.backingDevice(loop.Device)
		if err != nil || major != 0 {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.fuseConns, strconv.FormatUint(uint64(minor), 10))); err != nil {
			continue
		}
		if mounted == nil {
			mounted = s.mountedDevices()
		}
		if mounted[fmt.Sprintf("0:%d", minor)] {
			continue
		}
		stale = append(stale, loop)
	}
	sort.Slice(stale, func(i, j int) bool { return stale[i].Device < stale[j].Device })
	return stale
}

func (s staleLoopScan) orphanedConnections() []OrphanedFUSEConnection {
	entries, err := os.ReadDir(s.fuseConns)
	if err != nil {
		return nil
	}
	mounted := s.mountedDevices()
	var orphaned []OrphanedFUSEConnection
	for _, entry := range entries {
		minor := entry.Name()
		if _, err := strconv.ParseUint(minor, 10, 32); err != nil || mounted["0:"+minor] {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.fuseConns, minor, "waiting"))
		if err != nil {
			continue
		}
		if waiting, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && waiting > 0 {
			orphaned = append(orphaned, OrphanedFUSEConnection{Minor: minor, Waiting: waiting})
		}
	}
	sort.Slice(orphaned, func(i, j int) bool { return orphaned[i].Minor < orphaned[j].Minor })
	return orphaned
}

// inFlight reports whether a block device's inflight file shows reads or
// writes in flight.
func inFlight(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, field := range strings.Fields(string(data)) {
		if n, err := strconv.Atoi(field); err == nil && n > 0 {
			return true
		}
	}
	return false
}

// mountedDevices is every major:minor with a mount in the mount table.
func (s staleLoopScan) mountedDevices() map[string]bool {
	mounted := map[string]bool{}
	file, err := os.Open(s.mountInfo)
	if err != nil {
		return mounted
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		if fields := strings.Fields(scanner.Text()); len(fields) > 2 {
			mounted[fields[2]] = true
		}
	}
	return mounted
}

func loopBackingDevice(device string) (uint32, uint32, error) {
	fd, err := unix.Open(device, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, err
	}
	defer unix.Close(fd)
	info, err := unix.IoctlLoopGetStatus64(fd)
	if err != nil {
		return 0, 0, err
	}
	return unix.Major(info.Device), unix.Minor(info.Device), nil
}

// StaleFUSELoopDevices is the device names of the stale FUSE loops on the host
// now, for a run to record before it maps.
func StaleFUSELoopDevices() []string {
	return staleDevices(hostStaleLoopScan.find())
}

func staleDevices(loops []StaleFUSELoop) []string {
	devices := make([]string, 0, len(loops))
	for _, loop := range loops {
		devices = append(devices, loop.Device)
	}
	return devices
}

// ReleaseStaleFUSELoopsSince detaches the stale FUSE loops that were not stale
// when before was taken: what an interrupted PBS map of the run left, a loop its
// daemon attached and then died without detaching, after the file behind it was
// gone. A loop that is stuck (reads wait on it), or held by software RAID, LVM or
// dm-crypt devices, is not touched and is reported with what to do. A loop that
// was stale before is not this run's and is never touched. maps is how many maps
// the run began and never saw a loop for: a map leaves at most one loop, so more
// new stale loops than that are not all its own, and none is detached (they are
// reported). released names what was detached.
func ReleaseStaleFUSELoopsSince(ctx context.Context, before []string, maps int) (released []string, problems []error) {
	return releaseStaleSince(ctx, hostStaleLoopScan, before, maps, DetachLoop, 10, 200*time.Millisecond)
}

func releaseStaleSince(ctx context.Context, scan staleLoopScan, before []string, maps int, detach func(context.Context, string) error, attempts int, interval time.Duration) (released []string, problems []error) {
	was := map[string]bool{}
	for _, device := range before {
		was[device] = true
	}
	var fresh []StaleFUSELoop
	for _, loop := range scan.find() {
		if !was[loop.Device] {
			fresh = append(fresh, loop)
		}
	}
	if len(fresh) > maps {
		for _, loop := range fresh {
			problems = append(problems, fmt.Errorf("%s is a stale FUSE loop that appeared during this run, but only %d of the run's maps never reported a loop, so it cannot be shown to be the run's and was left; if nothing uses it, losetup -d %s", loop.Device, maps, loop.Device))
		}
		return nil, problems
	}
	for _, loop := range fresh {
		switch {
		case loop.Stuck:
			problems = append(problems, fmt.Errorf("%s is a stale FUSE loop that appeared during this run, and reads are stuck on it: its FUSE connection has requests waiting and no mount, so releasing it would hang. Abort the connection (echo 1 > /sys/fs/fuse/connections/<n>/abort, see certistack doctor), then losetup -d %s", loop.Device, loop.Device))
			continue
		case len(loop.Holders) > 0:
			problems = append(problems, fmt.Errorf("%s is a stale FUSE loop that appeared during this run, and %s hold it open: stop them first (%s), then losetup -d %s", loop.Device, HolderLabels(loop.Holders), strings.Join(StopCommands(loop.Holders), "; "), loop.Device))
			continue
		}
		if err := detach(ctx, loop.Device); err != nil {
			problems = append(problems, fmt.Errorf("release the stale FUSE loop %s the interrupted map left: %w", loop.Device, err))
			continue
		}
		gone := false
		for attempt := 0; attempt < attempts && !gone; attempt++ {
			if _, err := os.ReadFile(filepath.Join(scan.sysBlock, filepath.Base(loop.Device), "loop", "backing_file")); errors.Is(err, os.ErrNotExist) {
				gone = true
				break
			}
			select {
			case <-ctx.Done():
				attempt = attempts
			case <-time.After(interval):
			}
		}
		if !gone {
			problems = append(problems, fmt.Errorf("%s was detached but is still attached: something holds it open; check lsof and losetup -l, then losetup -d %s", loop.Device, loop.Device))
			continue
		}
		released = append(released, loop.Device)
	}
	return released, problems
}
