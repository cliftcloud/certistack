//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"fmt"
	"log/slog"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/progress"
)

const scanSpreadInterval = int64(1 << 30)

// numaRoot is where the host describes its NUMA nodes; tests replace it.
var numaRoot = sysutil.NUMANodeRoot

// scanSpread moves the scanning thread, every GiB, to the NUMA node with
// the most free memory (MemFree). The sandbox boots from the map's FUSE
// file's page cache. The loop device's worker fills that cache on the node
// of the CPU the read was queued from, so the scanning thread's CPU decides
// where the cache lands. Left alone, it all lands on one node, whose kswapd
// then evicts it while the other node is free. Spread, the cache can
// use every node's free memory (48 GiB split 42/58, nothing
// reclaimed). The scan's own pages are inactive file pages, so counting
// Inactive(file) as room would keep it on the node it is filling.
type scanSpread struct {
	nodes []sysutil.NUMANode
	sets  []unix.CPUSet
	orig  unix.CPUSet
	next  int64
	node  int
}

// startScanSpread spreads the scan when the host has two or more NUMA nodes
// whose CPUs the worker may use. It locks the scanning goroutine to its
// thread and moves it to the roomiest node. It returns nil, and the scan
// runs where the scheduler puts it, on a single-node host or when the
// thread's affinity can't be read.
func startScanSpread(device string) *scanSpread {
	nodes, err := sysutil.NUMANodes(numaRoot)
	if err != nil || len(nodes) < 2 {
		return nil
	}
	runtime.LockOSThread()
	s := &scanSpread{node: -1}
	if err := unix.SchedGetaffinity(0, &s.orig); err != nil {
		runtime.UnlockOSThread()
		slog.Warn("scan spread off: cannot read the thread's CPU affinity", "error", err)
		return nil
	}
	s.nodes, s.sets = usableNodes(nodes, s.orig)
	var ids []string
	for _, node := range s.nodes {
		ids = append(ids, fmt.Sprintf("node %d", node.ID))
	}
	if len(s.nodes) < 2 {
		runtime.UnlockOSThread()
		return nil
	}
	progress.Info("Storage", "Spreading %s's page cache over NUMA %s.", device, strings.Join(ids, " and "))
	s.move(0)
	return s
}

// usableNodes keeps the nodes with CPUs in allowed (a cpuset may restrict
// the worker), each with its allowed CPUs.
func usableNodes(nodes []sysutil.NUMANode, allowed unix.CPUSet) ([]sysutil.NUMANode, []unix.CPUSet) {
	var usable []sysutil.NUMANode
	var sets []unix.CPUSet
	for _, node := range nodes {
		var set unix.CPUSet
		set.Zero()
		for _, cpu := range node.CPUs {
			if allowed.IsSet(cpu) {
				set.Set(cpu)
			}
		}
		if set.Count() > 0 {
			usable = append(usable, node)
			sets = append(sets, set)
		}
	}
	return usable, sets
}

// ScanSpreadNodes is how many NUMA nodes a scan spreads its page cache over:
// those with CPUs this process may use, or 0 when it does not spread.
func ScanSpreadNodes() int {
	nodes, err := sysutil.NUMANodes(numaRoot)
	if err != nil || len(nodes) < 2 {
		return 0
	}
	var allowed unix.CPUSet
	if err := unix.SchedGetaffinity(0, &allowed); err != nil {
		return 0
	}
	if usable, _ := usableNodes(nodes, allowed); len(usable) >= 2 {
		return len(usable)
	}
	return 0
}

// at is called with the bytes read so far.
func (s *scanSpread) at(total int64) {
	if s == nil || total < s.next {
		return
	}
	s.move(total)
}

func (s *scanSpread) move(total int64) {
	s.next = total + scanSpreadInterval
	best, bestMB := -1, -1.0
	for i, node := range s.nodes {
		mb, err := sysutil.NodeMemFreeMB(node.Meminfo)
		if err == nil && mb > bestMB {
			best, bestMB = i, mb
		}
	}
	if best < 0 || best == s.node {
		return
	}
	if err := unix.SchedSetaffinity(0, &s.sets[best]); err != nil {
		slog.Warn("scan spread: could not move the scanning thread", "node", s.nodes[best].ID, "error", err)
		return
	}
	s.node = best
	slog.Debug("scan spread: reading on NUMA node", "node", s.nodes[best].ID, "free_mib", int64(bestMB), "offset_gib", total>>30)
}

// stop restores the thread's affinity and unlocks it.
func (s *scanSpread) stop() {
	if s == nil {
		return
	}
	_ = unix.SchedSetaffinity(0, &s.orig)
	runtime.UnlockOSThread()
}
