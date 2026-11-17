//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/cliftcloud/certistack/internal/sysutil"
)

// With the spread on, the scanning thread moves to the NUMA node with
// the most free memory, not the most free-plus-inactive (the scan's own
// pages are inactive), and gets its own CPUs back afterwards.
func TestScanSpreadMovesTheThreadToTheRoomiestNode(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Skip("needs two CPUs to stand in for two NUMA nodes")
	}
	root := t.TempDir()
	for node, body := range map[string][2]string{
		"node0": {"0", "Node 0 MemFree: 1048576 kB\nNode 0 Inactive(file): 8388608 kB\n"}, // a scan's own pages: not room
		"node1": {"1", "Node 1 MemFree: 4194304 kB\nNode 1 Inactive(file): 0 kB\n"},
	} {
		dir := filepath.Join(root, node)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cpulist"), []byte(body[0]+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "meminfo"), []byte(body[1]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	orig := numaRoot
	numaRoot = root
	defer func() { numaRoot = orig }()
	runtime.LockOSThread() // keep this test on one thread to compare affinities
	defer runtime.UnlockOSThread()
	var before unix.CPUSet
	if err := unix.SchedGetaffinity(0, &before); err != nil {
		t.Fatal(err)
	}
	if !before.IsSet(1) {
		t.Skip("CPU 1 is not available to this test")
	}

	s := startScanSpread("/dev/loop9")
	if s == nil || s.nodes[s.node].ID != 1 {
		t.Fatalf("spread = %+v, want it on node 1", s)
	}
	var during unix.CPUSet
	if err := unix.SchedGetaffinity(0, &during); err != nil {
		t.Fatal(err)
	}
	if during.Count() != 1 || !during.IsSet(1) {
		t.Errorf("thread affinity during the scan = %d CPUs, want only CPU 1", during.Count())
	}
	s.stop()
	var after unix.CPUSet
	if err := unix.SchedGetaffinity(0, &after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Errorf("affinity not restored: %d CPUs, want %d", after.Count(), before.Count())
	}
}

// A host with one NUMA node has nothing to spread over.
func TestScanSpreadIsOffOnASingleNode(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cpulist"), []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := numaRoot
	numaRoot = root
	defer func() { numaRoot = orig }()
	if s := startScanSpread("/dev/loop9"); s != nil {
		s.stop()
		t.Fatal("spread started on a single-node host")
	}
}

// A cpuset that confines the worker to one node's CPUs leaves nothing to
// spread over.
func TestUsableNodesHonoursTheAllowedCPUs(t *testing.T) {
	nodes := []sysutil.NUMANode{{ID: 0, CPUs: []int{0, 1}}, {ID: 1, CPUs: []int{2, 3}}}
	var allowed unix.CPUSet
	allowed.Zero()
	allowed.Set(1)
	allowed.Set(3)
	usable, sets := usableNodes(nodes, allowed)
	if len(usable) != 2 || sets[0].Count() != 1 || !sets[0].IsSet(1) || !sets[1].IsSet(3) {
		t.Fatalf("usable %+v", usable)
	}
	allowed.Clear(3)
	if usable, _ := usableNodes(nodes, allowed); len(usable) != 1 || usable[0].ID != 0 {
		t.Fatalf("confined to node 0: usable %+v", usable)
	}
}
