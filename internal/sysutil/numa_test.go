// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func writeNodeMeminfo(t *testing.T, root, node, body string) {
	t.Helper()
	dir := filepath.Join(root, node)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meminfo"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A test node under load: node1 held the scan's pages with 39 GiB free.
func TestNUMANodeCacheMB(t *testing.T) {
	root := t.TempDir()
	writeNodeMeminfo(t, root, "node0", "Node 0 MemTotal:       65970844 kB\nNode 0 MemFree:        44354764 kB\nNode 0 Active(file):     204800 kB\nNode 0 Inactive(file):  1048576 kB\n")
	writeNodeMeminfo(t, root, "node1", "Node 1 MemTotal:       66060288 kB\nNode 1 MemFree:        41000000 kB\nNode 1 Inactive(file):  2097152 kB\n")
	if err := os.MkdirAll(filepath.Join(root, "power"), 0o755); err != nil { // not a node
		t.Fatal(err)
	}
	nodes, err := NUMANodeCacheMB(root)
	if err != nil {
		t.Fatal(err)
	}
	sort.Float64s(nodes)
	if len(nodes) != 2 || int(nodes[0]) != 42087 || int(nodes[1]) != 44339 {
		t.Fatalf("nodes = %v MiB, want [42087 44339]", nodes)
	}
}

func TestNUMANodeCacheMBWithoutNodes(t *testing.T) {
	nodes, err := NUMANodeCacheMB(t.TempDir())
	if err != nil || len(nodes) != 0 {
		t.Fatalf("nodes = %v, err = %v; want none", nodes, err)
	}
}

func TestNUMANodeCacheMBRejectsAnIncompleteNode(t *testing.T) {
	root := t.TempDir()
	writeNodeMeminfo(t, root, "node0", "Node 0 MemFree: 1024 kB\n")
	if _, err := NUMANodeCacheMB(root); err == nil {
		t.Fatal("a node without Inactive(file) was accepted")
	}
}

func TestParseCPUList(t *testing.T) {
	for list, want := range map[string]string{
		"0-3,8-9": "[0 1 2 3 8 9]",
		"5":       "[5]",
		"":        "[]",
	} {
		cpus, err := ParseCPUList(list)
		if err != nil || fmt.Sprint(cpus) != want {
			t.Errorf("ParseCPUList(%q) = %v, %v; want %s", list, cpus, err, want)
		}
	}
	for _, bad := range []string{"a", "3-1", "0-x", "-1"} {
		if _, err := ParseCPUList(bad); err == nil {
			t.Errorf("ParseCPUList(%q) accepted", bad)
		}
	}
}

func TestNUMANodesSkipsMemoryOnlyNodes(t *testing.T) {
	root := t.TempDir()
	writeNodeMeminfo(t, root, "node0", "Node 0 MemFree: 1024 kB\nNode 0 Inactive(file): 0 kB\n")
	writeNodeMeminfo(t, root, "node1", "Node 1 MemFree: 1024 kB\nNode 1 Inactive(file): 0 kB\n")
	if err := os.WriteFile(filepath.Join(root, "node0", "cpulist"), []byte("0-3,8-11\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "node1", "cpulist"), []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	nodes, err := NUMANodes(root)
	if err != nil || len(nodes) != 1 || nodes[0].ID != 0 || len(nodes[0].CPUs) != 8 {
		t.Fatalf("nodes = %+v, %v; want node 0 with 8 CPUs", nodes, err)
	}
}
