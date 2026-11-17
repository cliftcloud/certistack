// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// NUMANodeRoot is where Linux describes the host's NUMA nodes.
const NUMANodeRoot = "/sys/devices/system/node"

// NUMANodeCacheMB returns, per NUMA node, the memory the node can give the
// page cache before its kswapd evicts pages that are in use: MemFree plus
// Inactive(file), in MiB. It returns nothing where the host describes no
// nodes.
func NUMANodeCacheMB(root string) ([]float64, error) {
	paths, err := filepath.Glob(filepath.Join(root, "node[0-9]*", "meminfo"))
	if err != nil {
		return nil, err
	}
	nodes := make([]float64, 0, len(paths))
	for _, path := range paths {
		mb, err := nodeCacheMB(path)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, mb)
	}
	return nodes, nil
}

// nodeCacheMB is one node's MemFree plus Inactive(file), in MiB.
func nodeCacheMB(path string) (float64, error) {
	free, inactiveFile, err := nodeMeminfo(path)
	return free + inactiveFile, err
}

// nodeMeminfo reads one node's MemFree and Inactive(file) in MiB from its
// meminfo ("Node 0 MemFree:  123 kB").
func nodeMeminfo(path string) (free, inactiveFile float64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var found int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[0] != "Node" {
			continue
		}
		var target *float64
		switch fields[2] {
		case "MemFree:":
			target = &free
		case "Inactive(file):":
			target = &inactiveFile
		default:
			continue
		}
		kb, err := strconv.ParseFloat(fields[3], 64)
		if err != nil {
			return 0, 0, fmt.Errorf("%s: %q: %w", path, scanner.Text(), err)
		}
		*target = kb / 1024
		found++
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if found < 2 {
		return 0, 0, fmt.Errorf("%s lacks MemFree or Inactive(file)", path)
	}
	return free, inactiveFile, nil
}

// NUMANode is one NUMA node: its ID, its CPUs and its meminfo file.
type NUMANode struct {
	ID      int
	CPUs    []int
	Meminfo string
}

// NUMANodes lists the host's NUMA nodes that have CPUs.
func NUMANodes(root string) ([]NUMANode, error) {
	dirs, err := filepath.Glob(filepath.Join(root, "node[0-9]*"))
	if err != nil {
		return nil, err
	}
	var nodes []NUMANode
	for _, dir := range dirs {
		id, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(dir), "node"))
		if err != nil {
			continue
		}
		list, err := os.ReadFile(filepath.Join(dir, "cpulist"))
		if err != nil {
			return nil, err
		}
		cpus, err := ParseCPUList(strings.TrimSpace(string(list)))
		if err != nil {
			return nil, fmt.Errorf("%s/cpulist: %w", dir, err)
		}
		if len(cpus) == 0 {
			continue // a memory-only node
		}
		nodes = append(nodes, NUMANode{ID: id, CPUs: cpus, Meminfo: filepath.Join(dir, "meminfo")})
	}
	return nodes, nil
}

// NodeMemFreeMB is one node's MemFree, in MiB.
func NodeMemFreeMB(meminfo string) (float64, error) {
	free, _, err := nodeMeminfo(meminfo)
	return free, err
}

// ParseCPUList parses a kernel CPU list such as "0-7,16-23".
func ParseCPUList(list string) ([]int, error) {
	var cpus []int
	if list == "" {
		return nil, nil
	}
	for _, part := range strings.Split(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("CPU list %q: %w", list, err)
		}
		last := first
		if isRange {
			if last, err = strconv.Atoi(hi); err != nil {
				return nil, fmt.Errorf("CPU list %q: %w", list, err)
			}
		}
		if first < 0 || last < first || last > 1<<16 {
			return nil, fmt.Errorf("CPU list %q: bad range %q", list, part)
		}
		for cpu := first; cpu <= last; cpu++ {
			cpus = append(cpus, cpu)
		}
	}
	return cpus, nil
}
