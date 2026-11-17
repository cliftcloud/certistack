// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	machineIDVersion = regexp.MustCompile(`^pc-(q35|i440fx)-([0-9]+\.[0-9]+)$`)
	metaCreationQEMU = regexp.MustCompile(`(?:^|,)creation-qemu=([0-9]+)\.([0-9]+)`)
)

// windowsRestoreMachine returns the machine a restore of the backup starts a
// Windows guest on, when the backup's machine type is unversioned, and
// whether the sandbox VM must be pinned to it explicitly.
//
// qemu-server's get_vm_machine starts such a guest on the machine version
// of the QEMU that created it (the meta line's creation-qemu major.minor)
// when that is 9.1 or later, and on 5.1 otherwise or without meta; if the
// node cannot run that version it uses the latest one installed, and it
// appends "+pve0". A restore keeps the backup's meta; CreateVM writes the
// node's own, which resolves to the latest version, and PVE refuses to set
// meta afterwards. So the sandbox VM is pinned only when a restore would run
// something other than the node's latest version; otherwise it keeps the
// backup's unversioned setting, as a restore does.
//
// requested is the backup's machine setting ("", "pc" or "q35", with any
// options), meta the backup's normalized meta line, and machineIDs the
// node's QEMU machine IDs (such as "pc-q35-11.0").
func windowsRestoreMachine(requested, meta string, machineIDs []string) (string, bool) {
	machineType, options, _ := strings.Cut(requested, ",")
	machineType = strings.TrimPrefix(machineType, "type=")
	family := ""
	switch machineType {
	case "", "pc":
		family = "i440fx"
	case "q35":
		family = "q35"
	default:
		return requested, false
	}

	available := map[string]bool{}
	latest := ""
	for _, id := range machineIDs {
		m := machineIDVersion.FindStringSubmatch(id)
		if m == nil || m[1] != family {
			continue
		}
		available[m[2]] = true
		if latest == "" || versionLess(latest, m[2]) {
			latest = m[2]
		}
	}
	if latest == "" {
		return requested, false
	}

	base := "5.1"
	if m := metaCreationQEMU.FindStringSubmatch(meta); m != nil {
		if created := m[1] + "." + m[2]; !versionLess(created, "9.1") {
			base = created
		}
	}
	if !available[base] {
		base = latest
	}
	if base == latest {
		return requested, false
	}
	pinned := "pc-" + family + "-" + base + "+pve0"
	if options != "" {
		pinned += "," + options
	}
	return pinned, true
}

// scanOrder returns the order in which to scan the restored disks: the boot
// disk last. The scan's reads stay in the host's page cache behind the PBS
// map, and the guest's first reads come from its boot disk, so on a VM whose
// disks together exceed free memory the disk it boots from is the freshest
// in the cache (a boot on cold PBS reads makes Windows services miss
// their start deadline).
func scanOrder(slots []string, bootSlot string) []int {
	order := make([]int, 0, len(slots))
	boot := -1
	for i, slot := range slots {
		if slot == bootSlot && boot < 0 {
			boot = i
			continue
		}
		order = append(order, i)
	}
	if boot >= 0 {
		order = append(order, boot)
	}
	return order
}

// orNone names an absent backup meta line in progress output.
func orNone(meta string) string {
	if meta == "" {
		return "the backup has no meta line"
	}
	return meta
}

// versionLess compares two major.minor versions.
func versionLess(a, b string) bool {
	aMajor, aMinor, _ := strings.Cut(a, ".")
	bMajor, bMinor, _ := strings.Cut(b, ".")
	am, _ := strconv.Atoi(aMajor)
	bm, _ := strconv.Atoi(bMajor)
	if am != bm {
		return am < bm
	}
	an, _ := strconv.Atoi(aMinor)
	bn, _ := strconv.Atoi(bMinor)
	return an < bn
}
