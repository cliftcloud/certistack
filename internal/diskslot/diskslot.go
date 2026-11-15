// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package diskslot knows Proxmox VE's disk slots: which exist on each bus,
// how PVE picks a VM's first disk, and how PBS names a slot's archive.
package diskslot

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// buses lists the disk buses in the order PVE resolves a VM's first disk
// (qemu-server Drive.pm: valid_drive_names, used by resolve_first_disk):
// ide, scsi, virtio, sata. Each has its highest slot index.
var buses = []struct {
	name     string
	maxIndex int
}{
	{"ide", 3},
	{"scsi", 30},
	{"virtio", 15},
	{"sata", 5},
}

var slotExpr = regexp.MustCompile(`^(ide|sata|scsi|virtio)([0-9]{1,2})$`)

// archiveExpr matches a PBS disk archive name, with or without its .img and
// .fidx suffixes.
var archiveExpr = regexp.MustCompile(`^drive-((?:ide|sata|scsi|virtio)[0-9]{1,2})(?:\.img(?:\.fidx)?)?$`)

// Parse splits a slot into its bus and index. ok is false for anything
// that is not a PVE disk slot, including a leading zero ("scsi01").
func Parse(slot string) (bus string, index int, ok bool) {
	m := slotExpr.FindStringSubmatch(slot)
	if m == nil || (len(m[2]) > 1 && m[2][0] == '0') {
		return "", 0, false
	}
	index, _ = strconv.Atoi(m[2])
	for _, b := range buses {
		if b.name == m[1] {
			return b.name, index, index <= b.maxIndex
		}
	}
	return "", 0, false
}

// Valid reports whether slot is a PVE disk slot: ide0-3, sata0-5,
// scsi0-30 or virtio0-15.
func Valid(slot string) bool {
	_, _, ok := Parse(slot)
	return ok
}

// Describe is the human description of the valid slots, for errors.
const Describe = "ide0-ide3, sata0-sata5, scsi0-scsi30 or virtio0-virtio15"

func rank(slot string) (int, int) {
	bus, index, _ := Parse(slot)
	for i, b := range buses {
		if b.name == bus {
			return i, index
		}
	}
	return len(buses), index
}

// Less orders slots the way PVE resolves a first disk: by bus (ide, scsi,
// virtio, sata), then by index.
func Less(a, b string) bool {
	busA, indexA := rank(a)
	busB, indexB := rank(b)
	if busA != busB {
		return busA < busB
	}
	return indexA < indexB
}

// Sort orders slots with Less.
func Sort(slots []string) {
	sort.Slice(slots, func(i, j int) bool { return Less(slots[i], slots[j]) })
}

// First returns the disk PVE would boot without an explicit boot order:
// the first slot by Less. It returns "" for no valid slot.
func First(slots []string) string {
	first := ""
	for _, slot := range slots {
		if Valid(slot) && (first == "" || Less(slot, first)) {
			first = slot
		}
	}
	return first
}

// BootDisk picks the disk a restored VM boots from: the first entry of the
// source's boot order that is one of the restored slots, else First.
// Non-disk boot entries (net0, a CD-ROM) are skipped.
func BootDisk(bootOrder, restored []string) string {
	have := make(map[string]bool, len(restored))
	for _, slot := range restored {
		have[slot] = true
	}
	for _, entry := range bootOrder {
		if have[entry] && Valid(entry) {
			return entry
		}
	}
	return First(restored)
}

// RestoredBootOrder is the boot order of a restored VM: the source's boot
// order restricted to the disks that are restored, in the source's order. It
// drops every entry that is not a restored disk (a CD-ROM, net0, a disk the
// plan leaves out, a repeat), so a restored VM never tries to boot from the
// network or from a disk it does not have. SeaBIOS shows the guest only the
// disks in the boot order, so a guest that boots from one disk and reads /boot
// from another (the source's "order=scsi0;scsi1") needs both. It is nil when
// the order names none of the restored disks; the caller then boots BootDisk
// alone. When it is not nil its first entry is the disk BootDisk picks.
func RestoredBootOrder(bootOrder, restored []string) []string {
	have := make(map[string]bool, len(restored))
	for _, slot := range restored {
		have[slot] = true
	}
	var order []string
	seen := make(map[string]bool, len(bootOrder))
	for _, entry := range bootOrder {
		if have[entry] && Valid(entry) && !seen[entry] {
			seen[entry] = true
			order = append(order, entry)
		}
	}
	return order
}

// ParseBootOrder reads a qemu-server.conf boot setting. PVE's boot property is
// "[[legacy=]<[acdn]{1,4}>] [,order=<device[;device...]>]": comma-separated
// properties in either order. An explicit "order=scsi0;ide2;net0" wins over
// the legacy letters; the legacy form ("cdn", or "legacy=cdn", plus a separate
// bootdisk key) boots bootdisk when "c" is in the letters, and PVE's default
// "boot:" is the legacy "cdn". A property it does not recognize (an unknown
// key, a repeated property, letters outside [acdn]) leaves the order unknown:
// it returns nil rather than guess.
func ParseBootOrder(boot, bootdisk string) []string {
	boot = strings.TrimSpace(boot)
	var order []string
	haveOrder, haveLegacy, legacyBoots := false, false, false
	if boot != "" {
		for _, property := range strings.Split(boot, ",") {
			property = strings.TrimSpace(property)
			if value, found := strings.CutPrefix(property, "order="); found {
				if haveOrder {
					return nil
				}
				haveOrder = true
				for _, entry := range strings.Split(value, ";") {
					if entry = strings.TrimSpace(entry); entry != "" {
						order = append(order, entry)
					}
				}
				continue
			}
			letters := strings.TrimPrefix(property, "legacy=")
			if haveLegacy || !legacyBootLetters(letters) {
				return nil
			}
			haveLegacy = true
			legacyBoots = strings.Contains(letters, "c")
		}
	}
	if haveOrder {
		return order
	}
	if bootdisk = strings.TrimSpace(bootdisk); bootdisk != "" && (boot == "" || legacyBoots) {
		return []string{bootdisk}
	}
	return nil
}

// legacyBootLetters reports whether s is one to four of PVE's legacy boot
// device letters (a floppy, c disk, d CD-ROM, n network).
func legacyBootLetters(s string) bool {
	if len(s) < 1 || len(s) > 4 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("acdn", r) {
			return false
		}
	}
	return true
}

// ArchiveSlot returns the slot a PBS disk archive belongs to, for example
// "virtio1" for "drive-virtio1.img.fidx".
func ArchiveSlot(archive string) (string, bool) {
	m := archiveExpr.FindStringSubmatch(archive)
	if m == nil || !Valid(m[1]) {
		return "", false
	}
	return m[1], true
}
