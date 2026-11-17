// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package diskslot

import (
	"reflect"
	"testing"
)

func TestValid(t *testing.T) {
	for slot, want := range map[string]bool{
		"scsi0": true, "scsi30": true, "scsi31": false,
		"virtio0": true, "virtio15": true, "virtio16": false,
		"sata0": true, "sata5": true, "sata6": false,
		"ide0": true, "ide3": true, "ide4": false,
		"scsi01": false, "efidisk0": false, "tpmstate0": false, "net0": false,
		"unused0": false, "SCSI0": false, "scsi": false, "": false,
	} {
		if got := Valid(slot); got != want {
			t.Errorf("Valid(%q) = %v, want %v", slot, got, want)
		}
	}
}

func TestOrderingFollowsPVE(t *testing.T) {
	slots := []string{"virtio0", "scsi10", "scsi2", "sata1", "ide0", "scsi0"}
	Sort(slots)
	if want := []string{"ide0", "scsi0", "scsi2", "scsi10", "virtio0", "sata1"}; !reflect.DeepEqual(slots, want) {
		t.Fatalf("Sort = %v, want %v", slots, want)
	}
	if got := First([]string{"virtio0", "scsi1", "scsi0"}); got != "scsi0" {
		t.Fatalf("First = %q, want scsi0", got)
	}
}

func TestBootDisk(t *testing.T) {
	for name, tc := range map[string]struct {
		order, restored []string
		want            string
	}{
		"explicit order wins":           {[]string{"virtio0", "scsi0"}, []string{"scsi0", "virtio0"}, "virtio0"},
		"network and cdrom are skipped": {[]string{"net0", "ide2", "sata0"}, []string{"sata0", "scsi0"}, "sata0"},
		"order names no restored disk":  {[]string{"net0"}, []string{"virtio1", "virtio0"}, "virtio0"},
		"no order: PVE first disk":      {nil, []string{"scsi0", "ide0"}, "ide0"},
		"scsi before a sata data disk":  {nil, []string{"sata0", "scsi0"}, "scsi0"},
		"virtio before sata":            {nil, []string{"sata0", "virtio1"}, "virtio1"},
		"scsi-only VM keeps scsi0":      {nil, []string{"scsi1", "scsi0"}, "scsi0"},
		"nothing restored":              {[]string{"scsi0"}, nil, ""},
	} {
		if got := BootDisk(tc.order, tc.restored); got != tc.want {
			t.Errorf("%s: BootDisk = %q, want %q", name, got, tc.want)
		}
	}
}

// The restored VM boots the source's order restricted to the disks it restored.
// A source with /boot on a second disk boots "order=scsi0;scsi1"; a restored VM
// with only the first disk in its order would never find /boot.
func TestRestoredBootOrder(t *testing.T) {
	for name, tc := range map[string]struct {
		order, restored []string
		want            []string
	}{
		"one disk":                              {[]string{"scsi0", "net0"}, []string{"scsi0"}, []string{"scsi0"}},
		"two disks keep their order":            {[]string{"scsi0", "scsi1"}, []string{"scsi0", "scsi1"}, []string{"scsi0", "scsi1"}},
		"second disk first":                     {[]string{"scsi1", "scsi0"}, []string{"scsi0", "scsi1"}, []string{"scsi1", "scsi0"}},
		"order is the source's, not the slots'": {[]string{"virtio0", "scsi0", "sata1"}, []string{"sata1", "scsi0", "virtio0"}, []string{"virtio0", "scsi0", "sata1"}},
		"cdrom and network are dropped":         {[]string{"scsi0", "ide2", "net0"}, []string{"scsi0"}, []string{"scsi0"}},
		"network first is dropped":              {[]string{"net0", "scsi0", "scsi1"}, []string{"scsi0", "scsi1"}, []string{"scsi0", "scsi1"}},
		"omitted disk is dropped":               {[]string{"scsi0", "scsi1", "scsi2"}, []string{"scsi0", "scsi2"}, []string{"scsi0", "scsi2"}},
		"omitted first disk":                    {[]string{"scsi1", "scsi0"}, []string{"scsi0"}, []string{"scsi0"}},
		"restored but not in the order":         {[]string{"scsi0"}, []string{"scsi0", "scsi1"}, []string{"scsi0"}},
		"duplicates collapse":                   {[]string{"scsi0", "scsi0", "scsi1"}, []string{"scsi0", "scsi1"}, []string{"scsi0", "scsi1"}},
		"firmware slots never boot":             {[]string{"efidisk0", "scsi0"}, []string{"efidisk0", "scsi0"}, []string{"scsi0"}},
		"order names no restored disk":          {[]string{"net0", "ide2"}, []string{"scsi0"}, nil},
		"no order":                              {nil, []string{"scsi0"}, nil},
		"nothing restored":                      {[]string{"scsi0"}, nil, nil},
	} {
		if got := RestoredBootOrder(tc.order, tc.restored); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: RestoredBootOrder = %v, want %v", name, got, tc.want)
		}
	}
	// The legacy form (bootdisk: with no boot: line) names one disk.
	if got := RestoredBootOrder(ParseBootOrder("", "scsi0"), []string{"scsi0", "scsi1"}); !reflect.DeepEqual(got, []string{"scsi0"}) {
		t.Errorf("legacy bootdisk: RestoredBootOrder = %v, want [scsi0]", got)
	}
	// Its first entry is the boot disk BootDisk picks, so the two never disagree.
	order, restored := []string{"scsi1", "ide2", "scsi0"}, []string{"scsi0", "scsi1"}
	if got := RestoredBootOrder(order, restored); len(got) == 0 || got[0] != BootDisk(order, restored) {
		t.Errorf("RestoredBootOrder %v does not lead with BootDisk %q", got, BootDisk(order, restored))
	}
}

func TestParseBootOrder(t *testing.T) {
	for name, tc := range map[string]struct {
		boot, bootdisk string
		want           []string
	}{
		"current":             {"order=scsi0;ide2;net0", "", []string{"scsi0", "ide2", "net0"}},
		"legacy with disk":    {"cdn", "virtio0", []string{"virtio0"}},
		"legacy without disk": {"dn", "virtio0", nil},
		"only bootdisk":       {"", "sata0", []string{"sata0"}},
		"nothing":             {"", "", nil},
	} {
		if got := ParseBootOrder(tc.boot, tc.bootdisk); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// PVE's boot property is "[[legacy=]<[acdn]{1,4}>] [,order=<device[;device...]>]":
// comma-separated properties, in either order, and an explicit order wins over
// the legacy letters.
func TestParseBootOrderCompoundProperty(t *testing.T) {
	for name, tc := range map[string]struct {
		boot, bootdisk string
		want           []string
	}{
		"legacy first then order":           {"legacy=cdn,order=scsi0;net0", "virtio0", []string{"scsi0", "net0"}},
		"order only":                        {"order=scsi0", "virtio0", []string{"scsi0"}},
		"order first then legacy":           {"order=scsi0,legacy=c", "virtio0", []string{"scsi0"}},
		"order with several then legacy":    {"order=scsi0;ide2,legacy=cdn", "", []string{"scsi0", "ide2"}},
		"bare letters then order":           {"cdn,order=scsi1;scsi0", "scsi0", []string{"scsi1", "scsi0"}},
		"order then bare letters":           {"order=scsi1;scsi0,cdn", "scsi0", []string{"scsi1", "scsi0"}},
		"bare letters":                      {"cdn", "virtio0", []string{"virtio0"}},
		"legacy key":                        {"legacy=cdn", "virtio0", []string{"virtio0"}},
		"legacy without c":                  {"legacy=dn", "virtio0", nil},
		"legacy without c and an order":     {"legacy=dn,order=scsi0", "virtio0", []string{"scsi0"}},
		"spaces around the properties":      {" legacy=cdn , order=scsi0;net0 ", "virtio0", []string{"scsi0", "net0"}},
		"an unknown property":               {"order=scsi0,color=red", "virtio0", nil},
		"an unknown property before":        {"color=red,order=scsi0", "virtio0", nil},
		"the order given twice":             {"order=scsi0,order=scsi1", "virtio0", nil},
		"the legacy letters given twice":    {"cdn,legacy=c", "virtio0", nil},
		"letters that are not boot devices": {"xyz", "virtio0", nil},
		"too many letters":                  {"cdnac", "virtio0", nil},
		"an empty property":                 {"order=scsi0,", "virtio0", nil},
	} {
		if got := ParseBootOrder(tc.boot, tc.bootdisk); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: ParseBootOrder(%q, %q) = %v, want %v", name, tc.boot, tc.bootdisk, got, tc.want)
		}
	}
}

func TestArchiveSlot(t *testing.T) {
	for archive, want := range map[string]string{
		"drive-scsi0":             "scsi0",
		"drive-virtio1.img":       "virtio1",
		"drive-sata2.img.fidx":    "sata2",
		"drive-ide0.img.fidx":     "ide0",
		"drive-efidisk0.img.fidx": "",
		"drive-scsi31.img.fidx":   "",
		"qemu-server.conf.blob":   "",
	} {
		got, ok := ArchiveSlot(archive)
		if got != want || ok != (want != "") {
			t.Errorf("ArchiveSlot(%q) = %q, %v; want %q", archive, got, ok, want)
		}
	}
}
