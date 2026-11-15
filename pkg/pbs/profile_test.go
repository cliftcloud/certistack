// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"fmt"
	"testing"
)

func TestParseVMProfile_AllowsSafeHardwareAndIgnoresCloudInit(t *testing.T) {
	profile, err := ParseVMProfile([]byte(`
cores: 4
sockets: 2
memory: 8192
balloon: 4096
cpuunits: 200
machine: pc-q35-8.1
ostype: l26
bios: seabios
scsihw: virtio-scsi-single
tags: production;postgres
scsi0: ceph-vm-ssd:vm-7031-disk-0,size=32G
scsi1: ceph-vm-ssd:vm-7031-disk-1,size=16G
sata0: local-lvm:cloudinit,media=cdrom
net0: e1000=00:11:22:33:44:55,bridge=vmbr0
hookscript: local:snippets/hook.pl
`))
	if err != nil {
		t.Fatal(err)
	}
	if profile.Cores != 4 || profile.Sockets != 2 || profile.MemoryMB != 8192 || profile.BalloonMB != 4096 || profile.CPUWeight != 200 {
		t.Fatalf("unexpected profile: %+v", profile)
	}
	if !profile.configuredDisks["scsi0"] || !profile.configuredDisks["scsi1"] || profile.configuredDisks["sata0"] {
		t.Fatalf("source disk layout was not parsed (the cloud-init CD-ROM is not a disk): %+v", profile.configuredDisks)
	}
	if len(profile.SourceTags) != 2 || profile.SourceTags[0] != "production" {
		t.Fatalf("source tags = %v", profile.SourceTags)
	}
	if profile.MAC != "00:11:22:33:44:55" {
		t.Fatalf("source MAC = %q", profile.MAC)
	}
	if profile.NICModel != "e1000" {
		t.Fatalf("source NIC model = %q", profile.NICModel)
	}
}

// A backup's cpuunits is held to PVE's own range, 1 through 262144; a value
// above it is not something a PVE API could have accepted (audit F116).
func TestParseVMProfileCPUUnitsRange(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
	}{{"0", false}, {"1", true}, {"262144", true}, {"262145", false}, {"500000", false}} {
		profile, err := ParseVMProfile([]byte("cpuunits: " + tc.value + "\n"))
		if (err == nil) != tc.ok {
			t.Errorf("cpuunits %s: error = %v, want accepted=%v", tc.value, err, tc.ok)
		}
		if err == nil && fmt.Sprint(profile.CPUWeight) != tc.value {
			t.Errorf("cpuunits %s parsed as %d", tc.value, profile.CPUWeight)
		}
	}
}

// A backup's memory is held to the shared minimum, PVE's own 16 MiB, not a
// private 32 (audit F118).
func TestParseVMProfileMemoryMinimum(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
	}{{"15", false}, {"16", true}, {"31", true}, {"32", true}, {"4194304", true}, {"4194305", false}} {
		profile, err := ParseVMProfile([]byte("memory: " + tc.value + "\n"))
		if (err == nil) != tc.ok {
			t.Errorf("memory %s: error = %v, want accepted=%v", tc.value, err, tc.ok)
		}
		if err == nil && fmt.Sprint(profile.MemoryMB) != tc.value {
			t.Errorf("memory %s parsed as %d", tc.value, profile.MemoryMB)
		}
	}
}

func TestParseVMProfileRejectsInvalidPrimaryNICMAC(t *testing.T) {
	_, err := ParseVMProfile([]byte("net0: virtio=not-a-mac,bridge=vmbr0\n"))
	if err == nil {
		t.Fatal("expected invalid source MAC to be rejected")
	}
}

func TestParseVMProfileRejectsUnsupportedPrimaryNICModel(t *testing.T) {
	_, err := ParseVMProfile([]byte("net0: unsupported=00:11:22:33:44:55,bridge=vmbr0\n"))
	if err == nil {
		t.Fatal("expected unsupported source NIC model to be rejected")
	}
}

func TestParseVMProfile_RecordsDisksOnEveryBus(t *testing.T) {
	profile, err := ParseVMProfile([]byte("boot: order=virtio0;net0\nvirtio0: ceph:vm-1-disk-0\nsata1: ceph:vm-1-disk-1\nide0: ceph:vm-1-disk-2\nscsi3: ceph:vm-1-disk-3,backup=0\nide2: none,media=cdrom\n"))
	if err != nil {
		t.Fatal(err)
	}
	for slot, want := range map[string]bool{"virtio0": true, "sata1": true, "ide0": true, "scsi3": false, "ide2": false} {
		if profile.configuredDisks[slot] != want {
			t.Errorf("%s backed up = %v, want %v", slot, profile.configuredDisks[slot], want)
		}
	}
	if len(profile.BootOrder) != 2 || profile.BootOrder[0] != "virtio0" {
		t.Fatalf("boot order = %v", profile.BootOrder)
	}
}

// A boot property that carries both settings keeps the source's explicit order
// through the profile and the layout reader (audit F117).
func TestSourceBootOrderSurvivesACompoundBootProperty(t *testing.T) {
	for _, boot := range []string{"legacy=cdn,order=scsi0;scsi1;net0", "order=scsi0;scsi1;net0,legacy=cdn"} {
		config := []byte("boot: " + boot + "\nbootdisk: scsi1\nscsi0: ceph:vm-1-disk-0\nscsi1: ceph:vm-1-disk-1\n")
		want := []string{"scsi0", "scsi1", "net0"}
		profile, err := ParseVMProfile(config)
		if err != nil {
			t.Fatal(err)
		}
		layout, err := ParseVMLayout(config)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(profile.BootOrder) != fmt.Sprint(want) || fmt.Sprint(layout.BootOrder) != fmt.Sprint(want) {
			t.Errorf("boot: %s: profile order %v, layout order %v, want %v", boot, profile.BootOrder, layout.BootOrder, want)
		}
	}
}

func TestParseSnapshotDrivesJSON_SortsAndNormalizesArchives(t *testing.T) {
	drives, err := ParseSnapshotDrivesJSON([]byte(`[
  {"filename":"qemu-server.conf.blob"},
  {"filename":"drive-scsi1.img.fidx"},
  {"filename":"drive-scsi0.img.fidx"},
  {"filename":"drive-scsi1.img.fidx"}
]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(drives) != 2 || drives[0] != (SourceDrive{Slot: "scsi0", Archive: "drive-scsi0"}) || drives[1] != (SourceDrive{Slot: "scsi1", Archive: "drive-scsi1"}) {
		t.Fatalf("unexpected drives: %+v", drives)
	}
}

func TestParseSnapshotDrivesJSON_FindsDisksOnEveryBus(t *testing.T) {
	drives, err := ParseSnapshotDrivesJSON([]byte(`[
  {"filename":"drive-virtio0.img.fidx"},
  {"filename":"drive-sata1.img.fidx"},
  {"filename":"drive-efidisk0.img.fidx"},
  {"filename":"drive-tpmstate0-backup.img.fidx"},
  {"filename":"drive-ide0.img.fidx"}
]`))
	want := []SourceDrive{{Slot: "ide0", Archive: "drive-ide0"}, {Slot: "virtio0", Archive: "drive-virtio0"}, {Slot: "sata1", Archive: "drive-sata1"}}
	if err != nil || len(drives) != 3 || drives[0] != want[0] || drives[1] != want[1] || drives[2] != want[2] {
		t.Fatalf("drives = %+v, %v; want %+v (firmware archives are not disks)", drives, err, want)
	}
	if _, err := ParseSnapshotDrivesJSON([]byte(`[{"filename":"drive-efidisk0.img.fidx"}]`)); err == nil {
		t.Fatal("a snapshot without any disk archive was accepted")
	}
}

// The plan command sizes each disk from its backed-up configuration.
func TestParseVMLayoutReadsDiskSizes(t *testing.T) {
	layout, err := ParseVMLayout([]byte("scsi0: local-lvm:vm-7214-disk-0,discard=on,size=40G\nscsi1: local-lvm:vm-7214-disk-1,size=8192M\nsata0: local:iso/x.iso,media=cdrom,size=5G\nscsi2: local-lvm:vm-7214-disk-2,backup=0,size=1T\nvirtio0: local:1/d.raw\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"scsi0": 40 << 30, "scsi1": 8 << 30}
	if len(layout.DiskBytes) != len(want) {
		t.Fatalf("DiskBytes = %v, want %v", layout.DiskBytes, want)
	}
	for slot, n := range want {
		if layout.DiskBytes[slot] != n {
			t.Errorf("%s: %d bytes, want %d", slot, layout.DiskBytes[slot], n)
		}
	}
	for value, n := range map[string]int64{"size=512K": 512 << 10, "size=1.5T": 3 << 39, "size=4096": 4096} {
		if got, ok := diskSizeBytes("x," + value); !ok || got != n {
			t.Errorf("%s: %d, %v; want %d", value, got, ok, n)
		}
	}
	if _, ok := diskSizeBytes("x,size=big"); ok {
		t.Error("size=big parsed")
	}
}

// A plan that inherits the backup's configuration (use_backup_config) sizes
// its disks from it too.
func TestParseVMProfileReadsDiskSizes(t *testing.T) {
	profile, err := ParseVMProfile([]byte("cores: 2\nmemory: 2048\nscsi0: local-lvm:vm-7011-disk-0,size=32G\nscsi1: local-lvm:vm-7011-disk-1,backup=0,size=8G\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.DiskBytes) != 1 || profile.DiskBytes["scsi0"] != 32<<30 {
		t.Fatalf("DiskBytes = %v, want scsi0 32 GiB only", profile.DiskBytes)
	}
}

// NaN, infinity, exponents and sizes past int64 became successful
// negative sizes. A size that is not in PVE's form, or beyond any real
// disk, is unknown: absent from DiskBytes, never a number.
func TestImpossibleDiskSizesAreUnknown(t *testing.T) {
	for _, size := range []string{"NaN", "+Inf", "Inf", "1e30", "9000000T", "-1G", "0x10", "1e3G", "2048T", " 4G", "4G4"} {
		value := "local:vm-7011-disk-0,size=" + size
		if n, ok := diskSizeBytes(value); ok {
			t.Errorf("size=%s: %d bytes, want unknown", size, n)
		}
		layout, layoutErr := ParseVMLayout([]byte("scsi0: " + value + "\n"))
		profile, profileErr := ParseVMProfile([]byte("scsi0: " + value + "\n"))
		if layoutErr != nil || profileErr != nil {
			t.Fatalf("size=%s: %v / %v", size, layoutErr, profileErr)
		}
		if _, ok := layout.DiskBytes["scsi0"]; ok {
			t.Errorf("size=%s: layout recorded %d bytes", size, layout.DiskBytes["scsi0"])
		}
		if _, ok := profile.DiskBytes["scsi0"]; ok {
			t.Errorf("size=%s: profile recorded %d bytes", size, profile.DiskBytes["scsi0"])
		}
	}
	// The largest accepted size still fits many disks in an int64 sum.
	if n, ok := diskSizeBytes("x,size=1024T"); !ok || n != maxSourceDiskBytes {
		t.Errorf("size=1024T: %d, %v; want 1 PiB", n, ok)
	}
}
