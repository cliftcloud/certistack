// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"reflect"
	"strings"
	"testing"
)

// uefiConfig is a Windows Server 2022 UEFI VM with a TPM as PVE writes it,
// plus a snapshot section that must be ignored.
const uefiConfig = `
bios: ovmf
boot: order=scsi0;net0
cores: 4
efidisk0: iscsi-vm:vm-7301-disk-0,efitype=4m,pre-enrolled-keys=1,size=4M
machine: pc-q35-9.0
memory: 4096
net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=70
ostype: win11
scsi0: iscsi-vm:vm-7301-disk-1,iothread=1,size=40G
scsihw: virtio-scsi-single
tpmstate0: iscsi-vm:vm-7301-disk-2,size=4M,version=v2.0

[before-patching]
efidisk0: iscsi-vm:vm-7301-disk-9,efitype=2m,size=128K
`

func TestParseVMProfileKeepsUEFIFirmwareState(t *testing.T) {
	profile, err := ParseVMProfile([]byte(uefiConfig))
	if err != nil {
		t.Fatal(err)
	}
	want := []FirmwareImage{
		{Slot: "efidisk0", Options: "efitype=4m,pre-enrolled-keys=1"},
		{Slot: "tpmstate0", Options: "version=v2.0"},
	}
	if profile.BIOS != "ovmf" || !reflect.DeepEqual(profile.Firmware, want) {
		t.Fatalf("firmware = %s %+v, want ovmf %+v", profile.BIOS, profile.Firmware, want)
	}
	layout, err := ParseVMLayout([]byte(uefiConfig))
	if err != nil || layout.BIOS != "ovmf" || !reflect.DeepEqual(layout.Firmware, want) {
		t.Fatalf("ParseVMLayout = %+v, %v; want the same firmware as ParseVMProfile", layout, err)
	}
	if !reflect.DeepEqual(layout.Disks, []string{"scsi0"}) || !reflect.DeepEqual(layout.BootOrder, []string{"scsi0", "net0"}) {
		t.Fatalf("layout disks %v, boot order %v", layout.Disks, layout.BootOrder)
	}
	if layout.Machine != "pc-q35-9.0" || layout.SCSIHW != "virtio-scsi-single" || layout.OSType != "win11" {
		t.Fatalf("layout hardware %q %q %q", layout.Machine, layout.SCSIHW, layout.OSType)
	}
	if _, err := ParseVMLayout([]byte("machine: q35;rm -rf\n")); err == nil {
		t.Fatal("an unsafe machine value was accepted")
	}
}

func TestParseVMLayoutIgnoresEverythingElse(t *testing.T) {
	// A NIC model ParseVMProfile refuses must not stop a layout-only read.
	layout, err := ParseVMLayout([]byte("bios: seabios\nnet0: exotic=BC:24:11:AA:BB:CC\nsata1: local:vm-1-disk-3\nbootdisk: sata1\n"))
	if err != nil || layout.BIOS != "seabios" || len(layout.Firmware) != 0 ||
		!reflect.DeepEqual(layout.Disks, []string{"sata1"}) || !reflect.DeepEqual(layout.BootOrder, []string{"sata1"}) {
		t.Fatalf("ParseVMLayout = %+v, %v", layout, err)
	}
}

// Balloon: 0 means the source has no balloon device; any other value,
// or none, leaves PVE's default device in place.
func TestParseBalloonDevicePresence(t *testing.T) {
	for config, want := range map[string]bool{
		"balloon: 0\n":    true,
		"balloon: 1024\n": false,
		"memory: 4096\n":  false,
	} {
		layout, err := ParseVMLayout([]byte(config))
		if err != nil || layout.NoBalloon != want {
			t.Fatalf("layout of %q: NoBalloon = %v, %v; want %v", config, layout.NoBalloon, err, want)
		}
		profile, err := ParseVMProfile([]byte(config))
		if err != nil || profile.NoBalloon != want {
			t.Fatalf("profile of %q: NoBalloon = %v, %v; want %v", config, profile.NoBalloon, err, want)
		}
	}
}

func TestParseAdditionalNICs(t *testing.T) {
	config := "net0: virtio=BC:24:11:00:00:01,bridge=vmbr0\n" +
		"net2: vmxnet3=bc:24:11:00:00:03,bridge=vmbr1,tag=40\n" +
		"net1: e1000-82545em=BC:24:11:00:00:02,bridge=vmbr0,firewall=1\n"
	want := []SourceNIC{
		{Slot: "net1", Model: "e1000-82545em", MAC: "BC:24:11:00:00:02"},
		{Slot: "net2", Model: "vmxnet3", MAC: "BC:24:11:00:00:03"},
	}
	profile, err := ParseVMProfile([]byte(config))
	if err != nil || !reflect.DeepEqual(profile.NICs, want) || profile.NICModel != "virtio" {
		t.Fatalf("profile NICs %+v net0 %q, err %v", profile.NICs, profile.NICModel, err)
	}
	layout, err := ParseVMLayout([]byte(config))
	if err != nil || !reflect.DeepEqual(layout.NICs, want) {
		t.Fatalf("layout NICs %+v, err %v", layout.NICs, err)
	}
	// A layout read never fails over a NIC: an unusable one keeps only its
	// slot, so the run reports it as omitted or refuses to attach it.
	layout, err = ParseVMLayout([]byte("net0: exotic=BC:24:11:00:00:01\nnet1: virtio=not-a-mac,bridge=vmbr0\n"))
	if err != nil || layout.MAC != "" || !reflect.DeepEqual(layout.NICs, []SourceNIC{{Slot: "net1"}}) {
		t.Fatalf("unusable NICs: %+v, %v", layout, err)
	}
	// use_backup_config's profile treats it the same way.
	profile, err = ParseVMProfile([]byte("net0: virtio=BC:24:11:00:00:01\nnet5: virtio=not-a-mac,bridge=vmbr0\n"))
	if err != nil || !reflect.DeepEqual(profile.NICs, []SourceNIC{{Slot: "net5"}}) {
		t.Fatalf("profile with an unusable net5: %+v, %v", profile.NICs, err)
	}
	if _, err := ParseVMProfile([]byte("net0: virtio=not-a-mac\n")); err == nil || !strings.Contains(err.Error(), "net0 MAC") {
		t.Fatalf("a malformed net0 error should name net0: %v", err)
	}
}

func TestParseMachineAndPVEDefaults(t *testing.T) {
	for value, want := range map[string]string{
		"pc-q35-9.0":                        "pc-q35-9.0",
		"q35,viommu=virtio":                 "q35,viommu=virtio",
		"type=q35,viommu=intel,enable-s3=1": "q35,viommu=intel,enable-s3=1",
		"q35,viommu=bogus,future-option=1":  "q35",
	} {
		got, err := parseMachine(value)
		if err != nil || got != want {
			t.Errorf("parseMachine(%q) = %q, %v; want %q", value, got, err, want)
		}
	}
	for _, bad := range []string{"q35;rm", "", "type="} {
		if _, err := parseMachine(bad); err == nil {
			t.Errorf("parseMachine(%q) accepted", bad)
		}
	}
	// No scsihw or ostype line: PVE runs the guest on lsi and "other".
	layout, err := ParseVMLayout([]byte("scsi0: local:vm-1-disk-0\n"))
	if err != nil || layout.SCSIHW != "lsi" || layout.OSType != "other" {
		t.Fatalf("layout defaults %q %q, %v", layout.SCSIHW, layout.OSType, err)
	}
	profile, err := ParseVMProfile([]byte("scsi0: local:vm-1-disk-0\nmachine: q35,viommu=virtio\n"))
	if err != nil || profile.SCSIHW != "lsi" || profile.OSType != "other" || profile.Machine != "q35,viommu=virtio" {
		t.Fatalf("profile %q %q %q, %v", profile.SCSIHW, profile.OSType, profile.Machine, err)
	}
}

func TestParseFirmwareDiskFailsClosed(t *testing.T) {
	for name, line := range map[string]string{
		"efidisk left out of the backup": "efidisk0: local:vm-1-disk-0,efitype=4m,backup=0",
		"unknown efitype":                "efidisk0: local:vm-1-disk-0,efitype=8m",
		"bad pre-enrolled-keys":          "efidisk0: local:vm-1-disk-0,pre-enrolled-keys=yes",
		"bad ms-cert":                    "efidisk0: local:vm-1-disk-0,ms-cert=2023;rm",
		"unknown TPM version":            "tpmstate0: local:vm-1-disk-1,version=v3.0",
	} {
		if _, err := ParseVMProfile([]byte("scsi0: local:vm-1-disk-2\n" + line + "\n")); err == nil {
			t.Errorf("%s: ParseVMProfile accepted it", name)
		}
		if _, err := ParseVMLayout([]byte(line + "\n")); err == nil {
			t.Errorf("%s: ParseVMLayout accepted it", name)
		}
	}
}

func TestParseSnapshotFirmwareJSONFindsFirmwareArchives(t *testing.T) {
	archives, err := ParseSnapshotFirmwareJSON([]byte(`[
  {"filename":"qemu-server.conf.blob"},
  {"filename":"drive-efidisk0.img.fidx"},
  {"filename":"drive-scsi0.img.fidx"},
  {"filename":"drive-tpmstate0-backup.img.fidx"},
  {"filename":"index.json.blob"}
]`))
	want := map[string]string{"efidisk0": "drive-efidisk0", "tpmstate0": "drive-tpmstate0-backup"}
	if err != nil || !reflect.DeepEqual(archives, want) {
		t.Fatalf("archives = %v, %v; want %v", archives, err, want)
	}

	if _, err := ParseSnapshotFirmwareJSON([]byte(`[{"filename":"drive-tpmstate0.img.fidx"},{"filename":"drive-tpmstate0-backup.img.fidx"}]`)); err == nil {
		t.Fatal("two TPM state archives were accepted")
	}

	firmware := []FirmwareImage{{Slot: "efidisk0"}, {Slot: "tpmstate0"}}
	if err := attachFirmwareArchives([]byte(`[{"filename":"drive-efidisk0.img.fidx"}]`), firmware); err == nil || !strings.Contains(err.Error(), "tpmstate0") {
		t.Fatalf("missing TPM archive: err %v, want a refusal naming tpmstate0", err)
	}
}
