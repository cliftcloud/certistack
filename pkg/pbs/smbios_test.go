// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"strings"
	"testing"
)

// A restore keeps the backup's SMBIOS identity (qmrestore regenerates
// the UUID only with --unique); CertiStack gave the sandbox VM a new one.
func TestParseSMBIOS1KeepsTheSourceIdentity(t *testing.T) {
	const uuid = "8b0e2d6a-4f1c-4c3e-9a55-0d2b8c6e7f10"
	for _, tc := range []struct{ in, want string }{
		{"uuid=" + uuid, "uuid=" + uuid},
		{"base64=1,manufacturer=Q2xpZnQgQ2xvdWQ=,product=Q2VydGlTdGFjaw==,uuid=" + uuid + ",serial=QUJDMTIz",
			"uuid=" + uuid + ",base64=1,manufacturer=Q2xpZnQgQ2xvdWQ=,product=Q2VydGlTdGFjaw==,serial=QUJDMTIz"},
		// Fields PVE would refuse, and unknown ones, are dropped; the uuid stays.
		{"uuid=" + uuid + ",serial=a b,sku=x;y,future=1,base64=2", "uuid=" + uuid},
		// Without a valid uuid nothing is carried: PVE generates a new identity.
		{"uuid=not-a-uuid,manufacturer=QQ==", ""},
		{"manufacturer=QQ==", ""},
		{"", ""},
	} {
		if got := parseSMBIOS1(tc.in); got != tc.want {
			t.Fatalf("parseSMBIOS1(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := SMBIOSUUID("uuid=" + uuid + ",base64=1"); got != uuid {
		t.Fatalf("SMBIOSUUID = %q", got)
	}

	config := []byte("smbios1: uuid=" + uuid + ",manufacturer=UVVFTVU=\nvmgenid: 1f0a9c1e-0000-4000-8000-000000000001\n")
	layout, err := ParseVMLayout(config)
	if err != nil || layout.SMBIOS1 != "uuid="+uuid+",manufacturer=UVVFTVU=" {
		t.Fatalf("layout SMBIOS1 = %q, %v", layout.SMBIOS1, err)
	}
	profile, err := ParseVMProfile(config)
	if err != nil || profile.SMBIOS1 != layout.SMBIOS1 {
		t.Fatalf("profile SMBIOS1 = %q, %v", profile.SMBIOS1, err)
	}
}

// PVE starts a Windows guest with an unversioned machine type on the
// machine version of its creation QEMU, read from the meta line, which a
// restore keeps and CreateVM replaces.
func TestParseMetaKeepsTheCreationQEMU(t *testing.T) {
	for in, want := range map[string]string{
		"creation-qemu=9.0.2,ctime=1726000000":        "creation-qemu=9.0.2,ctime=1726000000",
		"ctime=1726000000,creation-qemu=11.0.3":       "creation-qemu=11.0.3,ctime=1726000000",
		"creation-qemu=8.1":                           "creation-qemu=8.1",
		"creation-qemu=9.0.2,ctime=x,extra=1":         "creation-qemu=9.0.2",
		"creation-qemu=9.0.2;rm -rf,ctime=1726000000": "",
		"ctime=1726000000":                            "",
	} {
		if got := parseMeta(in); got != want {
			t.Errorf("parseMeta(%q) = %q, want %q", in, got, want)
		}
	}
	config := []byte("ostype: win10\nmeta: creation-qemu=9.0.2,ctime=1726000000\n")
	layout, err := ParseVMLayout(config)
	if err != nil || layout.Meta != "creation-qemu=9.0.2,ctime=1726000000" {
		t.Fatalf("layout Meta = %q, %v", layout.Meta, err)
	}
	profile, err := ParseVMProfile(config)
	if err != nil || profile.Meta != layout.Meta {
		t.Fatalf("profile Meta = %q, %v", profile.Meta, err)
	}
}

// A restore keeps the source's CD-ROM drives (a cloud-init drive or an ISO),
// so the guest finds the same controllers; the sandbox attaches them empty.
func TestParseCDROMSlots(t *testing.T) {
	config := []byte("scsi0: iscsi-vm:vm-7214-disk-0,size=40G\nsata0: iscsi-vm:vm-7214-cloudinit,media=cdrom\n" +
		"ide2: local:iso/virtio-win.iso,media=cdrom,size=700M\nide0: none,media=cdrom\nvirtio0: x:vm-1-disk-1,media=cdrom\n")
	layout, err := ParseVMLayout(config)
	if err != nil || strings.Join(layout.CDROMs, ",") != "ide0,ide2,sata0" || strings.Join(layout.Disks, ",") != "scsi0" {
		t.Fatalf("layout CDROMs %v disks %v, %v", layout.CDROMs, layout.Disks, err)
	}
	profile, err := ParseVMProfile(config)
	if err != nil || strings.Join(profile.CDROMs, ",") != "ide0,ide2,sata0" {
		t.Fatalf("profile CDROMs %v, %v", profile.CDROMs, err)
	}
}
