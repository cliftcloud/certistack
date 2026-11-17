// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"testing"
)

func TestParseVMBackupsJSON(t *testing.T) {
	data := []byte(`[
	  {"backup-type":"vm","backup-id":"101","backup-time":1790000000,"files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}],"comment":"db01\nsecond line"},
	  {"backup-type":"vm","backup-id":"101","backup-time":1790086400,"files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}],"comment":"db01-new"},
	  {"backup-type":"vm","backup-id":"101","backup-time":1790172800,"files":[{"filename":"drive-scsi0.img.fidx"}]},
	  {"backup-type":"vm","backup-id":"100","backup-time":"1790000000","files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}],"comment":"web\u0007 01"},
	  {"backup-type":"vm","backup-id":"102","backup-time":1790000000,"files":[{"filename":"drive-scsi0.img.fidx"}]},
	  {"backup-type":"ct","backup-id":"200","backup-time":1790000000,"files":[{"filename":"index.json.blob"}]},
	  {"backup-type":"vm","backup-id":"not-a-number","backup-time":1790000000},
	  {"backup-type":"vm","backup-id":"103","backup-time":1790000000}
	]`)
	backups, err := ParseVMBackupsJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 3 {
		t.Fatalf("got %d VMs (%+v), want 100, 101 and 103: containers, incomplete-only VMs and bad IDs are left out", len(backups), backups)
	}
	if b := backups[0]; b.VMID != 100 || b.Count != 1 || b.Comment != "web 01" || b.Latest != "vm/100/2026-09-21T14:13:20Z" {
		t.Errorf("vm 100 = %+v", b)
	}
	// The newest complete snapshot, not the newer aborted one.
	if b := backups[1]; b.VMID != 101 || b.Count != 2 || b.Comment != "db01-new" || b.Latest != "vm/101/2026-09-22T14:13:20Z" {
		t.Errorf("vm 101 = %+v", b)
	}
	// No file list: complete, as LatestSnapshot treats it.
	if b := backups[2]; b.VMID != 103 || b.Count != 1 {
		t.Errorf("vm 103 = %+v", b)
	}
	if _, err := ParseVMBackupsJSON([]byte(`{`)); err == nil {
		t.Error("malformed JSON was accepted")
	}
}

// The list says how big a VM's disks are, from the newest complete snapshot's
// image archives: what the operator needs to pick a small VM for a first run.
func TestParseVMBackupsJSONSumsTheNewestSnapshotsImages(t *testing.T) {
	data := []byte(`[
	  {"backup-type":"vm","backup-id":"100","backup-time":1790000000,"files":[{"filename":"index.json.blob","size":500},{"filename":"qemu-server.conf.blob","size":300},{"filename":"drive-scsi0.img.fidx","size":99999999999}]},
	  {"backup-type":"vm","backup-id":"100","backup-time":1790086400,"files":[{"filename":"index.json.blob","size":500},{"filename":"drive-scsi0.img.fidx","size":34359738368},{"filename":"drive-efidisk0.img.fidx","size":134217728},{"filename":"qemu-server.conf.blob","size":300}]},
	  {"backup-type":"vm","backup-id":"101","backup-time":1790000000,"files":[{"filename":"drive-scsi0.img.fidx"},{"filename":"index.json.blob"}]},
	  {"backup-type":"vm","backup-id":"102","backup-time":1790000000}
	]`)
	backups, err := ParseVMBackupsJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := backups[0].DiskBytes, int64(34359738368+134217728); got != want {
		t.Errorf("vm 100 DiskBytes = %d, want %d (the newest snapshot's images, not the older one's)", got, want)
	}
	if backups[1].DiskBytes != 0 || backups[2].DiskBytes != 0 {
		t.Errorf("a snapshot with no sizes listed: DiskBytes = %d and %d, want 0", backups[1].DiskBytes, backups[2].DiskBytes)
	}
}

func TestParseVMProfileReadsNameAndAgent(t *testing.T) {
	for _, tc := range []struct {
		config string
		name   string
		agent  bool
	}{
		{"name: web-01\nagent: 1\n", "web-01", true},
		{"name: db.example.com\nagent: enabled=1,fstrim_cloned_disks=1\n", "db.example.com", true},
		{"agent: 0\n", "", false},
		{"agent: enabled=0,type=virtio\n", "", false},
		{"name: -bad-\n", "", false},
		{"name: a b\n", "", false},
		{"", "", false},
	} {
		profile, err := ParseVMProfile([]byte(tc.config))
		if err != nil {
			t.Fatalf("%q: %v", tc.config, err)
		}
		if profile.Name != tc.name || profile.Agent != tc.agent {
			t.Errorf("%q: name %q agent %v, want %q %v", tc.config, profile.Name, profile.Agent, tc.name, tc.agent)
		}
	}
}
