// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"context"
	"testing"
)

// The length a mapped image must have is the one the snapshot's
// manifest lists for its archive. `snapshot files` gives it for every archive,
// encrypted or signed or not, and the fixed-index image archive's size is the
// image that was backed up.
func TestParseSnapshotImageBytesReadsTheManifestsImageSizes(t *testing.T) {
	for name, tc := range map[string]struct {
		files string
		want  map[string]int64
	}{
		"an encrypted snapshot": {encryptedFiles, map[string]int64{"scsi0": 34359738368}},
		"a signed snapshot": {
			`[{"filename":"index.json.blob","crypt-mode":"sign-only","size":652},{"filename":"drive-scsi0.img.fidx","crypt-mode":"sign-only","size":37748736},{"filename":"drive-virtio1.img.fidx","crypt-mode":"sign-only","size":1073741824}]`,
			map[string]int64{"scsi0": 37748736, "virtio1": 1 << 30},
		},
		"an unprotected snapshot": {
			`[{"filename":"drive-sata0.img.fidx","crypt-mode":"none","size":536870912}]`,
			map[string]int64{"sata0": 512 << 20},
		},
		// Firmware state is restored whole, not mapped: no disk slot, no entry.
		"firmware archives are not disks": {
			`[{"filename":"drive-efidisk0.img.fidx","size":540672},{"filename":"drive-tpmstate0-backup.img.fidx","size":4194304},{"filename":"drive-scsi0.img.fidx","size":1048576}]`,
			map[string]int64{"scsi0": 1 << 20},
		},
		"an archive without a size": {`[{"filename":"drive-scsi0.img.fidx"},{"filename":"drive-scsi1.img.fidx","size":1048576}]`, map[string]int64{"scsi1": 1 << 20}},
		"a size that is not a size": {
			`[{"filename":"drive-scsi0.img.fidx","size":0},{"filename":"drive-scsi1.img.fidx","size":-5},{"filename":"drive-scsi2.img.fidx","size":"big"},{"filename":"drive-scsi3.img.fidx","size":1.5e300},{"filename":"drive-scsi4.img.fidx","size":4611686018427387904}]`,
			nil,
		},
		"one entry's size is not a number": {`[{"filename":"drive-scsi0.img.fidx","size":"big"},{"filename":"drive-scsi1.img.fidx","size":1048576}]`, map[string]int64{"scsi1": 1 << 20}},
		"two different sizes for one slot": {`[{"filename":"drive-scsi0.img.fidx","size":1048576},{"filename":"drive-scsi0.img","size":2097152}]`, nil},
		"the same size twice":              {`[{"filename":"drive-scsi0.img.fidx","size":1048576},{"filename":"drive-scsi0.img","size":1048576}]`, map[string]int64{"scsi0": 1 << 20}},
		"not a list":                       {`{"filename":"drive-scsi0.img.fidx","size":1048576}`, nil},
		"not JSON":                         {`not json`, nil},
		"empty":                            {``, nil},
	} {
		got := ParseSnapshotImageBytes([]byte(tc.files))
		if len(got) != len(tc.want) {
			t.Errorf("%s: sizes = %v, want %v", name, got, tc.want)
			continue
		}
		for slot, n := range tc.want {
			if got[slot] != n {
				t.Errorf("%s: %s = %d, want %d", name, slot, got[slot], n)
			}
		}
	}
}

// The layout carries both sizes, so a disk whose configuration drifted (here
// size=33M for a 36 MiB volume) is checked against its image, not its config.
func TestLoadVMLayoutCarriesTheManifestsImageSizeBesideTheConfigurations(t *testing.T) {
	files := `[{"filename":"index.json.blob","crypt-mode":"none","size":652},
  {"filename":"qemu-server.conf.blob","crypt-mode":"none","size":480},
  {"filename":"drive-scsi0.img.fidx","crypt-mode":"none","size":37748736}]`
	fakeBackupClient(t, files, "boot: order=scsi0\nscsi0: local-lvm:vm-100-disk-0,iothread=1,size=33M\n")
	layout, err := (&Client{}).LoadVMLayout(context.Background(), "vm/100/2026-09-27T03:00:00Z", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if layout.DiskBytes["scsi0"] != 33<<20 || layout.ImageBytes["scsi0"] != 36<<20 {
		t.Fatalf("layout sizes: configuration %v, manifest %v; want 33 MiB and 36 MiB", layout.DiskBytes, layout.ImageBytes)
	}
	profile, err := (&Client{}).LoadVMProfile(context.Background(), "vm/100/2026-09-27T03:00:00Z", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if profile.DiskBytes["scsi0"] != 33<<20 || profile.ImageBytes["scsi0"] != 36<<20 {
		t.Fatalf("profile sizes: configuration %v, manifest %v", profile.DiskBytes, profile.ImageBytes)
	}
}
