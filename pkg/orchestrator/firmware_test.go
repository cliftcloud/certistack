// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// firmwareFixture is an orchestrator whose overlay storage is a temp
// directory and whose PBS restore writes the given images.
func firmwareFixture(t *testing.T, images map[string][]byte) (*Orchestrator, config.VM, *[]string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("overlay volume paths are Linux node paths")
	}
	storageRoot := t.TempDir()
	orch := New(&config.Plan{}, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir(), OverlayStorage: "certistack-scratch"}, nil, nil)
	orch.overlayVolumePathFn = func(_ context.Context, volume string) (string, error) {
		vmid, name, _ := strings.Cut(strings.TrimPrefix(volume, "certistack-scratch:"), "/")
		return filepath.Join(storageRoot, "images", vmid, name), nil
	}
	var restored []string
	orch.restoreImageFn = func(_ context.Context, snapshot, archive, target string) error {
		restored = append(restored, snapshot+" "+archive)
		data, ok := images[archive]
		if !ok {
			return errors.New("archive not in snapshot")
		}
		return os.WriteFile(target, data, 0o644)
	}
	vm := config.VM{
		VMID:      17301,
		SourcePBS: config.SourcePBS{Snapshot: "vm/7301/2026-09-27T03:00:00Z"},
		FirmwareDisks: []config.FirmwareDisk{
			{Slot: "efidisk0", Archive: "drive-efidisk0", Options: "efitype=4m,pre-enrolled-keys=1"},
			{Slot: "tpmstate0", Archive: "drive-tpmstate0-backup", Options: "version=v2.0"},
		},
	}
	return orch, vm, &restored
}

func TestRestoreFirmwareDisksRestoresPrivateVerifiedCopies(t *testing.T) {
	vars := bytes.Repeat([]byte{0xa5}, 540672)
	tpm := bytes.Repeat([]byte{0x5a}, 4<<20)
	orch, vm, restored := firmwareFixture(t, map[string][]byte{"drive-efidisk0": vars, "drive-tpmstate0-backup": tpm})
	timings := &attest.PhaseTimings{}

	volumes, evidence, err := orch.restoreFirmwareDisks(context.Background(), vm, 1, timings, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"vm/7301/2026-09-27T03:00:00Z drive-efidisk0", "vm/7301/2026-09-27T03:00:00Z drive-tpmstate0-backup"}; strings.Join(*restored, "|") != strings.Join(want, "|") {
		t.Fatalf("restores = %v, want %v", *restored, want)
	}
	wantVolumes := []pve.FirmwareVolume{
		{Slot: "efidisk0", Volume: "certistack-scratch:17301/certistack-delta-vm17301-efidisk0-1-0.raw", Options: "efitype=4m,pre-enrolled-keys=1"},
		{Slot: "tpmstate0", Volume: "certistack-scratch:17301/certistack-delta-vm17301-tpmstate0-1-1.raw", Options: "version=v2.0"},
	}
	if len(volumes) != 2 || volumes[0] != wantVolumes[0] || volumes[1] != wantVolumes[1] {
		t.Fatalf("volumes = %+v, want %+v", volumes, wantVolumes)
	}
	for i, content := range [][]byte{vars, tpm} {
		sum := sha256.Sum256(content)
		e := evidence[i]
		if e.Slot != wantVolumes[i].Slot || e.IntegrityStatus != "verified" || e.ImageDigest != hex.EncodeToString(sum[:]) || !strings.HasSuffix(e.ManifestReference, ".img.fidx") {
			t.Errorf("evidence[%d] = %+v", i, e)
		}
	}
	// The copies hold firmware secrets: private, and journaled for removal.
	if len(orch.record.DeltaFiles) != 2 {
		t.Fatalf("journaled %v, want both copies", orch.record.DeltaFiles)
	}
	for _, p := range orch.record.DeltaFiles {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v, err %v; want 0600", p, info.Mode(), err)
		}
	}
	orch.cleanup.Unwind()
	for _, p := range orch.record.DeltaFiles {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s survived cleanup", p)
		}
	}
}

func TestRestoreFirmwareDisksFailsClosed(t *testing.T) {
	t.Run("no overlay storage", func(t *testing.T) {
		orch, vm, _ := firmwareFixture(t, nil)
		orch.opts.OverlayStorage = ""
		if _, _, err := orch.restoreFirmwareDisks(context.Background(), vm, 1, nil, nil); err == nil || !strings.Contains(err.Error(), "overlay_storage") {
			t.Fatalf("err = %v, want the overlay storage requirement", err)
		}
	})
	t.Run("restore error leaves the path journaled", func(t *testing.T) {
		orch, vm, _ := firmwareFixture(t, map[string][]byte{"drive-efidisk0": []byte("vars")})
		if _, _, err := orch.restoreFirmwareDisks(context.Background(), vm, 1, nil, nil); err == nil || !strings.Contains(err.Error(), "tpmstate0") {
			t.Fatalf("err = %v, want the TPM restore failure", err)
		}
		if len(orch.record.DeltaFiles) != 2 {
			t.Fatalf("journaled %v, want the failed target too", orch.record.DeltaFiles)
		}
	})
	t.Run("not a firmware image", func(t *testing.T) {
		orch, vm, _ := firmwareFixture(t, map[string][]byte{"drive-efidisk0": make([]byte, maxFirmwareImageBytes+1)})
		vm.FirmwareDisks = vm.FirmwareDisks[:1]
		if _, _, err := orch.restoreFirmwareDisks(context.Background(), vm, 1, nil, nil); err == nil || !strings.Contains(err.Error(), "not a firmware state image") {
			t.Fatalf("err = %v, want the size refusal", err)
		}
	})
	t.Run("no firmware", func(t *testing.T) {
		orch, vm, restored := firmwareFixture(t, nil)
		vm.FirmwareDisks = nil
		volumes, evidence, err := orch.restoreFirmwareDisks(context.Background(), vm, 1, nil, nil)
		if err != nil || volumes != nil || evidence != nil || len(*restored) != 0 {
			t.Fatalf("BIOS VM: %v %v %v %v", volumes, evidence, err, *restored)
		}
	})
}

func TestBootSlotFor(t *testing.T) {
	drives := []config.SourceDrive{{Slot: "sata1"}, {Slot: "virtio0"}, {Slot: "scsi2"}}
	for name, tc := range map[string]struct {
		chosen, want string
		fails        bool
	}{
		"worker's choice":      {chosen: "virtio0", want: "virtio0"},
		"PVE's first disk":     {want: "scsi2"},
		"not a restored disk":  {chosen: "scsi0", fails: true},
		"firmware is not boot": {chosen: "efidisk0", fails: true},
	} {
		got, err := bootSlotFor(config.VM{VMID: 1, BootDisk: tc.chosen}, drives)
		if tc.fails != (err != nil) || got != tc.want {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
}

func TestManifestReference(t *testing.T) {
	for archive, want := range map[string]string{
		"drive-scsi0":                     "drive-scsi0.img.fidx",
		"drive-scsi0.img":                 "drive-scsi0.img.fidx",
		"drive-scsi0.img.fidx":            "drive-scsi0.img.fidx",
		"drive-tpmstate0-backup":          "drive-tpmstate0-backup.img.fidx",
		"drive-tpmstate0-backup.img.fidx": "drive-tpmstate0-backup.img.fidx",
	} {
		if got := manifestReference(archive); got != want {
			t.Errorf("manifestReference(%q) = %q, want %q", archive, got, want)
		}
	}
}
