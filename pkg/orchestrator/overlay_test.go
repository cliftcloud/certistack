// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOverlayNamingMatchesTheVolumeAPIContract(t *testing.T) {
	name := overlayFileName(17011, "scsi0", 1790184983835370240, 0)
	if name != "certistack-delta-vm17011-scsi0-1790184983835370240-0.qcow2" {
		t.Fatalf("overlay name = %q", name)
	}
	if got := overlayVolumeID("certistack-scratch", 17011, name); got != "certistack-scratch:17011/"+name {
		t.Fatalf("volume ID = %q", got)
	}
}

func TestCheckOverlayPathAcceptsOnlyTheVMImageDirectory(t *testing.T) {
	name := overlayFileName(17011, "scsi0", 1, 0)
	good := "/var/lib/vz/certistack-scratch/images/17011/" + name
	if err := checkOverlayPath(good, 17011, name); err != nil {
		t.Fatalf("valid overlay path rejected: %v", err)
	}
	for _, bad := range []string{
		"relative/images/17011/" + name,
		"/var/lib/vz/certistack-scratch/images/17012/" + name,
		"/var/lib/vz/certistack-scratch/private/17011/" + name,
		"/var/lib/vz/certistack-scratch/images/17011/other.qcow2",
		"/var/lib/vz/certistack-scratch/images/17011/../17011/" + name,
	} {
		if err := checkOverlayPath(bad, 17011, name); err == nil {
			t.Errorf("unsafe overlay path %q accepted", bad)
		}
	}
}

func TestPrepareOverlayDirRefusesToShareAVMImageDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "images", "17011")

	created, err := prepareOverlayDir(dir, 17011)
	if err != nil || !created {
		t.Fatalf("new directory: created=%v err=%v", created, err)
	}
	// A leftover overlay of the same VM is ours to replace.
	if err := os.WriteFile(filepath.Join(dir, overlayFileName(17011, "scsi0", 1, 0)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if created, err := prepareOverlayDir(dir, 17011); err != nil || created {
		t.Fatalf("own overlays: created=%v err=%v", created, err)
	}
	// Any other volume means the directory belongs to something else.
	if err := os.WriteFile(filepath.Join(dir, "vm-17011-disk-0.qcow2"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareOverlayDir(dir, 17011); err == nil || !strings.Contains(err.Error(), "refusing to share") {
		t.Fatalf("foreign volume error = %v", err)
	}
}

func TestRemoveEmptyOverlayDirIsIdempotentAndKeepsNonEmptyDirectories(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "images", "17011")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unexpected"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeEmptyOverlayDir(dir); err == nil {
		t.Fatal("a non-empty overlay directory was removed silently")
	}
	if err := os.Remove(filepath.Join(dir, "unexpected")); err != nil {
		t.Fatal(err)
	}
	if err := removeEmptyOverlayDir(dir); err != nil {
		t.Fatalf("empty directory: %v", err)
	}
	if err := removeEmptyOverlayDir(dir); err != nil {
		t.Fatalf("already removed: %v", err)
	}
}
