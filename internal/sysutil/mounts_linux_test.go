// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"os"
	"path/filepath"
	"testing"
)

// A directory is a mount point only if the kernel's mount table says
// a file system is mounted there.
func TestIsMountPoint(t *testing.T) {
	dir := t.TempDir()
	mounted := filepath.Join(dir, "mounted")
	spaced := filepath.Join(dir, "has space")
	plain := filepath.Join(dir, "plain")
	for _, p := range []string{mounted, spaced, plain} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	mountInfo := filepath.Join(dir, "mountinfo")
	table := "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n" +
		"40 22 0:35 / " + filepath.Join(real, "mounted") + " rw,relatime shared:1 - nfs4 nas:/pve rw\n" +
		"41 22 0:36 / " + real + "/has\\040space rw - tmpfs tmpfs rw\n"
	if err := os.WriteFile(mountInfo, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(mounted, link); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{mounted: true, spaced: true, link: true, plain: false, dir: false} {
		got, err := isMountPoint(mountInfo, path)
		if err != nil || got != want {
			t.Errorf("isMountPoint(%s) = %v, %v; want %v", path, got, err, want)
		}
	}
	if _, err := isMountPoint(mountInfo, filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing directory was checked")
	}
	if _, err := isMountPoint(filepath.Join(dir, "no-such-table"), plain); err == nil {
		t.Error("an unreadable mount table was treated as no mount")
	}
	// The real table: the root file system is mounted, a fresh directory is not.
	if ok, err := IsMountPoint("/"); err != nil || !ok {
		t.Errorf("IsMountPoint(/) = %v, %v", ok, err)
	}
	if ok, err := IsMountPoint(plain); err != nil || ok {
		t.Errorf("IsMountPoint(%s) = %v, %v", plain, ok, err)
	}
}
