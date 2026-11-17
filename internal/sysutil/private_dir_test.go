// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsurePrivateDirectoryCreatesOwnerOnlyDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "scratch")
	if err := EnsurePrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Fatalf("private directory mode = %04o, want 0700", got)
	}
}

func TestEnsurePrivateDirectoryRejectsSharedTemporaryDirectory(t *testing.T) {
	for _, directory := range []string{"/tmp", "/var/tmp", os.TempDir()} {
		if err := EnsurePrivateDirectory(directory); err == nil {
			t.Fatalf("shared temporary directory %q was accepted", directory)
		}
	}
}

func TestEnsurePrivateDirectoryDoesNotChmodExistingDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if err := EnsurePrivateDirectory(directory); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := EnsurePrivateDirectory(directory); err == nil {
		t.Fatal("existing non-private directory was accepted")
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Fatalf("existing directory mode changed to %04o", got)
	}
}

func TestEnsurePrivateDirectoryRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	if err := EnsurePrivateDirectory(filepath.Join(link, "nested")); err == nil {
		t.Fatal("directory beneath a symlinked parent was accepted")
	}
}
