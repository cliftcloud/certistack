//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package journal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenLock_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "lock")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatalf("create lock target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create lock symlink: %v", err)
	}

	_, err := openLock(link)
	if err == nil || !strings.Contains(err.Error(), "too many levels of symbolic links") {
		t.Fatalf("openLock error = %v, want symlink refusal", err)
	}
}

// A second operation on the host is refused with the message the CLI keys on,
// and the lock is free again once the first one lets go.
func TestOpenLock_SecondHolderIsRefusedUntilTheFirstReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := openLock(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := openLock(path)
	if err == nil {
		second.Close()
		t.Fatal("a second holder got the host lock while the first still had it")
	}
	if !strings.Contains(err.Error(), LockHeldMessage) {
		t.Fatalf("contention error = %v, want it to start with %q", err, LockHeldMessage)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := openLock(path)
	if err != nil {
		t.Fatalf("the lock was not free after the holder closed it: %v", err)
	}
	third.Close()
}
