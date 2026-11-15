//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// skipWithoutRenameNoReplace skips a test on a file system (or kernel) that
// cannot rename without replacing: there the exclusive-copy route is the only
// one, and it is tested separately.
func skipWithoutRenameNoReplace(t *testing.T, dir string) {
	t.Helper()
	from, to := filepath.Join(dir, "probe-from"), filepath.Join(dir, "probe-to")
	if err := os.WriteFile(from, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, from, unix.AT_FDCWD, to, unix.RENAME_NOREPLACE); err != nil {
		t.Skipf("this file system cannot rename without replacing: %v", err)
	}
	_ = os.Remove(to)
}

// refuseHardLinks makes the hard link of the publish step fail the way a file
// system without them does (FAT, some network and FUSE mounts: EPERM).
func refuseHardLinks(t *testing.T) {
	t.Helper()
	old := linkStagedPlan
	linkStagedPlan = func(oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EPERM}
	}
	t.Cleanup(func() { linkStagedPlan = old })
}

func stagePlan(t *testing.T, dir, content string) string {
	t.Helper()
	staged := filepath.Join(dir, ".plan.yaml.stage")
	if err := os.WriteFile(staged, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(staged, 0o644); err != nil {
		t.Fatal(err)
	}
	return staged
}

// On a file system that refuses hard links the plan used to be published by
// creating the final name exclusively and copying into it, so a reader (or an
// interrupted process) could see an incomplete plan at the name a later step
// opens. Where the kernel can rename without replacing, the staged file, which
// is already complete, takes the final name in one step: it is the same file
// afterwards, never a copy (audit FU-29).
func TestPlanIsPublishedWholeWhenTheFilesystemRefusesHardLinks(t *testing.T) {
	refuseHardLinks(t)
	dir := t.TempDir()
	skipWithoutRenameNoReplace(t, dir)
	staged := stagePlan(t, dir, "the complete plan\n")
	before, err := os.Stat(staged)
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "plan.yaml")
	if err := publishWithoutReplacing(staged, final); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(final)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Errorf("the final name is a copy of the staged plan, not the staged file itself: a reader could have seen it half written")
	}
	if data, _ := os.ReadFile(final); string(data) != "the complete plan\n" {
		t.Errorf("plan = %q", data)
	}
	if after.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", after.Mode().Perm())
	}
	if _, err := os.Lstat(staged); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staged name remains after it was renamed: %v", err)
	}
}

// The rename never replaces: a file that is there is refused as before, and
// stays as it was.
func TestRenameWithoutReplacingRefusesAnExistingFile(t *testing.T) {
	refuseHardLinks(t)
	dir := t.TempDir()
	skipWithoutRenameNoReplace(t, dir)
	staged := stagePlan(t, dir, "the plan\n")
	final := filepath.Join(dir, "plan.yaml")
	if err := os.WriteFile(final, []byte("someone else's plan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := publishWithoutReplacing(staged, final)
	if err == nil || !strings.Contains(err.Error(), "appeared while the plan was being written") {
		t.Fatalf("an existing file was not refused: %v", err)
	}
	if data, _ := os.ReadFile(final); string(data) != "someone else's plan\n" {
		t.Errorf("the existing file was replaced: %q", data)
	}
	if _, err := os.Stat(staged); err != nil {
		t.Errorf("the staged plan is gone after a refusal: %v", err)
	}
}

// Where the kernel or the file system cannot rename without replacing, the old
// route stays: create the final name exclusively and copy the plan into it.
func TestPlanFallsBackToAnExclusiveCopyWhereRenameWithoutReplacingIsUnsupported(t *testing.T) {
	refuseHardLinks(t)
	old := renameStagedPlan
	renameStagedPlan = func(string, string) error { return errRenameWithoutReplacingUnsupported }
	t.Cleanup(func() { renameStagedPlan = old })
	dir := t.TempDir()
	staged := stagePlan(t, dir, "the complete plan\n")
	final := filepath.Join(dir, "plan.yaml")
	if err := publishWithoutReplacing(staged, final); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(final); string(data) != "the complete plan\n" {
		t.Errorf("plan = %q", data)
	}
	if info, err := os.Stat(final); err != nil || info.Mode().Perm() != 0o644 {
		t.Errorf("published plan: %v, %v", info, err)
	}
	if _, err := os.Stat(staged); err != nil {
		t.Errorf("the staged plan was moved by the copy route: %v", err)
	}
	// A file that is already there is still refused on this route.
	other := filepath.Join(dir, "other.yaml")
	if err := os.WriteFile(other, []byte("not mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishWithoutReplacing(staged, other); err == nil || !strings.Contains(err.Error(), "appeared while the plan was being written") {
		t.Errorf("the copy route replaced or ignored an existing file: %v", err)
	}
}

// The whole write, as init runs it, leaves nothing behind on a file system
// without hard links.
func TestWritePlanFileWithoutHardLinksLeavesOnlyThePlan(t *testing.T) {
	refuseHardLinks(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "plan.yaml")
	if err := writePlanFile(path, []byte("the plan\n"), false); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "the plan\n" {
		t.Errorf("plan = %q", data)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "plan.yaml" {
		t.Errorf("directory holds %v, want only plan.yaml", entries)
	}
}
