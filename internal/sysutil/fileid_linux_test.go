//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Cleanup removes a path only while it holds the file the run
// created there.
func TestRemoveIfSameLeavesWhatIsNotTheRunsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.qcow2")
	writeFile(t, path, "ours")
	identity, err := FileIdentityOf(path)
	if err != nil {
		t.Fatal(err)
	}
	// The foreign file that appears later is made now, while the run's file
	// still holds its inode, and renamed into place below. Written after the
	// removal it could get the freed inode back, and on a file system whose
	// birth time has a coarse tick (ext4 on a 6.8 kernel) the same birth time
	// too, which no identity of path, inode and birth time can tell apart.
	foreign := filepath.Join(dir, "foreign.tmp")
	writeFile(t, foreign, "a foreign file that appeared later")

	// The file itself: removed. Absent: removed already.
	if got, err := CheckFileIdentity(path, identity); err != nil || got != FileSame {
		t.Fatalf("CheckFileIdentity of the run's file = %v, %v", got, err)
	}
	if err := RemoveIfSame(path, identity); err != nil {
		t.Fatalf("RemoveIfSame of the run's file: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the run's file survived: %v", err)
	}
	if err := RemoveIfSame(path, identity); err != nil {
		t.Fatalf("RemoveIfSame of an absent path: %v", err)
	}

	// Another file put at the path later: left alone, byte for byte.
	if err := os.Rename(foreign, path); err != nil {
		t.Fatal(err)
	}
	err = RemoveIfSame(path, identity)
	if !errors.Is(err, ErrNotOurs) {
		t.Fatalf("RemoveIfSame of a foreign file = %v, want ErrNotOurs", err)
	}
	if readFile(t, path) != "a foreign file that appeared later" {
		t.Fatal("the foreign file was changed")
	}

	// A symlink at the path (to anything, including a file with the recorded
	// identity) is not the run's file, and its target is not touched.
	target := filepath.Join(dir, "target")
	writeFile(t, target, "target")
	targetIdentity, err := FileIdentityOf(target)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.qcow2")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := RemoveIfSame(link, targetIdentity); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("RemoveIfSame through a symlink = %v, want ErrNotOurs", err)
	}
	if _, err := os.Lstat(link); err != nil || readFile(t, target) != "target" {
		t.Fatalf("the symlink or its target was removed: %v", err)
	}

	// A directory is not the run's file either.
	if err := os.Mkdir(filepath.Join(dir, "dir.qcow2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveIfSame(filepath.Join(dir, "dir.qcow2"), identity); !errors.Is(err, ErrNotOurs) {
		t.Fatalf("RemoveIfSame of a directory = %v, want ErrNotOurs", err)
	}
}

// A file that reuses the inode number of a removed one is told apart by its
// creation time, where the filesystem records it.
func TestCheckFileIdentityUsesTheCreationTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	writeFile(t, path, "x")
	identity, err := FileIdentityOf(path)
	if err != nil {
		t.Fatal(err)
	}
	if identity.BtimeNS == 0 {
		t.Skip("this filesystem records no creation time")
	}
	identity.BtimeNS++
	if got, err := CheckFileIdentity(path, identity); err != nil || got != FileOther {
		t.Fatalf("CheckFileIdentity with another creation time = %v, %v; want FileOther", got, err)
	}
	identity.BtimeNS = 0 // an identity recorded without one still matches on device and inode
	if got, err := CheckFileIdentity(path, identity); err != nil || got != FileSame {
		t.Fatalf("CheckFileIdentity without a recorded creation time = %v, %v; want FileSame", got, err)
	}
}

func TestPublishNoReplaceNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	final := filepath.Join(dir, "final")
	writeFile(t, staging, "ours")

	if err := PublishNoReplace(staging, final); err != nil {
		t.Fatalf("publish to a free name: %v", err)
	}
	if readFile(t, final) != "ours" {
		t.Fatal("the published file has other content")
	}
	ours, _ := FileIdentityOf(staging)
	published, _ := FileIdentityOf(final)
	if ours != published {
		t.Fatalf("publishing changed the file's identity: %+v then %+v", ours, published)
	}

	foreign := filepath.Join(dir, "foreign")
	writeFile(t, foreign, "someone else's")
	err := PublishNoReplace(staging, foreign)
	if !errors.Is(err, ErrPublishExists) {
		t.Fatalf("publish over a file = %v, want ErrPublishExists", err)
	}
	if readFile(t, foreign) != "someone else's" {
		t.Fatal("publishing replaced the file at the destination")
	}
	// A symlink at the destination counts as something there, even a dangling one.
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if err := PublishNoReplace(staging, dangling); !errors.Is(err, ErrPublishExists) {
		t.Fatalf("publish over a dangling symlink = %v, want ErrPublishExists", err)
	}
}
