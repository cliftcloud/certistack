//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
)

// A map file's daemon is called dead only on evidence: no pid file at all, or a
// pid that is not a running proxmox-backup-client. A pid file that cannot be
// read or holds no usable PID is not evidence, and what the daemon may still be
// serving is then neither aborted nor detached.
func TestMapDaemonIsNotCalledDeadWithoutEvidence(t *testing.T) {
	dir := t.TempDir()
	backing := filepath.Join(dir, "repo-vm-100.img")
	pidFile := strings.TrimSuffix(backing, ".img") + ".pid"

	if alive, unknown := mapDaemonState(backing); alive || unknown != "" || mapDaemonAlive(backing) {
		t.Fatalf("no pid file: alive=%v unknown=%q, want a dead daemon", alive, unknown)
	}
	// This test process is not a proxmox-backup-client: a pid file that names it is a dead daemon's.
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if alive, unknown := mapDaemonState(backing); alive || unknown != "" {
		t.Fatalf("a pid that is another program: alive=%v unknown=%q, want a dead daemon", alive, unknown)
	}

	for name, content := range map[string]string{"garbage": "not-a-pid\n", "empty": "", "pid 1": "1\n", "negative": "-7\n"} {
		if err := os.WriteFile(pidFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if alive, unknown := mapDaemonState(backing); alive || unknown == "" || !mapDaemonAlive(backing) {
			t.Errorf("%s: alive=%v unknown=%q alive-for-callers=%v; want unknown, which counts as running", name, alive, unknown, mapDaemonAlive(backing))
		}
	}
	// A pid file that is a directory cannot be read.
	_ = os.Remove(pidFile)
	if err := os.Mkdir(pidFile, 0o700); err != nil {
		t.Fatal(err)
	}
	if alive, unknown := mapDaemonState(backing); alive || unknown == "" {
		t.Errorf("unreadable pid file: alive=%v unknown=%q, want unknown", alive, unknown)
	}
}

// The last guard before a map's FUSE connection is aborted and its mount
// detached must not take an unreadable pid file for a dead daemon.
func TestRemoveMapFilesLeavesAMapWhosePidFileSaysNothing(t *testing.T) {
	dir := t.TempDir()
	backing := filepath.Join(dir, "repo-vm-100.img")
	pidFile := strings.TrimSuffix(backing, ".img") + ".pid"
	if err := os.WriteFile(backing, []byte("map"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFile, []byte("not-a-pid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var detached []string
	old := detachMount
	detachMount = func(path string) error { detached = append(detached, path); return syscall.EINVAL }
	t.Cleanup(func() { detachMount = old })

	err := removeMapFiles(leakFinder{runDir: dir}, journal.MapIntent{NameSuffix: "-vm-100.img"}, backing)
	if err == nil || !strings.Contains(err.Error(), "cannot be shown that no proxmox-backup-client serves it") {
		t.Fatalf("removeMapFiles = %v, want it left alone because the daemon cannot be shown to be gone", err)
	}
	if len(detached) != 0 {
		t.Fatalf("the mount was detached (%v) on the strength of an unreadable pid file", detached)
	}
	for _, path := range []string{backing, pidFile} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("%s was removed: %v", path, statErr)
		}
	}
}
