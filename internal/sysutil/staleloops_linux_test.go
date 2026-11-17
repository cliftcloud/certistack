//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// loop0 had backing "/" (its FUSE mount detached), was read-only,
// and its backing device 0:53 had a FUSE connection but no mount.
func TestStaleFUSELoops(t *testing.T) {
	root := t.TempDir()
	scan := staleLoopScan{
		sysBlock:  filepath.Join(root, "sys", "block"),
		fuseConns: filepath.Join(root, "fuse"),
		mountInfo: filepath.Join(root, "mountinfo"),
	}
	type loop struct {
		backing, ro   string
		major, minor  uint32
		statusErr     bool
		wantStale     bool
		fuseConnFound bool
	}
	loops := map[string]loop{
		"loop0": {backing: "/", ro: "1", minor: 53, fuseConnFound: true, wantStale: true},     // the stale-loop leak
		"loop1": {backing: "", ro: "1", minor: 54, fuseConnFound: true, wantStale: true},      // empty backing
		"loop2": {backing: "/run/pbs-loopdev/x.img", ro: "1", minor: 55, fuseConnFound: true}, // a live, named map
		"loop3": {backing: "/", ro: "0", minor: 56, fuseConnFound: true},                      // writable: not a map
		"loop4": {backing: "/", ro: "1", major: 8, minor: 1},                                  // backed by a real disk
		"loop5": {backing: "/", ro: "1", minor: 57},                                           // no FUSE connection
		"loop6": {backing: "/", ro: "1", minor: 58, fuseConnFound: true},                      // FUSE still mounted
		"loop7": {backing: "/", ro: "1", statusErr: true},                                     // unreadable status
	}
	if err := os.MkdirAll(scan.fuseConns, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, l := range loops {
		dir := filepath.Join(scan.sysBlock, name)
		if err := os.MkdirAll(filepath.Join(dir, "loop"), 0o755); err != nil {
			t.Fatal(err)
		}
		for file, content := range map[string]string{"loop/backing_file": l.backing + "\n", "ro": l.ro + "\n", "size": "67108864\n"} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if l.fuseConnFound {
			if err := os.Mkdir(filepath.Join(scan.fuseConns, fmt.Sprint(l.minor)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	mountinfo := "22 1 0:21 / /proc rw - proc proc rw\n130 30 0:58 / /run/pbs-loopdev/y.img rw - fuse proxmox-backup-client rw\n"
	if err := os.WriteFile(scan.mountInfo, []byte(mountinfo), 0o644); err != nil {
		t.Fatal(err)
	}
	opened := map[string]bool{}
	scan.backingDevice = func(device string) (uint32, uint32, error) {
		opened[device] = true
		l := loops[filepath.Base(device)]
		if l.statusErr {
			return 0, 0, errors.New("no such device")
		}
		return l.major, l.minor, nil
	}
	stale := scan.find()
	if len(stale) != 2 || stale[0].Device != "/dev/loop0" || stale[1].Device != "/dev/loop1" || stale[0].Bytes != 32<<30 {
		t.Fatalf("stale = %+v, want /dev/loop0 (32 GiB) and /dev/loop1", stale)
	}
	for _, name := range []string{"loop2", "loop3"} {
		if opened["/dev/"+name] {
			t.Errorf("%s was opened; only loops that look dead may be", name)
		}
	}
}

// Reads were stuck on loop0, so everything that opened it hung,
// losetup and vgs included. A loop with reads in flight is reported stuck
// and never opened; the connection holding it, with requests waiting and no
// mount, is listed so it can be aborted first.
func TestStaleFUSELoopsNeverOpensAStuckLoop(t *testing.T) {
	root := t.TempDir()
	scan := staleLoopScan{
		sysBlock:  filepath.Join(root, "sys", "block"),
		fuseConns: filepath.Join(root, "fuse"),
		mountInfo: filepath.Join(root, "mountinfo"),
		backingDevice: func(device string) (uint32, uint32, error) {
			t.Errorf("%s was opened", device)
			return 0, 0, errors.New("must not open")
		},
	}
	dir := filepath.Join(scan.sysBlock, "loop0")
	if err := os.MkdirAll(filepath.Join(dir, "loop"), 0o755); err != nil {
		t.Fatal(err)
	}
	for file, content := range map[string]string{"loop/backing_file": "/\n", "ro": "1\n", "size": "67108864\n", "inflight": "       1        0\n"} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for minor, waiting := range map[string]string{"53": "1", "54": "0", "58": "2"} {
		if err := os.MkdirAll(filepath.Join(scan.fuseConns, minor), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(scan.fuseConns, minor, "waiting"), []byte(waiting+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 58 is a live, mounted FUSE file system that is merely busy.
	if err := os.WriteFile(scan.mountInfo, []byte("130 30 0:58 / /mnt/sshfs rw - fuse.sshfs host: rw\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := scan.find()
	if len(stale) != 1 || stale[0].Device != "/dev/loop0" || !stale[0].Stuck || stale[0].Bytes != 32<<30 {
		t.Fatalf("stale = %+v, want loop0 stuck", stale)
	}
	conns := scan.orphanedConnections()
	if len(conns) != 1 || conns[0].Minor != "53" || conns[0].Waiting != 1 {
		t.Fatalf("orphaned connections = %+v, want only 53", conns)
	}
}

// A stale loop that devices the host assembled from its partitions hold is
// listed with them: losetup -d cannot release it until they are stopped.
func TestStaleFUSELoopsListsWhatHoldsThem(t *testing.T) {
	root := t.TempDir()
	scan := staleLoopScan{
		sysBlock:  filepath.Join(root, "sys", "block"),
		fuseConns: filepath.Join(root, "fuse"),
		mountInfo: filepath.Join(root, "mountinfo"),
		backingDevice: func(string) (uint32, uint32, error) {
			return 0, 53, nil
		},
	}
	if err := os.MkdirAll(filepath.Join(scan.fuseConns, "53"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scan.mountInfo, []byte("22 1 0:21 / /proc rw - proc proc rw\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{
		"loop0/loop", "loop0/loop0p1/holders/md126", "loop0/loop0p2/holders/md127", "loop0/holders",
		"loop1/loop",
	} {
		if err := os.MkdirAll(filepath.Join(scan.sysBlock, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"loop0", "loop1"} {
		for file, content := range map[string]string{"loop/backing_file": "/\n", "ro": "1\n", "size": "67108864\n"} {
			if err := os.WriteFile(filepath.Join(scan.sysBlock, name, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	stale := scan.find()
	if len(stale) != 2 || stale[0].Device != "/dev/loop0" || stale[1].Device != "/dev/loop1" {
		t.Fatalf("stale = %+v", stale)
	}
	if got := HolderLabels(stale[0].Holders); got != "md126, md127" {
		t.Fatalf("loop0 holders = %q, want md126, md127", got)
	}
	if len(stale[1].Holders) != 0 {
		t.Fatalf("loop1 holders = %+v, want none", stale[1].Holders)
	}
}

// A stale FUSE loop that appeared after the baseline is what an interrupted map
// left, and is detached; one that was stale before, one that is stuck and one
// that devices hold are not, and are reported where they need an operator.
func TestReleaseStaleFUSELoopsSinceTouchesOnlyWhatAppearedAfterTheBaseline(t *testing.T) {
	root := t.TempDir()
	scan := staleLoopScan{
		sysBlock:      filepath.Join(root, "sys", "block"),
		fuseConns:     filepath.Join(root, "fuse"),
		mountInfo:     filepath.Join(root, "mountinfo"),
		backingDevice: func(string) (uint32, uint32, error) { return 0, 53, nil },
	}
	if err := os.MkdirAll(filepath.Join(scan.fuseConns, "53"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scan.mountInfo, []byte("22 1 0:21 / /proc rw - proc proc rw\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"loop0/loop", "loop1/loop", "loop2/loop", "loop3/loop", "loop3/loop3p1/holders/md126", "loop3/holders", "loop4/loop"} {
		if err := os.MkdirAll(filepath.Join(scan.sysBlock, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, inflight := range map[string]string{"loop0": "0 0", "loop1": "0 0", "loop2": "1 0", "loop3": "0 0", "loop4": "0 0"} {
		files := map[string]string{"loop/backing_file": "/\n", "ro": "1\n", "size": "67108864\n", "inflight": inflight + "\n"}
		if name == "loop4" {
			files["loop/backing_file"] = "/run/pbs-loopdev/live.img\n" // a live map: not stale at all
		}
		for file, content := range files {
			if err := os.WriteFile(filepath.Join(scan.sysBlock, name, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	var detached []string
	detach := func(_ context.Context, device string) error {
		detached = append(detached, device)
		// losetup -d detaches it: the backing file goes with it.
		return os.Remove(filepath.Join(scan.sysBlock, filepath.Base(device), "loop", "backing_file"))
	}
	released, problems := releaseStaleSince(context.Background(), scan, []string{"/dev/loop0"}, 3, detach, 3, time.Millisecond)

	// loop0 was stale before the run; loop1 is new and alone; loop2 is stuck;
	// loop3 is held by md126; loop4 is a live map.
	if len(released) != 1 || released[0] != "/dev/loop1" || len(detached) != 1 || detached[0] != "/dev/loop1" {
		t.Fatalf("released %v, detached %v; want only /dev/loop1", released, detached)
	}
	if len(problems) != 2 || !strings.Contains(problems[0].Error(), "/dev/loop2") || !strings.Contains(problems[0].Error(), "stuck") || !strings.Contains(problems[1].Error(), "/dev/loop3") || !strings.Contains(problems[1].Error(), "md126") {
		t.Fatalf("problems = %v; want loop2 stuck and loop3 held, named with what to do", problems)
	}

	// A detach that does not take is reported, not counted released.
	released, problems = releaseStaleSince(context.Background(), scan, []string{"/dev/loop0", "/dev/loop2", "/dev/loop3"}, 1, func(context.Context, string) error { return nil }, 2, time.Millisecond)
	if len(released) != 0 {
		t.Fatalf("released %v after a detach that left the loop attached", released)
	}
	_ = problems
}

// More new stale loops than the run has unreported maps: they cannot all be the
// run's, so none is released.
func TestReleaseStaleFUSELoopsSinceReleasesNothingWhenThereAreMoreThanTheRunCouldHaveMade(t *testing.T) {
	root := t.TempDir()
	scan := staleLoopScan{
		sysBlock:      filepath.Join(root, "sys", "block"),
		fuseConns:     filepath.Join(root, "fuse"),
		mountInfo:     filepath.Join(root, "mountinfo"),
		backingDevice: func(string) (uint32, uint32, error) { return 0, 53, nil },
	}
	if err := os.MkdirAll(filepath.Join(scan.fuseConns, "53"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scan.mountInfo, []byte("22 1 0:21 / /proc rw - proc proc rw\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"loop1", "loop2"} {
		if err := os.MkdirAll(filepath.Join(scan.sysBlock, name, "loop"), 0o755); err != nil {
			t.Fatal(err)
		}
		for file, content := range map[string]string{"loop/backing_file": "/\n", "ro": "1\n", "size": "67108864\n"} {
			if err := os.WriteFile(filepath.Join(scan.sysBlock, name, file), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	detach := func(context.Context, string) error {
		t.Fatal("a loop was detached although two appeared for one unreported map")
		return nil
	}
	released, problems := releaseStaleSince(context.Background(), scan, nil, 1, detach, 1, time.Millisecond)
	if len(released) != 0 || len(problems) != 2 || !strings.Contains(problems[0].Error(), "only 1 of the run's maps") {
		t.Fatalf("released %v, problems %v; want both reported and none released", released, problems)
	}
	if released, problems := releaseStaleSince(context.Background(), scan, nil, 0, detach, 1, time.Millisecond); len(released) != 0 || len(problems) != 2 {
		t.Fatalf("with no unreported map: released %v, problems %v", released, problems)
	}
}
