//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

// A run killed while its PBS map was active: releasing the map's loop and
// aborting the dead daemon's FUSE connection is not all of it, as the map's FUSE
// mount stays in the mount table and its map file and pid file in the run
// directory. The journal here records the map's loop (the intent is resolved to
// it), unlike the dead-unseen case's, which recovery finds only through its
// intent.

// killedLoop is the loop device the killed run's map attached.
const killedLoop = "/dev/loop2"

// killedMap is a fake host whose journal records a PBS map's loop, with the
// map's FUSE mount in the mount table and its map file in the run directory.
type killedMap struct {
	*labHost
	root, stateDir string
	img, pidFile   string
	log            string
}

// newKilledMap makes the host. pid is what the map's pid file names (none when
// 0): a process that is not there, as the killed daemon's.
func newKilledMap(t *testing.T, pid int) *killedMap {
	t.Helper()
	root, stateDir := t.TempDir(), t.TempDir()
	h := newLabHost(t, root)
	at := reaperBoot.Add(10 * time.Hour)
	d := &deadFixture{t: t, maps: h.maps, at: at, pid: pid, written: 3 * time.Second}
	d.intent = labIntent(at)
	img := d.own("loop")
	h.mount(t, img)
	intent := d.intent
	intent.Device = killedLoop
	journalOf(t, stateDir, []journal.TrackedLoop{{Device: killedLoop, Backing: img}}, intent)
	return &killedMap{labHost: h, root: root, stateDir: stateDir, img: img,
		pidFile: strings.TrimSuffix(img, ".img") + ".pid",
		log:     installLabTools(t, h.maps.sysBlock, false)}
}

func (k *killedMap) loopAttached() bool {
	return exists(filepath.Join(k.maps.sysBlock, "loop2", "loop", "backing_file"))
}

func (k *killedMap) mounted(t *testing.T) bool {
	t.Helper()
	mounted, err := hostLeakFinder.mounted(k.img)
	if err != nil {
		t.Fatal(err)
	}
	return mounted
}

func (k *killedMap) phase(t *testing.T) string {
	t.Helper()
	return phaseOf(t, filepath.Join(k.stateDir, "active.json"))
}

// The explicit recovery of the killed run's map leaves nothing of it: the loop
// is released, and the dead FUSE mount is detached (through umount2, by the map
// file's path) and the map file and pid file removed.
func TestRecoverLockedRemovesTheMountAndFilesOfAReleasedMapWhoseDaemonDied(t *testing.T) {
	for name, pid := range map[string]int{
		"a pid file naming a process that is gone": 4242,
		"no pid file": 0,
	} {
		t.Run(name, func(t *testing.T) {
			k := newKilledMap(t, pid)
			if err := RecoverLocked(k.stateDir); err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if calls := callsIn(k.log); calls != "losetup -d "+killedLoop || k.loopAttached() {
				t.Fatalf("calls %q, loop attached %v; want only the detach, and the loop released", calls, k.loopAttached())
			}
			if fmt.Sprint(k.detached) != fmt.Sprint([]string{k.img}) {
				t.Fatalf("detached %v, want the map file's mount %s detached once", k.detached, k.img)
			}
			if exists(k.img) || exists(k.pidFile) || k.mounted(t) {
				t.Fatalf("map file kept %v, pid file kept %v, still mounted %v; want nothing of the map left", exists(k.img), exists(k.pidFile), k.mounted(t))
			}
			if !k.aborted(t) {
				t.Error("the dead daemon's FUSE connection was not aborted")
			}
			if phase := k.phase(t); phase != "cleaned" {
				t.Fatalf("phase = %q, want cleaned", phase)
			}
			if err := RecoverLocked(k.stateDir); err != nil {
				t.Fatalf("recovery of a cleaned journal: %v", err)
			}
		})
	}
}

// A mount that cannot be detached is reported, and the journal is not clean:
// recovery does not say the state is reconciled while the map's mount is there.
// The loop was released all the same.
func TestRecoverLockedReportsAReleasedMapWhoseMountCannotBeDetached(t *testing.T) {
	k := newKilledMap(t, 4242)
	old := detachMount
	t.Cleanup(func() { detachMount = old })
	detachMount = func(string) error { return syscall.EBUSY }

	err := RecoverLocked(k.stateDir)
	if err == nil || !strings.Contains(err.Error(), "released "+killedLoop+", but its PBS map's FUSE mount or files could not be removed") ||
		!strings.Contains(err.Error(), "detach the stale FUSE mount") || strings.Contains(err.Error(), "automation") {
		t.Fatalf("recovery = %v, want the mount that stayed reported, without the repository", err)
	}
	if k.loopAttached() || !exists(k.img) || !k.mounted(t) || k.phase(t) != "cleanup_failed" {
		t.Fatalf("loop attached %v, map file kept %v, mounted %v, phase %q; want the loop released, the map's files kept and the journal unclean",
			k.loopAttached(), exists(k.img), k.mounted(t), k.phase(t))
	}
}

// Only the run's own map is cleaned up. When the pid file names something that
// is not the run's map daemon, the loop is detached and nothing else is done:
// the map file, the pid file and the mount may be that process's.
func TestRecoverLockedLeavesTheFilesWhenThePidFileNamesAnotherProcess(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	for _, tc := range []struct {
		name string
		proc func(t *testing.T, root string)
	}{
		{"a CT backup has the PID", func(t *testing.T, root string) {
			fakeProc(t, root, 300, []string{"/usr/bin/proxmox-backup-client", "backup", "root.pxar:/", "--backup-type", "ct"}, at)
		}},
		{"a program that is not a PBS client has the PID", func(t *testing.T, root string) {
			fakeProc(t, root, 300, []string{"/usr/sbin/sshd"}, at)
		}},
		{"another operation's map of the same snapshot has the PID", func(t *testing.T, root string) {
			argv := []string{"/usr/bin/proxmox-backup-client", "map", "--repository", otherRepo, labSnapshot, labArchive}
			fakeMapProc(t, root, 300, argv, at.Add(time.Second), otherRepo, "", "")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKilledMap(t, 300)
			tc.proc(t, k.root)

			if err := RecoverLocked(k.stateDir); err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if calls := callsIn(k.log); calls != "losetup -d "+killedLoop || k.loopAttached() {
				t.Fatalf("calls %q, loop attached %v; want only the detach, and the loop released", calls, k.loopAttached())
			}
			if len(k.detached) != 0 || !exists(k.img) || !exists(k.pidFile) || !k.mounted(t) || !present(k.root, 300) {
				t.Fatalf("detached %v, map file kept %v, pid file kept %v, mounted %v, process kept %v; want the loop detached and nothing else touched",
					k.detached, exists(k.img), exists(k.pidFile), k.mounted(t), present(k.root, 300))
			}
			if phase := k.phase(t); phase != "cleaned" {
				t.Fatalf("phase = %q, want cleaned", phase)
			}
		})
	}
}

// What the pid file named when the loop was detached decides, not what it names
// afterwards: the other process that had the PID exits while the loop is
// released, and the files, which may have been its own, are still not touched.
func TestRecoverLockedLeavesTheFilesWhenTheOtherProcessExitsDuringTheRelease(t *testing.T) {
	k := newKilledMap(t, 300)
	fakeProc(t, k.root, 300, []string{"/usr/sbin/sshd"}, reaperBoot.Add(10*time.Hour))
	old := releaseLoopHolders
	t.Cleanup(func() { releaseLoopHolders = old })
	releaseLoopHolders = func(context.Context, string, []sysutil.LoopIdentity) ([]sysutil.LoopHolder, error) {
		if err := os.RemoveAll(filepath.Join(k.root, "300")); err != nil {
			t.Error(err)
		}
		return nil, nil
	}

	if err := RecoverLocked(k.stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if calls := callsIn(k.log); calls != "losetup -d "+killedLoop || k.loopAttached() {
		t.Fatalf("calls %q, loop attached %v; want only the detach, and the loop released", calls, k.loopAttached())
	}
	if len(k.detached) != 0 || !exists(k.img) || !exists(k.pidFile) || !k.mounted(t) || present(k.root, 300) {
		t.Fatalf("detached %v, map file kept %v, pid file kept %v, mounted %v, process kept %v; want the files left and the process gone",
			k.detached, exists(k.img), exists(k.pidFile), k.mounted(t), present(k.root, 300))
	}
}

// releaseLoop makes the loop leave the kernel, as a detach by an earlier
// recovery did.
func (k *killedMap) releaseLoop(t *testing.T) {
	t.Helper()
	if err := os.Remove(filepath.Join(k.maps.sysBlock, "loop2", "loop", "backing_file")); err != nil {
		t.Fatal(err)
	}
}

// A removal that failed is retried by the next recovery. The loop is gone by
// then, and the dead mount and the map files, still there, are still the run's
// to remove: the journal does not turn clean with the remnant in place.
func TestRecoverLockedRetriesTheRemovalOfAReleasedMapsFiles(t *testing.T) {
	k := newKilledMap(t, 4242)
	working := detachMount
	t.Cleanup(func() { detachMount = working })
	detachMount = func(string) error { return syscall.EBUSY }

	err := RecoverLocked(k.stateDir)
	if err == nil || !strings.Contains(err.Error(), "could not be removed") {
		t.Fatalf("first recovery = %v, want the mount that could not be detached reported", err)
	}
	if k.loopAttached() || !exists(k.img) || !k.mounted(t) || k.phase(t) != "cleanup_failed" {
		t.Fatalf("loop attached %v, map file kept %v, mounted %v, phase %q; want the loop released, the map's files kept and the journal unclean",
			k.loopAttached(), exists(k.img), k.mounted(t), k.phase(t))
	}

	detachMount = working
	if err := RecoverLocked(k.stateDir); err != nil {
		t.Fatalf("second recovery: %v", err)
	}
	if exists(k.img) || exists(k.pidFile) || k.mounted(t) || fmt.Sprint(k.detached) != fmt.Sprint([]string{k.img}) {
		t.Fatalf("map file kept %v, pid file kept %v, mounted %v, detached %v; want the retry to remove the mount and both files",
			exists(k.img), exists(k.pidFile), k.mounted(t), k.detached)
	}
	if calls := callsIn(k.log); calls != "losetup -d "+killedLoop || k.phase(t) != "cleaned" {
		t.Fatalf("calls %q, phase %q; want the loop detached once, by the first recovery, and the journal clean", calls, k.phase(t))
	}
}

// A recorded loop that is gone and a map that left nothing: the end state. No
// file is made or removed, and another map's files in the run directory are not
// touched.
func TestRecoverLockedAcceptsAGoneLoopWhoseMapLeftNothing(t *testing.T) {
	k := newKilledMap(t, 4242)
	k.releaseLoop(t)
	for _, path := range []string{k.img, k.pidFile, k.maps.mountInfo} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(k.maps.mountInfo, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	others := []string{filepath.Join(k.maps.runDir, "other-map.img"), filepath.Join(k.maps.runDir, "other-map.pid")}
	for _, path := range others {
		if err := os.WriteFile(path, []byte("4343\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if err := RecoverLocked(k.stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if calls := callsIn(k.log); calls != "" || k.phase(t) != "cleaned" {
		t.Fatalf("calls %q, phase %q; want no command run and the journal clean", calls, k.phase(t))
	}
	entries, err := os.ReadDir(k.maps.runDir)
	if err != nil || len(entries) != len(others) || !exists(others[0]) || !exists(others[1]) {
		t.Fatalf("run directory = %v, %v; want only the other map's two files", entries, err)
	}
}

// A gone loop is no reason to touch a map that something else may be serving: a
// live client under the pid file (the run's own daemon, which still runs, or
// another operation's map), a pid file that names another program or no
// process, or cannot be read. The files and the mount stay, and the recovery,
// which succeeds without this step, succeeds.
func TestRecoverLockedLeavesTheFilesOfAGoneLoopsMapThatIsNotShownToBeDead(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	ownArgv := []string{"/usr/bin/proxmox-backup-client", "map", "--repository", ownRepo, "--ns", "team-a", labSnapshot, labArchive}
	otherArgv := []string{"/usr/bin/proxmox-backup-client", "map", "--repository", otherRepo, labSnapshot, labArchive}
	for _, tc := range []struct {
		name string
		set  func(t *testing.T, k *killedMap)
		live bool // the process under PID 300 stays
	}{
		{"the run's own daemon still runs", func(t *testing.T, k *killedMap) {
			fakeMapProc(t, k.root, 300, ownArgv, at.Add(time.Second), ownRepo, "team-a", ownToken)
		}, true},
		{"another operation's map runs", func(t *testing.T, k *killedMap) {
			fakeMapProc(t, k.root, 300, otherArgv, at.Add(time.Second), otherRepo, "", "")
		}, true},
		{"a CT backup has the PID", func(t *testing.T, k *killedMap) {
			fakeProc(t, k.root, 300, []string{"/usr/bin/proxmox-backup-client", "backup", "root.pxar:/", "--backup-type", "ct"}, at)
		}, true},
		{"a program that is not a PBS client has the PID", func(t *testing.T, k *killedMap) {
			fakeProc(t, k.root, 300, []string{"/usr/sbin/sshd"}, at)
		}, true},
		{"the pid file names no process", func(t *testing.T, k *killedMap) {
			if err := os.WriteFile(k.pidFile, []byte("not-a-pid\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"the pid file cannot be read", func(t *testing.T, k *killedMap) {
			if err := os.Remove(k.pidFile); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(k.pidFile, 0o755); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKilledMap(t, 300)
			tc.set(t, k)
			k.releaseLoop(t)

			if err := RecoverLocked(k.stateDir); err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if len(k.detached) != 0 || !exists(k.img) || !exists(k.pidFile) || !k.mounted(t) || (tc.live && !present(k.root, 300)) {
				t.Fatalf("detached %v, map file kept %v, pid file kept %v, mounted %v, process kept %v; want nothing touched",
					k.detached, exists(k.img), exists(k.pidFile), k.mounted(t), present(k.root, 300))
			}
			if calls := callsIn(k.log); calls != "" || k.phase(t) != "cleaned" {
				t.Fatalf("calls %q, phase %q; want no command run and the journal clean", calls, k.phase(t))
			}
		})
	}
}

// Maps made over a dead one stack their mounts on one path, and one detach
// takes off the top one only. removeMapFiles detaches again while the path is
// still mounted, at most eight times, then reports it.
func TestRemoveMapFilesDetachesStackedMounts(t *testing.T) {
	for _, tc := range []struct {
		name           string
		stacked, calls int
		stays          bool
	}{
		{"one mount", 1, 1, false},
		{"three stacked mounts", 3, 3, false},
		{"eight stacked mounts", 8, 8, false},
		{"nine stacked mounts", 9, 8, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			maps := hostWithProcs(t, t.TempDir(), noSignal(t))
			finder := leakFinder{sysBlock: maps.sysBlock, runDir: maps.runDir, mountInfo: maps.mountInfo, fuseConns: t.TempDir()}
			backing := filepath.Join(maps.runDir, "stacked-vm-100.img")
			pidFile := strings.TrimSuffix(backing, ".img") + ".pid"
			for path, content := range map[string]string{backing: "", pidFile: "4242\n"} {
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			// The table lists the path once for each mount on it; a detach takes one off.
			stacked := tc.stacked
			writeTable := func() {
				var table strings.Builder
				for i := 0; i < stacked; i++ {
					fmt.Fprintf(&table, "%d 30 0:%d / %s rw - fuse proxmox-backup-client rw\n", 800+i, 70+i, backing)
				}
				if err := os.WriteFile(maps.mountInfo, []byte(table.String()), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			writeTable()
			calls := 0
			old := detachMount
			t.Cleanup(func() { detachMount = old })
			detachMount = func(path string) error {
				if path != backing {
					t.Errorf("detached %s, want the map file's path", path)
				}
				calls++
				if stacked > 0 {
					stacked--
				}
				writeTable()
				return nil
			}

			err := removeMapFiles(finder, journal.MapIntent{NameSuffix: "-vm-100.img"}, backing)
			if calls != tc.calls {
				t.Errorf("%d detaches, want %d", calls, tc.calls)
			}
			if tc.stays {
				if err == nil || !strings.Contains(err.Error(), "is still mounted; detach it with umount -l") || !exists(backing) || !exists(pidFile) {
					t.Fatalf("removeMapFiles = %v, map file kept %v, pid file kept %v; want the mount that stayed reported and the files kept", err, exists(backing), exists(pidFile))
				}
				return
			}
			if err != nil || exists(backing) || exists(pidFile) {
				t.Fatalf("removeMapFiles = %v, map file kept %v, pid file kept %v; want every mount detached and both files removed", err, exists(backing), exists(pidFile))
			}
		})
	}
}

// The files are the PBS map's only in the map run directory: a loop the journal
// recorded on a file anywhere else is not a loop a run made. It is left
// attached, that file and its pid file are not touched, and the journal is
// kept.
func TestRecoverLockedTouchesNoFileOutsideTheMapRunDirectory(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	h := newLabHost(t, root)
	outside := filepath.Join(t.TempDir(), "map.img")
	pidFile := strings.TrimSuffix(outside, ".img") + ".pid"
	for path, content := range map[string]string{outside: "", pidFile: "4242\n"} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h.maps.add("loop2", filepath.Dir(outside), "map.img", time.Time{})
	h.mount(t, outside)
	log := installLabTools(t, h.maps.sysBlock, false)
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: killedLoop, Backing: outside}})

	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "left "+killedLoop+" attached: the journal records it on "+outside+", which is not a PBS map file") {
		t.Fatalf("recovery = %v, want the loop left attached and said why", err)
	}
	if calls := callsIn(log); calls != "" {
		t.Fatalf("calls %q, want none", calls)
	}
	if len(h.detached) != 0 || !exists(outside) || !exists(pidFile) || phaseOf(t, path) != "cleanup_failed" {
		t.Fatalf("detached %v, file kept %v, pid file kept %v, phase %q; want nothing touched and the journal kept",
			h.detached, exists(outside), exists(pidFile), phaseOf(t, path))
	}
}

// The daemon was dead when recovery looked, and another map of the same
// snapshot and archive has come up under the pid file by the time the loop is
// released. Its files are not the dead daemon's: they stay, and the release
// is complete.
func TestRecoverLockedLeavesTheFilesOfAReleasedMapThatAnotherMapNowServes(t *testing.T) {
	k := newKilledMap(t, 4242)
	old := releaseLoopHolders
	t.Cleanup(func() { releaseLoopHolders = old })
	releaseLoopHolders = func(context.Context, string, []sysutil.LoopIdentity) ([]sysutil.LoopHolder, error) {
		argv := []string{"/usr/bin/proxmox-backup-client", "map", "--repository", otherRepo, labSnapshot, labArchive}
		fakeMapProc(t, k.root, 300, argv, reaperBoot.Add(11*time.Hour), otherRepo, "", "")
		if err := os.WriteFile(k.pidFile, []byte("300\n"), 0o644); err != nil {
			t.Error(err)
		}
		return nil, nil
	}

	if err := RecoverLocked(k.stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if calls := callsIn(k.log); calls != "losetup -d "+killedLoop || k.loopAttached() {
		t.Fatalf("calls %q, loop attached %v; want only the detach, and the loop released", calls, k.loopAttached())
	}
	if len(k.detached) != 0 || !exists(k.img) || !exists(k.pidFile) || !k.mounted(t) || !present(k.root, 300) {
		t.Fatalf("detached %v, map file kept %v, pid file kept %v, mounted %v, process kept %v; want the live map left as it is",
			k.detached, exists(k.img), exists(k.pidFile), k.mounted(t), present(k.root, 300))
	}
	if phase := k.phase(t); phase != "cleaned" {
		t.Fatalf("phase = %q, want cleaned", phase)
	}
}
