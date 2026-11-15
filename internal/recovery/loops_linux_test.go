//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

// fakeLoopTools installs a proxmox-backup-client and a losetup that only log
// their calls (the client then runs clientBody), and makes them the only
// commands on PATH: no real loop device or map is ever touched. It returns the
// log's path.
func fakeLoopTools(t *testing.T, clientBody string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	// A command that succeeds releases the loop as the kernel would: its sysfs
	// entry goes (the sysfs is sysutil.SysBlockDir, which hostWithProcs points at
	// the fake host's).
	forget := "[ \"$1\" = -d ] && /bin/rm -f '" + sysutil.SysBlockDir + "'/\"${2##*/}\"/loop/backing_file"
	client := "#!/bin/sh\nprintf 'proxmox-backup-client %s\\n' \"$*\" >> '" + log + "'\n(" + clientBody + "\n)\nrc=$?\n[ $rc -eq 0 ] && [ \"$1\" = unmap ] && /bin/rm -f '" + sysutil.SysBlockDir + "'/\"${2##*/}\"/loop/backing_file\nexit $rc\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(client), 0o755); err != nil {
		t.Fatal(err)
	}
	losetup := "#!/bin/sh\nprintf 'losetup %s\\n' \"$*\" >> '" + log + "'\n" + forget + "\n"
	if err := os.WriteFile(filepath.Join(dir, "losetup"), []byte(losetup), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return log
}

// callsIn is what the fake commands were asked, one line each.
func callsIn(log string) string {
	data, _ := os.ReadFile(log)
	return strings.TrimSpace(string(data))
}

// journalOf writes a journal at stateDir holding the given loops and the
// intents (resolved ones name their device).
func journalOf(t *testing.T, stateDir string, loops []journal.TrackedLoop, intents ...journal.MapIntent) string {
	t.Helper()
	path := filepath.Join(stateDir, "active.json")
	if err := journal.Write(path, journal.Record{RunID: "loops", Phase: "cleanup_failed", Loops: loops, MapIntents: intents}); err != nil {
		t.Fatal(err)
	}
	return path
}

// phaseOf is the journal's phase after a recovery.
func phaseOf(t *testing.T, path string) string {
	t.Helper()
	record, err := journal.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return record.Phase
}

// resolvedIntent is ownIntent whose map became device.
func resolvedIntent(at time.Time, device string) journal.MapIntent {
	intent := ownIntent(at)
	intent.Device = device
	return intent
}

// The run's map is gone and its loop number is another file's now.
// Recovery of the recorded loop detaches nothing and signals nothing, says the
// device is no longer the run's, and, when nothing of the run's map remains,
// is complete.
func TestRecoverLockedLeavesAReusedLoopAlone(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	maps := hostWithProcs(t, root, noSignal(t))
	log := fakeLoopTools(t, "exit 19")
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", "/elsewhere", "foreign-map.img", time.Time{}) // now another map's
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, resolvedIntent(at, "/dev/loop7"))

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery = %v, want it complete: nothing of the run's map remains", err)
	}
	if calls := callsIn(log); calls != "" {
		t.Fatalf("commands ran against another file's loop:\n%s", calls)
	}
	if phase := phaseOf(t, path); phase != "cleaned" {
		t.Fatalf("phase = %q, want cleaned", phase)
	}
}

// The same, when something of the run's map remains: its daemon still
// runs under the map's pid file, or its FUSE mount is still there. Not clean:
// the loop is still left alone.
func TestRecoverLockedReportsWhatRemainsOfAMapWhoseLoopWasReused(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(t *testing.T, root, recorded, mountInfo string)
		want string
	}{
		{"its daemon runs", func(t *testing.T, root, recorded, _ string) {
			fakeMapProc(t, root, 500, mapArgv(ownRepo), reaperBoot.Add(10*time.Hour), ownRepo, "team-a", ownToken)
			if err := os.WriteFile(strings.TrimSuffix(recorded, ".img")+".pid", []byte("500\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "a proxmox-backup-client (PID 500) still runs"},
		{"its mount remains", func(t *testing.T, _, recorded, mountInfo string) {
			table := "812 30 0:77 / " + strings.ReplaceAll(recorded, `\`, `\134`) + " rw - fuse proxmox-backup-client rw\n"
			if err := os.WriteFile(mountInfo, []byte(table), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "its FUSE mount is still there"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, stateDir := t.TempDir(), t.TempDir()
			at := reaperBoot.Add(10 * time.Hour)
			maps := hostWithProcs(t, root, noSignal(t))
			log := fakeLoopTools(t, "exit 19")
			recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
			tc.set(t, root, recorded, maps.mountInfo)
			maps.add("loop7", "/elsewhere", "foreign-map.img", time.Time{})
			path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, resolvedIntent(at, "/dev/loop7"))

			err := RecoverLocked(stateDir)
			if err == nil || !strings.Contains(err.Error(), "/dev/loop7 backs another file now") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("recovery = %v, want it incomplete: %s", err, tc.want)
			}
			if calls := callsIn(log); calls != "" || phaseOf(t, path) != "cleanup_failed" {
				t.Fatalf("calls:\n%s\nphase %q; want nothing run and the journal kept", calls, phaseOf(t, path))
			}
		})
	}
}

// An identity that cannot be established is not a reason to detach:
// the kernel's answer unreadable, or no identity recorded for a device that is
// attached.
func TestRecoverLockedLeavesALoopWhoseIdentityIsNotKnown(t *testing.T) {
	for name, tc := range map[string]struct {
		unreadable bool
		recorded   string
	}{
		"the backing cannot be read": {unreadable: true, recorded: "/run/pbs-loopdev/x.img"},
		"no identity was recorded":   {recorded: ""},
		"a whitespace-only identity": {recorded: "  "},
	} {
		t.Run(name, func(t *testing.T) {
			root, stateDir := t.TempDir(), t.TempDir()
			at := reaperBoot.Add(10 * time.Hour)
			maps := hostWithProcs(t, root, noSignal(t))
			log := fakeLoopTools(t, "exit 0")
			maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
			if tc.unreadable {
				backing := filepath.Join(maps.sysBlock, "loop7", "loop", "backing_file")
				if err := os.Remove(backing); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(backing, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: tc.recorded}}, resolvedIntent(at, "/dev/loop7"))
			err := RecoverLocked(stateDir)
			if err == nil || !strings.Contains(err.Error(), "inspect recorded loop device /dev/loop7") {
				t.Fatalf("recovery = %v, want the loop reported as not known", err)
			}
			if calls := callsIn(log); calls != "" || phaseOf(t, path) != "cleanup_failed" {
				t.Fatalf("calls:\n%s\nphase %q; want nothing run and the journal kept", calls, phaseOf(t, path))
			}
		})
	}
}

// A recorded loop that is gone is the end state; the run's own loop is
// released.
func TestRecoverLockedReleasesTheRunsOwnLoopAndAcceptsAGoneOne(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	maps := hostWithProcs(t, root, noSignal(t))
	log := fakeLoopTools(t, "exit 19") // the client's unmap is never run: only the detach releases the loop
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}, {Device: "/dev/loop8", Backing: recorded}}, resolvedIntent(at, "/dev/loop7"))
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if calls := callsIn(log); calls != "losetup -d /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant the verified detach for /dev/loop7 only: the map has no daemon to stop", calls)
	}
	if phase := phaseOf(t, path); phase != "cleaned" {
		t.Fatalf("phase = %q", phase)
	}
}

// The number of the loop is another map's the moment the daemon has exited and
// released it: between the stop and the detach. Recovery then detaches nothing,
// and, as nothing of the run's map remains, is complete. (Before, the same
// reuse between the client's refusal and the fallback detach.)
func TestRecoverLockedRechecksBeforeTheDetachThatFollowsTheDaemonsStop(t *testing.T) {
	signalFile := filepath.Join(t.TempDir(), "signal")
	root, stateDir := t.TempDir(), t.TempDir()
	real := realReaper()
	maps := hostWithProcs(t, root, noSignal(t))
	hostMapReaper = real
	recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
	sysfs := filepath.Join(maps.sysBlock, "loop7", "loop", "backing_file")
	daemon := startFakeClient(t, "record", realMapArgv(ownRepo), append(realMapEnv(ownRepo, "team-a", ownToken),
		fakeClientSignalFile+"="+signalFile,
		fakeClientOnSignalFile+"="+sysfs, fakeClientOnSignalText+"=/elsewhere/foreign-map.img\n"))
	if err := os.WriteFile(strings.TrimSuffix(recorded, ".img")+".pid", []byte(strconv.Itoa(daemon.id.PID)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	log := fakeLoopTools(t, "exit 19")
	intent := intentFor(t, daemon)
	intent.Device = "/dev/loop7"
	path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, intent)
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if !daemon.exited(5 * time.Second) {
		t.Fatal("the daemon was not stopped")
	}
	if calls := callsIn(log); calls != "" {
		t.Fatalf("calls:\n%s\nwant nothing run: the device was another file's before the detach", calls)
	}
	if phase := phaseOf(t, path); phase != "cleaned" {
		t.Fatalf("phase = %q", phase)
	}
}

// The map's daemon is stopped only when it is the run's own, and by recovery
// itself: the client's unmap, which signals the PID in the map's pid file
// unchecked, is never run. A PID that another PBS client (a CT backup, a
// restore, another operation's map) has now is not the run's daemon: nothing is
// signalled, and the loop is only detached. The run's own daemon, by its token,
// is sent SIGINT through a pidfd (the process that stands in for it here, as a
// fake PID has none), then the loop is detached.
func TestRecoverLockedStopsTheMapDaemonOnlyWhenItIsTheRunsOwn(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	for _, tc := range []struct {
		name      string
		proc      func(t *testing.T, root string)
		intent    func(journal.MapIntent) journal.MapIntent
		stops     bool
		wantError string
	}{
		{"a CT backup has the PID", func(t *testing.T, root string) {
			fakeProc(t, root, 300, []string{"/usr/bin/proxmox-backup-client", "backup", "root.pxar:/", "--backup-type", "ct"}, at)
		}, nil, false, ""},
		{"a restore has the PID", func(t *testing.T, root string) {
			fakeProc(t, root, 300, []string{"/usr/bin/proxmox-backup-client", "restore", mapSnapshot, mapArchive, "map"}, at)
		}, nil, false, ""},
		{"another operation's map has the PID", func(t *testing.T, root string) {
			fakeMapProc(t, root, 300, mapArgv(otherRepo), at, otherRepo, "", "")
		}, nil, false, ""},
		{"a map of the run's source without its token has the PID", func(t *testing.T, root string) {
			fakeMapProc(t, root, 300, mapArgv(ownRepo), at, ownRepo, "team-a", "")
		}, nil, false, ""},
		{"a program that is not a PBS client has the PID", func(t *testing.T, root string) {
			fakeProc(t, root, 300, []string{"/usr/sbin/sshd"}, at)
		}, nil, false, ""},
		{"the run's own daemon has the PID", func(t *testing.T, root string) {
			fakeMapProc(t, root, 300, mapArgv(ownRepo), at, ownRepo, "team-a", ownToken)
		}, nil, true, ""},
		{"an earlier version's journal: the exact map of the snapshot and archive has the PID", func(t *testing.T, root string) {
			fakeMapProc(t, root, 300, mapArgv(ownRepo), at, ownRepo, "team-a", "")
		}, func(i journal.MapIntent) journal.MapIntent { i.Token, i.Owner = "", ""; return i }, true, ""},
		{"the PID's environment cannot be read", func(t *testing.T, root string) {
			fakeMapProc(t, root, 300, mapArgv(ownRepo), at, ownRepo, "team-a", ownToken)
			if err := os.Remove(filepath.Join(root, "300", "environ")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(root, "300", "environ"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, nil, false, "environment of PID 300"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, stateDir := t.TempDir(), t.TempDir()
			maps := hostWithProcs(t, root, noSignal(t))
			standIn := standInForDaemon(t)
			hostMapReaper.pidfdOpen = standIn.open
			log := fakeLoopTools(t, "exit 0")
			recorded := filepath.Join(maps.runDir, "repo"+scsi1Tail)
			maps.add("loop7", maps.runDir, "repo"+scsi1Tail, time.Time{})
			if err := os.WriteFile(strings.TrimSuffix(recorded, ".img")+".pid", []byte("300\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			tc.proc(t, root)
			intent := resolvedIntent(at, "/dev/loop7")
			if tc.intent != nil {
				intent = tc.intent(intent)
			}
			path := journalOf(t, stateDir, []journal.TrackedLoop{{Device: "/dev/loop7", Backing: recorded}}, intent)
			err := RecoverLocked(stateDir)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || callsIn(log) != "" || standIn.opened != 0 {
					t.Fatalf("recovery = %v, calls %q, pidfds %d; want it incomplete (%s), nothing run or signalled", err, callsIn(log), standIn.opened, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if calls := callsIn(log); calls != "losetup -d /dev/loop7" {
				t.Fatalf("calls:\n%s\nwant the verified detach only: the client's unmap is never run", calls)
			}
			want := ""
			if tc.stops {
				want = "interrupt"
			}
			if got := standIn.signalled(); got != want {
				t.Fatalf("the process under the PID received %q, want %q", got, want)
			}
			if (standIn.opened == 1) != tc.stops {
				t.Fatalf("%d pidfd(s) opened, want one exactly when the run's own daemon is stopped (%v)", standIn.opened, tc.stops)
			}
			if phase := phaseOf(t, path); phase != "cleaned" {
				t.Fatalf("phase = %q", phase)
			}
		})
	}
}

// What the guard says, on its own.
func TestUnmapGuardForTellsWhatTheClientWouldSignal(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	fakeProc(t, root, 301, []string{"/usr/sbin/sshd"}, at)
	fakeMapProc(t, root, 302, mapArgv(ownRepo), at, ownRepo, "team-a", ownToken)
	fakeMapProc(t, root, 303, mapArgv(ownRepo), at, ownRepo, "team-a", otherToken)
	// A run gives its map --ns: that map is the run's own daemon, while a command
	// with two --ns is not in CertiStack's form at all.
	fakeMapProc(t, root, 305, []string{"/usr/bin/proxmox-backup-client", "map", "--repository", ownRepo, "--ns", "team-a", mapSnapshot, mapArchive}, at, ownRepo, "team-a", ownToken)
	fakeMapProc(t, root, 306, []string{"/usr/bin/proxmox-backup-client", "map", "--repository", ownRepo, "--ns", "team-a", "--ns", "team-b", mapSnapshot, mapArchive}, at, ownRepo, "team-a", ownToken)
	fakeProc(t, root, 304, []string{"/usr/bin/proxmox-backup-client", "map", "a", "b"}, at)
	if err := os.Remove(filepath.Join(root, "304", "cmdline")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "304", "cmdline"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(filepath.Join(root, "304", "cmdline"), os.O_RDWR, 0); err == nil {
			time.Sleep(50 * time.Millisecond)
			f.Close()
		}
	})
	r := testReaper(root, noSignal(t))
	r.readTimeout = 100 * time.Millisecond
	intent := ownIntent(at)
	dir := t.TempDir()
	backing := filepath.Join(dir, "map.img")
	for _, tc := range []struct {
		pidFile *string
		want    unmapGuard
	}{
		{nil, unmapStopDaemon},           // no pid file
		{ptr("junk\n"), unmapDetachOnly}, // names no process
		{ptr("1\n"), unmapDetachOnly},    //
		{ptr("299\n"), unmapStopDaemon},  // nobody has the PID
		{ptr("301\n"), unmapDetachOnly},  // another program
		{ptr("302\n"), unmapStopDaemon},  // the run's own daemon
		{ptr("303\n"), unmapDetachOnly},  // another map's token
		{ptr("304\n"), unmapUnknown},     // cannot be read
		{ptr("305\n"), unmapStopDaemon},  // the run's own daemon, started with --ns
		{ptr("306\n"), unmapDetachOnly},  // two --ns: not a map CertiStack starts
	} {
		_ = os.Remove(filepath.Join(dir, "map.pid"))
		name := "absent"
		if tc.pidFile != nil {
			name = strings.TrimSpace(*tc.pidFile)
			if err := os.WriteFile(filepath.Join(dir, "map.pid"), []byte(*tc.pidFile), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if got, why := r.unmapGuardFor(backing, intent); got != tc.want {
			t.Errorf("pid file %s: guard = %v (%s), want %v", name, got, why, tc.want)
		}
	}
	// A pid file that cannot be read.
	pidFile := filepath.Join(dir, "map.pid")
	_ = os.Remove(pidFile)
	if err := os.Mkdir(pidFile, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.unmapGuardFor(backing, intent); got != unmapUnknown {
		t.Errorf("an unreadable pid file: guard = %v, want unknown", got)
	}
}

func ptr(s string) *string { return &s }

// A journaled PID that a live proxmox-backup-client of another operation
// has now is not the run's process: the pid file that names it is that
// daemon's own, and its loop is reported, never detached.
func TestRecoverLockedNeverClaimsTheLoopOfAMapThatHasAJournaledPID(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	intent.AddProcess(journal.Process{PID: 4242, StartTicks: "1"}) // the run's daemon, gone
	fakeMapProc(t, root, 4242, mapArgv(otherRepo), at.Add(90*time.Second), otherRepo, "", "")
	maps := hostWithProcs(t, root, noSignal(t))
	log := fakeLoopTools(t, "exit 0")
	maps.addPID("loop5", maps.runDir, "repository-b"+scsi1Tail, at.Add(91*time.Second), 4242)
	path := journalOf(t, stateDir, nil, intent)

	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "/dev/loop5") || !strings.Contains(err.Error(), "4242") {
		t.Fatalf("recovery = %v, want /dev/loop5 reported", err)
	}
	if calls := callsIn(log); calls != "" || phaseOf(t, path) != "cleanup_failed" {
		t.Fatalf("calls:\n%s\nphase %q; want another operation's live map left alone", calls, phaseOf(t, path))
	}
}

// Removing a map's files never aborts the FUSE connection of, or unmounts,
// a map a live proxmox-backup-client serves.
func TestRemoveMapFilesRefusesAMapALiveClientServes(t *testing.T) {
	root := t.TempDir()
	fakeMapProc(t, root, 600, mapArgv(otherRepo), reaperBoot.Add(time.Hour), otherRepo, "", "")
	maps := hostWithProcs(t, root, noSignal(t))
	backing := filepath.Join(maps.runDir, "repo"+scsi1Tail)
	pidFile := strings.TrimSuffix(backing, ".img") + ".pid"
	for _, file := range []string{backing, pidFile} {
		if err := os.WriteFile(file, []byte("600\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := removeMapFiles(hostLeakFinder, ownIntent(reaperBoot.Add(time.Hour)), backing)
	if err == nil || !strings.Contains(err.Error(), "live proxmox-backup-client") || strings.Contains(err.Error(), "repo") {
		t.Fatalf("removeMapFiles = %v, want it refused, without the repository", err)
	}
	for _, file := range []string{backing, pidFile} {
		if _, err := os.Stat(file); err != nil {
			t.Errorf("%s was removed", filepath.Base(file))
		}
	}
}

// The run's own daemon is stopped and its pid file names it, but the file
// was written more than the window after the intent (a slow map): its loop is
// the run's, and released, not dropped.
func TestRecoverLockedClaimsTheLoopOfTheRunsDaemonWhoseLatePidFile(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	var signalled []int
	maps := hostWithProcs(t, root, func(p journal.Process, _ syscall.Signal) error {
		signalled = append(signalled, p.PID)
		return os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID))) // killed mid-cleanup: loop and pid file stay
	})
	log := fakeLoopTools(t, "exit 0")
	maps.addPID("loop7", maps.runDir, "repo"+scsi1Tail, at.Add(4*time.Minute), 100)
	path := journalOf(t, stateDir, nil, ownIntent(at))

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if fmt.Sprint(signalled) != "[100]" || callsIn(log) != "losetup -d /dev/loop7" {
		t.Fatalf("signalled %v, calls:\n%s\nwant the daemon stopped and its loop released", signalled, callsIn(log))
	}
	if phase := phaseOf(t, path); phase != "cleaned" {
		t.Fatalf("phase = %q", phase)
	}
}

// A process that carries the run's token is the run's, whenever it
// started: the start is btime plus ticks, and btime moves with the wall clock.
// It is stopped, journaled, and its loop released; if it cannot be stopped the
// journal is not cleaned.
func TestRecoverLockedStopsTheRunsTokenProcessOutsideTheWindow(t *testing.T) {
	for _, started := range []time.Duration{-5 * time.Second, 10 * time.Minute} {
		t.Run(started.String(), func(t *testing.T) {
			root, stateDir := t.TempDir(), t.TempDir()
			at := reaperBoot.Add(10 * time.Hour)
			fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(started), ownRepo, "team-a", ownToken)
			var signalled []int
			maps := hostWithProcs(t, root, func(p journal.Process, _ syscall.Signal) error {
				signalled = append(signalled, p.PID)
				return os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID)))
			})
			log := fakeLoopTools(t, "exit 0")
			maps.addPID("loop7", maps.runDir, "repo"+scsi1Tail, at.Add(20*time.Second), 100)
			path := journalOf(t, stateDir, nil, ownIntent(at))
			if err := RecoverLocked(stateDir); err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if fmt.Sprint(signalled) != "[100]" || callsIn(log) != "losetup -d /dev/loop7" || phaseOf(t, path) != "cleaned" {
				t.Fatalf("signalled %v, calls:\n%s\nphase %q; want the daemon stopped and its loop released", signalled, callsIn(log), phaseOf(t, path))
			}
		})
	}

	// Not stoppable: not clean, and the process is journaled.
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(-5*time.Second), ownRepo, "team-a", ownToken)
	hostWithProcs(t, root, func(journal.Process, syscall.Signal) error { return syscall.EPERM })
	path := journalOf(t, stateDir, nil, ownIntent(at))
	if err := RecoverLocked(stateDir); err == nil || !strings.Contains(err.Error(), "PBS map process 100") {
		t.Fatalf("recovery = %v, want the surviving process reported", err)
	}
	record, _ := journal.Load(path)
	if record.Phase == "cleaned" || len(record.MapIntents[0].Processes) != 1 {
		t.Fatalf("journal = %+v", record)
	}
}

// Without the token the window still tells a heuristic apart: a process
// that started outside it is not the run's map, one inside it may be and is
// reported.
func TestMapReaperKeepsTheWindowForProcessesWithoutTheToken(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(-time.Hour), ownRepo, "team-a", "")
	fakeMapProc(t, root, 101, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", "")
	err := testReaper(root, noSignal(t)).stop(&intent, nil)
	if err == nil || !strings.Contains(err.Error(), "process 101") || strings.Contains(err.Error(), "process 100") {
		t.Fatalf("stop = %v, want only the process inside the window reported", err)
	}
}

// A leftover without a pid file whose owner cannot be established is
// reported, whether or not a look-alike map runs: it is not dropped because
// something that resembles the run's map runs.
func TestRecoverLockedReportsAPidlessLeftoverWhateverRuns(t *testing.T) {
	for _, withOther := range []bool{false, true} {
		t.Run(fmt.Sprint("other map running=", withOther), func(t *testing.T) {
			root, stateDir := t.TempDir(), t.TempDir()
			at := reaperBoot.Add(10 * time.Hour)
			if withOther {
				fakeMapProc(t, root, 700, []string{"/usr/bin/proxmox-backup-client", "map", "--repository", otherRepo, "--ns", "x", mapSnapshot, mapArchive}, at.Add(-time.Hour), otherRepo, "", "")
			}
			maps := hostWithProcs(t, root, noSignal(t))
			mounted := filepath.Join(maps.runDir, "secretrepo"+scsi1Tail)
			if err := os.WriteFile(mounted, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			table := "812 30 0:77 / " + strings.ReplaceAll(mounted, `\`, `\134`) + " rw - fuse proxmox-backup-client rw\n"
			if err := os.WriteFile(maps.mountInfo, []byte(table), 0o644); err != nil {
				t.Fatal(err)
			}
			path := journalOf(t, stateDir, nil, ownIntent(at))
			err := RecoverLocked(stateDir)
			if err == nil || !strings.Contains(err.Error(), "has no pid file") || strings.Contains(err.Error(), "secretrepo") || phaseOf(t, path) != "cleanup_failed" {
				t.Fatalf("recovery = %v, phase %q; want the leftover reported and the journal kept", err, phaseOf(t, path))
			}
			if _, err := os.Stat(mounted); err != nil {
				t.Fatal("the leftover was removed")
			}
		})
	}
}

// A pid file that names a process whose command line never answers does
// not hang the search for leftovers, and does not make the process dead.
func TestFindReadsTheDaemonThroughTheBoundedReader(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeProc(t, root, 500, []string{"/usr/bin/proxmox-backup-client", "map", "x", "y"}, at.Add(time.Second))
	cmdline := filepath.Join(root, "500", "cmdline")
	if err := os.Remove(cmdline); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(cmdline, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(cmdline, os.O_RDWR, 0); err == nil {
			time.Sleep(50 * time.Millisecond)
			f.Close()
		}
	})
	maps := hostWithProcs(t, root, noSignal(t))
	hostMapReaper.readTimeout = 100 * time.Millisecond
	maps.addPID("loop5", maps.runDir, "repo"+scsi1Tail, at.Add(2*time.Second), 500)
	finder := leakFinder{sysBlock: maps.sysBlock, runDir: maps.runDir, mountInfo: maps.mountInfo}

	type answer struct {
		leaked []LeakedMap
		errs   []error
		alive  bool
	}
	done := make(chan answer, 1)
	go func() {
		leaked, errs := finder.find(intent, nil, hostMapReaper.evidence(intent, false))
		done <- answer{leaked, errs, mapDaemonAlive(filepath.Join(maps.runDir, "repo"+scsi1Tail))}
	}()
	select {
	case got := <-done:
		if len(got.leaked) != 0 || len(got.errs) != 1 || !got.alive {
			t.Fatalf("leaked %v, errs %v, alive %v; want the loop reported, not claimed, and the daemon not called dead", got.leaked, got.errs, got.alive)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("find still blocked: a /proc read has no timeout")
	}
}

// Of the journal: processes journaled in an earlier boot do not run. A
// recorded boot that is not this one drops them, whatever runs under their
// PIDs now; the journal is written with this boot.
func TestMapReaperIgnoresJournaledProcessesOfAnEarlierBoot(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	setBoot := func(id string) {
		dir := filepath.Join(root, "sys", "kernel", "random")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "boot_id"), []byte(id+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	setBoot("boot-two")
	// PID 100 is a map of the same snapshot and archive now, with the journaled
	// start time: only the boot tells it from the run's earlier process.
	fakeMapProc(t, root, 100, mapArgv(otherRepo), at.Add(time.Second), otherRepo, "", "")
	self, err := statIdentity(root, 100)
	if err != nil {
		t.Fatal(err)
	}
	intent := ownIntent(at)
	intent.BootID = "boot-one"
	intent.AddProcess(self)
	r := testReaper(root, noSignal(t))
	if err := r.stop(&intent, nil); err != nil {
		t.Fatalf("stop = %v, want the foreign map left alone and nothing reported", err)
	}
	if ev := r.evidence(intent, false); len(ev.ours) != 0 {
		t.Fatalf("evidence names %v from an earlier boot", ev.ours)
	}

	// The run's own map now: journaled with this boot, and the earlier boot's
	// processes gone from the record.
	fakeMapProc(t, root, 200, mapArgv(ownRepo), at.Add(2*time.Second), ownRepo, "team-a", ownToken)
	persisted := 0
	r.signal = exits(root)
	if err := r.stop(&intent, func() error { persisted++; return nil }); err != nil {
		t.Fatal(err)
	}
	if intent.BootID != "boot-two" || len(intent.Processes) != 1 || intent.Processes[0].PID != 200 || persisted != 1 {
		t.Fatalf("intent = %+v, persisted %d; want boot-two and only process 200", intent, persisted)
	}
}

// A journaled process whose command line cannot be read is still signalled:
// it may run, and the signal goes through a pidfd only after the PID and start
// time are checked again. It is reported while it survives.
func TestMapReaperSignalsAJournaledProcessWhoseCommandLineCannotBeRead(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	self, err := statIdentity(root, 100)
	if err != nil {
		t.Fatal(err)
	}
	cmdline := filepath.Join(root, "100", "cmdline")
	if err := os.Remove(cmdline); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cmdline, 0o755); err != nil { // cannot be read
		t.Fatal(err)
	}
	intent := ownIntent(at)
	intent.AddProcess(self)
	var sent []syscall.Signal
	r := testReaper(root, func(_ journal.Process, sig syscall.Signal) error { sent = append(sent, sig); return nil })
	err = r.stop(&intent, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot read the command line of PBS map process 100") || !strings.Contains(err.Error(), "still runs") {
		t.Fatalf("stop = %v, want the unreadable process reported as running", err)
	}
	if fmt.Sprint(sent) != fmt.Sprint([]syscall.Signal{syscall.SIGINT, syscall.SIGKILL}) {
		t.Fatalf("sent %v, want SIGINT and SIGKILL", sent)
	}
}

// With this boot's identity unreadable, a journaled process cannot be shown to
// be of this boot, whatever runs under its PID and start time now: it is not
// taken for the run's, not signalled, and recovery says so (audit F94).
func TestMapReaperTakesNoJournaledProcessForTheRunsWhenTheBootIsUnreadable(t *testing.T) {
	root := t.TempDir() // no sys/kernel/random/boot_id: the boot identity cannot be read
	at := reaperBoot.Add(10 * time.Hour)
	fakeMapProc(t, root, 100, mapArgv(otherRepo), at.Add(time.Second), otherRepo, "", "")
	self, err := statIdentity(root, 100)
	if err != nil {
		t.Fatal(err)
	}
	intent := ownIntent(at)
	intent.BootID = "boot-one"
	intent.AddProcess(self)
	r := testReaper(root, noSignal(t))

	err = r.stop(&intent, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot read this boot's identity") {
		t.Fatalf("stop = %v, want the unreadable boot identity reported and nothing signalled", err)
	}
	if ev := r.evidence(intent, false); len(ev.ours) != 0 {
		t.Fatalf("evidence names %v although the boot cannot be compared", ev.ours)
	}
}
