//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
)

// A test cluster's real map names: the repository escaped, then the suffix.
const (
	scsi1Name = `backup\x40pbs\x21ci\x2dtoken\x40192.0.2.5\x3a8007\x3apbs\x2ddata\x3avm-7214-2026\x2d09\x2d27T03\x3a12\x3a59Z-drive\x2dscsi1.img`
	scsi1Tail = `\x3avm-7214-2026\x2d09\x2d27T03\x3a12\x3a59Z-drive\x2dscsi1.img`
	scsi0Name = `backup\x40pbs\x21ci\x2dtoken\x40192.0.2.5\x3a8007\x3apbs\x2ddata\x3avm-7214-2026\x2d09\x2d27T03\x3a12\x3a59Z-drive\x2dscsi0.img`
)

type fakeMaps struct {
	t         *testing.T
	sysBlock  string
	runDir    string
	mountInfo string // an empty mount table
}

func newFakeMaps(t *testing.T) fakeMaps {
	root := t.TempDir()
	f := fakeMaps{t: t, sysBlock: filepath.Join(root, "sys", "block"), runDir: filepath.Join(root, "run", "pbs-loopdev"), mountInfo: filepath.Join(root, "mountinfo")}
	if err := os.MkdirAll(f.runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.mountInfo, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// add attaches loopN to a map file named name whose daemon, PID 4242,
// wrote its pid file at created. A zero created writes no pid file.
func (f fakeMaps) add(loop, dir, name string, created time.Time) {
	f.addPID(loop, dir, name, created, 4242)
}

// addPID is add for a daemon with the given PID.
func (f fakeMaps) addPID(loop, dir, name string, created time.Time, pid int) {
	f.t.Helper()
	sysDir := filepath.Join(f.sysBlock, loop, "loop")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sysDir, "backing_file"), []byte(filepath.Join(dir, name)+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
	if created.IsZero() {
		return
	}
	pidFile := filepath.Join(dir, name[:len(name)-len(".img")]+".pid")
	if err := os.WriteFile(pidFile, []byte(fmt.Sprint(pid)), 0o644); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chtimes(pidFile, created, created); err != nil {
		f.t.Fatal(err)
	}
}

// stoppedDaemon is the evidence after recovery stopped the run's map
// daemon, PID 4242, which is gone, and no map of the archive runs.
func stoppedDaemon() mapEvidence {
	return mapEvidence{
		ours:        map[int]journal.Process{4242: {PID: 4242, StartTicks: "100"}},
		gone:        func(journal.Process) bool { return true },
		daemonAlive: func(int) bool { return false },
	}
}

func devices(leaks []LeakedMap) string {
	var names []string
	for _, leak := range leaks {
		names = append(names, leak.Device)
	}
	return strings.Join(names, " ")
}

// A worker killed while it maps leaves a loop device it never
// journaled. Recovery claims exactly the map its intent names, created in
// its window by the map's own daemon, and nothing else.
func TestLeakFinderClaimsOnlyTheIntendedMap(t *testing.T) {
	f := newFakeMaps(t)
	at := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	f.add("loop3", f.runDir, scsi1Name, at.Add(4*time.Second))   // the leak
	f.add("loop4", f.runDir, scsi0Name, at.Add(4*time.Second))   // another archive
	f.add("loop5", f.runDir, "x"+scsi1Name, at.Add(-time.Hour))  // same archive, mapped an hour earlier by someone else
	f.add("loop6", "/elsewhere", scsi1Name, time.Time{})         // not a PBS map
	f.add("loop8", f.runDir, "z"+scsi1Name, at.Add(time.Second)) // already tracked by the journal
	finder := leakFinder{sysBlock: f.sysBlock, runDir: f.runDir}

	intent := journal.MapIntent{Snapshot: "vm/7214/2026-09-27T03:12:59Z", Archive: "drive-scsi1.img", NameSuffix: scsi1Tail, At: at}
	leaked, errs := finder.find(intent, map[string]bool{"/dev/loop8": true}, stoppedDaemon())
	if len(leaked) != 1 || leaked[0].Device != "/dev/loop3" || leaked[0].Backing != filepath.Join(f.runDir, scsi1Name) || len(errs) != 0 {
		t.Fatalf("leaked = %+v, %v; want only /dev/loop3", leaked, errs)
	}
	if got, errs := finder.find(journal.MapIntent{At: at}, nil, stoppedDaemon()); len(got) != 0 || len(errs) != 0 {
		t.Fatalf("an intent without a name suffix claimed %+v, %v", got, errs)
	}
}

// The map name carries the repository only as a prefix recovery
// cannot compute, so two maps of the same snapshot and archive from
// different repositories, made in the intent's window, look alike. A loop
// is the run's only when its pid file names one of the map's own processes
// that recovery stopped. A live map of another operation is left alone;
// a dead one nothing ties to the run is left and reported, and named
// without its repository.
func TestLeakFinderClaimsOnlyLoopsOfTheMapsOwnProcesses(t *testing.T) {
	f := newFakeMaps(t)
	at := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	in := at.Add(time.Second)
	f.addPID("loop3", f.runDir, "repository-a"+scsi1Tail, in, 4242)                 // the run's: its daemon was stopped
	f.addPID("loop4", f.runDir, "repository-b"+scsi1Tail, in, 4343)                 // a dead map recovery never identified
	f.addPID("loop5", f.runDir, "repository-c"+scsi1Tail, in, 4444)                 // another operation's live map
	f.addPID("loop6", f.runDir, "repository-d"+scsi1Tail, at.Add(-time.Hour), 4545) // older: someone else's
	finder := leakFinder{sysBlock: f.sysBlock, runDir: f.runDir}
	intent := journal.MapIntent{Snapshot: "vm/7214/2026-09-27T03:12:59Z", Archive: "drive-scsi1.img", NameSuffix: scsi1Tail, At: at}
	ev := stoppedDaemon()
	ev.daemonAlive = func(pid int) bool { return pid == 4444 }
	ev.judge = func(pid int) (verdict, string) { return verdictOther, "" } // 4444 provably is another operation's map
	leaked, errs := finder.find(intent, nil, ev)
	if devices(leaked) != "/dev/loop3" {
		t.Fatalf("leaked %s, want only /dev/loop3", devices(leaked))
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "/dev/loop4") || !strings.Contains(errs[0].Error(), "4343") || strings.Contains(errs[0].Error(), "repository-b") {
		t.Fatalf("errs = %v, want /dev/loop4 reported without its repository", errs)
	}
	// A live map that is not proved to be another operation's is reported,
	// never dropped.
	ev.judge = func(pid int) (verdict, string) { return verdictUnproven, "nothing shows whose it is" }
	if leaked, errs := finder.find(intent, nil, ev); devices(leaked) != "/dev/loop3" || len(errs) != 2 || !strings.Contains(errs[1].Error(), "/dev/loop5") {
		t.Fatalf("leaked %s, errs %v; want /dev/loop3 claimed, /dev/loop4 and /dev/loop5 reported", devices(leaked), errs)
	}

	// While the run's own daemon still runs (its stop failed, and was
	// reported), its loop stays.
	ev.gone = func(journal.Process) bool { return false }
	if leaked, _ := finder.find(intent, nil, ev); len(leaked) != 0 {
		t.Fatalf("leaked %s while the map's daemon still runs", devices(leaked))
	}
	// Recovery that identified no process of the run's map claims nothing,
	// and reports every leftover it cannot show is another operation's.
	if leaked, errs := finder.find(intent, nil, mapEvidence{gone: ev.gone, daemonAlive: ev.daemonAlive}); len(leaked) != 0 || len(errs) != 3 {
		t.Fatalf("leaked %s, %v; want nothing claimed, three reported", devices(leaked), errs)
	}
}

// A stopped daemon can leave its loop without a pid file. Such a
// loop is the run's only when recovery stopped the map's own process, that
// process left no pid file, no map of the snapshot and archive runs, and
// it is the only one.
func TestLeakFinderSettlesLoopsWithoutPidFile(t *testing.T) {
	at := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	intent := journal.MapIntent{Snapshot: "vm/7214/2026-09-27T03:12:59Z", Archive: "drive-scsi1.img", NameSuffix: scsi1Tail, At: at}
	for _, tc := range []struct {
		name     string
		loops    int
		ev       func(mapEvidence) mapEvidence
		ownPid   bool // the run's daemon left a pid file (for another loop)
		claimed  string
		reported int
	}{
		{name: "the run's", loops: 1, claimed: "/dev/loop7"},
		{name: "a map still runs", loops: 1, ev: func(ev mapEvidence) mapEvidence { ev.running = true; return ev }, reported: 1},
		{name: "another map runs, none of the run's found", loops: 1, ev: func(ev mapEvidence) mapEvidence { ev.running, ev.ours = true, nil; return ev }, reported: 1},
		{name: "none of the run's found", loops: 1, ev: func(ev mapEvidence) mapEvidence { ev.ours = nil; return ev }, reported: 1},
		{name: "two alike", loops: 2, reported: 2},
		{name: "the run's daemon left its own", loops: 1, ownPid: true, claimed: "/dev/loop3", reported: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeMaps(t)
			f.add("loop7", f.runDir, "y"+scsi1Name, time.Time{})
			if tc.loops > 1 {
				f.add("loop9", f.runDir, "w"+scsi1Name, time.Time{})
			}
			if tc.ownPid {
				f.add("loop3", f.runDir, scsi1Name, at.Add(time.Second))
			}
			ev := stoppedDaemon()
			if tc.ev != nil {
				ev = tc.ev(ev)
			}
			leaked, errs := (leakFinder{sysBlock: f.sysBlock, runDir: f.runDir}).find(intent, nil, ev)
			if devices(leaked) != tc.claimed || len(errs) != tc.reported {
				t.Fatalf("leaked %q, errs %v; want %q and %d reported", devices(leaked), errs, tc.claimed, tc.reported)
			}
		})
	}
}

func TestTrackedLoopsIncludesTheLegacySingleLoop(t *testing.T) {
	tracked := trackedLoops(journal.Record{LoopDevice: "/dev/loop1", Loops: []journal.TrackedLoop{{Device: "/dev/loop2"}}})
	if !tracked["/dev/loop1"] || !tracked["/dev/loop2"] || len(tracked) != 2 {
		t.Fatalf("tracked = %v", tracked)
	}
}

// A killed daemon's thread waited on its own FUSE file, so the
// connection stayed open and every open of the loop hung. Recovery aborts
// the connection of a map it removes, found through the mount table, and
// nothing else's.
func TestAbortMapConnection(t *testing.T) {
	f := newFakeMaps(t)
	fuseConns := filepath.Join(t.TempDir(), "connections")
	mountInfo := filepath.Join(t.TempDir(), "mountinfo")
	ours := filepath.Join(f.runDir, scsi1Name)
	blockBacked := filepath.Join(f.runDir, "b"+scsi1Name)
	table := "812 30 0:53 / " + strings.ReplaceAll(ours, `\`, `\134`) + " rw - fuse proxmox-backup-client rw\n" +
		"813 30 8:1 / " + strings.ReplaceAll(blockBacked, `\`, `\134`) + " rw - ext4 /dev/sda1 rw\n"
	if err := os.WriteFile(mountInfo, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	abortFile := filepath.Join(fuseConns, "53", "abort")
	if err := os.MkdirAll(filepath.Dir(abortFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abortFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	finder := leakFinder{sysBlock: f.sysBlock, runDir: f.runDir, mountInfo: mountInfo, fuseConns: fuseConns}
	if aborted, err := finder.abortMapConnection(ours); err != nil || !aborted {
		t.Fatalf("our map: aborted %v, %v", aborted, err)
	}
	if data, _ := os.ReadFile(abortFile); string(data) != "1" {
		t.Fatalf("abort file = %q", data)
	}
	for name, backing := range map[string]string{
		"a mount that is not FUSE":   blockBacked,
		"a file outside the run dir": filepath.Join(t.TempDir(), scsi1Name),
		"a map whose mount is gone":  filepath.Join(f.runDir, "gone"+scsi1Name),
	} {
		if aborted, err := finder.abortMapConnection(backing); err != nil || aborted {
			t.Errorf("%s: aborted %v, %v", name, aborted, err)
		}
	}
}

// Recovery names a map file for an operator without the repository its
// name starts with.
func TestPathlessDropsTheMapFilePath(t *testing.T) {
	_, err := os.ReadFile(filepath.Join(t.TempDir(), scsi1Name))
	if got := pathless(err); strings.Contains(got, "automation") || !strings.Contains(got, "no such file") {
		t.Fatalf("pathless = %q", got)
	}
	label := (leakFinder{runDir: pbsMapRunDir}).mapLabel(journal.MapIntent{NameSuffix: scsi1Tail})
	if label != pbsMapRunDir+"/*"+scsi1Tail {
		t.Fatalf("label = %q", label)
	}
}

// A loop device whose backing file cannot be read may be the map's. It is
// reported, not passed over, so a recovery with nothing else to say does not end
// clean, and its map file is not taken for an unused one.
func TestLeakFinderReportsWhatItCannotInspect(t *testing.T) {
	at := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	intent := journal.MapIntent{Snapshot: "vm/7214/2026-09-27T03:12:59Z", Archive: "drive-scsi1.img", NameSuffix: scsi1Tail, At: at}
	unreadable := func(f fakeMaps, loop string) {
		dir := filepath.Join(f.sysBlock, loop, "loop")
		if err := os.MkdirAll(filepath.Join(dir, "backing_file"), 0o755); err != nil { // a directory cannot be read as a file
			t.Fatal(err)
		}
	}

	t.Run("find reports an unreadable loop", func(t *testing.T) {
		f := newFakeMaps(t)
		f.add("loop3", f.runDir, scsi1Name, at.Add(time.Second))
		unreadable(f, "loop9")
		leaked, errs := (leakFinder{sysBlock: f.sysBlock, runDir: f.runDir}).find(intent, nil, stoppedDaemon())
		if devices(leaked) != "/dev/loop3" || len(errs) != 1 || !strings.Contains(errs[0].Error(), "/dev/loop9") {
			t.Fatalf("leaked %q, errs %v; want loop3 claimed and loop9 reported", devices(leaked), errs)
		}
	})

	t.Run("orphans removes no map file while a loop cannot be read", func(t *testing.T) {
		f := newFakeMaps(t)
		// The map file of the run exists with its pid file and no readable loop.
		name := "repository-a" + scsi1Tail
		if err := os.WriteFile(filepath.Join(f.runDir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		pid := filepath.Join(f.runDir, strings.TrimSuffix(name, ".img")+".pid")
		if err := os.WriteFile(pid, []byte("4242"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(pid, at.Add(time.Second), at.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		finder := leakFinder{sysBlock: f.sysBlock, runDir: f.runDir, mountInfo: f.mountInfo}
		if orphans, errs := finder.orphans(intent, stoppedDaemon()); len(errs) != 0 || len(orphans) != 1 {
			t.Fatalf("control, every loop readable: orphans %v, errs %v; want the map file", orphans, errs)
		}
		unreadable(f, "loop9")
		orphans, errs := finder.orphans(intent, stoppedDaemon())
		if len(orphans) != 0 || len(errs) == 0 || !strings.Contains(errs[len(errs)-1].Error(), "left in place") {
			t.Fatalf("orphans %v, errs %v; want no file removed and the unreadable loop reported", orphans, errs)
		}
	})

	t.Run("an unreadable pid file is not evidence that the run's process wrote none", func(t *testing.T) {
		f := newFakeMaps(t)
		name := "repository-a" + scsi1Tail
		if err := os.Mkdir(filepath.Join(f.runDir, strings.TrimSuffix(name, ".img")+".pid"), 0o755); err != nil {
			t.Fatal(err)
		}
		// A directory is not a regular file, so it is skipped by design; make the
		// unreadable case a regular file the reader may not open.
		path := filepath.Join(f.runDir, "other"+strings.TrimSuffix(scsi1Tail, ".img")+".pid")
		if err := os.WriteFile(path, []byte("4242"), 0o000); err != nil {
			t.Fatal(err)
		}
		if os.Geteuid() == 0 {
			t.Skip("root can read a mode 000 file")
		}
		wrote, err := (leakFinder{sysBlock: f.sysBlock, runDir: f.runDir}).oursWrotePidFile(intent, stoppedDaemon())
		if !wrote || err == nil {
			t.Fatalf("oursWrotePidFile = %v, %v; want unknown (true) with the reason", wrote, err)
		}
	})
}
