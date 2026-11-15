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
	"github.com/cliftcloud/certistack/pkg/pbs"
)

// The map a lab drill (SIGTERM to the controller as a tier's first VM was
// mapping its snapshot) left: proxmox-backup-client had written its pid file
// and attached a loop, and the daemon then died with the signal before
// recovery could see its process. The journal has the intent, with the owner
// and token the map was begun with, and no process.
const (
	labSnapshot = "vm/7031/2026-10-05T03:01:20Z"
	labArchive  = "drive-scsi0.img"
	labTail     = `\x3avm-7031-2026\x2d10\x2d05T03\x3a01\x3a20Z-drive\x2dscsi0.img`
	labPrefix   = `automation\x40pbs\x21lab\x2dtoken\x40192.0.2.5\x3a8007\x3apbs\x2ddata`
	// otherPrefix is another repository's map of the same snapshot and archive.
	otherPrefix = `audit\x40pbs\x21t\x40repo\x2db\x3a8007\x3aother\x2dstore`
)

func labIntent(at time.Time) journal.MapIntent {
	return journal.MapIntent{Snapshot: labSnapshot, Archive: labArchive, NameSuffix: labTail, At: at,
		Owner: pbs.MapOwner(ownRepo, "team-a", labSnapshot, labArchive), Token: ownToken}
}

func TestLabMapNameIsTheOneTheClientMakes(t *testing.T) {
	suffix, err := pbs.MapNameSuffix(labSnapshot, labArchive)
	if err != nil || suffix != labTail {
		t.Fatalf("MapNameSuffix = %q, %v; want %q", suffix, err, labTail)
	}
}

// deadFixture is a fake host with an intent and the leftovers of maps of it.
type deadFixture struct {
	t       *testing.T
	maps    fakeMaps
	finder  leakFinder
	intent  journal.MapIntent
	at      time.Time
	pid     int           // what the intent's own leftover's pid file names
	written time.Duration // when it was written, after the intent
}

func newDeadFixture(t *testing.T) *deadFixture {
	maps := newFakeMaps(t)
	at := time.Date(2026, 10, 5, 3, 1, 20, 0, time.UTC)
	return &deadFixture{t: t, maps: maps, at: at, intent: labIntent(at), pid: 4242, written: 2 * time.Second,
		finder: leakFinder{sysBlock: maps.sysBlock, runDir: maps.runDir, mountInfo: maps.mountInfo}}
}

// leftover makes a leftover named prefix + the intent's tail: its map file, a
// pid file naming pid written written after the intent (none when pid is 0),
// and a loop device on the map file when loop is set. It returns the map
// file's path.
func (d *deadFixture) leftover(prefix, loop string, pid int, written time.Duration) string {
	d.t.Helper()
	name := prefix + labTail
	path := filepath.Join(d.maps.runDir, name)
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		d.t.Fatal(err)
	}
	if loop != "" {
		d.maps.add(loop, d.maps.runDir, name, time.Time{})
	}
	if pid != 0 {
		pidFile := strings.TrimSuffix(path, ".img") + ".pid"
		if err := os.WriteFile(pidFile, []byte(fmt.Sprint(pid)), 0o644); err != nil {
			d.t.Fatal(err)
		}
		when := d.at.Add(written)
		if err := os.Chtimes(pidFile, when, when); err != nil {
			d.t.Fatal(err)
		}
	}
	return path
}

// own makes the intent's own leftover, as a loop device and its map file
// (layout "loop") or as the map file alone ("files").
func (d *deadFixture) own(layout string) string {
	d.t.Helper()
	loop := ""
	if layout == "loop" {
		loop = "loop2"
	}
	return d.leftover(labPrefix, loop, d.pid, d.written)
}

// look runs both consumers of the claim over the fixture.
func (d *deadFixture) look(ev mapEvidence) (loops []LeakedMap, files []string, errs []error) {
	d.t.Helper()
	loops, errs = d.finder.find(d.intent, nil, ev)
	files, fileErrs := d.finder.orphans(d.intent, ev)
	return loops, files, append(errs, fileErrs...)
}

func errorText(errs []error) string {
	var text []string
	for _, err := range errs {
		text = append(text, err.Error())
	}
	return strings.Join(text, "\n")
}

// unseenDaemon is the evidence when recovery identified no process of the
// run's map and no proxmox-backup-client runs: the daemon died before
// recovery looked.
func unseenDaemon() mapEvidence {
	return mapEvidence{gone: func(journal.Process) bool { return true }, daemonAlive: func(int) bool { return false }}
}

// The map the drill left is the run's, whether recovery meets it as a loop
// device or, once that is released, as its map file.
func TestDeadUnseenDaemonLeftoverIsTheRuns(t *testing.T) {
	t.Run("a loop device and its files", func(t *testing.T) {
		d := newDeadFixture(t)
		path := d.own("loop")
		loops, files, errs := d.look(unseenDaemon())
		if len(loops) != 1 || loops[0].Device != "/dev/loop2" || loops[0].Backing != path || len(files) != 0 || len(errs) != 0 {
			t.Fatalf("loops %+v, files %v, errs %v; want only /dev/loop2 (its files are the loop's until it is released)", loops, files, errs)
		}
	})
	t.Run("its files once the loop is released", func(t *testing.T) {
		d := newDeadFixture(t)
		path := d.own("files")
		loops, files, errs := d.look(unseenDaemon())
		if len(loops) != 0 || fmt.Sprint(files) != fmt.Sprint([]string{path}) || len(errs) != 0 {
			t.Fatalf("loops %+v, files %v, errs %v; want only %s", loops, files, errs, path)
		}
	})
	t.Run("a map file without a pid file stays pid-less", func(t *testing.T) {
		d := newDeadFixture(t)
		d.pid = 0
		d.own("files")
		loops, files, errs := d.look(unseenDaemon())
		if len(loops) != 0 || len(files) != 0 || !strings.Contains(errorText(errs), "no process of the run's map") {
			t.Fatalf("loops %+v, files %v, errs %v; want the pid-less rule's refusal, not this one's claim", loops, files, errs)
		}
	})
}

// The window is closed at both ends: a pid file a second before the intent,
// and one three minutes after it, are the map's; any earlier or later is not.
func TestDeadUnseenDaemonWindowEnds(t *testing.T) {
	for name, tc := range map[string]struct {
		written time.Duration
		claimed bool
	}{
		"a second before the intent":    {-time.Second, true},
		"just before that":              {-time.Second - time.Millisecond, false},
		"at the end of the window":      {mapLeakWindow, true},
		"just after the window":         {mapLeakWindow + time.Second, false},
		"with the intent":               {0, true},
		"a client that was slow to map": {2*time.Minute + 30*time.Second, true},
	} {
		for _, layout := range []string{"loop", "files"} {
			t.Run(layout+"/"+name, func(t *testing.T) {
				d := newDeadFixture(t)
				d.written = tc.written
				d.own(layout)
				loops, files, _ := d.look(unseenDaemon())
				if got := len(loops) + len(files); (got == 1) != tc.claimed || got > 1 {
					t.Fatalf("claimed %d (loops %+v, files %v), want claimed=%v", got, loops, files, tc.claimed)
				}
			})
		}
	}
}

// Everything that is not exactly that one leftover stays as it was: not
// claimed, and reported unless it is provably another operation's.
func TestDeadUnseenDaemonLeftoverIsNotClaimedUnlessItIsTheOnly(t *testing.T) {
	type tc struct {
		name   string
		setup  func(d *deadFixture, ev *mapEvidence)
		want   []string // in the report
		silent bool     // provably another operation's: left without a word
	}
	liveClient := func(pids ...int) func(int) bool {
		return func(pid int) bool {
			for _, p := range pids {
				if p == pid {
					return true
				}
			}
			return false
		}
	}
	cases := []tc{
		{name: "a pid file older than the intent", silent: true,
			setup: func(d *deadFixture, _ *mapEvidence) { d.written = -2 * time.Second }},
		{name: "a pid file later than the window", want: []string{"its map process 4242 is gone, and recovery never identified it as the run's"},
			setup: func(d *deadFixture, _ *mapEvidence) { d.written = mapLeakWindow + time.Second }},
		{name: "a second dead leftover that is a loop device", want: []string{"2 leftovers of the same snapshot and archive are in that state", "it is not claimed because"},
			setup: func(d *deadFixture, _ *mapEvidence) { d.leftover(otherPrefix, "loop3", 4343, 3*time.Second) }},
		{name: "a second dead leftover that is a map file", want: []string{"2 leftovers of the same snapshot and archive are in that state"},
			setup: func(d *deadFixture, _ *mapEvidence) { d.leftover(otherPrefix, "", 4343, 3*time.Second) }},
		{name: "two loop devices on one map file", want: []string{"leftovers of the same snapshot and archive are in that state"},
			setup: func(d *deadFixture, _ *mapEvidence) {
				name := labPrefix + labTail
				d.maps.add("loop3", d.maps.runDir, name, time.Time{})
				d.maps.add("loop4", d.maps.runDir, name, time.Time{})
			}},
		{name: "a map of the same snapshot and archive runs", want: []string{"a map of the same snapshot and archive runs, or recovery could not tell"},
			setup: func(_ *deadFixture, ev *mapEvidence) { ev.running = true }},
		{name: "the pid names a live proxmox-backup-client", want: []string{"names the live proxmox-backup-client 4242"},
			setup: func(_ *deadFixture, ev *mapEvidence) { ev.daemonAlive = liveClient(4242) }},
		{name: "the pid names a live client the judge cannot tell", want: []string{"nothing shows whose map it is"},
			setup: func(_ *deadFixture, ev *mapEvidence) {
				ev.daemonAlive = liveClient(4242)
				ev.judge = func(int) (verdict, string) { return verdictUnproven, "nothing shows whose map it is" }
			}},
		{name: "the pid names a live client that is provably another operation's", silent: true,
			setup: func(_ *deadFixture, ev *mapEvidence) {
				ev.daemonAlive = liveClient(4242)
				ev.judge = func(int) (verdict, string) { return verdictOther, "" }
			}},
		{name: "the pid was the run's own and a live client has it now", want: []string{"which the run's map process had and a live proxmox-backup-client has now"},
			setup: func(_ *deadFixture, ev *mapEvidence) {
				ev.ours = map[int]journal.Process{4242: {PID: 4242, StartTicks: "100"}}
				ev.daemonAlive = liveClient(4242)
			}},
		{name: "the journal records no owner", want: []string{"does not record the owner and token"},
			setup: func(d *deadFixture, _ *mapEvidence) { d.intent.Owner = "" }},
		{name: "the journal records no token", want: []string{"does not record the owner and token"},
			setup: func(d *deadFixture, _ *mapEvidence) { d.intent.Token = "" }},
		{name: "an older journal records neither", want: []string{"does not record the owner and token"},
			setup: func(d *deadFixture, _ *mapEvidence) { d.intent.Owner, d.intent.Token = "", "" }},
		{name: "another repository's leftover whose live client cannot be told apart", want: []string{"another leftover of the same snapshot and archive is not provably another operation's", "nothing shows whose map it is"},
			setup: func(d *deadFixture, ev *mapEvidence) {
				d.leftover(otherPrefix, "", 4444, 3*time.Second)
				ev.daemonAlive = liveClient(4444)
				ev.judge = func(int) (verdict, string) { return verdictUnproven, "nothing shows whose map it is" }
			}},
		{name: "a leftover of the run's own process, which still runs", want: []string{"another leftover of the same snapshot and archive is not provably another operation's"},
			setup: func(d *deadFixture, ev *mapEvidence) {
				d.leftover(otherPrefix, "", 4343, 3*time.Second)
				ev.ours = map[int]journal.Process{4343: {PID: 4343, StartTicks: "100"}}
				ev.gone = func(journal.Process) bool { return false }
				ev.daemonAlive = liveClient(4343)
			}},
		{name: "a leftover without a pid file", want: []string{"another leftover of the same snapshot and archive is not provably another operation's"},
			setup: func(d *deadFixture, _ *mapEvidence) { d.leftover(otherPrefix, "", 0, 0) }},
		{name: "a mount table that cannot be read", want: []string{"recovery could not list every leftover of the same snapshot and archive"},
			setup: func(d *deadFixture, _ *mapEvidence) { d.finder.mountInfo = filepath.Join(d.t.TempDir(), "absent") }},
	}
	for _, layout := range []string{"loop", "files"} {
		for _, c := range cases {
			t.Run(layout+"/"+c.name, func(t *testing.T) {
				d := newDeadFixture(t)
				ev := unseenDaemon()
				c.setup(d, &ev)
				d.own(layout)
				loops, files, errs := d.look(ev)
				if len(loops) != 0 || len(files) != 0 {
					t.Fatalf("claimed loops %+v, files %v; want nothing", loops, files)
				}
				text := errorText(errs)
				if c.silent && len(errs) != 0 {
					t.Fatalf("reported %q; want it left without a word: it is provably another operation's", text)
				}
				if !c.silent && len(errs) == 0 {
					t.Fatal("nothing was reported: a leftover that is not proved the run's is reported, never dropped")
				}
				for _, want := range c.want {
					if !strings.Contains(text, want) {
						t.Errorf("report %q lacks %q", text, want)
					}
				}
				// The repository is in every map name and may name an API token.
				if strings.Contains(text, "automation") || strings.Contains(text, "audit") {
					t.Errorf("report names a repository: %q", text)
				}
			})
		}
	}
}

// What the rule counts is the leftovers that could be the run's: those
// provably another operation's, or whose names do not end with the intent's,
// are not among them.
func TestDeadUnseenDaemonLeftoverIgnoresWhatIsNotItsCompetition(t *testing.T) {
	for _, layout := range []string{"loop", "files"} {
		t.Run(layout, func(t *testing.T) {
			d := newDeadFixture(t)
			// Another archive and another snapshot of the same VM, dead pids in the
			// window, and a name that ends with only part of the intent's.
			for _, name := range []string{
				labPrefix + strings.Replace(labTail, "scsi0", "scsi1", 1),
				labPrefix + strings.Replace(labTail, "05T03", "05T04", 1),
				labPrefix + labTail[len(`\x3a`):],
				labPrefix + "x" + labTail[1:],
			} {
				path := filepath.Join(d.maps.runDir, name)
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				pidFile := strings.TrimSuffix(path, ".img") + ".pid"
				if err := os.WriteFile(pidFile, []byte("4343"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(pidFile, d.at.Add(time.Second), d.at.Add(time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			// One older than the intent, and a live client of another operation.
			d.leftover(otherPrefix, "", 4444, -time.Hour)
			d.leftover(`x\x2d`+otherPrefix, "", 4545, 3*time.Second)
			ev := unseenDaemon()
			ev.daemonAlive = func(pid int) bool { return pid == 4545 }
			ev.judge = func(int) (verdict, string) { return verdictOther, "" }
			// Recovery stopped a process of the run's map, which left no pid file.
			ev.ours = map[int]journal.Process{4300: {PID: 4300, StartTicks: "100"}}
			path := d.own(layout)

			loops, files, errs := d.look(ev)
			if len(errs) != 0 {
				t.Fatalf("errs = %v", errs)
			}
			switch layout {
			case "loop":
				if len(loops) != 1 || loops[0].Backing != path || len(files) != 0 {
					t.Fatalf("loops %+v, files %v; want only %s", loops, files, path)
				}
			default:
				if len(loops) != 0 || fmt.Sprint(files) != fmt.Sprint([]string{path}) {
					t.Fatalf("loops %+v, files %v; want only %s", loops, files, path)
				}
			}
		})
	}
}

// A leftover that is proved the run's by its process is the one map the
// intent made: a dead, unidentified one beside it is not claimed.
func TestDeadUnseenDaemonLeftoverYieldsToTheProvenOne(t *testing.T) {
	for _, layout := range []string{"loop", "files"} {
		t.Run(layout, func(t *testing.T) {
			d := newDeadFixture(t)
			ev := unseenDaemon()
			ev.ours = map[int]journal.Process{4343: {PID: 4343, StartTicks: "100"}} // stopped by recovery
			proven := d.leftover(otherPrefix, "", 4343, 3*time.Second)
			d.own(layout)
			loops, files, errs := d.look(ev)
			if len(loops) != 0 || fmt.Sprint(files) != fmt.Sprint([]string{proven}) {
				t.Fatalf("claimed loops %+v, files %v; want only the proven leftover %s", loops, files, proven)
			}
			if text := errorText(errs); !strings.Contains(text, "not provably another operation's") {
				t.Fatalf("errs = %q, want the dead leftover reported", text)
			}
		})
	}
}

// installLabTools makes a proxmox-backup-client that only logs, and a losetup
// that logs and, unless fail, detaches the loop as the kernel would (its sysfs
// entry goes). They come first on PATH, so no real loop device is touched. It
// returns the log's path.
func installLabTools(t *testing.T, sysBlock string, fail bool) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	client := "#!/bin/sh\nprintf 'proxmox-backup-client %s\\n' \"$*\" >> '" + log + "'\n"
	losetup := "#!/bin/sh\nprintf 'losetup %s\\n' \"$*\" >> '" + log + "'\n"
	if fail {
		losetup += "exit 1\n"
	} else {
		losetup += "[ \"$1\" = -d ] && rm -f '" + sysBlock + "'/\"${2##*/}\"/loop/backing_file\n"
	}
	for name, body := range map[string]string{"proxmox-backup-client": client, "losetup": losetup} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	return log
}

// labHost is a fake host for RecoverLocked: the maps' sysfs, run directory and
// mount table, a FUSE connection directory, and a mount detach that records
// what it was asked to.
type labHost struct {
	maps      fakeMaps
	abortFile string
	detached  []string
}

func newLabHost(t *testing.T, root string) *labHost {
	maps := hostWithProcs(t, root, noSignal(t))
	fuse := filepath.Join(t.TempDir(), "connections")
	abort := filepath.Join(fuse, "77", "abort")
	if err := os.MkdirAll(filepath.Dir(abort), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abort, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	hostLeakFinder.fuseConns = fuse
	h := &labHost{maps: maps, abortFile: abort}
	old := detachMount
	t.Cleanup(func() { detachMount = old })
	detachMount = func(path string) error {
		h.detached = append(h.detached, path)
		return os.WriteFile(maps.mountInfo, nil, 0o644) // the mount is gone from the table
	}
	return h
}

// mount puts the map file in the mount table as the FUSE mount of device 0:77.
func (h *labHost) mount(t *testing.T, path string) {
	t.Helper()
	table := "812 30 0:77 / " + strings.ReplaceAll(path, `\`, `\134`) + " rw,nosuid,nodev - fuse proxmox-backup-client rw,user_id=0,group_id=0\n"
	if err := os.WriteFile(h.maps.mountInfo, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h *labHost) aborted(t *testing.T) bool {
	t.Helper()
	data, err := os.ReadFile(h.abortFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(data) == "1"
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// The drill, end to end: recovery releases the loop (aborting the dead
// daemon's FUSE connection first), removes the map file and its pid file, and
// a later attempt completes the journal when the first could not detach the
// loop. The node is no longer stuck at cleanup_failed.
func TestRecoverLockedReleasesAMapWhoseDaemonDiedUnseen(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	h := newLabHost(t, root)
	d := &deadFixture{t: t, maps: h.maps, at: reaperBoot.Add(10 * time.Hour), pid: 4242, written: 3 * time.Second}
	d.intent = labIntent(d.at)
	img := d.own("loop")
	pidFile := strings.TrimSuffix(img, ".img") + ".pid"
	h.mount(t, img)
	path := journalOf(t, stateDir, nil, d.intent)

	// The first attempt cannot detach the loop: the map is claimed (not
	// reported as unproven), its FUSE connection is aborted, and the journal
	// stays for another attempt.
	log := installLabTools(t, h.maps.sysBlock, true)
	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "/dev/loop2") || strings.Contains(err.Error(), "nothing proves") || strings.Contains(err.Error(), "automation") {
		t.Fatalf("first recovery = %v, want the failed detach of /dev/loop2 and no refusal", err)
	}
	if calls := callsIn(log); calls != "losetup -d /dev/loop2" || !h.aborted(t) || !exists(img) || phaseOf(t, path) != "cleanup_failed" {
		t.Fatalf("calls %q, aborted %v, map file kept %v, phase %q; want the detach tried, the connection aborted, the files kept and the journal unclean",
			calls, h.aborted(t), exists(img), phaseOf(t, path))
	}

	// The next one detaches the loop, removes the leftover files and cleans the
	// journal.
	log = installLabTools(t, h.maps.sysBlock, false)
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("second recovery: %v", err)
	}
	if calls := callsIn(log); calls != "losetup -d /dev/loop2" {
		t.Fatalf("calls %q, want only the detach of /dev/loop2", calls)
	}
	if exists(img) || exists(pidFile) || fmt.Sprint(h.detached) != fmt.Sprint([]string{img}) {
		t.Fatalf("map file kept %v, pid file kept %v, detached %v; want both removed and the mount detached once", exists(img), exists(pidFile), h.detached)
	}
	if phase := phaseOf(t, path); phase != "cleaned" {
		t.Fatalf("phase = %q, want cleaned", phase)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery of a cleaned journal: %v", err)
	}
}

// The same when no loop is left: the map file alone is removed.
func TestRecoverLockedRemovesTheFilesOfAMapWhoseDaemonDiedUnseen(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	h := newLabHost(t, root)
	d := &deadFixture{t: t, maps: h.maps, at: reaperBoot.Add(10 * time.Hour), pid: 4242, written: 3 * time.Second}
	d.intent = labIntent(d.at)
	img := d.own("files")
	pidFile := strings.TrimSuffix(img, ".img") + ".pid"
	h.mount(t, img)
	path := journalOf(t, stateDir, nil, d.intent)
	log := installLabTools(t, h.maps.sysBlock, false)

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if exists(img) || exists(pidFile) || fmt.Sprint(h.detached) != fmt.Sprint([]string{img}) || !h.aborted(t) {
		t.Fatalf("map file kept %v, pid file kept %v, detached %v, aborted %v; want both removed, the connection aborted and the mount detached",
			exists(img), exists(pidFile), h.detached, h.aborted(t))
	}
	if calls := callsIn(log); calls != "" || phaseOf(t, path) != "cleaned" {
		t.Fatalf("calls %q, phase %q; want no command run and the journal clean", calls, phaseOf(t, path))
	}
}

// Two leftovers that could each be the run's, or a live look-alike map, keep
// the node's refusal exactly as it was: nothing is touched, and the journal
// stays unclean.
func TestRecoverLockedStillRefusesWhenTheMapIsNotTheOnlyCandidate(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, root string, d *deadFixture)
		want  string
	}{
		{"another dead leftover of the same snapshot and archive", func(_ *testing.T, _ string, d *deadFixture) {
			d.leftover(otherPrefix, "", 4343, 4*time.Second)
		}, "2 leftovers of the same snapshot and archive are in that state"},
		{"a live map of the same snapshot and archive, started by hand", func(t *testing.T, root string, _ *deadFixture) {
			argv := []string{"/usr/bin/proxmox-backup-client", "map", "--repository", otherRepo, labSnapshot, labArchive}
			fakeMapProc(t, root, 800, argv, at.Add(time.Second), otherRepo, "", "")
		}, "a map of the same snapshot and archive runs"},
		{"a pid that a live proxmox-backup-client has, which maps the run's source without its token", func(t *testing.T, root string, _ *deadFixture) {
			argv := []string{"/usr/bin/proxmox-backup-client", "map", "--repository", ownRepo, "--ns", "team-a", labSnapshot, labArchive}
			fakeMapProc(t, root, 4242, argv, at.Add(time.Second), ownRepo, "team-a", "")
		}, "nothing shows it is another operation's or the run's"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, stateDir := t.TempDir(), t.TempDir()
			h := newLabHost(t, root)
			d := &deadFixture{t: t, maps: h.maps, at: at, pid: 4242, written: 3 * time.Second}
			d.intent = labIntent(at)
			img := d.own("loop")
			h.mount(t, img)
			tc.setup(t, root, d)
			path := journalOf(t, stateDir, nil, d.intent)
			log := installLabTools(t, h.maps.sysBlock, false)

			err := RecoverLocked(stateDir)
			if err == nil || !strings.Contains(err.Error(), "nothing proves it is") || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "automation") {
				t.Fatalf("recovery = %v, want the refusal (%s)", err, tc.want)
			}
			if calls := callsIn(log); calls != "" || h.aborted(t) || len(h.detached) != 0 || !exists(img) || phaseOf(t, path) != "cleanup_failed" {
				t.Fatalf("calls %q, aborted %v, detached %v, map file kept %v, phase %q; want nothing touched and the journal unclean",
					calls, h.aborted(t), h.detached, exists(img), phaseOf(t, path))
			}
		})
	}
}
