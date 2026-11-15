//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"golang.org/x/sys/unix"
)

var reaperBoot = time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)

const (
	mapSnapshot = "vm/7214/2026-09-27T03:12:59Z"
	mapArchive  = "drive-scsi1.img"
	ownRepo     = "audit@pbs!t@repo-a:8007:store"
	otherRepo   = "audit@pbs!t@repo-b:8007:other-store"
	ownToken    = "0123456789abcdef0123456789abcdef"
	otherToken  = "fedcba9876543210fedcba9876543210"
)

// fakeProc writes /proc/<pid>/cmdline and stat for a process started at
// the given time after reaperBoot, and an empty environ.
func fakeProc(t *testing.T, root string, pid int, argv []string, started time.Time) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	ticks := started.Sub(reaperBoot) * clockTicks / time.Second
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[19] = fmt.Sprint(int64(ticks))
	stat := fmt.Sprintf("%d (proxmox-backup) S %s", pid, strings.Join(fields[1:], " "))
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeEnviron(t, root, pid)
}

// fakeEnviron writes /proc/<pid>/environ.
func fakeEnviron(t *testing.T, root string, pid int, env ...string) {
	t.Helper()
	data := strings.Join(env, "\x00")
	if len(env) > 0 {
		data += "\x00"
	}
	if err := os.WriteFile(filepath.Join(root, fmt.Sprint(pid), "environ"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mapArgv is the command line a run starts a map with.
func mapArgv(repository string) []string {
	return []string{"/usr/bin/proxmox-backup-client", "map", "--repository", repository, mapSnapshot, mapArchive}
}

// fakeMapProc is fakeProc for a proxmox-backup-client map of the test
// snapshot and archive that reads from repository and namespace, and
// carries token (none when empty). Its environment also holds a password.
func fakeMapProc(t *testing.T, root string, pid int, argv []string, started time.Time, repository, namespace, token string) {
	t.Helper()
	fakeProc(t, root, pid, argv, started)
	env := []string{"PATH=/usr/bin", "PBS_REPOSITORY=" + repository, "PBS_PASSWORD=must-not-leak"}
	if namespace != "" {
		env = append(env, "PBS_NAMESPACE="+namespace)
	}
	if token != "" {
		env = append(env, pbs.MapTokenEnv+"="+token)
	}
	fakeEnviron(t, root, pid, env...)
}

// ownIntent is the journaled intent of the map that reads the test
// snapshot and archive from ownRepo's namespace team-a, begun at at.
func ownIntent(at time.Time) journal.MapIntent {
	return journal.MapIntent{Snapshot: mapSnapshot, Archive: mapArchive, NameSuffix: scsi1Tail, At: at,
		Owner: pbs.MapOwner(ownRepo, "team-a", mapSnapshot, mapArchive), Token: ownToken}
}

// testReaper reads the fake proc tree at root, waits for nothing, and
// sends signals through signal.
func testReaper(root string, signal func(journal.Process, syscall.Signal) error) mapReaper {
	return mapReaper{
		procRoot: root,
		bootTime: func() (time.Time, error) { return reaperBoot, nil },
		signal:   signal,
		sleep:    func(time.Duration) {},
		// A fake PID has no pidfd, and the real process that has the number must
		// never be signalled: a test that stops a fake daemon says which pidfd
		// stands for it (pidfdStandIn).
		pidfdOpen: func(int, int) (int, error) { return -1, unix.ENOSYS },
	}
}

// exits is a fake signal that ends the process on any signal.
func exits(root string) func(journal.Process, syscall.Signal) error {
	return func(p journal.Process, _ syscall.Signal) error {
		return os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID)))
	}
}

// noSignal is a fake signal that fails the test.
func noSignal(t *testing.T) func(journal.Process, syscall.Signal) error {
	return func(p journal.Process, sig syscall.Signal) error {
		t.Errorf("signal %v to process %d", sig, p.PID)
		return nil
	}
}

// present reports whether the fake process pid still has its /proc entry.
func present(root string, pid int) bool {
	_, err := os.Stat(filepath.Join(root, fmt.Sprint(pid), "stat"))
	return err == nil
}

// The map daemon a killed worker's client forked is still fetching
// when recovery runs. Recovery stops exactly that process: SIGINT first,
// and SIGKILL only for one that ignores it.
func TestMapReaperStopsOnlyTheIntentsMapProcesses(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	other := []string{"/usr/bin/proxmox-backup-client", "map", "--repository", ownRepo, mapSnapshot, "drive-scsi0.img"}
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)       // the daemon: stops on SIGINT
	fakeMapProc(t, root, 101, mapArgv(ownRepo), at.Add(2*time.Second), ownRepo, "team-a", ownToken)     // a daemon that ignores SIGINT
	fakeMapProc(t, root, 102, other, at.Add(time.Second), ownRepo, "team-a", ownToken)                  // another archive
	fakeMapProc(t, root, 103, mapArgv(ownRepo), at.Add(-time.Hour), ownRepo, "team-a", "")              // the same map by hand, started an hour earlier: no token, outside the window
	fakeMapProc(t, root, 104, []string{"/usr/bin/vim", "map", mapSnapshot, mapArchive}, at, "", "", "") // not PBS

	var signals, kills []int
	r := testReaper(root, func(p journal.Process, sig syscall.Signal) error {
		if sig == syscall.SIGKILL {
			kills = append(kills, p.PID)
			return os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID)))
		}
		signals = append(signals, p.PID)
		if p.PID == 100 {
			return os.RemoveAll(filepath.Join(root, "100")) // exits cleanly
		}
		return nil
	})
	r.grace = 10 * time.Millisecond
	if err := r.stop(&intent, nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	sort.Ints(signals)
	if fmt.Sprint(signals) != "[100 101]" || fmt.Sprint(kills) != "[101]" || len(intent.Processes) != 2 {
		t.Fatalf("SIGINT %v, SIGKILL %v, journaled %v; want SIGINT to 100 and 101, SIGKILL to 101 only", signals, kills, intent.Processes)
	}
	for _, pid := range []int{102, 103, 104} {
		if !present(root, pid) {
			t.Errorf("process %d was touched", pid)
		}
	}
	if !r.isMapDaemon(102) || r.isMapDaemon(104) || r.isMapDaemon(999) {
		t.Error("isMapDaemon misidentifies processes")
	}
}

// Another operation can map the same snapshot and archive in the
// intent's window: from another repository, from another namespace, or by
// hand. A restore whose target is named "map" has the same words in its
// command line. Recovery stops only the run's own map: CertiStack's command
// form, the intent's repository and namespace, and the run's token. The
// others are left running; the one it cannot tell apart is reported.
func TestMapReaperStopsOnlyTheRunsOwnMap(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	started := at.Add(time.Second)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), started, ownRepo, "team-a", ownToken)                                                                                             // the run's own map
	fakeMapProc(t, root, 101, mapArgv(otherRepo), started, otherRepo, "team-a", "")                                                                                               // another repository
	fakeMapProc(t, root, 102, mapArgv(ownRepo), started, ownRepo, "team-b", "")                                                                                                   // another namespace
	fakeMapProc(t, root, 103, []string{"/usr/bin/proxmox-backup-client", "restore", "--repository", otherRepo, mapSnapshot, mapArchive, "map"}, started, otherRepo, "team-a", "") // a restore into "map"
	fakeMapProc(t, root, 105, []string{"/usr/bin/proxmox-backup-client", "map", "--repository", ownRepo, "--verbose", mapSnapshot, mapArchive}, started, ownRepo, "", "")         // an option Map never passes
	fakeMapProc(t, root, 104, mapArgv(ownRepo), at.Add(-time.Hour), ownRepo, "team-a", "")                                                                                        // the run's map an hour earlier
	fakeMapProc(t, root, 106, mapArgv(ownRepo), started, ownRepo, "team-a", "")                                                                                                   // by hand: same source, no token

	var signaled []int
	persisted := 0
	r := testReaper(root, func(p journal.Process, sig syscall.Signal) error {
		if sig != syscall.SIGINT {
			t.Errorf("signal %v to %d", sig, p.PID)
		}
		if persisted == 0 {
			t.Errorf("process %d signalled before it was journaled", p.PID)
		}
		signaled = append(signaled, p.PID)
		return os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID)))
	})
	err := r.stop(&intent, func() error { persisted++; return nil })
	if fmt.Sprint(signaled) != "[100]" {
		t.Fatalf("signalled %v, want only the run's own map 100", signaled)
	}
	if len(intent.Processes) != 1 || intent.Processes[0].PID != 100 {
		t.Fatalf("journaled %+v, want process 100", intent.Processes)
	}
	if err == nil || !strings.Contains(err.Error(), "PBS map process 106") || strings.Contains(err.Error(), "must-not-leak") || strings.Contains(err.Error(), ownRepo) {
		t.Fatalf("err = %v, want only the hand-started look-alike 106 reported, without credentials or the repository", err)
	}
	for _, pid := range []int{101, 102, 103, 104, 105, 106} {
		if !present(root, pid) {
			t.Errorf("process %d was touched", pid)
		}
		if pid != 106 && strings.Contains(err.Error(), fmt.Sprintf("process %d ", pid)) {
			t.Errorf("process %d was reported: %v", pid, err)
		}
	}
}

// A run gives the client its namespace as --ns (the 3.x client ignores
// PBS_NAMESPACE), so the map recovery looks for has --ns in its command line.
// Its own map is found with --ns, in either form, and without it (a map an
// earlier build left, which gave the namespace only in the environment); the
// option beats the variable, as it does in the client, so another namespace's
// map is another operation's even where the variable names the run's; a map with
// a second or an empty --ns is not in CertiStack's form at all.
func TestMapReaperStopsAMapStartedWithNsAndNeverAnother(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	started := at.Add(time.Second)
	cmd := func(options ...string) []string {
		return append(append([]string{"/usr/bin/proxmox-backup-client", "map"}, options...), mapSnapshot, mapArchive)
	}
	fakeMapProc(t, root, 100, cmd("--repository", ownRepo, "--ns", "team-a"), started, ownRepo, "team-a", ownToken)                   // the run's map: --ns and the variable
	fakeMapProc(t, root, 101, cmd("--repository", ownRepo, "--ns=team-a"), started, ownRepo, "", ownToken)                            // --ns alone, inline form
	fakeMapProc(t, root, 102, cmd("--repository", ownRepo), started, ownRepo, "team-a", ownToken)                                     // an earlier build's map: the variable alone
	fakeMapProc(t, root, 103, cmd("--repository", ownRepo, "--ns", "team-b"), started, ownRepo, "team-a", "")                         // another namespace, though the variable names the run's
	fakeMapProc(t, root, 104, cmd("--repository", ownRepo, "--ns", "team-a"), started, ownRepo, "", "")                               // by hand: the run's source, no token
	fakeMapProc(t, root, 105, cmd("--repository", ownRepo, "--ns", "team-b"), started, ownRepo, "team-a", ownToken)                   // the run's token, from another namespace
	fakeMapProc(t, root, 106, cmd("--repository", ownRepo, "--ns", "team-a", "--ns", "team-a"), started, ownRepo, "team-a", ownToken) // a second --ns
	fakeMapProc(t, root, 107, cmd("--repository", ownRepo, "--ns", ""), started, ownRepo, "team-a", ownToken)                         // an empty --ns

	var signaled []int
	r := testReaper(root, func(p journal.Process, _ syscall.Signal) error {
		signaled = append(signaled, p.PID)
		return os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID)))
	})
	err := r.stop(&intent, func() error { return nil })
	sort.Ints(signaled)
	if fmt.Sprint(signaled) != "[100 101 102]" {
		t.Fatalf("signalled %v, want the run's own maps 100, 101 and 102: with --ns, with --ns= and without", signaled)
	}
	if err == nil || !strings.Contains(err.Error(), "process 104") || !strings.Contains(err.Error(), "process 105") {
		t.Fatalf("err = %v, want the look-alike 104 and the run's token from another namespace 105 reported", err)
	}
	for _, pid := range []int{103, 104, 105, 106, 107} {
		if !present(root, pid) {
			t.Errorf("process %d was touched", pid)
		}
		if (pid == 103 || pid == 106 || pid == 107) && strings.Contains(err.Error(), fmt.Sprintf("process %d ", pid)) {
			t.Errorf("process %d was reported: %v", pid, err)
		}
	}
}

// Two runs of the same snapshot and archive from the same
// repository and namespace (the host lock allows one at a time, a second
// host with a shared repository or a manual run does not) each carry their
// own token. Recovery of one run stops its own map and leaves the other's
// running, with nothing to report: a process with another run's token is
// not this run's.
func TestMapReaperOfTwoRunsStopsOnlyEachRunsOwnMap(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	first, second := ownIntent(at), ownIntent(at)
	second.Token = otherToken
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	fakeMapProc(t, root, 200, mapArgv(ownRepo), at.Add(2*time.Second), ownRepo, "team-a", otherToken)

	var signaled []int
	r := testReaper(root, func(p journal.Process, _ syscall.Signal) error {
		signaled = append(signaled, p.PID)
		return os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID)))
	})
	if err := r.stop(&first, nil); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if fmt.Sprint(signaled) != "[100]" || !present(root, 200) {
		t.Fatalf("signalled %v, want only 100; 200 present %v", signaled, present(root, 200))
	}
	if err := r.stop(&second, nil); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if fmt.Sprint(signaled) != "[100 200]" {
		t.Fatalf("signalled %v, want 100 then 200", signaled)
	}
	if len(first.Processes) != 1 || first.Processes[0].PID != 100 || len(second.Processes) != 1 || second.Processes[0].PID != 200 {
		t.Fatalf("journaled %+v and %+v", first.Processes, second.Processes)
	}
}

// A process that carries the run's token yet maps from another
// repository or namespace than the run's is contradictory evidence: left,
// reported.
func TestMapReaperReportsATokenFromAnotherSource(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 100, mapArgv(otherRepo), at.Add(time.Second), otherRepo, "team-a", ownToken)
	err := testReaper(root, noSignal(t)).stop(&intent, nil)
	if err == nil || !strings.Contains(err.Error(), "process 100") || strings.Contains(err.Error(), otherRepo) || len(intent.Processes) != 0 {
		t.Fatalf("err = %v, journaled %v; want it reported and not stopped", err, intent.Processes)
	}
}

// A journal from an earlier version names no token to know a run's map by, and
// its snapshot and archive are what any map of them has. Recovery stops none of
// its candidates, however many there are, and reports each without its
// repository; the intent stays unresolved for an operator.
func TestMapReaperLegacyIntentStopsNoProcess(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	legacy := journal.MapIntent{Snapshot: mapSnapshot, Archive: mapArchive, NameSuffix: scsi1Tail, At: at}
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", "")
	r := testReaper(root, noSignal(t))

	// The only candidate is not the run's on that account.
	err := r.stop(&legacy, nil)
	if err == nil || !strings.Contains(err.Error(), "process 100") || !strings.Contains(err.Error(), "predates") || strings.Contains(err.Error(), "repo-a") || len(legacy.Processes) != 0 {
		t.Fatalf("err = %v, journaled %v; want the candidate reported and not stopped", err, legacy.Processes)
	}
	// Nor are two.
	fakeMapProc(t, root, 101, mapArgv(otherRepo), at.Add(2*time.Second), otherRepo, "", "")
	err = r.stop(&legacy, nil)
	if err == nil || !strings.Contains(err.Error(), "100, 101") || strings.Contains(err.Error(), "repo-b") {
		t.Fatalf("err = %v, want both reported", err)
	}
	// With no candidate there is nothing to report.
	if err := os.RemoveAll(filepath.Join(root, "100")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "101")); err != nil {
		t.Fatal(err)
	}
	if err := r.stop(&legacy, nil); err != nil {
		t.Fatalf("stop without a candidate: %v", err)
	}
}

// A candidate whose environment (so its repository, namespace and
// token) cannot be read cannot be told apart from the run's map: left,
// reported.
func TestMapReaperReportsAMapItCannotIdentify(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	environ := filepath.Join(root, "100", "environ")
	if err := os.Remove(environ); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(environ, 0o755); err != nil { // reads fail with EISDIR
		t.Fatal(err)
	}
	err := testReaper(root, noSignal(t)).stop(&intent, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot read the environment of PBS map process 100") || len(intent.Processes) != 0 {
		t.Fatalf("err = %v, journaled %v; want the unreadable map reported and not stopped", err, intent.Processes)
	}
}

// A process the run's map can be, but whose command line cannot be
// read, is not a proof that no map runs; nor is a host whose processes
// cannot be listed or dated.
func TestMapReaperTreatsUnreadableProcAsUnknown(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	root := t.TempDir()
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	fakeProc(t, root, 300, []string{"/usr/sbin/sshd"}, reaperBoot)
	cmdline := filepath.Join(root, "300", "cmdline")
	if err := os.Remove(cmdline); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cmdline, 0o755); err != nil { // reads fail with EISDIR
		t.Fatal(err)
	}
	// Process 300 may be a map: 100 is stopped, and the failure is reported.
	r := testReaper(root, exits(root))
	err := r.stop(&intent, nil)
	if err == nil || !strings.Contains(err.Error(), "command line of process 300") || len(intent.Processes) != 1 {
		t.Fatalf("stop = %v, journaled %v; want 100 stopped and process 300 reported", err, intent.Processes)
	}
	if running, err := r.mapRunning(intent); running || err == nil {
		t.Fatalf("mapRunning = %v, %v; want the unreadable process reported", running, err)
	}

	// The state of a process that is a map, unreadable, is the same.
	stat := filepath.Join(root, "100", "stat")
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	if err := os.Remove(stat); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stat, 0o755); err != nil {
		t.Fatal(err)
	}
	fresh := ownIntent(at)
	if err := testReaper(root, noSignal(t)).stop(&fresh, nil); err == nil || !strings.Contains(err.Error(), "state of PBS map process 100") {
		t.Fatalf("stop = %v, want the unreadable state reported", err)
	}

	noBoot := testReaper(t.TempDir(), noSignal(t))
	noBoot.bootTime = func() (time.Time, error) { return time.Time{}, errors.New("no btime") }
	if err := noBoot.stop(&fresh, nil); err == nil || !strings.Contains(err.Error(), "boot time") {
		t.Fatalf("stop = %v, want the boot time failure", err)
	}
	if _, err := noBoot.mapRunning(intent); err == nil {
		t.Fatal("mapRunning without a boot time reported no map")
	}
	noList := testReaper(filepath.Join(t.TempDir(), "absent"), noSignal(t))
	if _, err := noList.mapRunning(intent); err == nil {
		t.Fatal("mapRunning without a process list reported no map")
	}
	if err := noList.stop(&fresh, nil); err == nil {
		t.Fatal("stop without a process list reported nothing")
	}
}

// A process whose command line or environment never answers (a map
// daemon wedged in the kernel holds its memory lock) is an
// unreadable entry, reported, not a recovery that hangs with it.
func TestMapReaperTreatsAHungProcEntryAsUnreadable(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	fakeProc(t, root, 300, []string{"/usr/sbin/sshd"}, reaperBoot)
	hang := func(pid int, name string) {
		path := filepath.Join(root, fmt.Sprint(pid), name)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0o644); err != nil { // opening it for reading waits for a writer
			t.Fatal(err)
		}
		t.Cleanup(func() { // let the stuck read end
			if f, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
				time.Sleep(50 * time.Millisecond)
				f.Close()
			}
		})
	}
	hang(300, "cmdline")
	hang(100, "environ")
	r := testReaper(root, noSignal(t))
	r.readTimeout = 100 * time.Millisecond
	start := time.Now()
	err := r.stop(&intent, nil)
	if time.Since(start) > 10*time.Second {
		t.Fatal("stop waited for the hung entries")
	}
	if err == nil || !strings.Contains(err.Error(), "command line of process 300") || !strings.Contains(err.Error(), "environment of PBS map process 100") || !strings.Contains(err.Error(), "no answer within") {
		t.Fatalf("err = %v, want both hung entries reported", err)
	}
	if len(intent.Processes) != 0 {
		t.Fatalf("journaled %v: a process whose environment cannot be read is not proved the run's", intent.Processes)
	}
}

// A map process that survives SIGINT and SIGKILL (both refused
// here) is an error, not a warning, and the journal names it.
func TestMapReaperReportsAMapProcessThatSurvivesItsStop(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 201, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	var sent []syscall.Signal
	r := testReaper(root, func(_ journal.Process, sig syscall.Signal) error { sent = append(sent, sig); return syscall.EPERM })
	err := r.stop(&intent, nil)
	if err == nil || !strings.Contains(err.Error(), "PBS map process 201") || !strings.Contains(err.Error(), "SIGKILL: operation not permitted") {
		t.Fatalf("err = %v, want the surviving map process reported with its signal failures", err)
	}
	if fmt.Sprint(sent) != fmt.Sprint([]syscall.Signal{syscall.SIGINT, syscall.SIGKILL}) {
		t.Fatalf("sent %v", sent)
	}
	if len(intent.Processes) != 1 || intent.Processes[0].PID != 201 {
		t.Fatalf("journaled %v, want process 201", intent.Processes)
	}
	if running, err := r.mapRunning(intent); !running || err != nil {
		t.Fatalf("mapRunning = %v, %v", running, err)
	}
}

// A process an earlier attempt journaled is the map's own for as
// long as it runs as itself, even where this attempt cannot read what
// identified it then. It is stopped again, and while it survives, reported.
func TestMapReaperStopsAJournaledProcessAgain(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	self, err := statIdentity(root, 100)
	if err != nil {
		t.Fatal(err)
	}
	intent.AddProcess(self)
	// Neither its environment nor its token can be told any more.
	if err := os.Remove(filepath.Join(root, "100", "environ")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "100", "environ"), 0o755); err != nil {
		t.Fatal(err)
	}

	var sent []syscall.Signal
	r := testReaper(root, func(_ journal.Process, sig syscall.Signal) error { sent = append(sent, sig); return nil })
	err = r.stop(&intent, nil)
	if err == nil || !strings.Contains(err.Error(), "PBS map process 100") || !strings.Contains(err.Error(), "still runs") {
		t.Fatalf("err = %v, want the journaled process reported as running", err)
	}
	if fmt.Sprint(sent) != fmt.Sprint([]syscall.Signal{syscall.SIGINT, syscall.SIGKILL}) {
		t.Fatalf("sent %v, want SIGINT then SIGKILL to the journaled process", sent)
	}
	if strings.Contains(err.Error(), "cannot read the environment") {
		t.Fatalf("err = %v: the journaled process needed no other proof", err)
	}
	r.signal = exits(root)
	if err := r.stop(&intent, nil); err != nil {
		t.Fatalf("stop once it exits: %v", err)
	}
	if present(root, 100) {
		t.Fatal("the journaled process was not stopped")
	}
}

// statIdentity is the identity of a fake process.
func statIdentity(root string, pid int) (journal.Process, error) {
	stat, err := os.ReadFile(filepath.Join(root, fmt.Sprint(pid), "stat"))
	if err != nil {
		return journal.Process{}, err
	}
	return process.ParseIdentity(pid, string(stat))
}

// A journaled PID that names another process now (its map exited
// and the PID was reused, in this boot or in a later one) is never
// signalled, and does not keep recovery from completing.
func TestMapReaperNeverSignalsAReusedPID(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeProc(t, root, 100, []string{"/usr/sbin/sshd", "-D"}, at.Add(time.Hour)) // another start time
	fakeProc(t, root, 101, []string{"/usr/sbin/sshd", "-D"}, at.Add(time.Second))
	self101, err := statIdentity(root, 101) // the same start time, in a later boot
	if err != nil {
		t.Fatal(err)
	}
	fakeProc(t, root, 102, mapArgv(ownRepo), at.Add(time.Second)) // a map, but of another archive
	fakeEnviron(t, root, 102, "PBS_REPOSITORY="+ownRepo, "PBS_NAMESPACE=team-a")
	self102, err := statIdentity(root, 102)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "102", "cmdline"), []byte(strings.Join([]string{"/usr/bin/proxmox-backup-client", "map", mapSnapshot, "drive-scsi0.img"}, "\x00")+"\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	intent.AddProcess(journal.Process{PID: 100, StartTicks: "1"})
	intent.AddProcess(self101)
	intent.AddProcess(self102)
	if err := testReaper(root, noSignal(t)).stop(&intent, nil); err != nil {
		t.Fatalf("stop = %v, want nothing to stop and nothing to report", err)
	}
	for _, pid := range []int{100, 101, 102} {
		if !present(root, pid) {
			t.Errorf("process %d was touched", pid)
		}
	}
}

// A pid file that names a PID another program has now names a
// process that is not the journaled one: it is gone, and its leftovers are
// the run's; the journaled process itself, while it runs as itself, is not.
func TestMapEvidenceTellsAReusedPIDFromTheJournaledProcess(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 4242, []string{"/usr/sbin/sshd", "-D"}, reaperBoot.Add(time.Hour))
	fakeMapProc(t, root, 4343, mapArgv(ownRepo), reaperBoot.Add(2*time.Hour), ownRepo, "team-a", ownToken)
	selfSSHD, err := statIdentity(root, 4242)
	if err != nil {
		t.Fatal(err)
	}
	selfMap, err := statIdentity(root, 4343)
	if err != nil {
		t.Fatal(err)
	}
	intent := ownIntent(reaperBoot.Add(2 * time.Hour))
	intent.AddProcess(journal.Process{PID: 4242, StartTicks: "7"}) // the map's, long gone: 4242 was reused
	intent.AddProcess(selfMap)
	ev := testReaper(root, noSignal(t)).evidence(intent, false)
	if !ev.gone(intent.Processes[0]) || ev.gone(selfMap) || ev.gone(selfSSHD) {
		t.Fatalf("gone: reused PID %v, the map running %v, the program that has the PID %v; want true, false, false",
			ev.gone(intent.Processes[0]), ev.gone(selfMap), ev.gone(selfSSHD))
	}
}

// A map process that exits at the moment recovery signals it (the
// signal finds no process) is stopped, not a failure; an exit after SIGINT
// spares the SIGKILL.
func TestMapReaperStopRacingExit(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	fakeMapProc(t, root, 101, mapArgv(ownRepo), at.Add(2*time.Second), ownRepo, "team-a", ownToken)
	var sent []string
	r := testReaper(root, func(p journal.Process, sig syscall.Signal) error {
		sent = append(sent, fmt.Sprint(p.PID, " ", sig))
		if err := os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID))); err != nil {
			t.Fatal(err)
		}
		if p.PID == 100 {
			return syscall.ESRCH // it was gone when the signal arrived
		}
		return nil
	})
	if err := r.stop(&intent, nil); err != nil {
		t.Fatalf("stop = %v, want both stopped", err)
	}
	if len(sent) != 2 || len(intent.Processes) != 2 {
		t.Fatalf("sent %v, journaled %v; want one SIGINT each and no SIGKILL", sent, intent.Processes)
	}
}

// Only a proxmox-backup-client map that has the snapshot and
// archive among its arguments may hold back the leftovers without a pid
// file: not a restore into "map", not another subcommand.
func TestMapRunningNeedsAMapCommand(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 100, []string{"/usr/bin/proxmox-backup-client", "restore", mapSnapshot, mapArchive, "map"}, at, ownRepo, "", "")
	fakeMapProc(t, root, 101, []string{"/usr/bin/proxmox-backup-client", "snapshot", "map", mapSnapshot, mapArchive}, at, ownRepo, "", "")
	fakeMapProc(t, root, 102, []string{"/usr/bin/vim", "map", mapSnapshot, mapArchive}, at, "", "", "")
	r := testReaper(root, noSignal(t))
	if running, err := r.mapRunning(intent); running || err != nil {
		t.Fatalf("mapRunning = %v, %v with no map running", running, err)
	}
	// A map in any form of the command does: an option Map never passes.
	fakeMapProc(t, root, 103, []string{"/usr/bin/proxmox-backup-client", "map", "--verbose", mapSnapshot, mapArchive}, at, ownRepo, "", "")
	if running, err := r.mapRunning(intent); !running || err != nil {
		t.Fatalf("mapRunning = %v, %v with a map of another form running", running, err)
	}
}

// A killed daemon's leftovers are looked at only once it is gone; the
// environment it is identified by keeps only the names needed.
func TestReadMapEnvKeepsOnlyTheSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environ")
	data := "PBS_PASSWORD=secret\x00PBS_REPOSITORY=first\x00PBS_REPOSITORY=second\x00PBS_ENCRYPTION_PASSWORD=x\x00PBS_NAMESPACE=ns\x00" + pbs.MapTokenEnv + "=tok\x00"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	env, err := (mapReaper{}).mapEnv(path)
	if err != nil || len(env) != 3 || env["PBS_REPOSITORY"] != "first" || env["PBS_NAMESPACE"] != "ns" || env[pbs.MapTokenEnv] != "tok" {
		t.Fatalf("env = %v, %v", env, err)
	}
}

func TestExitedReadsTheStateAfterTheCommand(t *testing.T) {
	for stat, want := range map[string]bool{
		"7 (proxmox-backup) Z 1 7":  true,
		"7 (proxmox-backup) X 1 7":  true,
		"7 (proxmox-backup) D 1 7":  false,
		"7 (a) Z (b) S 1 7":         false,
		"7 (proxmox-backup) S 1 7 ": false,
	} {
		if got := exited(stat); got != want {
			t.Errorf("exited(%q) = %v", stat, got)
		}
	}
}

// A killed daemon leaves its map file and pid file: they are removed when
// their daemon, one of the map's own, is gone and no loop uses them, and
// only then.
func TestLeakFinderOrphans(t *testing.T) {
	f := newFakeMaps(t)
	at := time.Date(2026, 9, 27, 13, 0, 0, 0, time.UTC)
	f.add("loop3", f.runDir, "a"+scsi1Name, at.Add(time.Second)) // still attached to a loop
	for _, name := range []string{"b" + scsi1Name, "c" + scsi1Name, "d" + scsi1Name, "e" + scsi0Name, "f" + scsi1Name} {
		created := at.Add(time.Second)
		if name[0] == 'd' {
			created = at.Add(-time.Hour) // someone else's, older
		}
		pid := filepath.Join(f.runDir, strings.TrimSuffix(name, ".img")+".pid")
		if err := os.WriteFile(pid, []byte(map[byte]string{'b': "4242", 'c': "4343", 'd': "4242", 'e': "4242", 'f': "4444"}[name[0]]), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(pid, created, created); err != nil {
			t.Fatal(err)
		}
	}
	finder := leakFinder{sysBlock: f.sysBlock, runDir: f.runDir, mountInfo: f.mountInfo}
	intent := journal.MapIntent{Snapshot: mapSnapshot, Archive: mapArchive, NameSuffix: scsi1Tail, At: at}
	ev := mapEvidence{
		ours:        map[int]journal.Process{4242: {PID: 4242, StartTicks: "1"}, 4343: {PID: 4343, StartTicks: "2"}},
		gone:        func(p journal.Process) bool { return p.PID != 4343 }, // c's daemon still runs
		daemonAlive: func(int) bool { return false },
	}
	orphans, unproven := finder.orphans(intent, ev)
	want := filepath.Join(f.runDir, "b"+scsi1Name)
	if len(orphans) != 1 || orphans[0] != want {
		t.Fatalf("orphans = %v, want only %s", orphans, want)
	}
	// f's daemon, 4444, was never identified as the run's: reported, and
	// named without the repository.
	if len(unproven) != 1 || !strings.Contains(unproven[0].Error(), "4444") || strings.Contains(unproven[0].Error(), "automation") {
		t.Fatalf("unproven = %v", unproven)
	}
}

// A map daemon stopped early in its fork has mounted its FUSE file
// but written no pid file. Once no map of the snapshot and archive runs,
// its mount (found in the mount table, whose octal escapes are undone) is
// a dead leftover of the run's map, which recovery stopped; a pid file
// from outside the intent's window still marks someone else's map.
func TestLeakFinderOrphansWithoutPidFile(t *testing.T) {
	f := newFakeMaps(t)
	at := time.Date(2026, 9, 27, 17, 52, 54, 0, time.UTC)
	mounted := filepath.Join(f.runDir, "f"+scsi1Name)
	older := filepath.Join(f.runDir, "h"+scsi1Name)
	if err := os.WriteFile(older, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	olderPid := strings.TrimSuffix(older, ".img") + ".pid"
	if err := os.WriteFile(olderPid, []byte("4242"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(olderPid, at.Add(-time.Hour), at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	escape := func(path string) string { return strings.ReplaceAll(path, `\`, `\134`) }
	table := strings.Join([]string{
		"22 1 0:21 / /proc rw,nosuid - proc proc rw",
		"812 30 0:77 / " + escape(mounted) + " rw,nosuid,nodev,relatime - fuse proxmox-backup-client rw,user_id=0,group_id=0",
		"813 30 0:78 / " + escape(filepath.Join(f.runDir, "e"+scsi0Name)) + " rw - fuse proxmox-backup-client rw",
		"814 30 0:79 / " + escape(filepath.Join(t.TempDir(), "i"+scsi1Name)) + " rw - fuse proxmox-backup-client rw",
	}, "\n") + "\n"
	if err := os.WriteFile(f.mountInfo, []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	finder := leakFinder{sysBlock: f.sysBlock, runDir: f.runDir, mountInfo: f.mountInfo}
	if yes, err := finder.mounted(mounted); !yes || err != nil {
		t.Fatalf("mounted misreads the mount table: %v, %v", yes, err)
	}
	intent := journal.MapIntent{NameSuffix: scsi1Tail, At: at}
	stopped := mapEvidence{ours: map[int]journal.Process{77: {PID: 77, StartTicks: "1"}}, gone: func(journal.Process) bool { return true }, daemonAlive: func(int) bool { return false }}
	if got, errs := finder.orphans(intent, stopped); fmt.Sprint(got) != fmt.Sprint([]string{mounted}) || len(errs) != 0 {
		t.Fatalf("orphans = %v, %v; want the pid-less mount %s", got, errs, mounted)
	}
	running := stopped
	running.running = true
	if got, errs := finder.orphans(intent, running); len(got) != 0 || len(errs) != 1 {
		t.Fatalf("orphans = %v, %v while a map of the archive still runs, want none, reported", got, errs)
	}
	// Recovery stopped no process of the run's map: nothing ties the mount to
	// the run.
	if got, errs := finder.orphans(intent, mapEvidence{gone: stopped.gone, daemonAlive: stopped.daemonAlive}); len(got) != 0 || len(errs) != 1 {
		t.Fatalf("orphans = %v, %v with no process of the run's map, want none, reported", got, errs)
	}
	// An unreadable mount table does not show that no mount is left.
	finder.mountInfo = filepath.Join(t.TempDir(), "absent")
	if _, errs := finder.orphans(intent, stopped); len(errs) == 0 {
		t.Fatal("orphans without a mount table reported nothing")
	}
}

// A map process killed after ignoring SIGINT may still be exiting; stop
// waits for it to be gone before the map's files are looked at.
func TestMapReaperWaitsForAKilledProcessToExit(t *testing.T) {
	root := t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 200, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	killed, sleepsAfterKill := false, 0
	r := testReaper(root, func(_ journal.Process, sig syscall.Signal) error { // frozen: ignores SIGINT
		killed = killed || sig == syscall.SIGKILL
		return nil
	})
	r.sleep = func(time.Duration) {
		if killed {
			if sleepsAfterKill++; sleepsAfterKill == 3 {
				_ = os.RemoveAll(filepath.Join(root, "200")) // reaped
			}
		}
	}
	r.grace = 10 * time.Millisecond
	r.reapWait = time.Minute
	if err := r.stop(&intent, nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !killed || sleepsAfterKill != 3 {
		t.Fatalf("killed %v, waited %d polls; want stop to return once the killed process is gone", killed, sleepsAfterKill)
	}
	if running, err := r.mapRunning(intent); running || err != nil {
		t.Fatalf("mapRunning = %v, %v after the map process exited", running, err)
	}
}

// A command stuck in the kernel can't be killed; recovery stops waiting for
// it instead of hanging with it.
func TestWaitWatchedStopsWaitingForAStuckCommand(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	stuck := runWatched(func() error { <-release; return nil })
	if finished, _ := waitWatched(stuck, 10*time.Millisecond); finished {
		t.Fatal("a stuck command finished")
	}
	quick := runWatched(func() error { return errors.New("exit status 255") })
	if finished, err := waitWatched(quick, time.Second); !finished || err == nil {
		t.Fatalf("finished %v, err %v", finished, err)
	}
}

// What runs under a PID is read through the bounded reader, and a
// process that cannot be read is neither dead nor another program.
func TestHolderOfTellsWhatRunsUnderAPID(t *testing.T) {
	root := t.TempDir()
	fakeProc(t, root, 300, []string{"/usr/bin/proxmox-backup-client", "backup", "root.pxar:/"}, reaperBoot)
	fakeProc(t, root, 301, []string{"/usr/sbin/sshd"}, reaperBoot)
	fakeProc(t, root, 303, []string{"/usr/bin/proxmox-backup-client", "map", "a", "b"}, reaperBoot)
	if err := os.WriteFile(filepath.Join(root, "303", "stat"), []byte("303 (proxmox-backup) Z 1 2 3"), 0o644); err != nil { // a zombie
		t.Fatal(err)
	}
	fakeProc(t, root, 304, []string{"/usr/bin/proxmox-backup-client", "map", "a", "b"}, reaperBoot)
	if err := os.Remove(filepath.Join(root, "304", "cmdline")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "304", "cmdline"), 0o644); err != nil { // never answers
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(filepath.Join(root, "304", "cmdline"), os.O_RDWR, 0); err == nil {
			time.Sleep(50 * time.Millisecond)
			f.Close()
		}
	})
	fakeProc(t, root, 305, []string{"/usr/bin/proxmox-backup-client", "map", "a", "b"}, reaperBoot)
	if err := os.Remove(filepath.Join(root, "305", "stat")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "305", "stat"), 0o755); err != nil { // cannot be read
		t.Fatal(err)
	}
	r := testReaper(root, noSignal(t))
	r.readTimeout = 100 * time.Millisecond
	for pid, want := range map[int]holder{300: holderClient, 301: holderOther, 302: holderNone, 303: holderNone, 304: holderUnknown, 305: holderUnknown} {
		if got := r.holderOf(pid); got != want {
			t.Errorf("holderOf(%d) = %v, want %v", pid, got, want)
		}
	}
	// A process that cannot be read may be a live daemon: it is never called
	// dead, and is never called the map's own.
	if !r.daemonAlive(304) || !r.daemonAlive(305) || r.daemonAlive(301) || r.daemonAlive(303) || r.daemonAlive(302) || !r.isMapDaemon(300) || r.isMapDaemon(304) {
		t.Error("daemonAlive or isMapDaemon misjudge a process")
	}
}
