// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// mapTestOrchestrator is an orchestrator whose PVE reports no VM 9001 and
// whose PBS client is configured with pbsConfig, and its state directory.
func mapTestOrchestrator(t *testing.T, pbsConfig pbs.Config) (*Orchestrator, string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/cluster/resources":
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
		case "/api2/json/nodes/localhost/qemu/9001/status/current":
			http.Error(w, `{"errors": "Configuration file does not exist"}`, http.StatusNotFound)
		default:
			t.Errorf("unexpected PVE request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	o := New(&config.Plan{}, Options{NodeName: "localhost", StateDir: stateDir, ScratchDir: t.TempDir()}, pbs.New(pbsConfig), pve.NewClient(pve.Config{BaseURL: server.URL}))
	return o, stateDir
}

const mapTestSnapshot = "vm/7214/2026-09-27T03:12:59Z"

func mapTestVM() config.VM {
	return config.VM{VMID: 9001, SourceVMID: 7214, SourcePBS: config.SourcePBS{Snapshot: mapTestSnapshot, Drives: []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}}}
}

// A run journals each map, before it starts it, with what it reads
// from (never the repository) and a token, and gives the token to the
// client's process: recovery knows the map's processes by them. The
// journaled owner is the one recovery reads back from the process's
// command line and environment.
func TestMapIsJournaledWithTheTokenItsProcessCarries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "call.log")
	script := "#!/bin/sh\n{ echo \"$0 $*\"; env; } > " + log + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	pbsConfig := pbs.Config{Repository: "u@pbs!tok@pbs.example:store", Namespace: "team-a", Password: "secret-password"}
	o, stateDir := mapTestOrchestrator(t, pbsConfig)
	if _, err := o.bootAndVerifyVM(context.Background(), mapTestVM(), 60, nil); err == nil {
		t.Fatal("the map of a failing client succeeded")
	}

	record, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(record.MapIntents) != 1 {
		t.Fatalf("map intents = %+v", record.MapIntents)
	}
	intent := record.MapIntents[0]
	want, err := pbs.New(pbsConfig).MapOwner(mapTestSnapshot, "drive-scsi0")
	if err != nil {
		t.Fatal(err)
	}
	if intent.Owner != want || len(intent.Token) != 32 {
		t.Fatalf("journaled intent = %+v, want owner %s and a token", intent, want)
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "pbs.example") || strings.Contains(string(data), "u@pbs") || strings.Contains(string(data), "secret-password") {
		t.Fatalf("the journal holds the repository or the password:\n%s", data)
	}

	call, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("the client was not run: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(call)), "\n")
	argv := append([]string{"proxmox-backup-client"}, strings.Fields(lines[0])[1:]...)
	env := map[string]string{}
	for _, line := range lines[1:] {
		if name, value, ok := strings.Cut(line, "="); ok {
			env[name] = value
		}
	}
	if env[pbs.MapTokenEnv] != intent.Token {
		t.Fatalf("the client's %s = %q, want the journaled token", pbs.MapTokenEnv, env[pbs.MapTokenEnv])
	}
	m, ok := pbs.ParseMapCommand(argv)
	if !ok || m.Snapshot != mapTestSnapshot || m.Archive != "drive-scsi0.img" {
		t.Fatalf("the client's command line %v is not a map recovery recognizes", argv)
	}
	if got := m.Owner(env); got != intent.Owner {
		t.Fatalf("recovery reads the owner %s from the process, the journal has %s", got, intent.Owner)
	}
	// The namespace is on the command line, where the 3.x client reads it, and
	// recovery reads it from there: the owner does not need the variable.
	if !m.HasNamespace || m.Namespace != "team-a" {
		t.Fatalf("the client's command line %v carries no --ns team-a", argv)
	}
	delete(env, "PBS_NAMESPACE")
	if got := m.Owner(env); got != intent.Owner {
		t.Fatalf("without the variable recovery reads the owner %s, the journal has %s", got, intent.Owner)
	}
}

// mapRun is an orchestrator for a whole run of a plan whose one VM (9001) is
// free to be made and whose PBS map is made by the client that PATH holds: it
// reaches the map, and fails at the overlay or before.
func mapRun(t *testing.T) (*Orchestrator, string) {
	t.Helper()
	fake := &lockingPVE{intercept: func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/resources":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
			return true
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/localhost/qemu/9001/status/current":
			http.Error(w, `{"errors": "Configuration file does not exist"}`, http.StatusNotFound)
			return true
		}
		return false
	}}
	plan := ephemeralPlan()
	plan.Tiers = []config.Tier{{Level: 1, Name: "Core", VMs: []config.VM{mapTestVM()}}}
	stateDir := t.TempDir()
	o := New(plan, Options{NodeName: "localhost", StateDir: stateDir, ScratchDir: t.TempDir()}, pbs.New(pbs.Config{Repository: "u@pbs!tok@pbs.example:store"}), fake.serve(t))
	o.hostAddresses = &fakeHostAddressManager{}
	return o, stateDir
}

// Orchestrator side: when the release of a failed map's leftovers
// fails, teardown tries again, and a failure there is a cleanup failure: the
// run ends cleanup_failed, its journal keeps the intent and the process the
// release found, and it is not marked cleaned over a map process that still
// runs. Once the second try succeeds, the run ends cleaned.
func TestFailedMapReleaseKeepsTheRunUnclean(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the node worker needs Linux host memory and mount-table semantics")
	}
	for _, secondSucceeds := range []bool{false, true} {
		t.Run(map[bool]string{false: "still runs", true: "released by the retry"}[secondSucceeds], func(t *testing.T) {
			o, stateDir := mapRun(t)
			calls := 0
			o.unmapLeakedMapsFn = func(intents []*journal.MapIntent, _ map[string]bool, persist func() error) error {
				calls++
				if len(intents) != 1 || intents[0] != &o.record.MapIntents[0] {
					t.Fatalf("release of %v, want the record's own intent", intents)
				}
				if calls == 2 && secondSucceeds {
					return nil
				}
				intents[0].AddProcess(journal.Process{PID: 4242, StartTicks: "1"})
				if err := persist(); err != nil {
					t.Fatal(err)
				}
				return errors.New("PBS map process 4242 still runs")
			}
			// No proxmox-backup-client runs here, so the map fails.
			t.Setenv("PATH", t.TempDir())
			res, err := o.Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), "release a partial map") {
				t.Fatalf("Run = %v, want the map error and the failed release", err)
			}
			record, loadErr := journal.Load(filepath.Join(stateDir, "active.json"))
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if calls != 2 || res.TeardownEvidence == nil {
				t.Fatalf("%d releases, evidence %+v; want the release tried at teardown too", calls, res.TeardownEvidence)
			}
			if intent := record.MapIntents[0]; intent.Token == "" || len(intent.Processes) != 1 {
				t.Fatalf("journaled intent = %+v, want its token and the process the release found", intent)
			}
			if secondSucceeds {
				if !res.TeardownEvidence.AllCleaned || record.Phase != "cleaned" {
					t.Fatalf("phase %q, evidence %+v; want cleaned once the retry released the map", record.Phase, res.TeardownEvidence)
				}
				return
			}
			if res.TeardownEvidence.AllCleaned || record.Phase != "cleanup_failed" || !strings.Contains(strings.Join(record.CleanupErrors, "\n"), "4242") {
				t.Fatalf("phase %q, errors %v, evidence %+v; want cleanup_failed naming the process", record.Phase, record.CleanupErrors, res.TeardownEvidence)
			}
		})
	}
}

// loopFixture is a private sysfs with /dev/loop7 attached to owned, and a
// proxmox-backup-client that maps to it (and runs extra for any other command)
// and a losetup that only log their calls: no real device or map is touched.
type loopFixture struct {
	t     *testing.T
	log   string
	state string // the backing_file of /dev/loop7
}

const (
	// ownedLoopName is the name proxmox-backup-client gives the file of a map
	// of the test VM's disk (mapTestSnapshot's drive-scsi0) from the test
	// repository.
	ownedLoopName      = `u\x40pbs\x21tok\x40pbs.example\x3astore\x3avm-7214-2026\x2d09\x2d27T03\x3a12\x3a59Z-drive\x2dscsi0.img`
	ownedLoopBacking   = "/run/pbs-loopdev/" + ownedLoopName
	foreignLoopBacking = "/run/pbs-loopdev/certistack-test-foreign-map.img"
)

func newLoopFixture(t *testing.T, extra string) *loopFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake proxmox-backup-client is a shell script")
	}
	dir := t.TempDir()
	f := &loopFixture{t: t, log: filepath.Join(dir, "calls.log"), state: filepath.Join(dir, "sys", "loop7", "loop", "backing_file")}
	old := sysutil.SysBlockDir
	t.Cleanup(func() { sysutil.SysBlockDir = old })
	sysutil.SysBlockDir = filepath.Join(dir, "sys")
	if err := os.MkdirAll(filepath.Dir(f.state), 0o755); err != nil {
		t.Fatal(err)
	}
	f.attach(ownedLoopBacking)
	// A command that succeeds releases the loop as the kernel would, its sysfs
	// entry going, unless the test has kept the loop (keepLoop).
	forget := "[ -e '" + filepath.Join(dir, "keeploop") + "' ] || /bin/rm -f '" + f.state + "'"
	client := "#!/bin/sh\nprintf 'proxmox-backup-client %s\\n' \"$*\" >> '" + f.log + "'\ncase \"$1\" in\nmap) echo 'Image mapped to /dev/loop7'; exit 0;;\nesac\n(" + strings.ReplaceAll(extra, "STATE", "'"+f.state+"'") + "\n)\nrc=$?\n[ $rc -eq 0 ] && { " + forget + "; }\nexit $rc\n"
	if err := os.WriteFile(filepath.Join(dir, "proxmox-backup-client"), []byte(client), 0o755); err != nil {
		t.Fatal(err)
	}
	losetup := "#!/bin/sh\nprintf 'losetup %s\\n' \"$*\" >> '" + f.log + "'\n" + forget + "\n"
	if err := os.WriteFile(filepath.Join(dir, "losetup"), []byte(losetup), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return f
}

// keepLoop makes the fake commands leave the loop in the kernel after they
// succeed: it stays attached, as a loop something else holds open does.
func (f *loopFixture) keepLoop() {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.log), "keeploop"), nil, 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// diskseq sets the disk sequence number the fixture's /dev/loop7 reports.
func (f *loopFixture) diskseq(n int) {
	f.t.Helper()
	path := filepath.Join(filepath.Dir(filepath.Dir(f.state)), "diskseq")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d\n", n)), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *loopFixture) attach(file string) {
	f.t.Helper()
	if err := os.WriteFile(f.state, []byte(file+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

// calls is what the fake commands were asked, one line each, without the map
// call that made the loop.
func (f *loopFixture) calls() string {
	data, _ := os.ReadFile(f.log)
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if !strings.HasPrefix(line, "proxmox-backup-client map ") && line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

// logCall adds a line to the log the fake commands write, so that the order of
// a step that is not a command (stopping a daemon) shows with theirs.
func (f *loopFixture) logCall(line string) {
	f.t.Helper()
	log, err := os.OpenFile(f.log, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		f.t.Fatal(err)
	}
	defer log.Close()
	fmt.Fprintln(log, line)
}

// mapAndFail maps the test VM's disk (the fixture's client makes /dev/loop7),
// fails at its overlay, and leaves the unmap of the loop on the cleanup stack.
func (f *loopFixture) mapAndFail(o *Orchestrator) {
	f.t.Helper()
	if _, err := o.bootAndVerifyVM(context.Background(), mapTestVM(), 60, nil); err == nil || !strings.Contains(err.Error(), "delta overlay") {
		f.t.Fatalf("bootAndVerifyVM = %v, want it to fail at the overlay, after the map", err)
	}
	if len(o.record.Loops) != 1 || o.record.Loops[0].Device != "/dev/loop7" || o.record.Loops[0].Backing != ownedLoopBacking {
		f.t.Fatalf("journaled loops = %+v, want /dev/loop7 with the backing it had when mapped", o.record.Loops)
	}
}

// The run's map is gone before normal teardown and another map has the loop
// number: the unmap the cleanup stack registered (the client, which the fake
// refuses, then losetup -d by path) would detach the other map's device.
// Nothing runs against it, teardown says the device is no longer the run's,
// and the run is clean because nothing of its map remains.
func TestNormalCleanupLeavesAReusedLoopAlone(t *testing.T) {
	f := newLoopFixture(t, "exit 19")
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	f.attach(foreignLoopBacking) // the run's map went away; another map took the number

	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures = %v, want none: the device is not the run's", failures)
	}
	if calls := f.calls(); calls != "" {
		t.Fatalf("commands ran against another map's loop:\n%s", calls)
	}
	all, unmapped, errs := o.verifyTrackedLoopsUnmapped()
	if !all || len(errs) != 0 || len(unmapped) != 1 {
		t.Fatalf("verification = all %v, unmapped %v, errs %v; want the run's map not on the device, and clean", all, unmapped, errs)
	}
}

// The same, when something of the run's map remains (its FUSE mount,
// or a daemon under its pid file): the loop is still left alone, and neither
// teardown nor the verifier calls the run clean.
func TestNormalCleanupReportsWhatRemainsOfAMapWhoseLoopWasReused(t *testing.T) {
	f := newLoopFixture(t, "exit 19")
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	o.reusedLoopNoteFn = func(device, backing string) (string, error) {
		if backing != ownedLoopBacking {
			t.Errorf("remnants looked for under %q", backing)
		}
		return "", errors.New(device + " backs another file now, so it was left alone, but the run's PBS map is not gone: its FUSE mount is still there")
	}
	f.mapAndFail(o)
	f.attach(foreignLoopBacking)

	failures := o.cleanup.Unwind()
	if len(failures) != 1 || !strings.Contains(failures[0].Err.Error(), "is not gone") {
		t.Fatalf("teardown failures = %v, want the remaining map reported", failures)
	}
	if calls := f.calls(); calls != "" {
		t.Fatalf("commands ran against another map's loop:\n%s", calls)
	}
	if all, unmapped, errs := o.verifyTrackedLoopsUnmapped(); all || len(unmapped) != 0 || len(errs) != 1 {
		t.Fatalf("verification = all %v, unmapped %v, errs %v; want not clean", all, unmapped, errs)
	}
}

// Reuse between the daemon's stop and the detach, and the run's own loop,
// which is still released. The client's unmap is never run.
func TestNormalCleanupRechecksBeforeTheDetachThatFollowsTheDaemonsStop(t *testing.T) {
	f := newLoopFixture(t, "exit 19")
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return true, nil }
	stopped := 0
	o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
		stopped++
		f.attach(foreignLoopBacking) // the daemon exits, and another map has the number
		return "", nil
	}
	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures = %v", failures)
	}
	if calls := f.calls(); stopped != 1 || calls != "" {
		t.Fatalf("daemon stopped %d times, calls:\n%s\nwant it stopped and nothing run: the device was another map's before the detach", stopped, calls)
	}

	f = newLoopFixture(t, "exit 19")
	o, _ = mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures = %v", failures)
	}
	if calls := f.calls(); calls != "losetup -d /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant the run's own loop released by the verified detach, the client never run", calls)
	}
}

// The map's daemon is stopped by CertiStack, through the verified process, never
// by the client's unmap (which signals the PID in the map's pid file
// unchecked). When the pid file names a process that is not the run's map
// daemon, normal teardown stops nothing: it detaches the loop itself. When it is
// the run's own, the daemon is stopped after what holds the loop and before the
// detach, and one that cannot be stopped leaves the loop attached.
func TestNormalCleanupStopsTheMapDaemonItselfAndSignalsNoOtherProcess(t *testing.T) {
	f := newLoopFixture(t, "exit 0")
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	o.mayStopMapDaemonFn = func(backing string, intent journal.MapIntent) (bool, error) {
		if backing != ownedLoopBacking || intent.Token == "" || intent.Device != "/dev/loop7" {
			t.Errorf("guard asked about %q, intent %+v", backing, intent)
		}
		return false, nil
	}
	o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
		t.Error("a daemon was stopped though the pid file names a process that is not the run's")
		return "", nil
	}
	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures = %v", failures)
	}
	if calls := f.calls(); calls != "losetup -d /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant the verified detach only", calls)
	}

	// A guard that cannot tell leaves the map alone, and teardown fails.
	f = newLoopFixture(t, "exit 0")
	o, _ = mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return false, errors.New("the pid file cannot be read") }
	o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
		t.Error("a daemon was stopped though the guard could not tell")
		return "", nil
	}
	if failures := o.cleanup.Unwind(); len(failures) != 1 || f.calls() != "" {
		t.Fatalf("failures %v, calls %q; want the map left alone and reported", failures, f.calls())
	}

	// The run's own daemon: stopped once, with the backing and intent of this
	// map, after the holders and before the detach.
	f = newLoopFixture(t, "exit 0")
	f.holderFake(nil, nil)
	o, _ = mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return true, nil }
	o.stopMapDaemonFn = func(backing string, intent journal.MapIntent) (string, error) {
		if backing != ownedLoopBacking || intent.Token == "" || intent.Device != "/dev/loop7" {
			t.Errorf("daemon stopped for %q, intent %+v", backing, intent)
		}
		f.logCall("stop daemon")
		return "", nil
	}
	if failures := o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures = %v", failures)
	}
	if calls := f.calls(); calls != "holders /dev/loop7\nstop daemon\nlosetup -d /dev/loop7" {
		t.Fatalf("calls:\n%s\nwant the holders, the daemon, then the detach", calls)
	}

	// A daemon that cannot be stopped leaves the loop attached, and teardown
	// reports it.
	f = newLoopFixture(t, "exit 0")
	o, _ = mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return true, nil }
	o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
		return "", errors.New("the PBS map daemon 4242 was sent SIGINT and has not exited")
	}
	failures := o.cleanup.Unwind()
	if len(failures) != 1 || !strings.Contains(failures[0].Err.Error(), "4242") || !strings.Contains(failures[0].Err.Error(), "unmap /dev/loop7") || f.calls() != "" {
		t.Fatalf("failures %v, calls %q; want the daemon reported and no detach under it", failures, f.calls())
	}
	if all, _, errs := o.verifyTrackedLoopsUnmapped(); all || len(errs) != 1 {
		t.Fatalf("verification = all %v, errs %v; want the loop reported still mapped", all, errs)
	}

	// A pid file that names a process that exited between the guard and the stop,
	// or one that is not the run's by then, is a note, not a failure: the loop is
	// detached.
	f = newLoopFixture(t, "exit 0")
	o, _ = mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	f.mapAndFail(o)
	o.mayStopMapDaemonFn = func(string, journal.MapIntent) (bool, error) { return true, nil }
	o.stopMapDaemonFn = func(string, journal.MapIntent) (string, error) {
		return "the map's pid file names PID 4242, which runs another program now", nil
	}
	if failures := o.cleanup.Unwind(); len(failures) != 0 || f.calls() != "losetup -d /dev/loop7" {
		t.Fatalf("failures %v, calls %q; want the verified detach alone", failures, f.calls())
	}
}

// A loop the run cannot recognize as its own (its identity could not
// be read right after the map) is never detached by device path: the map is
// released through its intent, which proves its processes the run's.
func TestMappedLoopWithoutAnIdentityIsReleasedThroughItsIntent(t *testing.T) {
	f := newLoopFixture(t, "exit 19")
	if err := os.Remove(f.state); err != nil { // its backing cannot be read
		t.Fatal(err)
	}
	if err := os.Mkdir(f.state, 0o755); err != nil {
		t.Fatal(err)
	}
	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	released := 0
	o.unmapLeakedMapsFn = func(intents []*journal.MapIntent, _ map[string]bool, _ func() error) error {
		released++
		if len(intents) != 1 || intents[0].Device != "" {
			t.Errorf("released %+v, want the unresolved intent", intents)
		}
		return nil
	}
	_, err := o.bootAndVerifyVM(context.Background(), mapTestVM(), 60, nil)
	if err == nil || !strings.Contains(err.Error(), "verify mapped PBS loop identity") {
		t.Fatalf("bootAndVerifyVM = %v, want the identity failure", err)
	}
	if released != 1 || len(o.record.Loops) != 0 {
		t.Fatalf("%d releases, loops %+v; want the map released through its intent and no loop recorded", released, o.record.Loops)
	}
	if failures := o.cleanup.Unwind(); len(failures) != 0 || f.calls() != "" {
		t.Fatalf("teardown failures %v, calls %q; want nothing run against the device by path", failures, f.calls())
	}
}
