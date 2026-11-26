//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"golang.org/x/sys/unix"
)

// fakeClientMode makes this test binary stand in for a proxmox-backup-client
// map daemon: started with it in its environment, before any test runs, it
// prints "ready" and waits to be signaled. It is only ever started by
// startFakeClient, as a child of a test.
const fakeClientMode = "CERTISTACK_TEST_FAKE_MAP_CLIENT"

// fakeClientSignalFile names the file the "record" mode writes the name of the
// first signal it receives to, then exits.
const fakeClientSignalFile = "CERTISTACK_TEST_FAKE_MAP_CLIENT_SIGNAL_FILE"

// fakeClientOnSignalFile and fakeClientOnSignalText make the "record" mode
// write the text to the file (what the kernel would show after the daemon has
// released its loop) before it exits.
const (
	fakeClientOnSignalFile = "CERTISTACK_TEST_FAKE_MAP_CLIENT_ON_SIGNAL_FILE"
	fakeClientOnSignalText = "CERTISTACK_TEST_FAKE_MAP_CLIENT_ON_SIGNAL_TEXT"
)

func init() {
	mode := os.Getenv(fakeClientMode)
	if mode == "" {
		return
	}
	if mode == "record" {
		// Takes any signal a stop could send, and says which one came first.
		received := make(chan os.Signal, 4)
		signal.Notify(received, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGQUIT)
		fmt.Println("ready")
		got := <-received
		_ = os.WriteFile(os.Getenv(fakeClientSignalFile), []byte(got.String()), 0o644)
		if file := os.Getenv(fakeClientOnSignalFile); file != "" {
			_ = os.WriteFile(file, []byte(os.Getenv(fakeClientOnSignalText)), 0o644)
		}
		os.Exit(0)
	}
	interrupted := make(chan os.Signal, 1)
	if mode == "ignore" {
		signal.Ignore(syscall.SIGINT, syscall.SIGTERM) // only SIGKILL ends it
	} else {
		signal.Notify(interrupted, syscall.SIGINT) // exits on SIGINT, as the map daemon does
	}
	fmt.Println("ready")
	if mode == "ignore" {
		select {}
	}
	<-interrupted
	os.Exit(0)
}

// fakeClient is a real process whose /proc entry looks like a map daemon's.
type fakeClient struct {
	cmd  *exec.Cmd
	id   journal.Process
	done chan error // the result of Wait
}

// startFakeClient starts a process with the command line argv and the
// environment env, in mode ("stop" stops on SIGINT, "ignore" ignores SIGINT
// and SIGTERM), and waits until it is ready. The test reaps it.
func startFakeClient(t *testing.T, mode string, argv, env []string) *fakeClient {
	t.Helper()
	if fd, err := unix.PidfdOpen(os.Getpid(), 0); err != nil {
		t.Skipf("pidfd_open is not available: %v", err)
	} else {
		unix.Close(fd)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Args = argv
	cmd.Env = append([]string{fakeClientMode + "=" + mode}, env...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &fakeClient{cmd: cmd, done: make(chan error, 1)}
	waiting := false
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		if waiting {
			<-c.done
		} else {
			_ = cmd.Wait()
		}
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("the fake client is not ready: %q, %v", line, err)
	}
	waiting = true
	go func() { c.done <- cmd.Wait() }()
	if c.id, err = process.ProcessIdentity(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	return c
}

// exited reports whether the process has exited within d.
func (c *fakeClient) exited(d time.Duration) bool {
	select {
	case err := <-c.done:
		c.done <- err
		return true
	case <-time.After(d):
		return false
	}
}

// realMapEnv is the environment of a real map process of the test map.
func realMapEnv(repository, namespace, token string) []string {
	env := []string{"PATH=/usr/bin", "PBS_REPOSITORY=" + repository, "PBS_PASSWORD=must-not-leak"}
	if namespace != "" {
		env = append(env, "PBS_NAMESPACE="+namespace)
	}
	if token != "" {
		env = append(env, pbs.MapTokenEnv+"="+token)
	}
	return env
}

// realReaper reads the host's own /proc and signals through pidfds, waiting
// only briefly.
func realReaper() mapReaper {
	r := hostMapReaper
	r.grace = 300 * time.Millisecond
	r.reapWait = 3 * time.Second
	r.sleep = func(time.Duration) { time.Sleep(10 * time.Millisecond) }
	return r
}

// realSnapshot is a snapshot no other run of these tests maps: the host's
// /proc is shared with every other test run on it (from another checkout,
// say), and what runs there must not look like this test's map.
var realSnapshot = fmt.Sprintf("vm/%d/2026-09-27T03:12:59Z", 20000+os.Getpid())

// realMapArgv is mapArgv for realSnapshot.
func realMapArgv(repository string) []string {
	return []string{"/usr/bin/proxmox-backup-client", "map", "--repository", repository, realSnapshot, mapArchive}
}

// intentFor is ownIntent of realSnapshot for a map that began when c started.
func intentFor(t *testing.T, c *fakeClient) journal.MapIntent {
	t.Helper()
	boot, err := hostBootTime()
	if err != nil {
		t.Fatal(err)
	}
	var ticks int64
	fmt.Sscan(c.id.StartTicks, &ticks)
	intent := ownIntent(boot.Add(time.Duration(ticks) * time.Second / clockTicks))
	intent.Snapshot = realSnapshot
	intent.Owner = pbs.MapOwner(ownRepo, "team-a", realSnapshot, mapArchive)
	return intent
}

// Against real processes and the real /proc: the run's own map,
// found by its command line, its environment's repository, namespace and
// token, stops on SIGINT; a map of the same snapshot and archive from
// another repository, one from another namespace, another run's, and a
// restore into "map" run on, unsignaled.
func TestRealMapProcessesAreToldApartByTheirEnvironment(t *testing.T) {
	own := startFakeClient(t, "stop", realMapArgv(ownRepo), realMapEnv(ownRepo, "team-a", ownToken))
	intent := intentFor(t, own)
	others := map[string]*fakeClient{
		"another repository": startFakeClient(t, "stop", realMapArgv(otherRepo), realMapEnv(otherRepo, "team-a", "")),
		"another namespace":  startFakeClient(t, "stop", realMapArgv(ownRepo), realMapEnv(ownRepo, "team-b", "")),
		"another run":        startFakeClient(t, "stop", realMapArgv(ownRepo), realMapEnv(ownRepo, "team-a", otherToken)),
		"a restore into map": startFakeClient(t, "stop", []string{"proxmox-backup-client", "restore", "--repository", ownRepo, realSnapshot, mapArchive, "map"}, realMapEnv(ownRepo, "team-a", ownToken)),
	}
	persisted := false
	err := realReaper().stop(&intent, func() error { persisted = true; return nil })
	if err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !own.exited(5*time.Second) || !persisted || len(intent.Processes) != 1 || intent.Processes[0] != own.id {
		t.Fatalf("own map exited %v, journaled %v (persisted %v); want it stopped and journaled", own.exited(0), intent.Processes, persisted)
	}
	for name, other := range others {
		if other.exited(200 * time.Millisecond) {
			t.Errorf("the map of %s was stopped", name)
		}
	}
}

// Against a real process that ignores SIGINT and SIGTERM: recovery
// sends SIGINT, waits, kills it, and returns once it is gone.
func TestRealMapProcessThatIgnoresSIGINTIsKilled(t *testing.T) {
	stubborn := startFakeClient(t, "ignore", realMapArgv(ownRepo), realMapEnv(ownRepo, "team-a", ownToken))
	intent := intentFor(t, stubborn)
	// It does ignore both.
	_ = syscall.Kill(stubborn.id.PID, syscall.SIGTERM)
	_ = syscall.Kill(stubborn.id.PID, syscall.SIGINT)
	if stubborn.exited(300 * time.Millisecond) {
		t.Fatal("the fake client does not ignore SIGINT and SIGTERM")
	}
	if err := realReaper().stop(&intent, nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !stubborn.exited(5 * time.Second) {
		t.Fatal("the process that ignores SIGINT still runs")
	}
	if len(intent.Processes) != 1 || intent.Processes[0] != stubborn.id {
		t.Fatalf("journaled %v", intent.Processes)
	}
}

// A journaled process is stopped again, by its journaled identity
// alone, when a retry finds it still running.
func TestRealJournaledMapProcessIsStoppedOnRetry(t *testing.T) {
	stubborn := startFakeClient(t, "ignore", realMapArgv(ownRepo), realMapEnv(ownRepo, "team-a", ownToken))
	// The journal names it, and no token: only its identity.
	intent := intentFor(t, stubborn)
	intent.Token = "ffffffffffffffffffffffffffffffff"
	intent.AddProcess(stubborn.id)
	if err := realReaper().stop(&intent, nil); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if !stubborn.exited(5 * time.Second) {
		t.Fatal("the journaled process still runs")
	}
}

// A signal goes only to the process the journal names. A PID that
// names another process now (a different start time) is not signaled, and
// a process that has already exited is not an error.
func TestSignalRecordedNeverSignalsAReusedPID(t *testing.T) {
	c := startFakeClient(t, "stop", realMapArgv(ownRepo), realMapEnv(ownRepo, "team-a", ownToken))
	reused := journal.Process{PID: c.id.PID, StartTicks: c.id.StartTicks + "1"}
	if err := signalRecorded(reused, syscall.SIGKILL); err != nil {
		t.Fatalf("signal to a reused PID: %v", err)
	}
	if c.exited(300 * time.Millisecond) {
		t.Fatal("a process that is not the journaled one was signaled")
	}
	if err := signalRecorded(c.id, syscall.SIGINT); err != nil {
		t.Fatalf("signal: %v", err)
	}
	if !c.exited(5 * time.Second) {
		t.Fatal("the journaled process was not signaled")
	}
	// A stop that races with an exit: the process is gone when the signal is
	// sent.
	if err := signalRecorded(c.id, syscall.SIGKILL); err != nil {
		t.Fatalf("signal to a process that exited: %v", err)
	}
	if err := signalRecorded(journal.Process{PID: 4194000, StartTicks: "1"}, syscall.SIGKILL); err != nil {
		t.Fatalf("signal to a PID nobody has: %v", err)
	}
}

// The real /proc is read as the fake one is: the candidates are
// found by command line, owner and token, and told to be in the intent's
// window or not; a process with the run's token is the run's whenever it
// started.
func TestRealCandidatesCarryTheirOwnerAndToken(t *testing.T) {
	c := startFakeClient(t, "stop", realMapArgv(ownRepo), realMapEnv(ownRepo, "team-a", ownToken))
	intent := intentFor(t, c)
	// Other processes of the host may look the same; the test's own is found
	// among them.
	mine := func(found []mapCandidate) (mapCandidate, bool) {
		for _, f := range found {
			if f.proc == c.id {
				return f, true
			}
		}
		return mapCandidate{}, false
	}
	found, err := realReaper().candidates(intent)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := mine(found)
	if !ok || got.token != ownToken || got.owner != intent.Owner || got.envErr != nil || !got.inWindow {
		t.Fatalf("candidates = %+v, want the process with its owner and token, in the window", found)
	}
	intent.At = intent.At.Add(time.Hour)
	found, err = realReaper().candidates(intent)
	if got, ok = mine(found); err != nil || !ok || got.inWindow {
		t.Fatalf("candidates of a map begun an hour later = %+v, %v; want the process, outside the window", found, err)
	}
	if v, why := judge(intent, got); v != verdictOurs || why != reasonToken {
		t.Fatalf("judge = %v, %v; want the run's own map, by its token, however late it started", v, why)
	}
}
