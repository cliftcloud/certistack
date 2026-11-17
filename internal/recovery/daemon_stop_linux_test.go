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
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cliftcloud/certistack/internal/recoverhint"
)

// The tests of stopMapDaemon run real processes against the host's
// real /proc, except the ones that need a PID to change hands between two reads,
// which run a fake /proc tree and give the reaper a pidfd of a real process
// that must not be signalled.

// pidFileOf writes the pid file of a map file in a directory of its own, with
// content, and returns the map file's path.
func pidFileOf(t *testing.T, content string) string {
	t.Helper()
	backing := filepath.Join(t.TempDir(), "map.img")
	if err := os.WriteFile(strings.TrimSuffix(backing, ".img")+".pid", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return backing
}

// recordingDaemon starts a real process that stands for the run's map daemon:
// the command line of a map of realSnapshot, the run's token in its environment,
// and the first signal it receives written to the returned file before it
// exits.
func recordingDaemon(t *testing.T, mode string) (*fakeClient, string) {
	t.Helper()
	signalFile := filepath.Join(t.TempDir(), "signal")
	c := startFakeClient(t, mode, realMapArgv(ownRepo), append(realMapEnv(ownRepo, "team-a", ownToken), fakeClientSignalFile+"="+signalFile))
	return c, signalFile
}

// pidfdStandIn is what a reaper whose /proc is a fake tree opens a pidfd of: a
// fake PID has no pidfd, and a real process that happens to have the number
// must never be signalled, so the reaper is given the pidfd of a real process
// of the test's own that stands for the process under the PID, and records the
// signal it gets (and exits on it, which the stop sees through the pidfd).
type pidfdStandIn struct {
	proc       *fakeClient
	signalFile string
	opened     int
}

func standInForDaemon(t *testing.T) *pidfdStandIn {
	t.Helper()
	proc, file := recordingDaemon(t, "record")
	return &pidfdStandIn{proc: proc, signalFile: file}
}

// open is the reaper's pidfdOpen.
func (s *pidfdStandIn) open(_, flags int) (int, error) {
	s.opened++
	return unix.PidfdOpen(s.proc.id.PID, flags)
}

// signalled is the signal the stand-in received, "" if none.
func (s *pidfdStandIn) signalled() string { return signalled(s.signalFile) }

// signalled is the signal a recording daemon received, "" if none.
func signalled(file string) string {
	data, _ := os.ReadFile(file)
	return string(data)
}

// The run's own daemon, named by the pid file, is verified, sent SIGINT through
// a pidfd (the signal the client's unmap sends), and waited for.
func TestStopMapDaemonSignalsTheVerifiedDaemonWithSIGINT(t *testing.T) {
	daemon, signalFile := recordingDaemon(t, "record")
	intent := intentFor(t, daemon)
	backing := pidFileOf(t, strconv.Itoa(daemon.id.PID)+"\n")
	r := realReaper()
	r.daemonWait = 5 * time.Second

	note, err := r.stopMapDaemon(backing, intent)
	if err != nil || note != "" {
		t.Fatalf("stopMapDaemon = %q, %v; want the daemon stopped without a note", note, err)
	}
	if r.alive(daemon.id) {
		t.Fatal("stopMapDaemon returned before the daemon exited")
	}
	if got := signalled(signalFile); got != "interrupt" {
		t.Fatalf("the daemon received %q, want SIGINT (\"interrupt\")", got)
	}
}

// A process the pid file names that is not the run's daemon is not signalled,
// whatever it is: another operation's map, another namespace's, a map without
// the run's token, a restore into a file named map, another program. The
// answer says why, and the caller detaches the loop alone.
func TestStopMapDaemonSignalsNothingThatIsNotTheRunsDaemon(t *testing.T) {
	own, ownSignal := recordingDaemon(t, "record")
	intent := intentFor(t, own)
	for name, start := range map[string]func(t *testing.T) *fakeClient{
		"another run's token": func(t *testing.T) *fakeClient {
			return startFakeClient(t, "stop", realMapArgv(ownRepo), realMapEnv(ownRepo, "team-a", otherToken))
		},
		"a map without the token": func(t *testing.T) *fakeClient {
			return startFakeClient(t, "stop", realMapArgv(ownRepo), realMapEnv(ownRepo, "team-a", ""))
		},
		"another snapshot's map": func(t *testing.T) *fakeClient {
			argv := []string{"/usr/bin/proxmox-backup-client", "map", "--repository", ownRepo, "vm/1/2026-01-01T00:00:00Z", mapArchive}
			return startFakeClient(t, "stop", argv, realMapEnv(ownRepo, "team-a", ownToken))
		},
		"a restore into a file named map": func(t *testing.T) *fakeClient {
			argv := []string{"proxmox-backup-client", "restore", "--repository", ownRepo, realSnapshot, mapArchive, "map"}
			return startFakeClient(t, "stop", argv, realMapEnv(ownRepo, "team-a", ownToken))
		},
		"another program": func(t *testing.T) *fakeClient {
			return startFakeClient(t, "stop", []string{"/usr/sbin/sshd"}, realMapEnv(ownRepo, "team-a", ownToken))
		},
	} {
		t.Run(name, func(t *testing.T) {
			other := start(t)
			backing := pidFileOf(t, strconv.Itoa(other.id.PID))
			r := realReaper()
			r.daemonWait = 5 * time.Second
			note, err := r.stopMapDaemon(backing, intent)
			if err != nil || note == "" {
				t.Fatalf("stopMapDaemon = %q, %v; want a note saying nothing was signalled", note, err)
			}
			if other.exited(300 * time.Millisecond) {
				t.Fatalf("the process under the pid file was signalled: %s", note)
			}
			if signalled(ownSignal) != "" {
				t.Fatal("the run's own daemon was signalled, though the pid file names another process")
			}
		})
	}
}

// A daemon that ignores SIGINT is reported once the bounded wait is over, and
// is not killed: the client's unmap never killed it, and the loop stays with
// it.
func TestStopMapDaemonReportsADaemonThatIgnoresSIGINTAndDoesNotKillIt(t *testing.T) {
	daemon, _ := recordingDaemon(t, "ignore")
	intent := intentFor(t, daemon)
	backing := pidFileOf(t, strconv.Itoa(daemon.id.PID))
	r := realReaper()
	r.daemonWait = 400 * time.Millisecond

	start := time.Now()
	note, err := r.stopMapDaemon(backing, intent)
	waited := time.Since(start)
	if err == nil || note != "" {
		t.Fatalf("stopMapDaemon = %q, %v; want an error", note, err)
	}
	for _, want := range []string{"PBS map daemon " + strconv.Itoa(daemon.id.PID), "has not exited", "nothing was killed", recoverhint.Again} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "repo-a") || strings.Contains(err.Error(), "must-not-leak") {
		t.Errorf("error names the repository or a secret: %v", err)
	}
	if waited < 400*time.Millisecond || waited > 4*time.Second {
		t.Errorf("waited %v, want the bounded wait of 400ms", waited)
	}
	if daemon.exited(300 * time.Millisecond) {
		t.Fatal("the daemon that ignores SIGINT was killed")
	}
}

// A missing pid file has no daemon to stop; one that cannot be read is
// unknown (an error, nothing signalled); one that names no process, or that
// names a PID nobody has, signals nothing.
func TestStopMapDaemonOfAMissingUnreadableOrEmptyPidFile(t *testing.T) {
	daemon, signalFile := recordingDaemon(t, "record")
	intent := intentFor(t, daemon)
	r := realReaper()
	r.daemonWait = time.Second

	missing := filepath.Join(t.TempDir(), "map.img")
	if note, err := r.stopMapDaemon(missing, intent); err != nil || note != "" {
		t.Errorf("a missing pid file: %q, %v; want nothing to stop", note, err)
	}

	unreadable := filepath.Join(t.TempDir(), "map.img")
	if err := os.Mkdir(strings.TrimSuffix(unreadable, ".img")+".pid", 0o755); err != nil {
		t.Fatal(err)
	}
	if note, err := r.stopMapDaemon(unreadable, intent); err == nil || note != "" || !strings.Contains(err.Error(), "pid file cannot be read") || strings.Contains(err.Error(), unreadable) {
		t.Errorf("an unreadable pid file: %q, %v; want an error that names no path", note, err)
	}

	for _, content := range []string{"", "junk\n", "0\n", "1\n", "-7\n"} {
		if note, err := r.stopMapDaemon(pidFileOf(t, content), intent); err != nil || note == "" {
			t.Errorf("pid file %q: %q, %v; want a note that no process is named", content, note, err)
		}
	}
	if note, err := r.stopMapDaemon(pidFileOf(t, "4194000\n"), intent); err != nil || note != "" {
		t.Errorf("a PID nobody has: %q, %v; want nothing to stop", note, err)
	}
	if daemon.exited(200*time.Millisecond) || signalled(signalFile) != "" {
		t.Fatal("a process was signalled though no pid file named it")
	}
}

// The PID changes hands between the first look and the signal. With the pidfd
// open the process under the PID is looked at again, and a start time that
// changed, a command line that is no longer the daemon's, or a process that is
// gone, signals nothing. The fake /proc tree holds the daemon that was first
// seen; the pidfd opener, which runs between the two looks, changes the tree
// and hands over the pidfd of a real process that must not be signalled.
func TestStopMapDaemonSignalsNothingWhenThePIDChangesHandsAfterTheCheck(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	for name, tc := range map[string]struct {
		change func(t *testing.T, root string)
		want   string
	}{
		"the start time changed": {func(t *testing.T, root string) {
			fakeMapProc(t, root, 700, mapArgv(ownRepo), at.Add(time.Hour), ownRepo, "team-a", ownToken)
		}, "taken by another process"},
		"another program has the PID": {func(t *testing.T, root string) {
			fakeProc(t, root, 700, []string{"/usr/sbin/sshd"}, at.Add(time.Hour))
		}, "another program"},
		"another operation's map has it": {func(t *testing.T, root string) {
			fakeMapProc(t, root, 700, mapArgv(otherRepo), at.Add(time.Hour), otherRepo, "", otherToken)
		}, "a map that the run did not start"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			fakeMapProc(t, root, 700, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
			bystander, signalFile := recordingDaemon(t, "record")
			r := testReaper(root, noSignal(t))
			r.daemonWait = 300 * time.Millisecond
			opened := 0
			r.pidfdOpen = func(pid, flags int) (int, error) {
				opened++
				if pid != 700 {
					t.Errorf("pidfd opened for PID %d, want the pid file's 700", pid)
				}
				tc.change(t, root)
				return unix.PidfdOpen(bystander.id.PID, 0) // what the PID names now
			}
			note, err := r.stopMapDaemon(pidFileOf(t, "700\n"), ownIntent(at))
			if err != nil || !strings.Contains(note, tc.want) {
				t.Fatalf("stopMapDaemon = %q, %v; want a note containing %q and no signal", note, err, tc.want)
			}
			if opened != 1 {
				t.Fatalf("pidfd opened %d times, want once", opened)
			}
			if bystander.exited(300*time.Millisecond) || signalled(signalFile) != "" {
				t.Fatal("the process that has the PID now was signalled")
			}
		})
	}
}

// The daemon exits between the first look and the pidfd: nothing is left to
// stop. A kernel without pidfd_open cannot bind the signal to what was looked
// at: nothing is signalled, and the daemon is reported to the operator.
func TestStopMapDaemonWhenThePidfdCannotBeOpened(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	root := t.TempDir()
	fakeMapProc(t, root, 700, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	r := testReaper(root, noSignal(t))
	backing := pidFileOf(t, "700\n")

	r.pidfdOpen = func(int, int) (int, error) { return -1, unix.ESRCH }
	if note, err := r.stopMapDaemon(backing, ownIntent(at)); err != nil || note != "" {
		t.Errorf("a daemon that exited meanwhile: %q, %v; want nothing to stop", note, err)
	}

	r.pidfdOpen = func(int, int) (int, error) { return -1, unix.ENOSYS }
	note, err := r.stopMapDaemon(backing, ownIntent(at))
	if err == nil || note != "" || !strings.Contains(err.Error(), "pidfd") || !strings.Contains(err.Error(), "kill -INT 700") {
		t.Errorf("no pidfd: %q, %v; want an error that says how to stop it by hand", note, err)
	}
}

// A process that has exited but is not reaped, or whose thread group is held by
// a thread wedged on its own FUSE file, shows as a zombie: the pidfd does not
// say it exited, its state does, as everywhere else in recovery.
func TestStopMapDaemonCountsAZombieAsExited(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	root := t.TempDir()
	fakeMapProc(t, root, 700, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	stuck, _ := recordingDaemon(t, "ignore") // its pidfd never says exited
	r := testReaper(root, noSignal(t))
	r.daemonWait = 5 * time.Second
	r.pidfdOpen = func(int, int) (int, error) { return unix.PidfdOpen(stuck.id.PID, 0) }
	time.AfterFunc(250*time.Millisecond, func() {
		stat := filepath.Join(root, "700", "stat")
		data, err := os.ReadFile(stat)
		if err != nil {
			return
		}
		_ = os.WriteFile(stat, []byte(strings.Replace(string(data), ") S ", ") Z ", 1)), 0o644)
	})

	start := time.Now()
	note, err := r.stopMapDaemon(pidFileOf(t, "700\n"), ownIntent(at))
	if err != nil || note != "" {
		t.Fatalf("stopMapDaemon = %q, %v; want the zombie counted as exited", note, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("took %v: the zombie was not seen", time.Since(start))
	}
}

// A daemon of an earlier boot is not the run's: the pid file is of a boot that
// has gone, whatever runs under that PID now. A boot that cannot be read cannot
// be compared, so nothing is signalled and the operator is told, as the map
// reaper does for the processes the journal names.
func TestStopMapDaemonComparesTheBootTheIntentWasJournaledIn(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	root := t.TempDir()
	fakeMapProc(t, root, 700, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	r := testReaper(root, noSignal(t))
	r.pidfdOpen = func(int, int) (int, error) { t.Error("a pidfd was opened"); return -1, unix.EPERM }
	intent := ownIntent(at)
	intent.BootID = "boot-one"
	backing := pidFileOf(t, "700\n")

	if note, err := r.stopMapDaemon(backing, intent); err == nil || note != "" || !strings.Contains(err.Error(), "boot") {
		t.Errorf("an unreadable boot identity: %q, %v; want an error", note, err)
	}
	dir := filepath.Join(root, "sys", "kernel", "random")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "boot_id"), []byte("boot-two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if note, err := r.stopMapDaemon(backing, intent); err != nil || !strings.Contains(note, "earlier boot") {
		t.Errorf("another boot: %q, %v; want a note that the map is of an earlier boot", note, err)
	}
}

// What the guard (the first look, before anything is stopped) and the stop (the
// second, bound to the pidfd) call the run's own daemon is the same thing: the
// stop reaches for a pidfd exactly where the guard lets the daemon be stopped
// and a process runs under the PID.
func TestTheGuardAndTheStopAgreeOnWhatIsTheRunsDaemon(t *testing.T) {
	at := reaperBoot.Add(10 * time.Hour)
	root := t.TempDir()
	fakeMapProc(t, root, 301, mapArgv(ownRepo), at, ownRepo, "team-a", ownToken)
	fakeMapProc(t, root, 302, mapArgv(ownRepo), at, ownRepo, "team-a", otherToken)
	fakeProc(t, root, 303, []string{"/usr/sbin/sshd"}, at)
	for _, tc := range []struct {
		pid     int
		guard   unmapGuard
		reaches bool
	}{
		{301, unmapStopDaemon, true},
		{302, unmapDetachOnly, false},
		{303, unmapDetachOnly, false},
		{304, unmapStopDaemon, false}, // nobody has the PID: nothing to stop
	} {
		opened := false
		r := testReaper(root, noSignal(t))
		r.pidfdOpen = func(int, int) (int, error) { opened = true; return -1, unix.ESRCH }
		backing := pidFileOf(t, fmt.Sprint(tc.pid))
		if got, why := r.unmapGuardFor(backing, ownIntent(at)); got != tc.guard {
			t.Errorf("PID %d: guard = %v (%s), want %v", tc.pid, got, why, tc.guard)
		}
		if _, err := r.stopMapDaemon(backing, ownIntent(at)); err != nil {
			t.Errorf("PID %d: %v", tc.pid, err)
		}
		if opened != tc.reaches {
			t.Errorf("PID %d: pidfd opened %v, want %v", tc.pid, opened, tc.reaches)
		}
	}
}
