//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// supervisorHarness runs a worker's actual supervisor or lease watch script
// on disposable files. Only its clock and its sleeps are replaced: the boot
// clock reads a file the test sets, and each sleep is short and counted, so
// the test knows the script has looked at the clock again.
type supervisorHarness struct {
	root, stateDir, workspaceRoot, workspace string
	worker, lease, env, key, pidFile         string
	result, progress                         string
	uptime, ticks, launches                  string
	recovered, term                          string
}

// newSupervisorHarness makes a workspace whose worker runs nodeRun for
// node-run and, for recover, records the call and exits recoverStatus. In
// nodeRun, @TERM@ names a file outside the workspace for the worker to mark
// that it got TERM.
func newSupervisorHarness(t *testing.T, nodeRun string, recoverStatus int) *supervisorHarness {
	t.Helper()
	root := t.TempDir()
	h := &supervisorHarness{root: root, stateDir: filepath.Join(root, "state")}
	h.workspaceRoot = filepath.Join(h.stateDir, "workers")
	h.workspace = filepath.Join(h.workspaceRoot, uuid.NewString())
	if err := os.MkdirAll(h.workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	h.worker = filepath.Join(h.workspace, "certistack-node")
	h.lease = filepath.Join(h.workspace, "controller.lease")
	h.env = filepath.Join(h.workspace, "runtime.env")
	h.key = filepath.Join(h.workspace, pbsKeyfileName)
	h.pidFile = filepath.Join(h.workspace, "worker.pid")
	h.result = filepath.Join(h.workspace, "worker-result.json")
	h.progress = filepath.Join(h.workspace, "worker-progress.log")
	h.uptime = filepath.Join(root, "uptime")
	h.ticks = filepath.Join(root, "ticks")
	h.launches = filepath.Join(root, "launches")
	h.recovered = filepath.Join(root, "recovered")
	h.term = filepath.Join(root, "term")
	nodeRun = strings.ReplaceAll(nodeRun, "@TERM@", shellQuote(h.term))
	body := "#!/bin/sh\nif [ \"$1\" = recover ]; then\n  : > " + shellQuote(h.recovered) + "\n  echo 'recovery ran' >&2\n  exit " + strconv.Itoa(recoverStatus) + "\nfi\n" + nodeRun + "\n"
	for file, data := range map[string]string{h.worker: body, h.lease: "", h.env: "PBS_PASSWORD=synthetic\n", h.key: "synthetic key\n"} {
		if err := os.WriteFile(file, []byte(data), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h.setUptime(t, 1000)
	// Each sleep of the script counts a tick; the launcher only records
	// the lease watch it was asked to start.
	h.write(t, filepath.Join(root, "tick"), "#!/bin/sh\nn=$(/usr/bin/cat "+shellQuote(h.ticks)+" 2>/dev/null || echo 0)\necho $((n + 1)) > "+shellQuote(h.ticks)+"\n/bin/sleep 0.005\n")
	launcher := filepath.Join(root, "systemd-run")
	// It records the start of the command line and, after it, the four
	// arguments the script is given: the lease's renewal time and stamp, and
	// the worker's PID and start time.
	h.write(t, launcher, "#!/bin/sh\nprintf '%s\\n' \"$*\" | /usr/bin/head -c 200 >> "+shellQuote(h.launches)+"\necho >> "+shellQuote(h.launches)+"\nshift $(($# - 4))\nprintf 'watch arguments: [%s] [%s] [%s] [%s]\\n' \"$1\" \"$2\" \"$3\" \"$4\" >> "+shellQuote(h.launches)+"\n")
	saved := leaseWatchLauncher
	leaseWatchLauncher = launcher
	t.Cleanup(func() { leaseWatchLauncher = saved })
	return h
}

func (h *supervisorHarness) write(t *testing.T, file, data string) {
	t.Helper()
	if err := os.WriteFile(file, []byte(data), 0o700); err != nil {
		t.Fatal(err)
	}
}

func (h *supervisorHarness) setUptime(t *testing.T, seconds int) {
	t.Helper()
	// Written whole and renamed, so the script never reads half of it.
	next := h.uptime + ".next"
	if err := os.WriteFile(next, []byte(strconv.Itoa(seconds)+".25 4000.50\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, h.uptime); err != nil {
		t.Fatal(err)
	}
}

// adapt replaces the script's boot clock and sleeps with the harness's.
func (h *supervisorHarness) adapt(t *testing.T, script string) string {
	t.Helper()
	if strings.Contains(script, "/bin/date +%s") || !strings.Contains(script, "/proc/uptime") {
		t.Fatal("the script does not read the boot clock")
	}
	tick := shellQuote(filepath.Join(h.root, "tick"))
	script = strings.ReplaceAll(script, "/proc/uptime", h.uptime)
	script = strings.ReplaceAll(script, "/bin/sleep 1\n", tick+"\n")
	return strings.ReplaceAll(script, "/bin/sleep 5\n", tick+"\n")
}

func (h *supervisorHarness) supervisor(t *testing.T) string {
	t.Helper()
	command := (&Executor{}).supervisedWorkerCommand(SSHConfig{}, "certistack-worker-test", h.workspaceRoot, h.workspace, h.pidFile, h.lease, h.stateDir, h.env, h.result, h.progress, []string{h.worker, "node-run"})
	if len(command) == 0 {
		t.Fatal("no supervisor command")
	}
	return h.adapt(t, launchedScript(t, command))
}

func (h *supervisorHarness) tickCount() int {
	data, _ := os.ReadFile(h.ticks)
	n, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return n
}

// waitTicks waits until the script has slept n more times, so it has read
// the clock and the lease again since the call.
func (h *supervisorHarness) waitTicks(t *testing.T, n int) {
	t.Helper()
	want := h.tickCount() + n
	for deadline := time.Now().Add(60 * time.Second); h.tickCount() < want; time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the script stopped polling: %d of %d ticks", h.tickCount(), want)
		}
	}
}

// start runs script in the background; wait returns its exit status.
func (h *supervisorHarness) start(t *testing.T, script string, args ...string) (wait func() (int, string, string)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	cmd := exec.CommandContext(ctx, "/bin/sh", append([]string{"-c", script, "certistack-test"}, args...)...)
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cancel)
	return func() (int, string, string) {
		err := cmd.Wait()
		cancel()
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), stdout.String(), stderr.String()
		} else if err != nil {
			t.Fatal(err)
		}
		return 0, stdout.String(), stderr.String()
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// A worker that exited with an ordinary failure, or was killed after
// it had written part of its result, was not recovered by its supervisor,
// which then ended; a controller that was gone left the run's resources to
// the node's next run. Any worker that does not finish is recovered now,
// whatever it wrote; a finished one leaves a lease watch.
func TestSupervisorRecoversEveryWorkerThatDoesNotFinish(t *testing.T) {
	for _, tc := range []struct {
		name, nodeRun string
		status        int
		recovered     bool
		message       string
	}{
		{"ordinary failure", "exit 2", 2, true, "The node worker failed with exit status 2; recovering its journal."},
		{"failure after a result", `printf '{"error":"x"}'; exit 1`, 1, true, "The node worker failed with exit status 1; recovering its journal."},
		{"killed after part of a result", `printf '{'; kill -9 $$`, 137, true, "The node worker ended by signal 9 before it finished; recovering its journal."},
		{"killed without a result", `kill -9 $$`, 137, true, "The node worker ended by signal 9 before it finished; recovering its journal."},
		{"finished", `printf '{"report":{}}'; exit 0`, 0, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newSupervisorHarness(t, tc.nodeRun, 0)
			status, stdout, _ := h.start(t, h.supervisor(t))()
			if status != tc.status {
				t.Fatalf("supervisor exit = %d, want the worker's %d", status, tc.status)
			}
			if exists(h.recovered) != tc.recovered {
				t.Fatalf("recovered = %v, want %v", exists(h.recovered), tc.recovered)
			}
			progress, _ := os.ReadFile(h.progress)
			if tc.message != "" && !strings.Contains(string(progress), tc.message) {
				t.Fatalf("progress lacks %q:\n%s", tc.message, progress)
			}
			if tc.recovered {
				kept, err := os.ReadFile(filepath.Join(h.stateDir, "logs", filepath.Base(h.workspace)+".log"))
				if err != nil || !strings.Contains(string(kept), "recovery ran") {
					t.Fatalf("recovery log kept beside the journal: %q, %v", kept, err)
				}
			}
			// The workspace stays for the controller, with a lease watch
			// for a controller that is gone.
			if !exists(h.env) || !exists(h.worker) {
				t.Fatal("the supervisor removed the workspace a live controller still needs")
			}
			launches, _ := os.ReadFile(h.launches)
			if !strings.Contains(string(launches), "--unit certistack-watch-"+filepath.Base(h.workspace)+" --collect --quiet /bin/sh -c") {
				t.Fatalf("no lease watch was started: %q", launches)
			}
			if tc.status == 0 && stdout != `{"report":{}}` {
				t.Fatalf("result = %q", stdout)
			}
		})
	}
}

// The supervisor ignored a failed read of the worker's result and
// exited with the worker's zero status, so the controller received an
// empty success. It now fails and says why.
func TestSupervisorFailsWhenItCannotReadTheResult(t *testing.T) {
	for name, fault := range map[string]string{
		"result removed":         `/usr/bin/rm -- "$result"`,
		"directory in its place": `/usr/bin/rm -- "$result" && /usr/bin/mkdir -- "$result"`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newSupervisorHarness(t, "", 0)
			h.write(t, h.worker, "#!/bin/sh\nresult="+shellQuote(h.result)+"\nprintf '{\"report\":{}}'\n"+fault+"\nexit 0\n")
			status, stdout, stderr := h.start(t, h.supervisor(t))()
			if status == 0 || stdout != "" || !strings.Contains(stderr, "CertiStack could not read the node worker result "+h.result) {
				t.Fatalf("status %d, stdout %q, stderr %q; want a failure that says why", status, stdout, stderr)
			}
		})
	}
}

// The lease and the cleanup grace compared /bin/date +%s with the
// lease's modification time, so a wall-clock step forward expired a fresh
// lease at once and a step back kept a stale one alive. They are measured
// on the boot clock now: here the lease names a time an hour off, as after a
// step, and only boot-clock time decides.
func TestSupervisorLeaseAndGraceIgnoreWallClockSteps(t *testing.T) {
	for _, step := range []time.Duration{time.Hour, -time.Hour} {
		t.Run("lease stamp off by "+step.String(), func(t *testing.T) {
			h := newSupervisorHarness(t, `trap 'echo term >> @TERM@; exit 143' TERM; while :; do /bin/sleep 0.01; done`, 0)
			term := h.term
			stamp := time.Now().Add(-step)
			if err := os.Chtimes(h.lease, stamp, stamp); err != nil {
				t.Fatal(err)
			}
			wait := h.start(t, h.supervisor(t))
			h.waitTicks(t, 2)
			// 80 s on the boot clock: the lease is fresh.
			h.setUptime(t, 1080)
			h.waitTicks(t, 3)
			if exists(term) {
				t.Fatal("the lease expired early")
			}
			// A renewal that names a time back in the past renews all the same.
			renewed := stamp.Add(-time.Hour)
			if err := os.Chtimes(h.lease, renewed, renewed); err != nil {
				t.Fatal(err)
			}
			h.waitTicks(t, 3)
			h.setUptime(t, 1160)
			h.waitTicks(t, 3)
			if exists(term) {
				t.Fatal("the renewed lease expired early")
			}
			h.setUptime(t, 1080+workerLeaseDurationSeconds+1)
			status, _, _ := wait()
			if status != 143 || !exists(term) || !exists(h.recovered) {
				t.Fatalf("status %d, term %v, recovered %v; want the lease expired and the run recovered", status, exists(term), exists(h.recovered))
			}
		})
	}

	// A worker that ignores TERM keeps its grace until the boot clock, not
	// the wall clock, runs it out.
	h := newSupervisorHarness(t, `trap 'echo term >> @TERM@' TERM; while :; do /bin/sleep 0.01; done`, 0)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(h.lease, future, future); err != nil {
		t.Fatal(err)
	}
	wait := h.start(t, h.supervisor(t))
	h.waitTicks(t, 2)
	h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
	for deadline := time.Now().Add(10 * time.Second); !exists(h.term); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the lease did not expire")
		}
	}
	h.setUptime(t, 1000+workerLeaseDurationSeconds+1+gracefulWorkerStopTimeout-1)
	h.waitTicks(t, 3)
	if progress, _ := os.ReadFile(h.progress); strings.Contains(string(progress), "grace period exhausted") {
		t.Fatal("the grace ran out early")
	}
	h.setUptime(t, 1000+workerLeaseDurationSeconds+1+gracefulWorkerStopTimeout)
	status, _, _ := wait()
	progress, _ := os.ReadFile(filepath.Join(h.stateDir, "logs", filepath.Base(h.workspace)+".log"))
	if status != 137 || !strings.Contains(string(progress), "grace period exhausted") || !exists(h.recovered) {
		t.Fatalf("status %d, recovered %v; want KILL once the grace ran out, then recovery:\n%s", status, exists(h.recovered), progress)
	}
}

// After a worker finished, nothing on the node watched the lease, so
// a controller lost at that moment left the run's credentials on the node
// until another run came. The lease watch acts once the lease is 90 s old
// on the boot clock: it recovers the journal and removes the workspace, or,
// when recovery fails, removes the credentials and keeps the rest.
func TestLeaseWatchCleansUpAfterAControllerThatIsGone(t *testing.T) {
	watch := func(h *supervisorHarness) string {
		return h.adapt(t, leaseWatchScript(workspaceShellVariables(h.lease, h.worker, h.stateDir, h.env, h.progress, h.workspace)))
	}
	stampOf := func(t *testing.T, h *supervisorHarness) string {
		out, err := exec.Command("/usr/bin/stat", "-c", "%y", "--", h.lease).Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}

	t.Run("the controller collects", func(t *testing.T) {
		h := newSupervisorHarness(t, "", 0)
		wait := h.start(t, watch(h), "1000", stampOf(t, h))
		h.waitTicks(t, 2)
		if err := os.RemoveAll(h.workspace); err != nil {
			t.Fatal(err)
		}
		if status, _, _ := wait(); status != 0 || exists(h.recovered) {
			t.Fatalf("status %d, recovered %v; want the watch to end, doing nothing", status, exists(h.recovered))
		}
	})

	t.Run("renewed, then gone", func(t *testing.T) {
		h := newSupervisorHarness(t, "", 0)
		wait := h.start(t, watch(h), "1000", stampOf(t, h))
		h.waitTicks(t, 2)
		h.setUptime(t, 1080)
		h.waitTicks(t, 2)
		past := time.Now().Add(-2 * time.Hour)
		if err := os.Chtimes(h.lease, past, past); err != nil {
			t.Fatal(err)
		}
		h.waitTicks(t, 2)
		h.setUptime(t, 1160)
		h.waitTicks(t, 3)
		if exists(h.recovered) || !exists(h.env) {
			t.Fatal("the watch acted while the lease was renewed")
		}
		h.setUptime(t, 1080+workerLeaseDurationSeconds+1)
		if status, _, _ := wait(); status != 0 || !exists(h.recovered) || exists(h.workspace) {
			t.Fatalf("status %d, recovered %v, workspace kept %v; want it recovered and removed", status, exists(h.recovered), exists(h.workspace))
		}
		kept, err := os.ReadFile(filepath.Join(h.stateDir, "logs", filepath.Base(h.workspace)+".log"))
		if err != nil || !strings.Contains(string(kept), "did not collect the finished worker") || !strings.Contains(string(kept), "recovery ran") {
			t.Fatalf("kept log = %q, %v", kept, err)
		}
	})

	t.Run("recovery fails", func(t *testing.T) {
		h := newSupervisorHarness(t, "", 1)
		h.write(t, h.result, `{"report":{}}`)
		wait := h.start(t, watch(h), "1000", stampOf(t, h))
		h.waitTicks(t, 2)
		h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
		if status, _, _ := wait(); status == 0 || !exists(h.recovered) {
			t.Fatalf("status %d, recovered %v", status, exists(h.recovered))
		}
		for _, secret := range []string{h.env, h.key, h.worker} {
			if exists(secret) {
				t.Errorf("%s was kept", filepath.Base(secret))
			}
		}
		note, err := os.ReadFile(filepath.Join(h.workspace, "credentials-removed.txt"))
		if err != nil || !strings.Contains(string(note), "the recovery of this run's journal failed") {
			t.Fatalf("note = %q, %v", note, err)
		}
		if !exists(h.result) || !exists(h.progress) {
			t.Fatal("the result or progress was removed with the credentials")
		}
	})

	t.Run("a controller that never collects", func(t *testing.T) {
		h := newSupervisorHarness(t, "", 0)
		wait := h.start(t, watch(h), "1000", stampOf(t, h))
		// Renewed every poll, yet bounded by the time a controller takes.
		for now := 1000; now <= 1000+workerCollectionSeconds; now += 60 {
			future := time.Now().Add(time.Duration(now) * time.Second)
			if err := os.Chtimes(h.lease, future, future); err != nil {
				t.Fatal(err)
			}
			h.setUptime(t, now)
			h.waitTicks(t, 2)
		}
		h.setUptime(t, 1000+workerCollectionSeconds+1)
		if status, _, _ := wait(); status != 0 || !exists(h.recovered) || exists(h.workspace) {
			t.Fatalf("status %d, recovered %v; want the workspace recovered and removed", status, exists(h.recovered))
		}
	})
}

// The supervisor's own lease-expiry recovery kept the workspace,
// credentials included, when that recovery failed.
func TestSupervisorRemovesCredentialsWhenLeaseRecoveryFails(t *testing.T) {
	h := newSupervisorHarness(t, `trap 'exit 143' TERM; while :; do /bin/sleep 0.01; done`, 1)
	wait := h.start(t, h.supervisor(t))
	h.waitTicks(t, 2)
	h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
	if status, _, _ := wait(); status == 0 || !exists(h.recovered) {
		t.Fatalf("status %d, recovered %v", status, exists(h.recovered))
	}
	for _, secret := range []string{h.env, h.key, h.worker} {
		if exists(secret) {
			t.Errorf("%s was kept", filepath.Base(secret))
		}
	}
	if note, err := os.ReadFile(filepath.Join(h.workspace, "credentials-removed.txt")); err != nil || !strings.Contains(string(note), "lease expired") {
		t.Fatalf("note = %q, %v", note, err)
	}
}

// Every signal the supervisor sends its worker follows a check that
// the PID is still that worker, with only builtins between the two.
func TestSupervisorSignalsOnlyItsIdentifiedWorker(t *testing.T) {
	h := newSupervisorHarness(t, "exit 0", 0)
	script := h.supervisor(t)
	if strings.Contains(script, "/bin/kill") {
		t.Fatal("the supervisor signals through /bin/kill, a separate process")
	}
	unidentified := 0
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "kill -") || !strings.Contains(line, "$worker_pid") {
			continue
		}
		if strings.HasPrefix(line, "worker_alive && kill -") {
			continue
		}
		// Before the worker can be identified it cannot have been reaped
		// either: the one signal sent then is the only other kind.
		if line == `kill -TERM "$worker_pid" 2>/dev/null` {
			unidentified++
			continue
		}
		t.Fatalf("an unchecked signal: %s", line)
	}
	if unidentified != 1 {
		t.Fatalf("%d signals before identification, want 1", unidentified)
	}
}
