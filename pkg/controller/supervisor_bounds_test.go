//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// stub writes an executable script named name and returns its path.
func (h *supervisorHarness) stub(t *testing.T, name, body string) string {
	t.Helper()
	file := filepath.Join(h.root, name)
	h.write(t, file, "#!/bin/sh\n"+body+"\n")
	return file
}

// replacing runs script with each command in replacements (as the script
// spells it, with its trailing space) replaced by the given command.
func replacing(script string, replacements map[string]string) string {
	for command, replacement := range replacements {
		script = strings.ReplaceAll(script, command, replacement)
	}
	return script
}

// logFaults are the ways keeping the recovery log can fail, and the
// commands they replace, if any. The first fails for real, the others by
// commands that fail as a full or failing disk makes them fail.
func logFaults(h *supervisorHarness, t *testing.T) map[string]func() map[string]string {
	return map[string]func() map[string]string{
		"logs is a regular file": func() map[string]string {
			h.write(t, filepath.Join(h.stateDir, "logs"), "not a directory")
			return nil
		},
		"the copy runs out of space": func() map[string]string {
			return map[string]string{"/usr/bin/cp -- ": h.stub(t, "cp", `echo "cp: error writing: No space left on device" >&2; exit 1`) + " -- "}
		},
		"the flush fails": func() map[string]string {
			return map[string]string{"/usr/bin/sync -- ": h.stub(t, "sync", `echo "sync: error syncing: Input/output error" >&2; exit 1`) + " -- "}
		},
		"the rename fails": func() map[string]string {
			return map[string]string{"/usr/bin/mv -fT -- ": h.stub(t, "mv", `echo "mv: cannot move: Read-only file system" >&2; exit 1`) + " -- "}
		},
	}
}

func noPartFiles(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".part") {
			t.Errorf("%s was left behind", entry.Name())
		}
	}
}

// The supervisor ignored a failed save of the recovery log and then
// removed the workspace, whose progress file was the log's only other copy,
// so the record of what recovery did was lost with no notice. The workspace
// now stays, without its credentials (the journal is clean), and the
// supervisor says it could not keep the log, with a status of its own.
func TestSupervisorKeepsTheWorkspaceWhenTheRecoveryLogCannotBeKept(t *testing.T) {
	worker := `trap 'exit 143' TERM; while :; do /bin/sleep 0.01; done`
	for name := range logFaults(&supervisorHarness{}, t) {
		t.Run(name, func(t *testing.T) {
			h := newSupervisorHarness(t, worker, 0)
			replacements := logFaults(h, t)[name]()
			wait := h.start(t, replacing(h.supervisor(t), replacements))
			h.waitTicks(t, 2)
			h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
			status, _, stderr := wait()
			if status != supervisorLogNotKeptStatus {
				t.Fatalf("status = %d, want %d (log not kept); stderr:\n%s", status, supervisorLogNotKeptStatus, stderr)
			}
			if !exists(h.recovered) {
				t.Error("the recovery did not run")
			}
			if !exists(h.workspace) || !exists(h.progress) {
				t.Fatal("the workspace, and the progress file that holds the log, was removed")
			}
			for _, secret := range []string{h.env, h.key, h.worker} {
				if exists(secret) {
					t.Errorf("%s was kept although the journal is clean and the controller gone", filepath.Base(secret))
				}
			}
			note, err := os.ReadFile(filepath.Join(h.workspace, "credentials-removed.txt"))
			if err != nil || !strings.Contains(string(note), "recovery log could not be kept") || !strings.Contains(string(note), "worker-progress.log") {
				t.Fatalf("note = %q, %v", note, err)
			}
			progress, _ := os.ReadFile(h.progress)
			for _, out := range []string{string(progress), stderr} {
				if !strings.Contains(out, "CertiStack could not keep the recovery log "+filepath.Join(h.stateDir, "logs", filepath.Base(h.workspace)+".log")) {
					t.Errorf("no notice of the failure in:\n%s", out)
				}
			}
			noPartFiles(t, filepath.Join(h.stateDir, "logs"))
		})
	}
}

// The lease watch keeps the workspace as well when it cannot keep
// the log of the recovery it ran.
func TestLeaseWatchKeepsTheWorkspaceWhenTheRecoveryLogCannotBeKept(t *testing.T) {
	for name := range logFaults(&supervisorHarness{}, t) {
		t.Run(name, func(t *testing.T) {
			h := newSupervisorHarness(t, "", 0)
			replacements := logFaults(h, t)[name]()
			script := replacing(h.adapt(t, leaseWatchScript(workspaceShellVariables(h.lease, h.worker, h.stateDir, h.env, h.progress, h.workspace))), replacements)
			wait := h.start(t, script, "1000", "")
			h.waitTicks(t, 2)
			h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
			status, _, _ := wait()
			if status != supervisorLogNotKeptStatus || !exists(h.recovered) || !exists(h.workspace) || exists(h.env) {
				t.Fatalf("status %d, recovered %v, workspace kept %v, environment kept %v; want the log failure reported, the workspace kept and its credentials gone", status, exists(h.recovered), exists(h.workspace), exists(h.env))
			}
			noPartFiles(t, filepath.Join(h.stateDir, "logs"))
		})
	}
}

// A worker that failed leaves its workspace for the controller, so
// a log that cannot be kept is reported and nothing is removed.
func TestSupervisorReportsARecoveryLogItCannotKeepAfterAFailedWorker(t *testing.T) {
	h := newSupervisorHarness(t, "exit 2", 0)
	replacements := logFaults(h, t)["logs is a regular file"]()
	status, _, stderr := h.start(t, replacing(h.supervisor(t), replacements))()
	if status != supervisorLogNotKeptStatus || !exists(h.recovered) || !exists(h.env) || !exists(h.worker) {
		t.Fatalf("status %d, recovered %v; want the log-not-kept status, its recovery run and its workspace kept", status, exists(h.recovered))
	}
	if !strings.Contains(stderr, "CertiStack could not keep the recovery log") {
		t.Fatalf("stderr = %q", stderr)
	}
}

// A log kept is whole: it is renamed into place, and one already
// there is replaced.
func TestKeepLogReplacesAnEarlierLogWholeOrNotAtAll(t *testing.T) {
	h := newSupervisorHarness(t, "exit 2", 0)
	logs := filepath.Join(h.stateDir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(logs, filepath.Base(h.workspace)+".log")
	h.write(t, kept, "an earlier log\n")
	status, _, _ := h.start(t, h.supervisor(t))()
	data, err := os.ReadFile(kept)
	if status != 2 || err != nil || !strings.Contains(string(data), "recovery ran") || strings.Contains(string(data), "an earlier log") {
		t.Fatalf("status %d, kept log %q, %v", status, data, err)
	}
	noPartFiles(t, logs)
}

// procStartTicks is the start time of process pid in /proc/<pid>/stat,
// which identifies it among reuses of its PID.
func procStartTicks(t *testing.T, pid int) string {
	t.Helper()
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	stat := string(data)
	fields := strings.Fields(stat[strings.LastIndex(stat, ") ")+2:])
	return fields[19]
}

// After the cleanup grace the supervisor sent SIGKILL on every pass
// and waited for the worker for ever, so a worker the kernel would not let
// go held it, its recovery and its result. It sends SIGKILL once, gives the
// worker forcedWorkerStopWaitSeconds, and then reports a stuck worker,
// with its PID, state and wait, in a status of its own: it starts no
// recovery while the worker may run on, keeps the workspace and the journal,
// and leaves the lease watch the worker's identity so that the watch
// recovers once the worker has ended.
func TestSupervisorBoundsItsWaitForAWorkerThatSurvivesSIGKILL(t *testing.T) {
	h := newSupervisorHarness(t, `trap '' TERM; while :; do /bin/sleep 0.01; done`, 0)
	// The model of a survivor changes only the one command that sends
	// SIGKILL: it succeeds and leaves the worker running.
	script := replacing(h.supervisor(t), map[string]string{`worker_alive && kill -KILL "$worker_pid" 2>/dev/null`: `worker_alive && echo killed >> ` + shellQuote(filepath.Join(h.root, "kills"))})
	if !strings.Contains(script, "echo killed") {
		t.Fatal("the supervisor's SIGKILL was not found")
	}
	wait := h.start(t, script)
	h.waitTicks(t, 2)
	h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
	h.waitTicks(t, 3)
	h.setUptime(t, 1000+workerLeaseDurationSeconds+1+gracefulWorkerStopTimeout)
	h.waitTicks(t, 3)
	// Within the wait after SIGKILL the supervisor still polls, and sends
	// it once only.
	h.setUptime(t, 1000+workerLeaseDurationSeconds+1+gracefulWorkerStopTimeout+forcedWorkerStopWaitSeconds-1)
	h.waitTicks(t, 5)
	if progress, _ := os.ReadFile(h.progress); strings.Contains(string(progress), "still running") {
		t.Fatalf("the worker was called stuck early:\n%s", progress)
	}
	h.setUptime(t, 1000+workerLeaseDurationSeconds+1+gracefulWorkerStopTimeout+forcedWorkerStopWaitSeconds)
	status, _, stderr := wait()
	kills, _ := os.ReadFile(filepath.Join(h.root, "kills"))
	if status != supervisorWorkerStuckStatus {
		t.Fatalf("status = %d, want %d (worker stuck); stderr:\n%s", status, supervisorWorkerStuckStatus, stderr)
	}
	if strings.Count(string(kills), "killed") != 1 {
		t.Errorf("SIGKILL sent %d times, want once", strings.Count(string(kills), "killed"))
	}
	if exists(h.recovered) {
		t.Error("recovery ran while the worker was still running")
	}
	if !exists(h.workspace) || !exists(h.env) || !exists(h.worker) || !exists(h.result) {
		t.Error("the workspace was touched")
	}
	pid, err := os.ReadFile(h.pidFile)
	if err != nil {
		t.Fatal(err)
	}
	workerPID := strings.TrimSpace(string(pid))
	if p, _ := strconv.Atoi(workerPID); p > 0 {
		defer func() { _ = exec.Command("/bin/kill", "-KILL", workerPID).Run() }()
	}
	for name, out := range map[string]string{"stderr": stderr, "progress": func() string { b, _ := os.ReadFile(h.progress); return string(b) }()} {
		for _, want := range []string{"PID " + workerPID, "state ", "is still running 30 s after SIGKILL", "its journal is not recovered", "The workspace and the journal are kept"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, out)
			}
		}
	}
	if progress, _ := os.ReadFile(h.progress); !strings.Contains(string(progress), `"level":"ERROR","stage":"Recovery"`) {
		t.Errorf("no machine-readable ERROR event:\n%s", progress)
	}
	launches, _ := os.ReadFile(h.launches)
	if !strings.Contains(string(launches), "certistack-watch-"+filepath.Base(h.workspace)) {
		t.Fatalf("no lease watch was left: %q", launches)
	}
	if p, _ := strconv.Atoi(workerPID); p > 0 {
		if want := "[" + workerPID + "] [" + procStartTicks(t, p) + "]\n"; !strings.HasSuffix(string(launches), want) {
			t.Errorf("the lease watch was not given the worker's identity %s: %q", want, launches)
		}
	}
}

// The lease watch recovers nothing while the worker it was given
// still runs, and recovers as soon as that process has ended. A process that
// only has the worker's PID now, with another start time, is not the worker.
func TestLeaseWatchWaitsForAWorkerThatSurvived(t *testing.T) {
	watch := func(h *supervisorHarness) string {
		return h.adapt(t, leaseWatchScript(workspaceShellVariables(h.lease, h.worker, h.stateDir, h.env, h.progress, h.workspace)))
	}
	t.Run("the worker runs on", func(t *testing.T) {
		h := newSupervisorHarness(t, "", 0)
		survivor := exec.Command("/bin/sleep", "60")
		if err := survivor.Start(); err != nil {
			t.Fatal(err)
		}
		reaped := make(chan struct{})
		go func() { _ = survivor.Wait(); close(reaped) }()
		t.Cleanup(func() { _ = survivor.Process.Kill(); <-reaped })
		wait := h.start(t, watch(h), "1000", "", strconv.Itoa(survivor.Process.Pid), procStartTicks(t, survivor.Process.Pid))
		h.waitTicks(t, 2)
		// The lease ran out long ago.
		h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
		h.waitTicks(t, 5)
		if exists(h.recovered) || !exists(h.env) {
			t.Fatal("the watch acted while the worker still ran")
		}
		_ = survivor.Process.Kill()
		<-reaped
		if status, _, _ := wait(); status != 0 || !exists(h.recovered) || exists(h.workspace) {
			t.Fatalf("status %d, recovered %v, workspace kept %v; want it recovered and removed once the worker ended", status, exists(h.recovered), exists(h.workspace))
		}
	})
	// The wait is bounded, because the workspace holds credentials: a worker
	// still there an hour on costs it them, and the journal is left for the
	// node's next run.
	t.Run("the worker runs on for good", func(t *testing.T) {
		h := newSupervisorHarness(t, "", 0)
		survivor := exec.Command("/bin/sleep", "60")
		if err := survivor.Start(); err != nil {
			t.Fatal(err)
		}
		reaped := make(chan struct{})
		go func() { _ = survivor.Wait(); close(reaped) }()
		t.Cleanup(func() { _ = survivor.Process.Kill(); <-reaped })
		wait := h.start(t, watch(h), "1000", "", strconv.Itoa(survivor.Process.Pid), procStartTicks(t, survivor.Process.Pid))
		h.waitTicks(t, 2)
		h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
		h.waitTicks(t, 3)
		h.setUptime(t, 1000+workerLeaseDurationSeconds+1+survivorWaitSeconds)
		h.waitTicks(t, 3)
		if !exists(h.env) {
			t.Fatal("the credentials went before the bound")
		}
		h.setUptime(t, 1000+workerLeaseDurationSeconds+1+survivorWaitSeconds+1)
		status, _, _ := wait()
		if status != supervisorWorkerStuckStatus || exists(h.recovered) || !exists(h.workspace) || exists(h.env) || exists(h.key) || exists(h.worker) {
			t.Fatalf("status %d, recovered %v, workspace kept %v, environment kept %v; want the credentials gone, nothing recovered, the workspace kept", status, exists(h.recovered), exists(h.workspace), exists(h.env))
		}
		if note, err := os.ReadFile(filepath.Join(h.workspace, "credentials-removed.txt")); err != nil || !strings.Contains(string(note), "was still running 3600 s after the controller's lease expired") {
			t.Fatalf("note = %q, %v", note, err)
		}
	})
	t.Run("the PID is another program's", func(t *testing.T) {
		h := newSupervisorHarness(t, "", 0)
		other := exec.Command("/bin/sleep", "60")
		if err := other.Start(); err != nil {
			t.Fatal(err)
		}
		reaped := make(chan struct{})
		go func() { _ = other.Wait(); close(reaped) }()
		t.Cleanup(func() { _ = other.Process.Kill(); <-reaped })
		wait := h.start(t, watch(h), "1000", "", strconv.Itoa(other.Process.Pid), "1")
		h.waitTicks(t, 2)
		h.setUptime(t, 1000+workerLeaseDurationSeconds+1)
		if status, _, _ := wait(); status != 0 || !exists(h.recovered) {
			t.Fatalf("status %d, recovered %v; want the recovery not to wait for another program", status, exists(h.recovered))
		}
	})
}
