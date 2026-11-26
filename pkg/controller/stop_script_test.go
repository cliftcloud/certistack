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
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
)

// startDetached starts argv outside this process's children, so a killed
// process is reaped by init rather than lingering as this test's zombie.
func startDetached(t *testing.T, argv string) int {
	t.Helper()
	out, err := exec.Command("/bin/sh", "-c", argv+" >/dev/null 2>&1 & echo $!").Output()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// running waits until pid runs path (its /proc/<pid>/exe): a process started
// in the background may not have exec'd yet, and a loaded machine may take
// long to get there. A test that read it earlier would see the shell.
func running(t *testing.T, pid int, path string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil && exe == path {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process %d never ran %s", pid, path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func alive(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	return err == nil && !strings.Contains(string(data), ") Z ")
}

// endsAfterStop reports whether a worker its stop called stopped ends. The
// stop script counts a worker as stopped once the kernel has released its
// program (its exe link is gone), when it can run nothing more; on a loaded
// machine the rest of its exit, to a zombie, can take a while longer. A
// process that is still alive well after that was not stopped.
func endsAfterStop(pid int) bool {
	for deadline := time.Now().Add(10 * time.Second); alive(pid); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			return false
		}
	}
	return true
}

// The stop script tells a gone worker (dead, or its PID now another
// program's, which must not be signaled) from its own running binary.
func TestWorkerStopScriptOnRealProcesses(t *testing.T) {
	dir := t.TempDir()
	worker := standInWorker(t, dir)
	pidFile := filepath.Join(dir, "worker.pid")
	stop := func() string {
		out, err := exec.Command("/bin/sh", "-c", workerStopScript(pidFile, worker)).CombinedOutput()
		if err != nil {
			t.Fatalf("stop script: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	record := func(pid int) {
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if got := stop(); got != "absent" {
		t.Fatalf("no pid file: %q", got)
	}

	dead := startDetached(t, "/bin/true")
	for deadline := time.Now().Add(30 * time.Second); alive(dead) && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
	record(dead)
	if got := stop(); got != "gone" {
		t.Fatalf("dead worker: %q", got)
	}

	other := startDetached(t, "/bin/sleep 30")
	defer syscall.Kill(other, syscall.SIGKILL)
	record(other)
	if got := stop(); got != "gone" || !alive(other) {
		t.Fatalf("another program's PID: %q, still alive %v; want gone and untouched", got, alive(other))
	}

	own := startDetached(t, worker+" 30")
	running(t, own, worker)
	record(own)
	if got := stop(); got != "stopped" || !endsAfterStop(own) {
		t.Fatalf("the worker: %q, still alive %v", got, alive(own))
	}

	deleted := startDetached(t, worker+" 30")
	running(t, deleted, worker)
	record(deleted)
	if err := os.Remove(worker); err != nil {
		t.Fatal(err)
	}
	if got := stop(); got != "stopped" || !endsAfterStop(deleted) {
		t.Fatalf("the worker with its binary deleted: %q, still alive %v", got, alive(deleted))
	}
}

// If the worker dies by a signal and the controller dies with it, the
// supervisor recovers its journal itself, as for any worker that does not
// finish, whatever it wrote, so it is not left to the node's next run.
func TestSupervisorRecoversAfterTheWorkerIsKilled(t *testing.T) {
	for _, tc := range []struct {
		name, nodeRun string
		recovered     bool
	}{
		{"killed", `kill -9 $$`, true},
		{"failed with a result", `printf '{"error":"x"}'; exit 1`, true},
		{"passed", `printf '{"report":{}}'; exit 0`, false},
	} {
		root := t.TempDir()
		workspace := filepath.Join(root, uuid.NewString())
		if err := os.Mkdir(workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		worker := filepath.Join(workspace, "certistack-node")
		marker := filepath.Join(root, "recovered")
		body := "#!/bin/sh\ncase \"$1\" in\nrecover) : > '" + marker + "' ;;\n*) " + tc.nodeRun + " ;;\nesac\n"
		if err := os.WriteFile(worker, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		lease := filepath.Join(workspace, "controller.lease")
		if err := os.WriteFile(lease, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		progress := filepath.Join(workspace, "worker-progress.log")
		command := (&Executor{}).supervisedWorkerCommand(SSHConfig{}, "certistack-worker-test", root, workspace,
			filepath.Join(workspace, "worker.pid"), lease, filepath.Join(root, "state"), filepath.Join(workspace, "runtime.env"),
			filepath.Join(workspace, "worker-result.json"), progress, []string{worker, "node-run"})
		if command == nil {
			t.Fatalf("%s: no supervisor command", tc.name)
		}
		_ = exec.Command("/bin/sh", "-c", launchedScript(t, command)).Run()
		_, err := os.Stat(marker)
		if recovered := err == nil; recovered != tc.recovered {
			log, _ := os.ReadFile(progress)
			t.Fatalf("%s: recovered = %v, want %v; progress:\n%s", tc.name, recovered, tc.recovered, log)
		}
		if tc.recovered {
			if log, _ := os.ReadFile(progress); tc.name == "killed" && !strings.Contains(string(log), "ended by signal 9 before it finished") {
				t.Fatalf("%s: progress lacks the reason:\n%s", tc.name, log)
			}
			if _, err := os.Stat(workspace); err != nil {
				t.Fatalf("%s: the supervisor removed the workspace the controller may still need", tc.name)
			}
		}
	}
}
