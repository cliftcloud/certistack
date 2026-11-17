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
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The worker stop's identity checks: the boot the worker was started in, the
// open /proc directory it pins, the executable it re-reads. Each of these
// tests fails when one of the three is taken out.

// nodeBoot is the node's boot ID.
func nodeBoot(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Skipf("no boot ID on this system: %v", err)
	}
	return strings.TrimSpace(string(data))
}

// copyOf writes a copy of the program at from to dir/name and returns its path.
func copyOf(t *testing.T, from, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Skipf("no %s on this system: %v", from, err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// startTicks is the start time of process pid, in clock ticks since boot (the
// 22nd field of /proc/<pid>/stat, read after the command name's last ") ").
func startTicks(t *testing.T, pid int) string {
	t.Helper()
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return ""
	}
	_, after, found := strings.Cut(string(data), ") ")
	fields := strings.Fields(after)
	if !found || len(fields) < 20 {
		return ""
	}
	return fields[19]
}

// The boot claim: the supervisor records the node's boot beside the PID file
// when it starts the worker, and the stop script compares that with the
// current boot, not two readings of its own, which differ only if the node
// rebooted while the script ran. A PID file from an earlier boot names
// whatever the node started since, and nothing is signalled (here, a process
// that is the worker's own binary by name, as the script's other checks cannot
// tell it from the worker).
func TestWorkerStopComparesTheBootTheSupervisorRecorded(t *testing.T) {
	dir := t.TempDir()
	worker := standInWorker(t, dir)
	pidFile, bootFile := filepath.Join(dir, "worker.pid"), filepath.Join(dir, "worker.boot")
	if got := workerBootPath(pidFile); got != bootFile {
		t.Fatalf("the boot record of %s is %s, want %s", pidFile, got, bootFile)
	}
	stop := func() string {
		out, err := exec.Command("/bin/sh", "-c", workerStopScriptWithin(pidFile, worker, 2)).CombinedOutput()
		if err != nil {
			t.Fatalf("stop script: %v: %s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	for _, tc := range []struct {
		name       string
		record     string // the boot file's content; "-" for no file
		want       string
		wantKilled bool
	}{
		{"recorded in this boot", nodeBoot(t) + "\n", "stopped", true},
		{"recorded in an earlier boot", uuid.NewString() + "\n", "gone", false},
		{"recorded as nothing readable", "\n", "stopped", true},
		{"recorded by a supervisor that recorded no boot", "-", "stopped", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pid := startDetached(t, worker+" 30")
			defer syscall.Kill(pid, syscall.SIGKILL)
			for i := 0; i < 100 && startTicks(t, pid) == ""; i++ {
				time.Sleep(10 * time.Millisecond)
			}
			if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_ = os.Remove(bootFile)
			if tc.record != "-" {
				if err := os.WriteFile(bootFile, []byte(tc.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got := stop()
			if got != tc.want || alive(pid) == tc.wantKilled {
				t.Fatalf("boot record %q: the stop script said %q and the worker is alive %v; want %q and alive %v",
					strings.TrimSpace(tc.record), got, alive(pid), tc.want, !tc.wantKilled)
			}
		})
	}
}

// The supervisor's half: it records the node's boot beside the PID,
// before it, and a PID is never left without the boot it belongs to.
func TestSupervisorRecordsTheBootBesideTheWorkersPID(t *testing.T) {
	run := func(t *testing.T, breakBootRecord bool) (workspace string, status int, progress string) {
		t.Helper()
		root := t.TempDir()
		workspace = filepath.Join(root, uuid.NewString())
		if err := os.Mkdir(workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		worker := filepath.Join(workspace, "certistack-node")
		body := "#!/bin/sh\ncase \"$1\" in\nrecover) : ;;\n*) /bin/sleep 1; printf '{\"report\":{}}' ;;\nesac\n"
		if err := os.WriteFile(worker, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		lease := filepath.Join(workspace, "controller.lease")
		if err := os.WriteFile(lease, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		pidFile := filepath.Join(workspace, "worker.pid")
		if breakBootRecord {
			// A directory where the boot record goes: it cannot be written.
			if err := os.Mkdir(workerBootPath(pidFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		progressFile := filepath.Join(workspace, "worker-progress.log")
		command := (&Executor{}).supervisedWorkerCommand(SSHConfig{}, "certistack-worker-test", root, workspace,
			pidFile, lease, filepath.Join(root, "state"), filepath.Join(workspace, "runtime.env"),
			filepath.Join(workspace, "worker-result.json"), progressFile, []string{worker, "node-run"})
		if command == nil {
			t.Fatal("no supervisor command")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		err := exec.CommandContext(ctx, "/bin/sh", "-c", launchedScript(t, command)).Run()
		status = 0
		if exit, ok := err.(*exec.ExitError); ok {
			status = exit.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		log, _ := os.ReadFile(progressFile)
		return workspace, status, string(log)
	}

	t.Run("the boot is recorded", func(t *testing.T) {
		workspace, status, progress := run(t, false)
		if status != 0 {
			t.Fatalf("the supervisor ended with status %d:\n%s", status, progress)
		}
		recorded, err := os.ReadFile(workerBootPath(filepath.Join(workspace, "worker.pid")))
		if err != nil {
			t.Fatalf("the supervisor recorded no boot: %v\n%s", err, progress)
		}
		if got := strings.TrimSpace(string(recorded)); got != nodeBoot(t) {
			t.Errorf("the recorded boot is %q, the node's is %q", got, nodeBoot(t))
		}
		if info, err := os.Stat(workerBootPath(filepath.Join(workspace, "worker.pid"))); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("the boot record is %v (%v), want a private file", info, err)
		}
		if _, err := os.Stat(filepath.Join(workspace, "worker.pid")); err != nil {
			t.Errorf("no PID was recorded: %v", err)
		}
	})
	t.Run("a boot that cannot be recorded stops the worker", func(t *testing.T) {
		workspace, status, progress := run(t, true)
		if status != 125 {
			t.Errorf("the supervisor ended with status %d, want 125 (the worker could not be recorded):\n%s", status, progress)
		}
		if _, err := os.Stat(filepath.Join(workspace, "worker.pid")); err == nil {
			t.Error("a PID was recorded for a worker whose boot was not")
		}
	})
}

// The executable claim: a worker that execs another program keeps its
// PID and its start time, and only the binary the stop script re-reads tells
// the two apart. The worker traps TERM and execs /bin/sleep; the script must
// leave the sleep alone. With the re-check gone it waited out the grace time
// and killed a program that is not the worker.
func TestWorkerStopLeavesAProgramThatReplacedTheWorkersBinaryAlone(t *testing.T) {
	dir := t.TempDir()
	worker := copyOf(t, "/bin/sh", dir, "certistack-node")
	body := filepath.Join(dir, "worker.sh")
	if err := os.WriteFile(body, []byte("trap 'exec /bin/sleep 60' TERM\nwhile :; do /bin/sleep 0.1; done\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pid := startDetached(t, worker+" "+body)
	defer syscall.Kill(pid, syscall.SIGKILL)
	for i := 0; i < 100 && startTicks(t, pid) == ""; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	pidFile := filepath.Join(dir, "worker.pid")
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workerBootPath(pidFile), []byte(nodeBoot(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ticksBefore := startTicks(t, pid)

	out, err := exec.Command("/bin/sh", "-c", workerStopScriptWithin(pidFile, worker, 2)).CombinedOutput()
	if err != nil {
		t.Fatalf("stop script: %v: %s", err, out)
	}
	exe, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if !alive(pid) {
		t.Fatalf("the stop script (%q) killed a program that replaced the worker's binary (now %q)", strings.TrimSpace(string(out)), exe)
	}
	if filepath.Base(exe) != "sleep" || startTicks(t, pid) != ticksBefore {
		t.Fatalf("the worker did not exec the sleep with its PID and start time (exe %q, start %q then %q); this test no longer builds its case", exe, ticksBefore, startTicks(t, pid))
	}
	if got := strings.TrimSpace(string(out)); got != "stopped" {
		t.Errorf("the stop script said %q, want stopped (the worker ended)", got)
	}
}

// The pin claim: the stop script opens the worker's /proc directory
// once and reads every later identity through that descriptor, which never
// follows the PID to a program that gets it later. Only a process with the
// worker's PID, its binary and its start tick can tell a pinned script from
// one that reads /proc/<pid>, so the case is built: in a private PID
// namespace, the worker is ended by the script's own TERM and replaced, in the
// same clock tick, by a second copy of the same binary under the same PID.
// A script that follows the PID takes the replacement for the worker, waits
// out the grace time and kills it.
func TestWorkerStopPinsTheWorkerAgainstAReplacementWithItsPIDBinaryAndStartTime(t *testing.T) {
	if !inPrivatePIDNamespace(t) {
		return
	}
	dir := t.TempDir()
	worker := copyOf(t, "/bin/sh", dir, "certistack-node")
	hold := filepath.Join(dir, "hold")
	if err := syscall.Mkfifo(hold, 0o600); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(dir, "worker.pid")

	const attempts = 300
	built := 0
	for attempt := 0; attempt < attempts && built == 0; attempt++ {
		// The worker blocks opening a pipe nobody writes, and ends at TERM.
		first := exec.Command(worker, "-c", "read -r _ < '"+hold+"'")
		if err := first.Start(); err != nil {
			t.Fatal(err)
		}
		pid := first.Process.Pid
		firstTicks := startTicks(t, pid)
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(workerBootPath(pidFile), []byte(nodeBoot(t)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		// The script's first TERM is where the worker ends and is replaced:
		// the hook sends it, tells the test, and waits for it to be done.
		signalled, resume := filepath.Join(dir, "signalled"), filepath.Join(dir, "resume")
		for _, fifo := range []string{signalled, resume} {
			_ = os.Remove(fifo)
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		hook := "hook_done=\nkill() {\n" +
			"  if [ -z \"$hook_done\" ]; then\n" +
			"    hook_done=1\n    command kill \"$@\"\n" +
			"    echo ended > " + shellQuote(signalled) + "\n" +
			"    read -r hook_go < " + shellQuote(resume) + "\n" +
			"  else\n    command kill \"$@\"\n  fi\n}\n"
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		stop := exec.CommandContext(ctx, "/bin/sh", "-c", hook+workerStopScriptWithin(pidFile, worker, 1))
		var output bytes.Buffer
		stop.Stdout, stop.Stderr = &output, &output
		if err := stop.Start(); err != nil {
			t.Fatal(err)
		}

		// A script that never reaches its TERM (the worker was not alive for
		// it) leaves the fifo unread: open it without blocking forever.
		gate := make(chan struct{})
		go func() {
			if f, err := os.Open(signalled); err == nil {
				buf := make([]byte, 8)
				_, _ = f.Read(buf)
				_ = f.Close()
			}
			close(gate)
		}()
		select {
		case <-gate:
		case <-time.After(10 * time.Second):
			cancel()
			t.Fatalf("the stop script never signalled the worker: %s", output.String())
		}
		_ = first.Wait() // ended by the TERM, and reaped: its PID is free
		var second *exec.Cmd
		if err := os.WriteFile("/proc/sys/kernel/ns_last_pid", []byte(strconv.Itoa(pid-1)), 0o600); err != nil {
			cancel()
			t.Fatal(err)
		}
		second = exec.Command(worker, "-c", "read -r _ < '"+hold+"'")
		if err := second.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		sameCase := second.Process.Pid == pid && startTicks(t, pid) == firstTicks && firstTicks != ""
		if err := os.WriteFile(resume, []byte("go\n"), 0o600); err != nil {
			cancel()
			t.Fatal(err)
		}
		err := stop.Wait()
		cancel()
		replacementAlive := alive(second.Process.Pid)
		_ = second.Process.Kill()
		_ = second.Wait()
		if !sameCase {
			continue // the two did not share a clock tick this time; try again
		}
		built++
		t.Logf("the replacement shared the worker's PID, binary and start tick on try %d", attempt+1)
		if err != nil {
			t.Fatalf("stop script: %v: %s", err, output.String())
		}
		if !replacementAlive {
			t.Errorf("the stop script (%q) killed the program that replaced the worker under its PID, with its binary and in its start tick", strings.TrimSpace(output.String()))
		}
		if got := strings.TrimSpace(output.String()); got != "stopped" {
			t.Errorf("the stop script said %q, want stopped (the worker ended)", got)
		}
	}
	if built == 0 {
		t.Skipf("the worker and its replacement did not share a start tick in %d tries", attempts)
	}
}
