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
)

// inPrivatePIDNamespace runs the calling test again as PID 1 of a private
// user, PID and mount namespace with its own /proc, where it may set the
// namespace's next PID, and reports whether this is that run. Outside, it
// skips the test where such namespaces are unavailable.
func inPrivatePIDNamespace(t *testing.T) bool {
	t.Helper()
	if os.Getenv("CERTISTACK_TEST_PRIVATE_PIDNS") == t.Name() {
		if os.Getpid() != 1 {
			t.Fatal("not PID 1 of a private PID namespace")
		}
		return true
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare(1) is needed for a private PID namespace")
	}
	if err := exec.Command(unshare, "--user", "--map-root-user", "--pid", "--fork", "--mount", "--mount-proc", "/bin/true").Run(); err != nil {
		t.Skipf("private PID namespaces are unavailable here: %v", err)
	}
	cmd := exec.Command(unshare, "--user", "--map-root-user", "--pid", "--fork", "--mount", "--mount-proc",
		os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), "CERTISTACK_TEST_PRIVATE_PIDNS="+t.Name())
	output, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+t.Name())) {
		t.Fatalf("in a private PID namespace: %v\n%s", err, output)
	}
	t.Logf("in a private PID namespace:\n%s", output)
	return false
}

// When the worker ends during the grace wait and another program gets its
// PID, that program must not be killed, as it would be by a script that
// checked the binary once and then sent TERM and KILL to the bare PID. Only
// the script's one-second sleeps are gated here, to hold the reuse window
// open; the real /proc and real signals decide.
func TestWorkerStopNeverSignalsAProgramThatReusedTheWorkersPID(t *testing.T) {
	if !inPrivatePIDNamespace(t) {
		return
	}
	for _, reuse := range []bool{true, false} {
		dir := t.TempDir()
		workerPath := filepath.Join(dir, "certistack-node")
		// The worker ignores TERM until the test lets it end, so it is still
		// running when the stop script first looks: a worker that died at once
		// would leave the script nothing to wait for (a zombie has ended), and
		// the window this test holds open would never exist. It is a copy of
		// sh, and so has the binary the script checks.
		shell, err := os.ReadFile("/bin/sh")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(workerPath, shell, 0o700); err != nil {
			t.Fatal(err)
		}
		pidPath := filepath.Join(dir, "worker.pid")
		ready, release := filepath.Join(dir, "ready"), filepath.Join(dir, "release")
		if err := syscall.Mkfifo(release, 0o600); err != nil {
			t.Fatal(err)
		}
		worker := exec.Command(workerPath, "-c", "trap '' TERM; : > '"+ready+"'; read -r _ < '"+release+"'; trap - TERM; kill -TERM $$")
		if err := worker.Start(); err != nil {
			t.Fatal(err)
		}
		pid := worker.Process.Pid
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the worker never ignored TERM")
			}
		}
		if err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		// The first sleep waits for the gate; the rest return at once.
		gate, first := filepath.Join(dir, "gate"), filepath.Join(dir, "first-sleep")
		if err := syscall.Mkfifo(gate, 0o600); err != nil {
			t.Fatal(err)
		}
		tick := filepath.Join(dir, "tick")
		if err := os.WriteFile(tick, []byte("#!/bin/sh\nif [ ! -e '"+first+"' ]; then\n  : > '"+first+"'\n  read -r _ < '"+gate+"'\nfi\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		script := workerStopScript(pidPath, workerPath)
		if strings.Count(script, "/bin/sleep 1") != 2 {
			t.Fatal("the stop script's sleeps changed; update this test")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		stop := exec.CommandContext(ctx, "/bin/sh", "-c", strings.ReplaceAll(script, "/bin/sleep 1", tick))
		var output bytes.Buffer
		stop.Stdout, stop.Stderr = &output, &output
		if err := stop.Start(); err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
			if _, err := os.Stat(first); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the stop script never waited: %s", output.String())
			}
		}
		// The worker got TERM and ignored it; let it end by TERM now, and reap
		// it, so its PID is free.
		if err := os.WriteFile(release, []byte("go\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := worker.Wait(); err == nil || worker.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGTERM {
			t.Fatalf("worker: %v, want ended by TERM", err)
		}
		var other *exec.Cmd
		if reuse {
			// The numbers of this namespace are shared by threads: the test
			// binary's own runtime (the race detector starts some) can take
			// the freed PID between rewinding the counter and Start, and
			// then it is gone for good. A single-threaded shell rewinds the
			// counter and forks the program in one go, so nothing can come
			// between; the shell waits for it, so it ends when the program
			// is signalled, which is what the check below looks for.
			gotPid := filepath.Join(dir, "other.pid")
			other = exec.Command("/bin/sh", "-c",
				"echo "+strconv.Itoa(pid-1)+" > /proc/sys/kernel/ns_last_pid; /bin/sleep 60 & echo $! > '"+gotPid+"'; wait")
			if err := other.Start(); err != nil {
				t.Fatal(err)
			}
			var got int
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
				if data, err := os.ReadFile(gotPid); err == nil {
					if n, convErr := strconv.Atoi(strings.TrimSpace(string(data))); convErr == nil {
						got = n
						break
					}
				}
				if time.Now().After(deadline) {
					t.Fatal("the other program never started")
				}
			}
			if got != pid {
				t.Fatalf("the other program got PID %d, not the worker's %d", got, pid)
			}
		}
		if err := os.WriteFile(gate, []byte("go\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err = stop.Wait()
		cancel()
		if err != nil || strings.TrimSpace(output.String()) != "stopped" {
			t.Fatalf("reuse=%v: stop script: %v, %q; want stopped", reuse, err, output.String())
		}
		if other != nil {
			// kill(pid, 0) succeeds for a SIGKILLed child that nobody has
			// reaped, so it cannot tell a program that was killed from one
			// that was not: reap it, and see whether it ends.
			ended := make(chan error, 1)
			go func() { ended <- other.Wait() }()
			select {
			case err := <-ended:
				t.Fatalf("the program that reused the worker's PID was signalled and ended: %v", err)
			case <-time.After(300 * time.Millisecond):
			}
			_ = other.Process.Kill()
			<-ended
		}
	}
}
