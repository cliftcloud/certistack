// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"golang.org/x/sys/unix"
)

func TestCommandContextUsesMinimalPBSEnvironment(t *testing.T) {
	t.Setenv("PVE_TOKEN_SECRET", "must-not-inherit")
	t.Setenv("PBS_PASSWORD", "pbs-secret")

	cmd := CommandContext(context.Background(), "true", nil, true)
	env := make(map[string]string)
	for _, entry := range cmd.Env {
		key, value, found := strings.Cut(entry, "=")
		if found {
			env[key] = value
		}
	}
	if _, ok := env["PVE_TOKEN_SECRET"]; ok {
		t.Fatal("PVE token secret was inherited by PBS command")
	}
	if env["PBS_PASSWORD"] != "pbs-secret" {
		t.Fatalf("PBS password environment = %q, want explicit PBS credential", env["PBS_PASSWORD"])
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatal("PBS command is missing SIGKILL parent-death protection")
	}
}

func TestParseIdentity(t *testing.T) {
	// Sample stat line from Linux procfs
	stat := "1234 (sleep 10) S 1 1234 1234 0 -1 4194304 68 0 0 0 0 0 0 0 20 0 1 0 54321 4194304 123 18446744073709551615"
	id, err := ParseIdentity(1234, stat)
	if err != nil {
		t.Fatalf("ParseIdentity failed: %v", err)
	}

	if id.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", id.PID)
	}
	if id.StartTicks != "54321" {
		t.Errorf("expected StartTicks '54321', got %s", id.StartTicks)
	}
}

func TestProcessIdentityCurrentProcess(t *testing.T) {
	id, err := ProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatalf("ProcessIdentity failed on current process: %v", err)
	}
	if id.PID != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), id.PID)
	}
	if id.StartTicks == "" {
		t.Errorf("expected non-empty StartTicks")
	}
}

func TestStopRecorded_ProcessLifecycle(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	id, err := ProcessIdentity(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("failed to get identity: %v", err)
	}

	// 1. Mismatched start ticks should refuse to kill
	mismatched := journal.Process{PID: id.PID, StartTicks: "9999999999"}
	err = StopRecorded(mismatched)
	if !errors.Is(err, ErrPIDReused) {
		t.Fatalf("expected StopRecorded to refuse mismatched StartTicks with ErrPIDReused, got %v", err)
	}

	// 2. Matching start ticks should kill successfully
	if err := StopRecorded(id); err != nil {
		t.Fatalf("StopRecorded failed: %v", err)
	}

	// Wait for process to terminate
	_ = cmd.Wait()

	// 3. Stopping already terminated process should succeed cleanly
	if err := StopRecorded(id); err != nil {
		t.Fatalf("StopRecorded on dead process returned error: %v", err)
	}
}

func TestStopRecorded_PidfdFallbackRequiresIdentity(t *testing.T) {
	identityErr := errors.New("permission denied")

	err := stopRecorded(
		journal.Process{PID: 1234, StartTicks: "54321"},
		func(int, int) (int, error) {
			return -1, errors.New("pidfd unavailable")
		},
		func(int) (journal.Process, error) {
			return journal.Process{}, identityErr
		},
	)
	if !errors.Is(err, identityErr) {
		t.Fatalf("StopRecorded error = %v, want identity error", err)
	}
}

// startDisposable starts a sleep child that the test kills and reaps.
func startDisposable(t *testing.T) (*exec.Cmd, journal.Process) {
	t.Helper()
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	identity, err := ProcessIdentity(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	return child, identity
}

// alive reports whether the recorded process still runs.
func alive(p journal.Process) bool {
	gone, err := recordedProcessExited(p)
	return err == nil && !gone
}

func noPidfd(int, int) (int, error) { return -1, unix.ENOSYS }

// Without a pidfd a signal sent by PID could land on whichever process holds
// the PID by then, so a process that is still the recorded one is left alone and
// reported; only the read-only outcomes (gone, PID reused) are answered.
func TestStopRecordedWithoutPidfdNeverSignalsByPID(t *testing.T) {
	t.Run("still the recorded process: error, and it keeps running", func(t *testing.T) {
		_, identity := startDisposable(t)
		err := stopRecorded(identity, noPidfd, ProcessIdentity)
		if err == nil || !strings.Contains(err.Error(), "not signaling it by PID") {
			t.Fatalf("stop = %v, want the refusal to signal by PID", err)
		}
		if !alive(identity) {
			t.Fatal("the recorded process was signaled although no pidfd could bind the signal to it")
		}
	})
	t.Run("already gone: nothing to stop", func(t *testing.T) {
		child, identity := startDisposable(t)
		_ = child.Process.Kill()
		_ = child.Wait()
		if err := stopRecorded(identity, noPidfd, ProcessIdentity); err != nil {
			t.Fatalf("stop of a process that was already gone = %v", err)
		}
	})
	t.Run("the PID now names another process: reused, not signaled", func(t *testing.T) {
		child, identity := startDisposable(t)
		recorded := identity
		recorded.StartTicks = identity.StartTicks + "0" // the record is of an earlier holder of the PID
		if err := stopRecorded(recorded, noPidfd, ProcessIdentity); !errors.Is(err, ErrPIDReused) {
			t.Fatalf("stop = %v, want ErrPIDReused", err)
		}
		if err := child.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("the unrelated process holding the PID was disturbed: %v", err)
		}
	})
	t.Run("pid 1 and a missing identity are refused", func(t *testing.T) {
		for _, p := range []journal.Process{{PID: 1, StartTicks: "1"}, {PID: 4242}} {
			if err := stopRecorded(p, noPidfd, ProcessIdentity); err == nil {
				t.Fatalf("stop of %+v was accepted", p)
			}
		}
	})
}

// With a pidfd the signal is bound to the checked process, and success needs
// the process confirmed gone.
func TestStopRecordedSucceedsOnlyOnceTheProcessIsGone(t *testing.T) {
	t.Run("pidfd kill confirmed", func(t *testing.T) {
		_, identity := startDisposable(t)
		if err := StopRecorded(identity); err != nil {
			t.Fatal(err)
		}
		if alive(identity) {
			t.Fatal("stop succeeded with the child alive")
		}
	})
	t.Run("already dead", func(t *testing.T) {
		child, identity := startDisposable(t)
		_ = child.Process.Kill()
		_ = child.Wait()
		if err := StopRecorded(identity); err != nil {
			t.Fatalf("stop of a process that had already exited = %v", err)
		}
	})
}

// waitStopped is what turns a delivered SIGKILL into a confirmed stop.
func TestWaitStoppedReportsWhatIsNotConfirmed(t *testing.T) {
	oldWait := stopWait
	stopWait = 300 * time.Millisecond
	t.Cleanup(func() { stopWait = oldWait })

	t.Run("still running when the wait runs out", func(t *testing.T) {
		_, identity := startDisposable(t)
		err := waitStopped(identity, -1)
		if err == nil || !strings.Contains(err.Error(), "has not exited") || !alive(identity) {
			t.Fatalf("wait = %v with the child alive = %v; want the unconfirmed exit reported", err, alive(identity))
		}
	})
	t.Run("exit unknown when the wait runs out", func(t *testing.T) {
		_, identity := startDisposable(t)
		old := processExited
		processExited = func(journal.Process) (bool, error) { return false, errors.New("read /proc: input/output error") }
		defer func() { processExited = old }()
		if err := waitStopped(identity, -1); err == nil || !strings.Contains(err.Error(), "whether it exited is unknown") {
			t.Fatalf("wait = %v, want the unknown exit reported", err)
		}
	})
	t.Run("exited", func(t *testing.T) {
		child, identity := startDisposable(t)
		_ = child.Process.Kill()
		_ = child.Wait()
		if err := waitStopped(identity, -1); err != nil {
			t.Fatalf("wait for an exited process = %v", err)
		}
	})
}

func TestRecordedProcessExited(t *testing.T) {
	child, identity := startDisposable(t)
	if gone, err := recordedProcessExited(identity); gone || err != nil {
		t.Fatalf("running child: exited = %v, %v", gone, err)
	}
	if gone, err := recordedProcessExited(journal.Process{PID: identity.PID, StartTicks: "1"}); !gone || err != nil {
		t.Fatalf("PID with another start time: exited = %v, %v", gone, err)
	}
	_ = child.Process.Kill()
	deadline := time.Now().Add(5 * time.Second)
	for {
		gone, err := recordedProcessExited(identity)
		if gone && err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("killed, unreaped child: exited = %v, %v", gone, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", identity.PID)); err != nil {
		t.Fatalf("the zombie's /proc entry is gone already (%v); this case needs it", err)
	}
	_ = child.Wait()
	if gone, err := recordedProcessExited(identity); !gone || err != nil {
		t.Fatalf("reaped child: exited = %v, %v", gone, err)
	}
}

// A stat line that cannot be read as an identity is an error, never a guess:
// StopRecorded compares the start ticks it gets with the recorded ones.
func TestParseIdentityRefusesWhatItCannotRead(t *testing.T) {
	valid := "1234 (sleep) S 1 1234 1234 0 -1 4194304 68 0 0 0 0 0 0 0 20 0 1 0 54321 4194304 123"
	for name, stat := range map[string]string{
		"empty":                    "",
		"no closing parenthesis":   "1234 (sleep S 1 1234 1234 0 -1",
		"nothing after the comm":   "1234 (sleep)",
		"fewer than 20 fields":     "1234 (sleep) S 1 1234 1234 0 -1 4194304 68 0 0 0 0 0 0 0 20 0 1",
		"non-numeric start ticks":  "1234 (sleep) S 1 1234 1234 0 -1 4194304 68 0 0 0 0 0 0 0 20 0 1 0 soon 4194304 123",
		"negative start ticks":     "1234 (sleep) S 1 1234 1234 0 -1 4194304 68 0 0 0 0 0 0 0 20 0 1 0 -5 4194304 123",
		"start ticks out of range": "1234 (sleep) S 1 1234 1234 0 -1 4194304 68 0 0 0 0 0 0 0 20 0 1 0 99999999999999999999999 4194304 123",
	} {
		if id, err := ParseIdentity(1234, stat); err == nil {
			t.Errorf("%s: parsed as %+v", name, id)
		}
	}
	// A comm with spaces and parentheses must not shift the fields.
	tricky := "1234 (a) b (c)) S 1 1234 1234 0 -1 4194304 68 0 0 0 0 0 0 0 20 0 1 0 777 4194304 123"
	if id, err := ParseIdentity(1234, tricky); err != nil || id.StartTicks != "777" {
		t.Errorf("comm with parentheses: %+v, %v", id, err)
	}
	if id, err := ParseIdentity(1234, valid); err != nil || id.StartTicks != "54321" {
		t.Errorf("valid line: %+v, %v", id, err)
	}
}
