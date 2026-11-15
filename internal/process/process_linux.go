// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package process provides safe process management on Linux, using pidfd and
// kernel start ticks to prevent PID reuse race conditions.
package process

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/recoverhint"
	"golang.org/x/sys/unix"
)

// Command returns an exec.Cmd with a sanitized, minimal environment.
// PBS credentials (passwords, tokens, encryption keys) are only attached if pbs is true.
func Command(name string, args []string, pbs bool) *exec.Cmd {
	return CommandContext(context.Background(), name, args, pbs)
}

// CommandContext returns an exec.Cmd with a sanitized environment and, on
// Linux, terminates it if the worker process exits unexpectedly.
func CommandContext(ctx context.Context, name string, args []string, pbs bool) *exec.Cmd {
	c := exec.CommandContext(ctx, name, args...)
	c.Env = MinimalEnvironment()
	if pbs {
		for _, key := range pbsEnvironmentNames {
			if value, ok := os.LookupEnv(key); ok {
				c.Env = append(c.Env, key+"="+value)
			}
		}
	}
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	// A program the command starts and leaves running can hold its output
	// pipes for as long as it lives: the wait for them is bounded, and a
	// command that ended on its own with them held is an error (ErrPipeHeld),
	// never a success with output that may be cut short.
	c.WaitDelay = PipeWaitDelay
	return c
}

// Run starts and waits for a command while keeping the creating OS thread
// pinned. Linux delivers Pdeathsig when that thread exits, so the lock must
// cover the complete command lifetime.
func Run(cmd *exec.Cmd) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return pipeHeld(cmd, cmd.Run())
}

// CombinedOutput is the Pdeathsig-safe equivalent of exec.Cmd.CombinedOutput.
func CombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	out, err := cmd.CombinedOutput()
	return out, pipeHeld(cmd, err)
}

// ProcessIdentity reads /proc/<pid>/stat and extracts the PID and kernel start ticks (field 22, index 19 after comm).
func ProcessIdentity(pid int) (journal.Process, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return journal.Process{}, err
	}
	return ParseIdentity(pid, string(b))
}

// ParseIdentity parses the contents of /proc/<pid>/stat safely handling whitespace and parentheses in the process comm.
func ParseIdentity(pid int, stat string) (journal.Process, error) {
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return journal.Process{}, errors.New("invalid process stat")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) <= 19 {
		return journal.Process{}, errors.New("incomplete process stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return journal.Process{}, err
	}
	return journal.Process{PID: pid, StartTicks: fields[19]}, nil
}

// ErrPIDReused is StopRecorded's refusal to signal a process that has the
// recorded PID but not its start time: the recorded process is gone, and the
// PID now names another one.
var ErrPIDReused = errors.New("PID was reused; refusing to signal an unrelated process")

// ErrBootUnreadable is StopRecorded's refusal to signal a process recorded in a
// boot that cannot be compared with this one, because this boot's identity
// cannot be read. The process is neither known gone nor known to be the
// recorded one, so it is left as it is and reported.
var ErrBootUnreadable = errors.New("this boot's identity cannot be read")

// bootIDPath is where the kernel names the running boot.
const bootIDPath = "/proc/sys/kernel/random/boot_id"

// readBootID reads this boot's identity; tests replace it.
var readBootID = func() (string, error) {
	data, err := os.ReadFile(bootIDPath)
	if err != nil {
		return "", err
	}
	boot := strings.TrimSpace(string(data))
	if boot == "" {
		return "", errors.New("the kernel's boot identity is empty")
	}
	return boot, nil
}

// CurrentBootID is this boot's identity (the kernel's boot_id), or an error
// when it cannot be read. A recorded process's PID and start ticks name it only
// within the boot they were read in: record this beside them.
func CurrentBootID() (string, error) {
	return readBootID()
}

// stopWait bounds how long StopRecorded waits for a killed process to exit.
// SIGKILL takes effect at once, but exiting can take a while (a QEMU frees
// all of its guest's memory, which for one with tens of GiB takes well over
// ten seconds), and a process in uninterruptible I/O exits only once that
// I/O returns. The wait is long enough for the first, and short enough that
// recovery, which stops its processes one after the other, is not held up
// by the second for long: it reports the process and keeps its resources.
var stopWait = 30 * time.Second

// processExited reports whether a recorded process has exited; tests
// replace it.
var processExited = recordedProcessExited

// StopRecorded terminates a recorded process safely using a pidfd, and
// returns nil only once the process is confirmed gone. If the process has
// already exited it returns nil; if the PID was reused by another process it
// returns ErrPIDReused without signaling it. A signal that fails, or a
// process still there stopWait after SIGKILL, is an error: the caller must
// not treat the process as stopped.
//
// Without a pidfd (an old kernel, or pidfd_open blocked) a process that is
// still the recorded one is not signalled: a signal sent by PID could land on
// an unrelated process that was given the PID in between, and nothing on this
// path can bind the signal to the process that was checked. The error says
// so and leaves the process for the operator.
//
// A recorded boot identity is checked first: a PID and start ticks name a
// process only within one boot, so a record of another boot is of a process
// that is gone (nil, nothing signalled), and one whose boot cannot be compared
// with this one (this boot's identity unreadable) is ErrBootUnreadable, not
// signalled either. A record without a boot identity is from a journal written
// before it was kept: it is judged by PID and start ticks alone, as it always
// was, which cannot rule out a process of a later boot that has both.
func StopRecorded(p journal.Process) error {
	return stopRecorded(p, unix.PidfdOpen, ProcessIdentity)
}

// recordedInAnotherBoot reports whether p was recorded in a boot other than
// this one. A record with no boot identity (a legacy journal) is not.
func recordedInAnotherBoot(p journal.Process) (bool, error) {
	if p.BootID == "" {
		return false, nil
	}
	boot, err := readBootID()
	if err != nil {
		return false, fmt.Errorf("%w (%v), so recorded process %d, which was recorded in a boot that cannot be compared with this one, is not taken for the recorded process and was not signalled: if it is the run's, stop it yourself and "+recoverhint.Again, ErrBootUnreadable, err, p.PID)
	}
	return boot != p.BootID, nil
}

func stopRecorded(
	p journal.Process,
	pidfdOpen func(int, int) (int, error),
	processIdentity func(int) (journal.Process, error),
) error {
	if p.PID <= 0 {
		return nil
	}
	if p.PID <= 1 || p.StartTicks == "" {
		return errors.New("invalid recorded process identity")
	}
	other, err := recordedInAnotherBoot(p)
	if err != nil {
		return err
	}
	if other {
		return nil // recorded in an earlier boot: that process ended with it
	}

	// Bind signalling to kernel process reference to avoid PID-reuse races
	fd, err := pidfdOpen(p.PID, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil // Process already dead
	}
	if err != nil {
		// No pidfd: read the identity so a process that is gone, or a PID that
		// now names another process, is still reported correctly, but never
		// signal by PID.
		current, idErr := processIdentity(p.PID)
		if errors.Is(idErr, os.ErrNotExist) {
			return nil
		}
		if idErr != nil {
			return fmt.Errorf("failed to verify recorded process identity: %w", idErr)
		}
		if current.StartTicks != p.StartTicks {
			return ErrPIDReused
		}
		return fmt.Errorf("recorded process %d is still running and pidfd_open is unavailable (%v): not signalling it by PID, because the PID could be reused by another process before the signal lands; stop it yourself (check it is the recorded process first) and "+recoverhint.Again, p.PID, err)
	}
	defer unix.Close(fd)

	current, err := processIdentity(p.PID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.StartTicks != p.StartTicks {
		return ErrPIDReused
	}

	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("stop recorded process %d: %w", p.PID, err)
	}
	return waitStopped(p, fd)
}

// waitStopped waits up to stopWait for a killed process to exit. pidfd is
// the process's pidfd, or -1 when there is none.
func waitStopped(p journal.Process, pidfd int) error {
	deadline := time.Now().Add(stopWait)
	for {
		if pidfd >= 0 {
			fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
			if _, err := unix.Poll(fds, 0); err == nil && fds[0].Revents&unix.POLLIN != 0 {
				return nil
			}
		}
		gone, err := processExited(p)
		if gone {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("recorded process %d was sent SIGKILL, but whether it exited is unknown: %w", p.PID, err)
			}
			return fmt.Errorf("recorded process %d was sent SIGKILL but has not exited after %v; it may be stuck in uninterruptible I/O", p.PID, stopWait)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// recordedProcessExited reports whether a recorded process has exited: its
// /proc entry is gone, its PID now names another process, or it is a zombie
// waiting for its parent (it runs nothing and holds no files any more).
func recordedProcessExited(p journal.Process) (bool, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", p.PID))
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	stat := string(b)
	current, err := ParseIdentity(p.PID, stat)
	if err != nil {
		return false, err
	}
	if current.StartTicks != p.StartTicks {
		return true, nil
	}
	state := strings.Fields(stat[strings.LastIndex(stat, ")")+1:])[0]
	return state == "Z" || state == "X", nil
}
