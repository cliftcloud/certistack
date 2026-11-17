//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package process

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/cliftcloud/certistack/internal/journal"
)

func Command(name string, args []string, pbs bool) *exec.Cmd {
	return CommandContext(context.Background(), name, args, pbs)
}

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
	// As on Linux: the wait for a command's output pipes is bounded.
	c.WaitDelay = PipeWaitDelay
	return c
}

func Run(cmd *exec.Cmd) error {
	return pipeHeld(cmd, cmd.Run())
}

func CombinedOutput(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	return out, pipeHeld(cmd, err)
}

func ProcessIdentity(pid int) (journal.Process, error) {
	// Non-Linux platforms cannot provide the kernel identity required for safe
	// PID reuse protection. Leave it empty so StopRecorded fails closed rather
	// than pretending that a made-up tick value identifies a process.
	return journal.Process{PID: pid}, nil
}

// CurrentBootID is empty off Linux, as ProcessIdentity's start ticks are: the
// platform has no kernel identity to record, and StopRecorded, which cannot
// verify a process there either, fails closed.
func CurrentBootID() (string, error) {
	return "", nil
}

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

func StopRecorded(p journal.Process) error {
	if p.PID <= 0 {
		return nil
	}
	if p.PID <= 1 || p.StartTicks == "" {
		return errors.New("invalid recorded process identity")
	}
	return errors.New("process identity verification unavailable on this platform")
}
