// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package sysutil wraps the host operations a run needs: external commands,
// qcow2 overlays, loop devices, bridges and network addresses, disks and
// mounts, and private directories.
package sysutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"time"

	"github.com/cliftcloud/certistack/internal/process"
)

const maxCommandOutputBytes = 1 << 20

// Result holds the output of an executed command.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// RunOptions controls command logging without changing command execution.
type RunOptions struct {
	// RedactArgs replaces every argument in command logs with [REDACTED].
	RedactArgs bool
}

// Run executes an external command with context and timeout.
// It captures stdout and stderr separately.
// Returns a Result and error. On non-zero exit, stderr remains available in the
// Result and the error contains only the exit status. On timeout, returns a
// context deadline error.
func Run(ctx context.Context, timeout time.Duration, binary string, args ...string) (*Result, error) {
	return run(ctx, timeout, nil, RunOptions{RedactArgs: true}, binary, args...)
}

// RunWithInput executes an external command with bounded standard input.
func RunWithInput(ctx context.Context, timeout time.Duration, input io.Reader, binary string, args ...string) (*Result, error) {
	return run(ctx, timeout, input, RunOptions{RedactArgs: true}, binary, args...)
}

// RunWithOptions executes an external command with explicit logging options.
func RunWithOptions(ctx context.Context, timeout time.Duration, options RunOptions, binary string, args ...string) (*Result, error) {
	return run(ctx, timeout, nil, options, binary, args...)
}

func run(ctx context.Context, timeout time.Duration, input io.Reader, options RunOptions, binary string, args ...string) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := process.CommandContext(ctx, binary, args, false)
	cmd.Stdin = input

	var stdout, stderr limitedOutputBuffer
	stdout.limit = maxCommandOutputBytes
	stderr.limit = maxCommandOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := process.Run(cmd)
	duration := time.Since(start)

	res := &Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: duration,
	}

	if err != nil {
		slog.Warn("command execution failed", "binary", binary, "args", commandArgsForLog(args, options.RedactArgs), "duration", duration, "error", err)

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return res, fmt.Errorf("command timed out after %v: %w", timeout, context.DeadlineExceeded)
		}
		if stdout.exceeded || stderr.exceeded {
			return res, fmt.Errorf("command output exceeded %d bytes per stream", maxCommandOutputBytes)
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, fmt.Errorf("command failed with exit code %d: %w", res.ExitCode, err)
		}

		return res, fmt.Errorf("command execution error: %w", err)
	}
	if stdout.exceeded || stderr.exceeded {
		return res, fmt.Errorf("command output exceeded %d bytes per stream", maxCommandOutputBytes)
	}

	slog.Debug("command executed successfully", "binary", binary, "args", commandArgsForLog(args, options.RedactArgs), "duration", duration)
	return res, nil
}

func commandArgsForLog(args []string, redact bool) []string {
	if !redact {
		return args
	}
	redacted := make([]string, len(args))
	for index := range args {
		redacted[index] = "[REDACTED]"
	}
	return redacted
}

type limitedOutputBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedOutputBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.exceeded = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.buffer.Write(p[:remaining])
		b.exceeded = true
		return len(p), nil
	}
	return b.buffer.Write(p)
}

func (b *limitedOutputBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

func (b *limitedOutputBuffer) String() string {
	return b.buffer.String()
}
