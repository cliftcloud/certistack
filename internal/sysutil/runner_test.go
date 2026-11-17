// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"bytes"
	"context"
	"log/slog"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRun_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX binary tests on windows")
	}
	ctx := context.Background()
	res, err := Run(ctx, 5*time.Second, "echo", "hello", "certistack")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	output := strings.TrimSpace(string(res.Stdout))
	if output != "hello certistack" {
		t.Errorf("expected 'hello certistack', got %q", output)
	}
	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
}

func TestRun_NonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX binary tests on windows")
	}
	ctx := context.Background()
	// sh -c "exit 42"
	res, err := Run(ctx, 5*time.Second, "sh", "-c", "exit 42")
	if err == nil {
		t.Fatal("expected error on non-zero exit, got nil")
	}
	if res.ExitCode != 42 {
		t.Errorf("expected exit code 42, got %d", res.ExitCode)
	}
}

func TestRun_NonZeroExitDoesNotEmbedStderrOrLogArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX shell tests on windows")
	}
	previousLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	res, err := Run(context.Background(), 5*time.Second, "sh", "-c", `printf 'stderr-secret' >&2; exit 42`)
	if err == nil {
		t.Fatal("expected error on non-zero exit, got nil")
	}
	if !strings.Contains(string(res.Stderr), "stderr-secret") {
		t.Fatalf("result did not preserve captured stderr: %q", res.Stderr)
	}
	if strings.Contains(err.Error(), "stderr-secret") {
		t.Fatalf("returned error embedded raw stderr: %q", err)
	}
	if strings.Contains(logs.String(), "stderr-secret") {
		t.Fatalf("command log exposed raw argv or stderr: %q", logs.String())
	}
}

func TestRun_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX binary tests on windows")
	}
	ctx := context.Background()
	// sleep for 2s with a 100ms timeout
	_, err := Run(ctx, 100*time.Millisecond, "sleep", "2")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("expected timed out error, got %v", err)
	}
}

func TestRun_DoesNotInheritConnectionCredentials(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX shell test on windows")
	}
	t.Setenv("PVE_TOKEN_SECRET", "pve-secret")
	t.Setenv("PBS_PASSWORD", "pbs-secret")

	res, err := Run(context.Background(), 5*time.Second, "sh", "-c", `printf '%s|%s' "${PVE_TOKEN_SECRET-unset}" "${PBS_PASSWORD-unset}"`)
	if err != nil {
		t.Fatalf("credential environment probe failed: %v", err)
	}
	if got := string(res.Stdout); got != "unset|unset" {
		t.Fatalf("child credential environment = %q, want unset|unset", got)
	}
}

func TestRun_BoundsCommandOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping POSIX shell test on windows")
	}
	res, err := Run(context.Background(), 5*time.Second, "sh", "-c", "head -c 1048577 /dev/zero")
	if err == nil || !strings.Contains(err.Error(), "output exceeded") {
		if res == nil {
			t.Fatalf("oversized command output error = %v (no result)", err)
		}
		t.Fatalf("oversized command output error = %v (stdout=%d stderr=%d)", err, len(res.Stdout), len(res.Stderr))
	}
	if res == nil || len(res.Stdout) > maxCommandOutputBytes || len(res.Stderr) > maxCommandOutputBytes {
		t.Fatalf("command output was not bounded: stdout=%d stderr=%d", len(res.Stdout), len(res.Stderr))
	}
}
