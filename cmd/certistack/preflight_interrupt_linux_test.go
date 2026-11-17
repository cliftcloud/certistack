// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/preflight"
	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// The handling of an interrupt during the host checks, at the call sites a
// unit test of the helpers does not reach.

// Doctor without a plan: the overlay branch that guards a doctor with a
// plan does not run, so the command's last guard is the only thing between an
// interrupted version request and a printed verdict (without it, the command
// prints "Preflight checks" and exits 2 instead of ending at once with 130). A
// held PVE request, then SIGINT, through the real signal contexts and the real
// command, with no plan.
func TestDoctorWithoutAPlanEndsAtTheFirstInterrupt(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		name := "text"
		if jsonOutput {
			name = "json"
		}
		t.Run(name, func(t *testing.T) {
			clearControllerEnvironment(t)
			server := newHeldPVE(t, true, 0)
			t.Setenv("PVE_URL", server.URL)
			t.Setenv("PVE_TOKEN_ID", "audit@pve!doctor")
			t.Setenv("PVE_TOKEN_SECRET", "AUDIT-ONLY-NOT-A-CREDENTIAL")
			t.Setenv("PATH", t.TempDir())
			root := t.TempDir()
			state := filepath.Join(root, "state")
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}

			signals := make(chan os.Signal, 2)
			var messages, stdout bytes.Buffer
			ctx, cleanupCtx, stop := newSignalContexts(signals, &messages)
			defer stop()
			cmd := newRootCmd(cleanupCtx)
			cmd.SetOut(&stdout)
			cmd.SetErr(io.Discard)
			args := []string{"doctor", "--scratch", filepath.Join(root, "scratch"), "--state-dir", state}
			if jsonOutput {
				args = append(args, "--json")
			}
			cmd.SetArgs(args)
			done := make(chan error, 1)
			go func() { done <- cmd.ExecuteContext(ctx) }()

			select {
			case <-server.held:
			case err := <-done:
				t.Fatalf("doctor ended before the request it was to be interrupted in: %v\n%s", err, stdout.String())
			case <-time.After(10 * time.Second):
				t.Fatal("the PVE request that is held never arrived")
			}
			first := time.Now()
			signals <- os.Interrupt
			var err error
			select {
			case err = <-done:
			case <-time.After(8 * time.Second):
				t.Fatal("doctor was still waiting for the PVE API 8 seconds after the first interrupt")
			}
			if elapsed := time.Since(first); elapsed > 4*time.Second {
				t.Errorf("doctor took %v to end after the first interrupt", elapsed)
			}
			if exitCodeForError(err) != exitCodeInterrupted {
				t.Errorf("exit %d (err %v), want the interrupted status %d", exitCodeForError(err), err, exitCodeInterrupted)
			}
			if err == nil || !strings.Contains(err.Error(), "interrupted before it reached a verdict") {
				t.Errorf("err = %v", err)
			}
			if out := stdout.String(); out != "" {
				t.Errorf("an interrupted doctor with no plan printed a verdict:\n%s", out)
			}
			// Doctor only reads, and says so.
			if got := messages.String(); strings.Contains(got, "waiting for CertiStack cleanup") || !strings.Contains(got, "Interrupt received; stopping") {
				t.Errorf("the first signal said %q", got)
			}
		})
	}
}

// Node-run: the worker's command hands the host checks its own
// context, and a worker stopped while it checks the host reports that it was
// stopped and not that the host refused. This tests the command's call of
// preflightRefusedResult, not only the function.
func TestNodeRunStoppedDuringPreflightHandsItsContextAndReportsAStop(t *testing.T) {
	for name := range workerEnvironmentNames {
		t.Setenv(name, "")
	}
	previousLock, previousPreflight := acquireHostLock, runPreflight
	t.Cleanup(func() { acquireHostLock, runPreflight = previousLock, previousPreflight })

	run := func(t *testing.T, stopped bool) nodeapi.RunResult {
		t.Helper()
		root := t.TempDir()
		lockPath := filepath.Join(root, "host.lock")
		acquireHostLock = func() (*os.File, error) { return os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) }
		var seen context.Context
		runPreflight = func(ctx context.Context, _ *config.Plan, _ preflight.Options) preflight.Result {
			seen = ctx
			return preflight.Result{Checks: []preflight.CheckItem{{Name: "pve_connectivity", Status: "failed", Detail: "failed to reach PVE API: context canceled"}}}
		}
		state, scratch := filepath.Join(root, "state"), filepath.Join(root, "scratch")
		envFile := filepath.Join(root, "runtime.env")
		if err := os.WriteFile(envFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		plan := writeValidationFixture(t, root, "plan.yaml")
		cmd := nodeRunCmd()
		var stdout bytes.Buffer
		cmd.SetOut(&stdout)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"--plan", plan, "--node", "pve-01", "--env-file", envFile, "--state-dir", state, "--scratch", scratch, "--output", filepath.Join(root, "reports"), "--run-id", "run-preflight-stop"})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if stopped {
			cancel()
		}
		if err := cmd.ExecuteContext(ctx); err != nil {
			t.Fatalf("node-run: %v\n%s", err, stdout.String())
		}
		var result nodeapi.RunResult
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatalf("the worker's result is not JSON: %v\n%s", err, stdout.String())
		}
		if seen == nil {
			t.Fatal("the host checks never ran")
		}
		return result
	}

	t.Run("stopped", func(t *testing.T) {
		result := run(t, true)
		if !strings.HasPrefix(result.Error, preflightInterruptedPrefix) || strings.Contains(result.Error, "pve_connectivity") {
			t.Errorf("a worker stopped during preflight reported %q", result.Error)
		}
		if result.Report == nil || result.Report.FailureReason != result.Error || result.Report.RunID != "run-preflight-stop" {
			t.Errorf("the evidence = %+v", result.Report)
		}
	})
	t.Run("the host checks get the command's context", func(t *testing.T) {
		// The checks saw a context that had ended, so they stopped where they
		// were, instead of running to their own time limits.
		root := t.TempDir()
		acquireHostLock = func() (*os.File, error) {
			return os.OpenFile(filepath.Join(root, "host.lock"), os.O_CREATE|os.O_RDWR, 0o600)
		}
		var ended bool
		runPreflight = func(ctx context.Context, _ *config.Plan, _ preflight.Options) preflight.Result {
			ended = ctx.Err() != nil
			return preflight.Result{Checks: []preflight.CheckItem{{Name: "pve_connectivity", Status: "failed", Detail: "context canceled"}}}
		}
		envFile := filepath.Join(root, "runtime.env")
		if err := os.WriteFile(envFile, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := nodeRunCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs([]string{"--plan", writeValidationFixture(t, root, "plan.yaml"), "--node", "pve-01", "--env-file", envFile, "--state-dir", filepath.Join(root, "state"), "--scratch", filepath.Join(root, "scratch"), "--run-id", "run-ctx"})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := cmd.ExecuteContext(ctx); err != nil {
			t.Fatal(err)
		}
		if !ended {
			t.Error("node-run gave the host checks a context that had not ended with the command's")
		}
	})
	t.Run("not stopped", func(t *testing.T) {
		result := run(t, false)
		if !strings.HasPrefix(result.Error, accept.PreflightFailurePrefix) || !strings.Contains(result.Error, "pve_connectivity") {
			t.Errorf("a worker that was not stopped reported %q", result.Error)
		}
	})
}
