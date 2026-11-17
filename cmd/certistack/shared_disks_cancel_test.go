// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/spf13/cobra"
)

// Doctor passes its context to the topology check as well as to pvesm, and does
// not turn a cancellation into a warning: a doctor that was interrupted reports
// no "unknown topology", and its exit status is the interruption's.
func TestDoctorsOverlayDiskCheckEndsWithItsContext(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("doctor's checks run on Linux")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := withOverlayDiskCheck(ctx, preflight.Result{}, &config.Plan{}, "", t.TempDir())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("withOverlayDiskCheck = %v, want the context's error", err)
	}
	if exitCodeForError(err) != exitCodeInterrupted {
		t.Fatalf("exit status %d, want the interrupted status %d", exitCodeForError(err), exitCodeInterrupted)
	}
	for _, check := range res.Checks {
		if check.Name == "overlay_disk" {
			t.Fatalf("an interrupted doctor reported %+v", check)
		}
	}

	// A context that is alive gets its answer.
	res, err = withOverlayDiskCheck(context.Background(), preflight.Result{}, &config.Plan{}, "", t.TempDir())
	if err != nil || len(res.Checks) != 1 || res.Checks[0].Name != "overlay_disk" {
		t.Fatalf("withOverlayDiskCheck = %+v, %v; want one overlay_disk check", res.Checks, err)
	}
}

// A plan that was cancelled is the context's error, not a refusal a run would
// give: `certistack plan` does not print "a run would refuse this plan" for it.
func TestComputePlanReturnsTheContextErrorNotARefusal(t *testing.T) {
	plan := &config.Plan{PlanID: "cancelled"} // not a plan a run accepts: PlanRun fails at once
	run := func(ctx context.Context) error {
		cmd := &cobra.Command{}
		cmd.SetContext(ctx)
		runPlan, err := computePlan(cmd, plan, "pve1", t.TempDir(), t.TempDir(), "", "")
		if err == nil && runPlan == nil {
			t.Fatal("computePlan returned neither a plan nor an error")
		}
		if err != nil && runPlan != nil {
			t.Fatalf("computePlan returned a plan and %v", err)
		}
		if err == nil && len(runPlan.Refusals) == 0 {
			t.Fatalf("an invalid plan was not refused: %+v", runPlan)
		}
		return err
	}
	if err := run(context.Background()); err != nil {
		t.Fatalf("a live context: %v; want the plan's own refusal in the plan", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := run(ctx)
	if !errors.Is(err, context.Canceled) || exitCodeForError(err) != exitCodeInterrupted {
		t.Fatalf("a cancelled context: %v (exit %d); want the context's error and the interrupted status", err, exitCodeForError(err))
	}
}
