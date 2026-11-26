// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// Without a plan, doctor has checked the host and nothing of the plan, so it
// cannot say the system is ready for a run.
func TestDoctorWithoutAPlanDoesNotSayTheSystemIsReady(t *testing.T) {
	_, args := readyHost(t, nil)
	out, err := runRootWithInput(t, "", append([]string{"doctor"}, args...)...)
	if err != nil {
		t.Fatalf("doctor on a ready host: %v\n%s", err, out)
	}
	if want := "Host tools present. Run doctor with your plan (or certistack check) before a run: some checks need the plan."; !strings.Contains(out, want) {
		t.Errorf("the verdict lacks %q:\n%s", want, out)
	}
	if strings.Contains(out, "ready for a run") {
		t.Errorf("doctor says the system is ready although it saw no plan:\n%s", out)
	}
}

// With the plan, the verdict covers it and keeps its sentence.
func TestDoctorWithAPlanKeepsTheReadySentence(t *testing.T) {
	root, args := readyHost(t, func(context.Context, *config.Plan, runner.Options) ([]runner.SourceCheck, error) {
		return []runner.SourceCheck{{VMID: 9100, Status: runner.SourcePassed, Detail: "vm/7011/2026-10-02T03:00:01Z; BIOS; 1 disk(s) restored"}}, nil
	})
	out, err := runRootWithInput(t, "", append([]string{"doctor", planWithScratch(t, root, "")}, args...)...)
	if err != nil {
		t.Fatalf("doctor with a plan: %v\n%s", err, out)
	}
	if !strings.Contains(out, "System is ready for a run.") || strings.Contains(out, "Host tools present") {
		t.Errorf("the verdict for a plan that was checked:\n%s", out)
	}
}

// A host the checks do not run on (not Linux) gets no verdict: doctor says that
// no check was run, never PASSED and never FAILED, and exits with a failure.
func TestDoctorSaysWhenNoCheckWasRun(t *testing.T) {
	_, args := readyHost(t, nil)
	runPreflight = func(context.Context, *config.Plan, preflight.Options) preflight.Result {
		return preflight.Result{Checks: []preflight.CheckItem{{Name: "Platform", Status: "skipped", Detail: "preflight checks run only on Linux"}}}
	}
	out, err := runRootWithInput(t, "", append([]string{"doctor"}, args...)...)
	if err == nil || !strings.Contains(err.Error(), "no preflight check was run") {
		t.Fatalf("doctor with no check run: err = %v\n%s", err, out)
	}
	for _, want := range []string{"[-] Platform", "preflight checks run only on Linux", "No check was run, so there is no verdict."} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"PASSED", "FAILED", "ready for a run"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the output says %q although no check was run:\n%s", unwanted, out)
		}
	}
}
