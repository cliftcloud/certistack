// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// Without a plan, doctor has checked the host and nothing of the plan, so it
// cannot say the system is ready for DR validation (hardening F13, CR1-13).
func TestDoctorWithoutAPlanDoesNotSayTheSystemIsReady(t *testing.T) {
	_, args := readyHost(t, nil)
	out, err := runRootWithInput(t, "", append([]string{"doctor"}, args...)...)
	if err != nil {
		t.Fatalf("doctor on a ready host: %v\n%s", err, out)
	}
	if want := "Host tools present. Run doctor with your plan (or certistack check) before a run: some checks need the plan."; !strings.Contains(out, want) {
		t.Errorf("the verdict lacks %q:\n%s", want, out)
	}
	if strings.Contains(out, "ready for DR validation") {
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
	if !strings.Contains(out, "System is ready for DR validation.") || strings.Contains(out, "Host tools present") {
		t.Errorf("the verdict for a plan that was checked:\n%s", out)
	}
}
