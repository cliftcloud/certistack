// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
)

// A node's memory refusal on a real plan (VMs, and a reservation
// worked out from them) is signed evidence the controller and the verifier hold
// to the plan: the sample must show a host that could not give what the plan
// reserves. TestPreflightFailureRetainsStructuredMemorySample builds its
// result on an empty plan and never reaches those rules, so the rule that the
// sample's requirement is the plan's reservation could be removed with every
// test green.
func TestMemoryRefusalOfARealPlanIsHeldToTheReservationOfThatPlan(t *testing.T) {
	plan := mustLoadFixturePlan()
	reservation, vms, _, err := admission.RecoveryMemoryReservation(plan)
	if err != nil || vms == 0 {
		t.Fatalf("the fixture plan's reservation is %d MiB for %d VM(s): %v", reservation, vms, err)
	}
	required := float64(reservation)
	refusal := func(mutate func(*admission.Evaluation)) []string {
		t.Helper()
		sample := admission.Evaluation{
			Checks: 1, Decision: admission.DecisionPreflightDeniedMemory,
			HostTotalMiB: required * 4, HostAvailableMiB: required / 2, RequiredAvailableMiB: required,
			HostRAMPercent: 87.5, ProjectedRAMPercent: 112.5,
		}
		mutate(&sample)
		result := preflightFailureResult(plan, "node-a", preflight.Result{
			Checks:           []preflight.CheckItem{{Name: "memory", Status: "failed", Detail: "available RAM is below the reservation"}},
			MemoryEvaluation: &sample,
		}, false)
		if result.Report == nil || result.Report.Admission == nil || result.Report.Admission.Evaluation == nil {
			t.Fatalf("the refusal carries no admission sample: %+v", result.Report)
		}
		if result.Report.Admission.RecoveryReservationMiB != reservation {
			t.Fatalf("the report reserves %d MiB, the plan %d", result.Report.Admission.RecoveryReservationMiB, reservation)
		}
		return attest.PolicyEvidenceProblems(result.Report, plan)
	}

	if problems := refusal(func(*admission.Evaluation) {}); len(problems) != 0 {
		t.Fatalf("an honest refusal of the plan's reservation was refused: %s", strings.Join(problems, "; "))
	}
	for name, mutate := range map[string]func(*admission.Evaluation){
		"a requirement that is not the plan's reservation": func(e *admission.Evaluation) { e.RequiredAvailableMiB = required + 1 },
		"a requirement below the plan's reservation":       func(e *admission.Evaluation) { e.RequiredAvailableMiB = required - 1 },
		"a host with enough memory":                        func(e *admission.Evaluation) { e.HostAvailableMiB = required },
		"more available memory than the host has":          func(e *admission.Evaluation) { e.HostAvailableMiB = e.HostTotalMiB + 1 },
		"a host with no memory":                            func(e *admission.Evaluation) { e.HostTotalMiB = 0 },
	} {
		problems := refusal(mutate)
		if len(problems) == 0 || !strings.Contains(strings.Join(problems, "; "), "preflight memory denial does not match the measured available memory and recovery reservation") {
			t.Errorf("%s was accepted as evidence of a memory refusal: %v", name, problems)
		}
	}
}
