// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// A worker report in which two VM records carry one wire target is
// the reporter's signed duplicate pass. The controller refuses it before it
// signs, naming the address and both VMs, however the records came to share it
// (here the second VM's result is made to record the first VM's target).
func TestControllerRefusesAWorkerReportWhoseVMRecordsShareAWireTarget(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.VMRecords[1].ProbeResults[0].Target = report.VMRecords[0].ProbeResults[0].Target
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "the node worker's report contradicts what was requested") ||
		!strings.Contains(err.Error(), "VMs 9001, 9002 each record a passing wire probe of") {
		t.Fatalf("err = %v, want the report refused for the shared wire target", err)
	}
	if result != nil {
		t.Fatalf("a result was returned for a refused report: %+v", result)
	}
	if saved := reportsSaved(t, opts.OutputDir); saved != 0 {
		t.Fatalf("%d file(s) saved for a refused report", saved)
	}

	// The control: the plan's own targets are distinct and the report is signed.
	control := workerReportFor(t, opts)
	if problems := attest.SharedWireTargetProblems(control.VMRecords); len(problems) != 0 {
		t.Fatalf("the plan's own report shares a target: %v", problems)
	}
	fake = &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: control}, journalPhase: "cleaned"}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err != nil {
		t.Fatalf("control refused: %v", err)
	}
}
