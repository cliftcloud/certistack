// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package preflight

import (
	"context"
	"testing"

	"github.com/cliftcloud/certistack/pkg/admission"
)

// A memory refusal keeps the sample that decided it, which the worker signs
// into its report (admission.evaluation). A test of the worker's command with a
// Result built by hand would stay green if the line that copies the sample into
// the Result (r.MemoryEvaluation = &evaluation) were removed, and a refused run
// would be signed with no measurement. This runs the real check on the real
// host.
func TestMemoryRefusalOfTheHostChecksKeepsTheSampleThatDecidedIt(t *testing.T) {
	const impossibleMiB = 1 << 30 // a pebibyte
	options := func(required int) Options {
		return Options{ScratchDir: t.TempDir(), StateDir: t.TempDir(), RequiredRAMMB: required}
	}

	result := Check(context.Background(), nil, options(impossibleMiB))
	var refused bool
	for _, item := range result.Checks {
		if item.Name == "memory" && item.Status == "failed" {
			refused = true
		}
	}
	if !refused || result.Ready {
		t.Fatalf("a requirement of %d MiB did not refuse the host: %+v", impossibleMiB, result.Checks)
	}
	sample := result.MemoryEvaluation
	if sample == nil {
		t.Fatal("the memory refusal kept no sample of the host's memory")
	}
	if sample.Decision != admission.DecisionPreflightDeniedMemory || sample.Checks != 1 {
		t.Errorf("the sample's decision is %q after %d check(s), want %q after 1", sample.Decision, sample.Checks, admission.DecisionPreflightDeniedMemory)
	}
	if sample.HostTotalMiB <= 0 || sample.HostAvailableMiB <= 0 || sample.HostAvailableMiB > sample.HostTotalMiB {
		t.Errorf("the sample's host memory is %.1f MiB available of %.1f MiB, which is no measurement", sample.HostAvailableMiB, sample.HostTotalMiB)
	}
	if sample.RequiredAvailableMiB != impossibleMiB || sample.RequiredAvailableMiB <= sample.HostAvailableMiB {
		t.Errorf("the sample requires %.0f MiB against %.1f available, want %d", sample.RequiredAvailableMiB, sample.HostAvailableMiB, impossibleMiB)
	}

	// A host that has the memory is not refused and keeps no sample.
	if ok := Check(context.Background(), nil, options(1)); ok.MemoryEvaluation != nil {
		t.Errorf("a requirement of 1 MiB kept a memory sample: %+v", ok.MemoryEvaluation)
	}
}
