// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"path/filepath"
	"testing"
)

// CopyWorkerPlan is the plan as the controller sent it, kept by a
// caller whose callee writes into the plan it is given. It must be the same
// plan (one canonical digest, for every plan a user can write) and share
// nothing with the original.
func TestCopyWorkerPlanIsTheSamePlanAndSharesNothingWithIt(t *testing.T) {
	var paths []string
	for _, pattern := range []string{
		filepath.Join("..", "..", "examples", "*.yaml"),
		filepath.Join("..", "..", "testdata", "plans", "*.yaml"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
	}
	loaded := 0
	for _, path := range paths {
		plan, err := LoadFromFile(path)
		if err != nil {
			continue // a fixture that exists to be refused
		}
		loaded++
		t.Run(filepath.Base(path), func(t *testing.T) {
			before, err := CanonicalWorkerPlanSHA256(plan)
			if err != nil {
				t.Fatal(err)
			}
			copied, err := CopyWorkerPlan(plan)
			if err != nil {
				t.Fatalf("the copy of a plan that loaded: %v", err)
			}
			if got, err := CanonicalWorkerPlanSHA256(copied); err != nil || got != before {
				t.Fatalf("the copy's digest is %s (%v), the plan's is %s", got, err, before)
			}
			// What the runner does to a plan as it goes.
			plan.Tiers[0].VMs[0].SourcePBS.Snapshot = "vm/1/2026-01-01T00:00:00Z"
			plan.Tiers[0].VMs[0].HardwareOverrides.MemoryMB += 4096
			plan.Tiers[0].VMs[0].SourceTags = append(plan.Tiers[0].VMs[0].SourceTags, "written-by-the-runner")
			if got, err := CanonicalWorkerPlanSHA256(copied); err != nil || got != before {
				t.Fatalf("writing into the plan changed its copy: digest %s (%v), want %s", got, err, before)
			}
			if changed, _ := CanonicalWorkerPlanSHA256(plan); changed == before {
				t.Fatal("the test's own edit did not change the plan's digest")
			}
		})
	}
	if loaded < 5 {
		t.Fatalf("only %d of %d shipped plans loaded; the test no longer covers them", loaded, len(paths))
	}
	if _, err := CopyWorkerPlan(nil); err == nil {
		t.Error("a nil plan was copied")
	}
}
