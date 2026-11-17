// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

//go:build linux

package main

import (
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/config"
)

// The memory shortage text comes from the node's own preflight, which
// reads /proc/meminfo, so it is built from the real check and sent through the
// node worker's refusal path.
func TestCapacityDenialRecognizesTheNodePreflightShortage(t *testing.T) {
	shortage := preflight.CheckMemory(1 << 40) // a petabyte of MiB
	if shortage == nil {
		t.Skip("the node's memory cannot be read here (no /proc/meminfo)")
	}
	plan := &config.Plan{PlanID: "guard"}
	result := preflightFailureResult(plan, "node-a", preflight.Result{Checks: []preflight.CheckItem{{Name: "memory", Status: "failed", Detail: shortage.Error()}}}, false)
	if !accept.CapacityDenial(result.Report.FailureReason) {
		t.Fatalf("the preflight's own memory shortage %q is not recognized as a capacity denial", result.Report.FailureReason)
	}
}
