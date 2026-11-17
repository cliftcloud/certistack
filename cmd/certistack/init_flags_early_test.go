// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// A --plan-id that no plan may have is the operator's value: init refuses it
// first, in words that say so, before it reads any backup's configuration
// (through a worker it stages on the node, with --ssh-host, or by mapping each
// backup, with --inspect).
func TestInitRefusesABadPlanIDBeforeItReadsTheNode(t *testing.T) {
	for _, planID := range []string{"bad id!", strings.Repeat("a", 129), "plan/../x"} {
		dir := initNode(t)
		read := false
		discover := runnerDiscover
		runnerDiscover = func(ctx context.Context, req initplan.Request, scratch string) (*initplan.Discovery, error) {
			read = true
			return discover(ctx, req, scratch)
		}
		_, _, err := runInit(t, context.Background(), initArgs(dir, "--plan-id", planID)...)
		if err == nil {
			t.Fatalf("--plan-id %q was accepted", planID)
		}
		if read {
			t.Errorf("--plan-id %q was refused only after init read the node: %v", planID, err)
		}
		if strings.Contains(err.Error(), "bug in init") || !strings.Contains(err.Error(), "--plan-id") {
			t.Errorf("--plan-id %q: the refusal does not name the flag, or blames init: %v", planID, err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "plan.yaml")); statErr == nil {
			t.Errorf("--plan-id %q: a plan was written", planID)
		}
	}
	// A plan_id the loader accepts is still accepted.
	dir := initNode(t)
	if _, stderr, err := runInit(t, context.Background(), initArgs(dir, "--plan-id", "nightly_DR-01")...); err != nil {
		t.Fatalf("a valid --plan-id was refused: %v\n%s", err, stderr)
	}
}
