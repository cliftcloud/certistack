// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
)

// A doctor run by a caller that has no context (RunE called directly, as a test
// or an embedder does) panicked at the first check of the context, which the
// disk check later reaches as exec.CommandContext(nil, ...). It runs, and
// reaches its verdict, as it does under Execute, which gives every command a
// context.
func TestDoctorRunWithoutAContextReachesItsVerdict(t *testing.T) {
	previous := runPreflight
	t.Cleanup(func() { runPreflight = previous })
	var seen context.Context
	runPreflight = func(ctx context.Context, _ *config.Plan, _ preflight.Options) preflight.Result {
		seen = ctx
		return preflight.Result{Ready: true, Checks: []preflight.CheckItem{{Name: "kvm", Status: "passed", Detail: "/dev/kvm is accessible"}}}
	}
	root := t.TempDir()
	cmd := doctorCmd()
	if cmd.Context() != nil {
		t.Fatal("a command nobody executed has a context; this test no longer builds its case")
	}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	if err := cmd.ParseFlags([]string{"--scratch", filepath.Join(root, "scratch"), "--state-dir", root}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("doctor without a context: %v\n%s", err, out.String())
	}
	if seen == nil {
		t.Fatal("the host checks were given no context")
	}
	if out.Len() == 0 {
		t.Error("doctor printed no verdict")
	}
}
