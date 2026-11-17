// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
)

// The overlay-disk check stops with the context and hands the context's error
// back, and every interrupted step of doctor ends with one answer: no verdict,
// the interrupted status, and a message that says so. An interrupt that lands
// in the overlay-disk check gets that answer too, not a bare "context canceled"
// straight out of the command.
func TestDoctorInterruptedInTheOverlayDiskCheckAnswersLikeEveryOtherStep(t *testing.T) {
	previous := runPreflight
	t.Cleanup(func() { runPreflight = previous })
	// A host that is ready, so the checks before the overlay-disk check finish
	// and the interrupt is first noticed there.
	runPreflight = func(context.Context, *config.Plan, preflight.Options) preflight.Result {
		return preflight.Result{Ready: true, Checks: []preflight.CheckItem{{Name: "kvm", Status: "passed", Detail: "/dev/kvm is accessible"}}}
	}
	t.Setenv("PVE_URL", "")
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_OVERLAY_STORAGE", "CERTISTACK_NODE", "PBS_NAMESPACE"} {
		t.Setenv(name, "")
	}
	root := t.TempDir()
	plan := writeValidationFixture(t, root, "plan.yaml")

	ctx, interrupt := context.WithCancel(context.Background())
	interrupt()
	var stdout bytes.Buffer
	cmd := newRootCmd(context.Background())
	cmd.SetOut(&stdout)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"doctor", "--plan", plan, "--scratch", filepath.Join(root, "scratch"), "--state-dir", t.TempDir()})
	err := cmd.ExecuteContext(ctx)

	if err == nil || !strings.Contains(err.Error(), "interrupted before it reached a verdict") {
		t.Fatalf("err = %v, want doctor's one interrupted message", err)
	}
	if exitCodeForError(err) != exitCodeInterrupted {
		t.Errorf("exit %d (err %v), want the interrupted status %d", exitCodeForError(err), err, exitCodeInterrupted)
	}
	if strings.Contains(stdout.String(), "Preflight checks") || strings.Contains(stdout.String(), "CertiStack Preflight Diagnostics") {
		t.Errorf("an interrupted doctor printed a verdict:\n%s", stdout.String())
	}
}
