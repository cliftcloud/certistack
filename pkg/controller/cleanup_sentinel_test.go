// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// A caller tells an unverified cleanup of the controller's own material on
// the node (the workspace, a retained workspace's key, the SSH staging
// directory) from any other failure with errors.Is, in every outcome of the
// run, and the wording an operator reads is unchanged.
func TestControllerMaterialCleanupFailureIsASentinelInEveryOutcome(t *testing.T) {
	const wording = "temporary controller material cleanup was not verified: "
	removeFails := []error{errors.New("first"), errors.New("second"), errors.New("third")}
	stagingFails := func(name, joined string) ([]byte, error, bool) {
		if name == "ssh" && strings.Contains(joined, "'/usr/bin/rm' '-rf' '/tmp/certistack-controller-") {
			return nil, errors.New("staging rm failed"), true
		}
		return nil, nil, false
	}
	for name, tc := range map[string]struct {
		fake       func(opts RunOptions) *fakeCommandRunner
		wantOutput string
	}{
		"a passing run whose workspace stays": {func(opts RunOptions) *fakeCommandRunner {
			return &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned", workspaceRemoveErrors: removeFails}
		}, "remove temporary node workspace after 3 attempts"},
		"a passing run whose staging directory stays": {func(opts RunOptions) *fakeCommandRunner {
			return &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned", hook: stagingFails}
		}, "remove temporary SSH staging directory after 3 attempts"},
		"a failed validation": {func(opts RunOptions) *fakeCommandRunner {
			report := workerReportFor(t, opts)
			report.AllPassed = false
			report.FailureReason = "service probe failed"
			return &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: "service probe failed"}, journalPhase: "cleaned", workspaceRemoveErrors: removeFails}
		}, "service probe failed"},
		"a lost worker": {func(opts RunOptions) *fakeCommandRunner {
			return &fakeCommandRunner{nodeRunError: errors.New("ssh session ended"), journalPhase: "cleaned", workspaceRemoveErrors: removeFails}
		}, "ssh session ended"},
	} {
		t.Run(name, func(t *testing.T) {
			opts := completedWorkerTeardownOptions(t)
			_, err := (&Executor{runner: tc.fake(opts)}).Run(context.Background(), opts)
			if err == nil || !errors.Is(err, ErrControllerMaterialCleanupUnverified) {
				t.Fatalf("err = %v, want it to wrap ErrControllerMaterialCleanupUnverified", err)
			}
			if !strings.Contains(err.Error(), wording) || !strings.Contains(err.Error(), tc.wantOutput) {
				t.Fatalf("err = %q, want the wording %q and %q", err, wording, tc.wantOutput)
			}
		})
	}
	// A run whose material was removed does not wrap it.
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err != nil || errors.Is(err, ErrControllerMaterialCleanupUnverified) {
		t.Fatalf("a clean run returned %v", err)
	}
}
