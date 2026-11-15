// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
)

// validate refuses a plan's storage.scratch_dir exactly when a run of the
// plan would: the rule config.ScratchDirProblem states is the one
// resolveScratchDir applies.
func TestTheScratchDirectoryRuleIsTheRunsRule(t *testing.T) {
	for _, dir := range []string{"/var/lib/certistack/scratch", " /srv/x ", "/tmp", "/var/tmp", "/dev/shm", "/", "x", "./x", "/a/../b",
		"/a/", "/a//b", "/a\\b", "/a\x00b", "/a\nb", "/tmp/x", "/..a", "/a..b"} {
		opts := RunOptions{ScratchDir: strings.TrimSpace(dir)}
		runRefuses := resolveScratchDir(&opts, nil) != nil
		validateRefuses := config.ScratchDirProblem(dir) != ""
		if runRefuses != validateRefuses {
			t.Errorf("scratch directory %q: the run refuses it: %v; validate refuses it: %v", dir, runRefuses, validateRefuses)
		}
	}
}
