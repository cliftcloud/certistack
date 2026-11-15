// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"
)

// `history` (per-VM last pass and recovery-time trend across a report
// directory) moved to the Enterprise Edition on 2026-10-08, before the first
// release; docs/community-commitments.md says so. The Community binary has no such
// command, and a person who types it is told it does not exist, not shown
// something that looks like it.
func TestHistoryIsNotACommunityCommand(t *testing.T) {
	for _, command := range newRootCmd(nil).Commands() {
		if command.Name() == "history" {
			t.Fatalf("the root registers %q: history is an Enterprise Edition feature (docs/community-commitments.md)", command.Name())
		}
		for _, alias := range command.Aliases {
			if alias == "history" {
				t.Fatalf("command %q answers to the alias history", command.Name())
			}
		}
	}
	stdout, _, err := runReportCommand(t, "history", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("certistack history = %q, %v; want an unknown command error", stdout, err)
	}
}
