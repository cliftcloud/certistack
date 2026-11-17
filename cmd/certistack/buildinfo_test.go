// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"runtime/debug"
	"testing"
)

func withBuildIdentity(t *testing.T, v, c, d string) {
	t.Helper()
	prevVersion, prevCommit, prevDate := version, commit, buildDate
	version, commit, buildDate = v, c, d
	t.Cleanup(func() { version, commit, buildDate = prevVersion, prevCommit, prevDate })
}

func TestApplyBuildInfoFillsDefaultsFromModuleAndVCS(t *testing.T) {
	withBuildIdentity(t, "dev", "unknown", "unknown")
	applyBuildInfo(&debug.BuildInfo{
		Main: debug.Module{Version: "v0.1.0"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123456789abcdef01234567"},
			{Key: "vcs.time", Value: "2026-09-22T12:00:00Z"},
			{Key: "vcs.modified", Value: "false"},
		},
	})
	if version != "v0.1.0" || commit != "0123456789ab" || buildDate != "2026-09-22T12:00:00Z" {
		t.Fatalf("unexpected identity: version=%q commit=%q buildDate=%q", version, commit, buildDate)
	}
}

func TestApplyBuildInfoMarksModifiedTreeDirty(t *testing.T) {
	withBuildIdentity(t, "dev", "unknown", "unknown")
	applyBuildInfo(&debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abcdef0"},
			{Key: "vcs.modified", Value: "true"},
		},
	})
	if version != "dev-dirty" || commit != "abcdef0" {
		t.Fatalf("expected dev-dirty/abcdef0, got version=%q commit=%q", version, commit)
	}
}

func TestApplyBuildInfoKeepsLdflagsValues(t *testing.T) {
	withBuildIdentity(t, "0.1.0", "363d994", "2026-09-22T00:00:00Z")
	applyBuildInfo(&debug.BuildInfo{
		Main:     debug.Module{Version: "v9.9.9"},
		Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "ffffffffffff"}, {Key: "vcs.modified", Value: "true"}},
	})
	if version != "0.1.0" || commit != "363d994" || buildDate != "2026-09-22T00:00:00Z" {
		t.Fatalf("ldflags identity must win, got version=%q commit=%q buildDate=%q", version, commit, buildDate)
	}
}

func TestApplyBuildInfoToleratesMissingInfo(t *testing.T) {
	withBuildIdentity(t, "dev", "unknown", "unknown")
	applyBuildInfo(nil)
	applyBuildInfo(&debug.BuildInfo{})
	if version != "dev" || commit != "unknown" || buildDate != "unknown" {
		t.Fatalf("defaults must survive empty build info, got version=%q commit=%q buildDate=%q", version, commit, buildDate)
	}
}
