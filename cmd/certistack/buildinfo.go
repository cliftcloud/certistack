// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"runtime/debug"
	"strings"
)

// applyBuildInfo fills in the build identity from the module and VCS metadata
// the Go toolchain embeds when a binary is produced without the Makefile's
// -ldflags, for example by `go install github.com/cliftcloud/certistack/cmd/certistack@v0.1.0`
// or a plain `go build` inside a clone. Values injected through -ldflags
// always take precedence, so release builds are unaffected.
//
// A module-proxy install carries a module version but no VCS revision; such a
// binary therefore reports its version and an unknown commit, and the release
// evidence gate (which requires a hexadecimal commit) continues to reject it.
// That is deliberate: only the signed release artifact or a Makefile build of
// a clean tagged checkout has a verifiable identity.
func applyBuildInfo(info *debug.BuildInfo) {
	if info == nil {
		return
	}
	// A version injected through -ldflags (from `git describe --dirty`) already
	// carries its own dirty marker and must be reported verbatim.
	derived := version == "dev"
	if derived && info.Main.Version != "" && info.Main.Version != "(devel)" {
		version = info.Main.Version
	}

	var revision, vcsTime string
	modified := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		case "vcs.time":
			vcsTime = setting.Value
		}
	}
	if commit == "unknown" && revision != "" {
		commit = revision
		if len(commit) > 12 {
			commit = commit[:12]
		}
	}
	if buildDate == "unknown" && vcsTime != "" {
		buildDate = vcsTime
	}
	// Newer toolchains already encode a modified tree as a "+dirty" pseudo-
	// version suffix; only add a marker when nothing in the label says so.
	if derived && modified && !strings.Contains(version, "dirty") {
		version += "-dirty"
	}
}
