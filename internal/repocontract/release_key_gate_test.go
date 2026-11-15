// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"os"
	"strings"
	"testing"
)

// SECURITY.md tells users how to verify a release with the release key and its
// fingerprint. Until those are published, the line carries a placeholder, and
// the release workflow must refuse to publish while a placeholder is left.
func TestReleaseWorkflowRefusesTheKeyPlaceholder(t *testing.T) {
	workflow, err := os.ReadFile(repoFile(".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	const placeholder = "<published with the release>"
	gate := "git grep -n -I -F '" + placeholder + "'"
	if !strings.Contains(text, gate) {
		t.Fatalf("release.yml does not check for the %q placeholder (want %q)", placeholder, gate)
	}
	i := strings.Index(text, gate)
	if !strings.Contains(text[i:min(len(text), i+400)], "exit 1") {
		t.Fatalf("the placeholder check in release.yml does not fail the release")
	}
}
