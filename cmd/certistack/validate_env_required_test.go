// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// The appliance's wrapper passes validate the mounted controller.env, so
// validate needs the file to be there. The appliance guide quotes this message
// for an operator who validates before the secrets are installed
// (internal/repocontract
// TestGuidesSayWhatTheAppliancesValidateAndRemoteInitNeed).
func TestValidateWithoutItsEnvironmentFileSaysSo(t *testing.T) {
	plan := writeValidationFixture(t, t.TempDir(), "plan.yaml")
	missing := filepath.Join(t.TempDir(), "controller.env")
	err := runRoot(t, io.Discard, "validate", "--env-file", missing, plan)
	if err == nil || !strings.HasPrefix(err.Error(), "open controller environment file: open "+missing+": ") {
		t.Fatalf("validate with an environment file that is not there: %v", err)
	}
	if exitCodeForError(err) != exitCodeInfrastructure {
		t.Errorf("exit %d, want %d", exitCodeForError(err), exitCodeInfrastructure)
	}
}
