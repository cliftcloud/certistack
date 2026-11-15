// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"io"
	"strings"
	"testing"
)

// A setup script prints a token's secret once and may fail on a later step:
// RunNodeScript's runner hands back what it printed, with the error. Every
// other command keeps the old rule (no output on error).
func TestTheScriptRunnerKeepsStdoutOfAFailedCommand(t *testing.T) {
	script := []string{"-c", `echo '{"value":"kept"}'; echo 'acl modify failed' >&2; exit 3`}
	out, err := runCommandOutput(context.Background(), "/bin/sh", script, io.Discard, true)
	if err == nil || string(out) != "{\"value\":\"kept\"}\n" || !strings.Contains(err.Error(), "acl modify failed") {
		t.Fatalf("kept: %q, %v", out, err)
	}
	out, err = runCommand(context.Background(), "/bin/sh", script, io.Discard)
	if err == nil || out != nil {
		t.Fatalf("runCommand: %q, %v", out, err)
	}
	var runner commandRunner = osCommandRunner{}
	if _, ok := runner.(scriptCommandRunner); !ok {
		t.Fatal("the OS runner does not keep a script's output")
	}
}
