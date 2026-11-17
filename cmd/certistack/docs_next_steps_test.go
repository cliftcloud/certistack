// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/controller"
)

// Step 5 of the quickstart says that a run's last line is the command that
// shows its report. After a pass, the lines runNextSteps prints end with a
// `certistack report show` of the saved report, and none is a verify-report
// command: the Community Edition's report is unsigned.
func TestTheQuickstartSaysWhatARunPrintsLast(t *testing.T) {
	quickstart := strings.Join(strings.Fields(markdownText(t, filepath.Join(docRoot, "docs", "quickstart.md"))), " ")
	if !strings.Contains(quickstart, "The run's last line is the command that shows its report") {
		t.Error("step 5 of docs/quickstart.md does not say that a run's last line is the command that shows its report")
	}
	const path = "/var/lib/certistack/reports/recovery-pve-node-01/0123abcd.json"
	lines := runNextSteps(&controller.Result{Report: &attest.Report{AllPassed: true}, ReportPath: path}, nil)
	if len(lines) == 0 {
		t.Fatal("run prints no next step after a pass")
	}
	if last := lines[len(lines)-1]; last != "Next: certistack report show "+path {
		t.Errorf("the last line after a pass is %q, want the report show command of %s", last, path)
	}
	for _, line := range lines {
		if strings.Contains(line, "verify-report") {
			t.Errorf("run prints a verify-report line after a pass: %q", line)
		}
	}
}
