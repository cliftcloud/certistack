// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"
)

// TestVerifyReportPrintsTheSoakChecks calls writeSoakSummary directly, so it
// would stay green if verify-report's text output stopped calling it. This
// test runs the compiled command on a signed report of a plan with a soak, and
// on one without.
func TestVerifyReportCommandPrintsTheSoakChecksOfASignedReport(t *testing.T) {
	text := verifyAuditReport(t, passReport(soakPlan()), "text")
	for _, want := range []string{"Tier Soak Service Checks:", "VM 9001: 4 check(s) of ", "PVE state read 5 time(s), 0 failed"} {
		if !strings.Contains(text, want) {
			t.Errorf("verify-report's output lacks %q:\n%s", want, text)
		}
	}
	// The summary follows the teardown evidence.
	if soak, teardown := strings.Index(text, "Tier Soak Service Checks:"), strings.Index(text, "Teardown & Safety Evidence:"); teardown < 0 || soak < teardown {
		t.Errorf("the soak checks are not printed after the teardown evidence (soak at %d, teardown at %d):\n%s", soak, teardown, text)
	}

	// A plan with no soak has no checks to show.
	if text := verifyAuditReport(t, passReport(mustLoadFixturePlan()), "text"); strings.Contains(text, "Tier Soak Service Checks:") {
		t.Errorf("a report of a plan with no soak printed a soak summary:\n%s", text)
	}
}
