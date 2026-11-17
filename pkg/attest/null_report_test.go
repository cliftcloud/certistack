// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest_test

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// DecodeReportUnverified says a file that is valid JSON but not a report
// object is an error: JSON null would otherwise decode into an empty report
// with no error, which a caller would show or tally as a report with nothing
// in it.
func TestAFileOfJSONNullIsNotAReportToTheUnverifiedDecoders(t *testing.T) {
	for _, document := range []string{"null", " null\n", "\tnull "} {
		if report, err := attest.DecodeReportUnverified([]byte(document)); err == nil || report != nil || !strings.Contains(err.Error(), "not a CertiStack report") {
			t.Errorf("DecodeReportUnverified(%q) = %v, %v; want an error that says it is not a report", document, report, err)
		}
		if report, err := attest.DecodeUnsignedReport([]byte(document)); err == nil || report != nil {
			t.Errorf("DecodeUnsignedReport(%q) = %v, %v; want an error", document, report, err)
		}
	}
	// An empty object is still a (very empty) report: the verdict rules refuse it.
	if _, err := attest.DecodeReportUnverified([]byte("{}")); err != nil {
		t.Errorf("DecodeReportUnverified of {} = %v", err)
	}
}
