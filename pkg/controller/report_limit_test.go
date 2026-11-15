// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// The verifier reads reports within size limits, and the controller
// signs what a worker returns, so the limits must let through everything the
// controller accepts: a report holds a worker's result (at most maxWorkerJSON
// bytes of JSON) and is saved indented, and one string of it may be the whole
// result. A controller limit raised without the verifier's would sign
// evidence nobody can check.
func TestReportLimitsHoldEverythingTheControllerAccepts(t *testing.T) {
	if attest.MaxReportFileBytes < 2*maxWorkerJSON {
		t.Errorf("attest.MaxReportFileBytes = %d, less than twice maxWorkerJSON (%d): a report of a full worker result, indented, could not be verified", attest.MaxReportFileBytes, 2*maxWorkerJSON)
	}
	if attest.MaxReportStringBytes < maxWorkerJSON {
		t.Errorf("attest.MaxReportStringBytes = %d, less than maxWorkerJSON (%d): one screenshot string could be refused", attest.MaxReportStringBytes, maxWorkerJSON)
	}
}
