// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package nodeapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
)

// The worker's standard output is one JSON document with these two field
// names; the controller reads them by name, so a rename is a protocol break.
func TestRunResultWireContract(t *testing.T) {
	onlyError, err := json.Marshal(RunResult{Error: "validation failed"})
	if err != nil {
		t.Fatal(err)
	}
	if string(onlyError) != `{"error":"validation failed"}` {
		t.Fatalf("error-only result = %s", onlyError)
	}
	empty, err := json.Marshal(RunResult{})
	if err != nil || string(empty) != `{}` {
		t.Fatalf("empty result = %s, %v", empty, err)
	}

	report := attest.BuildReport(&config.Plan{PlanID: "p", Name: "n"}, "node", time.Second, false, nil, "")
	both, err := json.Marshal(RunResult{Report: report, Error: "one probe failed"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(both), `"report":{`) || !strings.Contains(string(both), `"error":"one probe failed"`) {
		t.Fatalf("a failed validation must carry its report and its error together: %s", both)
	}
	var back RunResult
	if err := json.Unmarshal(both, &back); err != nil || back.Report == nil || back.Report.PlanID != "p" || back.Error != "one probe failed" {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
}
