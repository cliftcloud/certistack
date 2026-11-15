// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package acceptance

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// Review R1-04. Evaluate reads the contents of a report and nothing else: it
// cannot tell a report whose signature the caller verified from one anybody
// wrote. So the verdict says which it was told, and a caller that says nothing
// gets "not authenticated", the safe reading.
func TestTheVerdictCarriesWhetherTheCallerAuthenticatedTheReport(t *testing.T) {
	report := &attest.Report{}
	if got := Evaluate(report, Expectations{}).Authenticated; got {
		t.Error("a caller that did not say the report was authenticated got a verdict that says it was")
	}
	if got := Evaluate(report, Expectations{Authenticated: true}).Authenticated; !got {
		t.Error("a caller that authenticated the report got a verdict that says it was not")
	}
	data, err := json.Marshal(Evaluate(report, Expectations{}))
	if err != nil {
		t.Fatal(err)
	}
	// The member is last, so a consumer that matches the start of the object
	// (`"acceptance":{"verdict":"accepted"`) still matches.
	if !strings.HasSuffix(string(data), `,"authenticated":false}`) {
		t.Errorf("the verdict's JSON = %s, want it to end with the authenticated member", data)
	}
}
