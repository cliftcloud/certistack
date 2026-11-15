// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// DecodeReportUnverified returns what a file says and nothing more: it must
// read a signed report, an unsigned one and a tampered one alike (that is its
// purpose and its danger), and it must still refuse what a verifier refuses
// before decoding, and anything that is not a report object.
func TestDecodeReportUnverifiedReadsWhatTheFileSaysAndKeepsTheStructureLimits(t *testing.T) {
	_, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plan := &config.Plan{PlanID: "show-plan", Name: "Show plan"}
	report := BuildReport(plan, "node-1", 42*time.Second, true, []probe.VMValidationRecord{{VMID: 9001, Name: "web", AllPassed: true}}, "")
	if err := report.SignReport(privKey); err != nil {
		t.Fatal(err)
	}
	signed, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	var tampered map[string]any
	if err := json.Unmarshal(signed, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["all_passed"] = false
	tamperedBytes, _ := json.Marshal(tampered)
	delete(tampered, "signature")
	unsignedBytes, _ := json.Marshal(tampered)

	for name, data := range map[string][]byte{"signed": signed, "tampered": tamperedBytes, "unsigned": unsignedBytes} {
		got, err := DecodeReportUnverified(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.PlanID != "show-plan" || got.NodeFQDN != "node-1" || len(got.VMRecords) != 1 || got.VMRecords[0].VMID != 9001 {
			t.Errorf("%s: decoded %+v", name, got)
		}
		if want := name == "signed"; got.AllPassed != want {
			t.Errorf("%s: all_passed = %v, want %v (the file's own word)", name, got.AllPassed, want)
		}
	}
	// The same bytes are refused by the verifier when tampered: decoding them
	// unverified must not have been mistaken for checking them.
	if _, valid, err := VerifyReportSignatureOnly(tamperedBytes); valid || !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("the tampered report verified: valid=%v err=%v", valid, err)
	}

	for name, data := range map[string]string{
		"a repeated member name": `{"report_id":"a","report_id":"b"}`,
		"two documents":          `{"report_id":"a"} {"report_id":"b"}`,
		"truncated":              `{"report_id":"a","vm_records":[{"vmid":`,
		"an array":               `[1,2,3]`,
		"a string":               `"report"`,
		"a wrong member type":    `{"report_id":"a","all_passed":"yes"}`,
		"an integer beyond 2^53": `{"report_id":"a","rto_seconds":9007199254740993}`,
		"nothing":                ``,
	} {
		if got, err := DecodeReportUnverified([]byte(data)); err == nil {
			t.Errorf("%s was decoded: %+v", name, got)
		}
	}
}
