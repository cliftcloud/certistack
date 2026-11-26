// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
)

// Every verifier refuses a report that has no signature, and says so with a
// sentinel a caller can recognize: a signature taken off a report must never
// read as a report that was verified.
func TestVerifiersRefuseAnUnsignedReportWithTheSentinel(t *testing.T) {
	public, _ := testKeys(t)
	data, err := json.Marshal(unsignedTestReport())
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := attest.VerifyReport(data, []ed25519.PublicKey{public}); !errors.Is(err, attest.ErrReportUnsigned) || valid {
		t.Errorf("VerifyReport = valid %v, %v; want ErrReportUnsigned", valid, err)
	}
	if _, valid, err := attest.VerifyReportSignatureOnly(data); !errors.Is(err, attest.ErrReportUnsigned) || valid {
		t.Errorf("VerifyReportSignatureOnly = valid %v, %v; want ErrReportUnsigned", valid, err)
	}
	if got := attest.ErrReportUnsigned.Error(); got != "report is unsigned (no signature present)" {
		t.Errorf("the refusal reads %q; scripts match its words", got)
	}
}

func TestDecodeUnsignedReportReadsAReportWithNoSignatureMembers(t *testing.T) {
	report := unsignedTestReport()
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got, err := attest.DecodeUnsignedReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReportID != report.ReportID || got.PlanID != report.PlanID || got.Signature != "" {
		t.Errorf("decoded %+v", got)
	}
}

// A report with any signature member, valid or not, however little of a signature,
// is not an unsigned report, and the refusal names the member.
func TestDecodeUnsignedReportRefusesAnyReportThatCarriesASignatureMember(t *testing.T) {
	_, private := testKeys(t)
	signed := unsignedTestReport()
	if err := attesttest.SignReport(signed, private); err != nil {
		t.Fatal(err)
	}
	signedData, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attest.DecodeUnsignedReport(signedData); !errors.Is(err, attest.ErrReportSigned) {
		t.Errorf("a signed report: %v, want ErrReportSigned", err)
	}
	for _, member := range attest.UnsignedReportMembers() {
		for name, value := range map[string]string{"a value": `"x"`, "an empty string": `""`, "null": `null`} {
			var members map[string]json.RawMessage
			unsigned, _ := json.Marshal(unsignedTestReport())
			if err := json.Unmarshal(unsigned, &members); err != nil {
				t.Fatal(err)
			}
			members[member] = json.RawMessage(value)
			data, err := json.Marshal(members)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := attest.DecodeUnsignedReport(data); !errors.Is(err, attest.ErrReportSigned) || !strings.Contains(err.Error(), member) {
				t.Errorf("%s as %s: %v, want ErrReportSigned naming the member", member, name, err)
			}
		}
	}
}

// What a verifier checks of a document before it decodes any of it is checked
// here too.
func TestDecodeUnsignedReportHoldsTheReportToTheVerifiersLimits(t *testing.T) {
	for name, data := range map[string]string{
		"not JSON":                   `nonsense`,
		"a JSON array":               `[1,2]`,
		"a repeated member":          `{"report_id":"a","report_id":"b"}`,
		"an integer too large":       `{"rto_seconds":9007199254740993}`,
		"a member of the wrong type": `{"vm_records":"none"}`,
	} {
		if _, err := attest.DecodeUnsignedReport([]byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := attest.DecodeUnsignedReport(append([]byte(`{"x":"`), make([]byte, attest.MaxReportFileBytes+1)...)); err == nil {
		t.Error("a report over the size limit was accepted")
	}
}
