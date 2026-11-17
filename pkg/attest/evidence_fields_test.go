// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// The evidence fields of report schema 1.6 (and plan_sha256) are additive and
// omitempty: a report that carries none of them is what schema 1.5 wrote, and a
// report that carries them signs them.

var schema16Keys = []string{
	`"plan_sha256"`, `"cpu_weight"`, `"server_name"`, `"source_interface"`, `"source_address"`,
	`"require_qga"`, `"timeout_sec"`, `"retries"`, `"attempts"`, `"image_sha256"`,
}

const planDigest = "3b1c4fb0f6c1f6e19c5d2a9b7f6c1a8e2d4b6a0c9e8f7d6c5b4a39281706f5e4"

func reportWithEvidenceFields() *Report {
	report := BuildReport(&config.Plan{PlanID: "evidence-fields", Name: "Evidence fields"}, "node.example", 0, true, []probe.VMValidationRecord{{
		VMID: 9900, Name: "restore", VerificationStatus: "verified", AllPassed: true,
		RestoredHardware: &probe.RestoredHardware{Cores: 2, CPU: "host", CPUWeight: 500},
		ProbeResults: []probe.Result{
			{Type: "http", Target: "https://10.100.0.10:443/", Description: "web", Origin: "worker_host", ServerName: "app.example.com",
				SourceInterface: "csVn01", SourceAddress: "10.100.0.1", TimeoutSec: 20, Retries: 2, Attempts: 3, Passed: true},
			{Type: "qga", Target: "ping", Description: "agent", Origin: "guest_qga", RequireQGA: true, TimeoutSec: 30, Attempts: 1, Passed: true},
			{Type: "screendump", Target: "/var/run/qemu-server/9900.qmp", Description: "console", Origin: "hypervisor_qmp",
				ImageSHA256: strings.Repeat("ab", 32), TimeoutSec: 10, Attempts: 1, Passed: true},
		},
	}}, "")
	report.PlanSHA256 = planDigest
	return report
}

func signedBytes(t *testing.T, report *Report, key ed25519.PrivateKey) []byte {
	t.Helper()
	if err := report.SignReport(key); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSchema16ReportSchemaVersionIsTheOneThatAddsTheFields(t *testing.T) {
	// The fields are schema 1.6's; a later minor keeps them and says what it
	// adds in its own doc comment (see TestSchema17SoakIsTheMinorThatAddsIt).
	if minor, err := strconv.Atoi(strings.TrimPrefix(CurrentReportSchemaVersion, "1.")); err != nil || !strings.HasPrefix(CurrentReportSchemaVersion, "1.") || minor < 6 {
		t.Fatalf("CurrentReportSchemaVersion = %q; the evidence fields are schema 1.6, and the schema never goes back below it", CurrentReportSchemaVersion)
	}
	if got := reportWithEvidenceFields().ReportSchemaVersion; got != CurrentReportSchemaVersion {
		t.Fatalf("a built report says schema %q", got)
	}
}

// A report that records none of the new fields writes none of their keys, so
// it is byte-for-byte what schema 1.5 wrote for the same evidence.
func TestSchema16FieldsAreAbsentFromAReportThatHasNone(t *testing.T) {
	report := BuildReport(&config.Plan{PlanID: "p", Name: "n"}, "node.example", 0, true, []probe.VMValidationRecord{{
		VMID: 9900, VerificationStatus: "verified", AllPassed: true,
		RestoredHardware: &probe.RestoredHardware{Cores: 2, CPU: "host"},
		ProbeResults:     []probe.Result{{Type: "tcp", Target: "10.100.0.10:443", Description: "port", Origin: "worker_host", Passed: true}},
	}}, "")
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range schema16Keys {
		if bytes.Contains(data, []byte(key)) {
			t.Errorf("a report with none of the evidence fields writes %s: %s", key, data)
		}
	}
}

// The fields are signed: a report that carries them verifies, and changing
// any one of them, or dropping it, invalidates the signature. The same holds
// for a report without them, which still verifies as it did.
func TestSchema16FieldsAreCoveredByTheSignature(t *testing.T) {
	_, key, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signed := signedBytes(t, reportWithEvidenceFields(), key)
	for _, field := range schema16Keys {
		if !bytes.Contains(signed, []byte(field)) {
			t.Fatalf("the signed report does not carry %s: %s", field, signed)
		}
	}
	if verified, valid, err := VerifyReportSignatureOnly(signed); err != nil || !valid {
		t.Fatalf("report with the fields does not verify: valid=%v err=%v", valid, err)
	} else {
		results := verified.VMRecords[0].ProbeResults
		if verified.PlanSHA256 != planDigest || verified.VMRecords[0].RestoredHardware.CPUWeight != 500 ||
			results[0].ServerName != "app.example.com" || results[0].SourceAddress != "10.100.0.1" || results[0].Attempts != 3 ||
			!results[1].RequireQGA || results[2].ImageSHA256 != strings.Repeat("ab", 32) {
			t.Fatalf("the verified report lost a field: %+v", verified)
		}
	}
	for _, tamper := range []struct{ from, to string }{
		{`"plan_sha256": "` + planDigest + `"`, `"plan_sha256": "` + strings.Repeat("0", 64) + `"`},
		{`"cpu_weight": 500`, `"cpu_weight": 50`},
		{`"server_name": "app.example.com"`, `"server_name": "other.example.com"`},
		{`"source_address": "10.100.0.1"`, `"source_address": "10.100.0.2"`},
		{`"source_interface": "csVn01"`, `"source_interface": "csVn02"`},
		{`"require_qga": true`, `"require_qga": false`},
		{`"timeout_sec": 20`, `"timeout_sec": 200`},
		{`"retries": 2`, `"retries": 3`},
		{`"attempts": 3`, `"attempts": 1`},
		{`"image_sha256": "` + strings.Repeat("ab", 32) + `"`, `"image_sha256": "` + strings.Repeat("cd", 32) + `"`},
	} {
		if !bytes.Contains(signed, []byte(tamper.from)) {
			t.Fatalf("test bug: %s is not in the report", tamper.from)
		}
		if _, _, err := VerifyReportSignatureOnly(bytes.Replace(signed, []byte(tamper.from), []byte(tamper.to), 1)); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("changing %s: err = %v, want an invalid signature", tamper.from, err)
		}
	}
	// Removing a field is a change too.
	stripped := bytes.Replace(signed, []byte(`"plan_sha256": "`+planDigest+`",`), nil, 1)
	if _, _, err := VerifyReportSignatureOnly(stripped); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("removing plan_sha256: err = %v, want an invalid signature", err)
	}

	// A report without any of the fields, as an older CertiStack wrote it,
	// signs and verifies as before.
	old := BuildReport(&config.Plan{PlanID: "p", Name: "n"}, "node.example", 0, true, []probe.VMValidationRecord{{
		VMID: 9900, VerificationStatus: "verified", AllPassed: true,
		ProbeResults: []probe.Result{{Type: "tcp", Target: "10.100.0.10:443", Description: "port", Passed: true}},
	}}, "")
	old.ReportSchemaVersion = "1.5"
	if _, valid, err := VerifyReportSignatureOnly(signedBytes(t, old, key)); err != nil || !valid {
		t.Fatalf("a schema 1.5 report does not verify: valid=%v err=%v", valid, err)
	}
}

// Canonicalization keeps every field: the canonical form of the report holds
// the new members, is deterministic, and does not depend on the order or
// spacing of the members as written.
func TestSchema16CanonicalFormIsDeterministicAndKeepsTheFields(t *testing.T) {
	_, key, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signed := signedBytes(t, reportWithEvidenceFields(), key)
	canonical, err := CanonicalizeReportJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range schema16Keys {
		if !bytes.Contains(canonical, []byte(field)) {
			t.Errorf("the canonical form dropped %s", field)
		}
	}
	var generic map[string]any
	if err := json.Unmarshal(signed, &generic); err != nil {
		t.Fatal(err)
	}
	compact, err := json.Marshal(generic) // a different member order and spacing
	if err != nil {
		t.Fatal(err)
	}
	again, err := CanonicalizeReportJSON(compact)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, again) {
		t.Fatal("the canonical form depends on member order or spacing")
	}
	if _, valid, err := VerifyReportSignatureOnly(compact); err != nil || !valid {
		t.Fatalf("the re-encoded report does not verify: valid=%v err=%v", valid, err)
	}
}
