// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"

	"github.com/cliftcloud/certistack/pkg/probe"
)

func TestSignAndVerify_Roundtrip(t *testing.T) {
	_, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plan := &config.Plan{
		PlanID: "acme-erp-dr",
		Name:   "ACME ERP Test",
		Storage: config.Storage{
			PBSFingerprint: "SHA256:trusted-pbs",
			PBSNamespace:   "acme",
		},
		Compliance: config.Compliance{
			Frameworks:    []string{"DORA-Article-12", "SOC2-Type2-CC7.4"},
			RetentionDays: 365,
		},
	}

	vmRecords := []probe.VMValidationRecord{
		{
			VMID:         9001,
			Name:         "dc01",
			BootDuration: 12 * time.Second,
			AllPassed:    true,
			ProbeResults: []probe.Result{
				{
					Type:        "tcp",
					Target:      "10.100.0.10:389",
					Description: "LDAP port",
					Passed:      true,
					Duration:    5 * time.Millisecond,
				},
			},
		},
	}

	report := BuildReport(plan, "pve1.infra.local", 25*time.Second, true, vmRecords, "")

	if err := report.SignReport(privKey); err != nil {
		t.Fatalf("SignReport failed: %v", err)
	}

	if report.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
	if report.PublicKey == "" {
		t.Fatal("expected non-empty public key")
	}

	// Serialize to JSON and verify
	reportJSON, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report failed: %v", err)
	}

	verifiedReport, valid, err := VerifyReportSignatureOnly(reportJSON)
	if err != nil {
		t.Fatalf("VerifyReport error: %v", err)
	}
	if !valid {
		t.Fatal("expected report signature to be valid, got false")
	}
	if verifiedReport.PlanID != "acme-erp-dr" {
		t.Errorf("expected plan_id 'acme-erp-dr', got %s", verifiedReport.PlanID)
	}
	if verifiedReport.PBSFingerprint != "SHA256:trusted-pbs" || verifiedReport.PBSNamespace != "acme" {
		t.Fatalf("report PBS identity = %q/%q, want %q/%q", verifiedReport.PBSFingerprint, verifiedReport.PBSNamespace, "SHA256:trusted-pbs", "acme")
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	_, privKey, _ := GenerateKeyPair()

	plan := &config.Plan{
		PlanID: "tamper-test",
		Name:   "Tamper Test",
		Compliance: config.Compliance{
			Frameworks: []string{"HIPAA-164.308-A7"},
		},
	}

	report := BuildReport(plan, "node1", 10*time.Second, false, nil, "")
	_ = report.SignReport(privKey)

	// Tamper with the report by modifying AllPassed from false to true
	tamperedJSON, _ := json.Marshal(report)
	var tamperedMap map[string]interface{}
	_ = json.Unmarshal(tamperedJSON, &tamperedMap)
	tamperedMap["all_passed"] = true // Malicious modification
	tamperedBytes, _ := json.Marshal(tamperedMap)

	_, valid, err := VerifyReportSignatureOnly(tamperedBytes)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if valid {
		t.Fatal("expected tampered report signature to fail verification, but it passed!")
	}
}

// RFC 8785 canonicalization keeps the last of a duplicated member, but
// encoding/json merges a duplicated array of objects element by element. A
// prepended duplicate could therefore leave the signature valid while the
// verified struct gains skipped:true on a failed probe; it is refused.
func TestVerify_DuplicateKeysCannotAlterVerifiedResult(t *testing.T) {
	_, privKey, _ := GenerateKeyPair()
	plan := &config.Plan{PlanID: "duplicate-test", Name: "Duplicate Test"}
	report := BuildReport(plan, "node1", 10*time.Second, false, []probe.VMValidationRecord{{
		VMID: 9001,
		Name: "web01",
		ProbeResults: []probe.Result{
			{Type: "http", Target: "http://10.0.0.1:80/", Passed: false, Error: "HTTP probe failed"},
		},
	}}, "")
	if err := report.SignReport(privKey); err != nil {
		t.Fatal(err)
	}
	signed, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}

	for name, tamper := range map[string]func(string) string{
		"prepended probe_results": func(s string) string {
			return strings.Replace(s, `"probe_results":[`, `"probe_results":[{"skipped":true}],"probe_results":[`, 1)
		},
		"prepended vm_records": func(s string) string {
			return strings.Replace(s, `"vm_records":[`, `"vm_records":[{"probe_results":[{"skipped":true}]}],"vm_records":[`, 1)
		},
		"duplicate signature": func(s string) string {
			return strings.Replace(s, `"signature":`, `"signature":"00","signature":`, 1)
		},
	} {
		tampered := tamper(string(signed))
		if tampered == string(signed) {
			t.Fatalf("%s: tamper pattern did not apply", name)
		}
		verified, valid, err := VerifyReportSignatureOnly([]byte(tampered))
		if err == nil || valid || !strings.Contains(err.Error(), "duplicate JSON object key") {
			t.Fatalf("%s: VerifyReport = valid %v, err %v; want a duplicate-key rejection", name, valid, err)
		}
		if verified != nil {
			t.Fatalf("%s: VerifyReport returned a report for rejected input", name)
		}
	}

	verified, valid, err := VerifyReportSignatureOnly(signed)
	if err != nil || !valid {
		t.Fatalf("untampered report: valid %v, err %v", valid, err)
	}
	if got := verified.VMRecords[0].ProbeResults[0]; got.Skipped || got.Passed {
		t.Fatalf("verified probe = %+v, want the signed failed, unskipped probe", got)
	}
	if verified.Signature != report.Signature || verified.PublicKey != report.PublicKey || verified.SignerFingerprint != report.SignerFingerprint {
		t.Fatal("verified report lost its signature fields")
	}
}

func TestCheckReportDocumentRejectsDuplicateKeys(t *testing.T) {
	for input, wantErr := range map[string]bool{
		`{"a":1,"b":{"a":1}}`:           false,
		`{"a":[{"x":1},{"x":2}]}`:       false,
		`{"a":1,"a":1}`:                 true,
		`{"a":{"b":1,"b":2}}`:           true,
		`{"a":[{"x":1,"x":1}]}`:         true,
		`{"a":[[{"deep":1,"deep":2}]]}`: true,
		`{"a":1} {"a":2}`:               true,
	} {
		if err := checkReportDocument([]byte(input)); (err != nil) != wantErr {
			t.Errorf("checkReportDocument(%s) = %v, want error %v", input, err, wantErr)
		}
	}
}

func TestCanonicalization_Determinism(t *testing.T) {
	data1 := map[string]interface{}{
		"z": 1,
		"a": "hello",
		"m": []int{3, 2, 1},
	}
	data2 := map[string]interface{}{
		"a": "hello",
		"m": []int{3, 2, 1},
		"z": 1,
	}

	b1, err := Canonicalize(data1)
	if err != nil {
		t.Fatalf("Canonicalize data1 failed: %v", err)
	}

	b2, err := Canonicalize(data2)
	if err != nil {
		t.Fatalf("Canonicalize data2 failed: %v", err)
	}

	if !bytes.Equal(b1, b2) {
		t.Errorf("expected identical canonical bytes, got:\n1: %s\n2: %s", string(b1), string(b2))
	}
}

func TestReportSaveRefusesOverwriteWithoutForce(t *testing.T) {
	report := BuildReport(&config.Plan{PlanID: "overwrite-json"}, "node1", time.Second, true, nil, "")
	outPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(outPath, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := report.Save(outPath); err == nil {
		t.Fatal("Report.Save overwrote an existing report without force")
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "sentinel" {
		t.Fatalf("refused overwrite changed existing report: %q", data)
	}
	if err := report.SaveWithForce(outPath, true); err != nil {
		t.Fatalf("Report.SaveWithForce failed: %v", err)
	}
}

func TestVerify_TrustedKeyring(t *testing.T) {
	pubA, privA, _ := GenerateKeyPair()
	_, privAttacker, _ := GenerateKeyPair()

	plan := &config.Plan{PlanID: "keyring-test"}
	reportValid := BuildReport(plan, "node1", 5*time.Second, true, nil, "")
	_ = reportValid.SignReport(privA)
	validJSON, _ := json.Marshal(reportValid)

	reportAttacker := BuildReport(plan, "node1", 5*time.Second, true, nil, "")
	_ = reportAttacker.SignReport(privAttacker)
	attackerJSON, _ := json.Marshal(reportAttacker)

	trustedRing := []ed25519.PublicKey{pubA}

	// 1. Authorized signer succeeds
	_, valid, err := VerifyReport(validJSON, trustedRing)
	if err != nil || !valid {
		t.Fatalf("expected authorized report to pass verification, got err=%v, valid=%v", err, valid)
	}

	// 2. Attacker-signed report fails because signer key is not in trusted keyring
	_, valid, err = VerifyReport(attackerJSON, trustedRing)
	if err == nil || valid {
		t.Fatalf("expected attacker-signed report to be rejected by trusted keyring, got err=%v, valid=%v", err, valid)
	}
}

func TestReportKeepsSourceChunkHashesThroughSigning(t *testing.T) {
	_, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plan := &config.Plan{
		PlanID: "chunk-hash-report",
		Name:   "Chunk hash report",
		Compliance: config.Compliance{
			Frameworks:    []string{"DORA-Article-12", "SOC2-Type2-CC7.4", "HIPAA-164.308"},
			RetentionDays: 365,
		},
	}

	vmRecords := []probe.VMValidationRecord{
		{
			VMID:                9100,
			Name:                "postgres-primary",
			BootDuration:        14 * time.Second,
			BootDurationSeconds: 14.0,
			SourceSnapshot:      "vm/100/2026-09-14T02:00:00Z",
			SourceDrive:         "drive-scsi0.img.fidx",
			SourceChunkHashes: []string{
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
			},
			PBSVerifyStatus: "verified (0 chunk modifications, 0 checksum mismatches)",
			AllPassed:       true,
			ProbeResults: []probe.Result{
				{
					Type:        "tcp",
					Target:      "10.200.0.10:5432",
					Description: "PostgreSQL listener",
					Passed:      true,
					Duration:    4 * time.Millisecond,
				},
			},
		},
	}

	report := BuildReport(plan, "pve-node-01.infra.local", 28*time.Second, true, vmRecords, "")
	if err := report.SignReport(privKey); err != nil {
		t.Fatalf("SignReport failed: %v", err)
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	verified, valid, err := VerifyReportSignatureOnly(data)
	if err != nil || !valid {
		t.Fatalf("verify failed: err=%v, valid=%v", err, valid)
	}

	if len(verified.VMRecords) != 1 {
		t.Fatalf("expected 1 VM record, got %d", len(verified.VMRecords))
	}

	vm := verified.VMRecords[0]
	if len(vm.SourceChunkHashes) != 2 {
		t.Errorf("expected 2 chunk hashes, got %d", len(vm.SourceChunkHashes))
	}
	if vm.BootDurationSeconds != 14.0 {
		t.Errorf("expected boot duration 14.0, got %.2f", vm.BootDurationSeconds)
	}
	if vm.PBSVerifyStatus != "verified (0 chunk modifications, 0 checksum mismatches)" {
		t.Errorf("unexpected pbs verify status: %s", vm.PBSVerifyStatus)
	}
}

func TestKeyring_JSON_And_Fingerprint(t *testing.T) {
	keyHex := "9225debfa3c6555722d4d74c8ccdab065817e8fb373f05b92b28da5f0b0cd779"
	fp := FingerprintFromHex(keyHex)
	t.Logf("Computed fingerprint for key %s: %s", keyHex, fp)
	if fp == "" || !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("expected valid SHA-256 fingerprint, got %s", fp)
	}

	keyringJSON := fmt.Sprintf(`{
  "trusted_signers": [
    {
      "name": "pve-node-01 Automation Key",
      "public_key": "%s",
      "node": "pve-node-01"
    }
  ]
}`, keyHex)

	tmpKeyring := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(tmpKeyring, []byte(keyringJSON), 0644); err != nil {
		t.Fatalf("failed to write temp keyring: %v", err)
	}

	kr, err := LoadKeyringFile(tmpKeyring)
	if err != nil {
		t.Fatalf("LoadKeyringFile failed: %v", err)
	}

	if len(kr.TrustedSigners) != 1 {
		t.Fatalf("expected 1 trusted signer, got %d", len(kr.TrustedSigners))
	}

	signer := kr.FindSigner(keyHex)
	if signer == nil {
		t.Fatalf("signer not found in keyring")
	}

	if signer.Fingerprint != fp {
		t.Errorf("expected auto-populated fingerprint %s, got %s", fp, signer.Fingerprint)
	}
}

func TestReport_SchemaVersion(t *testing.T) {
	_, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plan := &config.Plan{PlanID: "schema-version-test", Name: "Schema Test"}
	rep := BuildReport(plan, "testnode.local", 15*time.Second, true, nil, "")
	if rep.ReportSchemaVersion != CurrentReportSchemaVersion {
		t.Fatalf("expected schema version %q, got %q", CurrentReportSchemaVersion, rep.ReportSchemaVersion)
	}
	if rep.ValidationMode != ValidationModeFullIntegrity {
		t.Fatalf("expected default validation mode %q, got %q", ValidationModeFullIntegrity, rep.ValidationMode)
	}

	if err := rep.SignReport(privKey); err != nil {
		t.Fatalf("SignReport failed: %v", err)
	}

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Verify "report_schema_version" is present in JSON
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		t.Fatalf("unmarshal map failed: %v", err)
	}
	if rawMap["report_schema_version"] != CurrentReportSchemaVersion {
		t.Errorf("expected JSON report_schema_version %q, got %v", CurrentReportSchemaVersion, rawMap["report_schema_version"])
	}

	verified, valid, err := VerifyReportSignatureOnly(data)
	if err != nil || !valid {
		t.Fatalf("VerifyReport failed: err=%v, valid=%v", err, valid)
	}
	if verified.ReportSchemaVersion != CurrentReportSchemaVersion {
		t.Errorf("expected verified schema version %q, got %q", CurrentReportSchemaVersion, verified.ReportSchemaVersion)
	}
}

func TestReport_ForwardCompatibility_FutureFields(t *testing.T) {
	_, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plan := &config.Plan{PlanID: "future-field-test", Name: "Future Fields"}
	rep := BuildReport(plan, "node1", 10*time.Second, true, nil, "")

	repJSON, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Simulate a future generator by adding fields unknown to the current struct
	var futureMap map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(repJSON))
	dec.UseNumber()
	if err := dec.Decode(&futureMap); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	futureMap["cluster_id"] = "proxmox-cl-east-01"
	futureMap["custom_metric"] = 12345.678
	futureMap["extra_tags"] = []interface{}{"critical", "tier1"}

	// Canonicalize and sign the future payload
	futureBytesWithoutSig, err := json.Marshal(futureMap)
	if err != nil {
		t.Fatalf("marshal future map failed: %v", err)
	}
	canonicalBytes, err := CanonicalizeReportJSON(futureBytesWithoutSig)
	if err != nil {
		t.Fatalf("canonicalize failed: %v", err)
	}

	sigHex := SignCanonical(canonicalBytes, privKey)
	pubKey := privKey.Public().(ed25519.PublicKey)
	futureMap["public_key"] = hex.EncodeToString(pubKey)
	futureMap["signer_fingerprint"] = Fingerprint(pubKey)
	futureMap["signature"] = sigHex

	fullFutureReportJSON, err := json.MarshalIndent(futureMap, "", "  ")
	if err != nil {
		t.Fatalf("marshal full future report failed: %v", err)
	}

	// The shipped VerifyReport must verify this report even though it has unknown fields!
	verified, valid, err := VerifyReportSignatureOnly(fullFutureReportJSON)
	if err != nil {
		t.Fatalf("expected future report to verify without error, got: %v", err)
	}
	if !valid {
		t.Fatal("expected future report signature to be valid, got false")
	}
	if verified.PlanID != "future-field-test" {
		t.Errorf("expected plan_id 'future-field-test', got %q", verified.PlanID)
	}
}

func TestReport_FutureField_TamperResistance(t *testing.T) {
	_, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plan := &config.Plan{PlanID: "tamper-future-test"}
	rep := BuildReport(plan, "node1", 5*time.Second, true, nil, "")
	if err := rep.SignReport(privKey); err != nil {
		t.Fatalf("SignReport failed: %v", err)
	}

	repJSON, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Tamper: Inject an unauthorized field into an already-signed report
	var tamperedMap map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(repJSON))
	dec.UseNumber()
	_ = dec.Decode(&tamperedMap)
	tamperedMap["injected_future_field"] = "malicious_payload"

	tamperedBytes, err := json.Marshal(tamperedMap)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	_, valid, err := VerifyReportSignatureOnly(tamperedBytes)
	if valid {
		t.Fatal("expected report with injected field to fail verification, but it passed!")
	}
}

func TestReport_VerifyRejectsMismatchedSignerFingerprint(t *testing.T) {
	_, privateKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := BuildReport(&config.Plan{PlanID: "fingerprint-test"}, "node1", time.Second, true, nil, "")
	if err := report.SignReport(privateKey); err != nil {
		t.Fatal(err)
	}
	report.SignerFingerprint = "forged fingerprint"
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := VerifyReportSignatureOnly(data); err == nil || valid {
		t.Fatalf("mismatched fingerprint verified: valid=%v err=%v", valid, err)
	}
}

func TestReport_VerifyExistingReportsOnDisk(t *testing.T) {
	candidates := []string{
		filepath.Join("..", "..", "reports", "39cb25a3-e318-40f4-9933-63a136ff9d73.json"),
		filepath.Join("..", "..", "reports", "smoke-7011", "6b7ca127-243f-4e63-bcf5-b4ec9a260b7a.json"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("skipping %s (not found on disk: %v)", path, err)
			continue
		}

		rep, valid, err := VerifyReportSignatureOnly(data)
		if err != nil {
			t.Errorf("failed to verify %s: %v", path, err)
			continue
		}
		if !valid {
			t.Errorf("signature invalid for %s", path)
		}
		if rep == nil || rep.ReportID == "" {
			t.Errorf("nil or empty report for %s", path)
		}
	}
}
