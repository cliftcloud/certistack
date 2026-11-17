// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

func TestVerifyReportJSONSummary(t *testing.T) {
	publicKey, privateKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := attest.BuildReport(&config.Plan{PlanID: "verified-summary", Name: "Verified summary"}, "node-a", time.Second, false, []probe.VMValidationRecord{{
		VMID:               9001,
		VerificationStatus: "incomplete",
		AllPassed:          false,
		ProbeResults: []probe.Result{{
			Type:   "validation",
			Passed: false,
		}, {
			Type:    "qga",
			Passed:  false,
			Skipped: true,
		}},
	}}, "")
	report.ValidationMode = attest.ValidationModeTestSkipIntegrity
	report.TeardownEvidence = &attest.TeardownEvidence{AllCleaned: true}
	if err := attesttest.SignReport(report, privateKey); err != nil {
		t.Fatal(err)
	}

	reportData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(reportPath, reportData, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := verifyReportCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--format", "json", "--allow-test-mode", "--trusted-key", hex.EncodeToString(publicKey), reportPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify report: %v", err)
	}

	var summary reportVerificationSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatalf("decode JSON summary: %v; output=%q", err, output.String())
	}
	if !summary.SignatureValid || summary.PlanID != report.PlanID || summary.ValidationMode != attest.ValidationModeTestSkipIntegrity || summary.TrustSource != "trusted-key:inline" {
		t.Fatalf("unexpected verified summary: %+v", summary)
	}
	if summary.AllPassed || !summary.AllCleaned || summary.VMCount != 1 || summary.FailedProbeCount != 1 || summary.IncompleteVMCount != 1 {
		t.Fatalf("incorrect evidence counters: %+v", summary)
	}
}

func TestVerifyReportBlocksTestModeJSONByDefault(t *testing.T) {
	publicKey, privateKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := attest.BuildReport(&config.Plan{PlanID: "blocked-test-mode"}, "node-a", time.Second, true, nil, "")
	report.ValidationMode = attest.ValidationModeTestSkipIntegrity
	if err := attesttest.SignReport(report, privateKey); err != nil {
		t.Fatal(err)
	}
	reportData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(reportPath, reportData, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := verifyReportCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--format", "json", "--trusted-key", hex.EncodeToString(publicKey), reportPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("verify-report accepted a test-mode report without --allow-test-mode")
	}
	var summary reportVerificationSummary
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil {
		t.Fatalf("decode blocked JSON summary: %v; output=%q", err, output.String())
	}
	if summary.AllPassed {
		t.Fatalf("blocked test-mode summary reported all_passed=true: %+v", summary)
	}
}

func TestVerifyReportRejectsImplicitWorkingDirectoryKeyring(t *testing.T) {
	publicKey, privateKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := attest.BuildReport(&config.Plan{PlanID: "cwd-keyring", Name: "CWD keyring"}, "node-a", time.Second, true, nil, "")
	if err := attesttest.SignReport(report, privateKey); err != nil {
		t.Fatal(err)
	}
	reportData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	workingDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(workingDirectory, "keyring.json"), []byte(`{"trusted_signers":[{"name":"cwd","public_key":"`+hex.EncodeToString(publicKey)+`"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(workingDirectory, "report.json")
	if err := os.WriteFile(reportPath, reportData, 0600); err != nil {
		t.Fatal(err)
	}
	oldWorkingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workingDirectory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWorkingDirectory) })

	cmd := verifyReportCmd()
	cmd.SetArgs([]string{reportPath})
	if err := cmd.Execute(); err == nil {
		t.Fatal("verify-report trusted an implicit keyring from the current working directory")
	}
}

func TestVerifyReportJSONInvalidSignatureWritesStatusToStderr(t *testing.T) {
	publicKey, privateKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := attest.BuildReport(&config.Plan{PlanID: "invalid-json-status"}, "node-a", time.Second, true, nil, "")
	if err := attesttest.SignReport(report, privateKey); err != nil {
		t.Fatal(err)
	}
	reportData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	reportData = bytes.Replace(reportData, []byte("invalid-json-status"), []byte("changed-json-status"), 1)
	reportPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(reportPath, reportData, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := verifyReportCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--format", "json", "--trusted-key", hex.EncodeToString(publicKey), reportPath})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("verify-report accepted a tampered report")
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid JSON verification polluted stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "REPORT SIGNATURE INVALID OR TAMPERED") {
		t.Fatalf("invalid signature status was not sent to stderr: error=%v stderr=%q", err, stderr.String())
	}
}

func TestVerifyReportTextUsesInlineTrustSourceAndSanitizesReportText(t *testing.T) {
	publicKey, privateKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := attest.BuildReport(&config.Plan{PlanID: "text-output", Name: "host\x1b[31mname"}, "node-a", time.Second, true, nil, "")
	if err := attesttest.SignReport(report, privateKey); err != nil {
		t.Fatal(err)
	}
	reportData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(reportPath, reportData, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := verifyReportCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"--trusted-key", hex.EncodeToString(publicKey), reportPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify-report text output: %v", err)
	}
	if !strings.Contains(output.String(), "inline trusted public key") {
		t.Fatalf("text output did not identify inline trust source: %q", output.String())
	}
	if strings.Contains(output.String(), "\x1b") {
		t.Fatalf("text output contains terminal control characters: %q", output.String())
	}
}

func TestVerifyReportTextIdentifiesFileTrustSources(t *testing.T) {
	publicKey, privateKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := attest.BuildReport(&config.Plan{PlanID: "file-trust-sources"}, "node-a", time.Second, true, nil, "")
	if err := attesttest.SignReport(report, privateKey); err != nil {
		t.Fatal(err)
	}
	reportData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	tempDir := t.TempDir()
	reportPath := filepath.Join(tempDir, "report.json")
	if err := os.WriteFile(reportPath, reportData, 0600); err != nil {
		t.Fatal(err)
	}
	publicKeyPath := filepath.Join(tempDir, "trusted.pub")
	publicKeyHex := hex.EncodeToString(publicKey)
	if err := os.WriteFile(publicKeyPath, []byte(publicKeyHex), 0600); err != nil {
		t.Fatal(err)
	}
	keyringPath := filepath.Join(tempDir, "keyring.json")
	keyringData := []byte(`{"trusted_signers":[{"name":"reviewer","public_key":"` + publicKeyHex + `"}]}`)
	if err := os.WriteFile(keyringPath, keyringData, 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("public key file", func(t *testing.T) {
		cmd := verifyReportCmd()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetArgs([]string{"--public-key", publicKeyPath, reportPath})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("verify report with public-key file: %v", err)
		}
		if !strings.Contains(output.String(), "public-key file") {
			t.Fatalf("public-key trust source was not identified: %q", output.String())
		}
	})

	t.Run("keyring file", func(t *testing.T) {
		cmd := verifyReportCmd()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetArgs([]string{"--keyring", keyringPath, reportPath})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("verify report with keyring: %v", err)
		}
		if !strings.Contains(output.String(), "trusted keyring") || !strings.Contains(output.String(), "reviewer") {
			t.Fatalf("keyring trust source was not identified: %q", output.String())
		}
	})
}
