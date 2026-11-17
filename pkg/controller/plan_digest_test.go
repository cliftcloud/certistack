// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// The controller records the SHA-256 of the plan file it read in the report it
// signs (plan_sha256), so verify-report --expect-plan can bind the report to
// those exact bytes. The digest is the controller's own: a worker report that
// carries another one has it replaced, and it is inside the signature.
func TestExecutorRunSignsTheDigestOfThePlanFileItRead(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	t.Setenv("CERTISTACK_ALLOW_TEST_MODE", "1")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	planFile := filepath.Join(t.TempDir(), "plan.yaml")
	// Bytes the loader ignores (a comment) still belong to the file: the digest
	// is of the file as it lies on disk.
	planBytes := append(append([]byte(nil), original...), []byte("\n# approved by change 1234\n")...)
	if err := os.WriteFile(planFile, planBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(planBytes)
	want := hex.EncodeToString(sum[:])

	signer := testSigner(t)
	opts := RunOptions{
		PlanPath: planFile, NodeName: "pve-01", ScratchDir: "/var/lib/certistack/scratch", StateDir: "/var/lib/certistack",
		OutputDir: t.TempDir(), Signer: signer, SkipIntegrity: true, Writer: &bytes.Buffer{},
		Build: BuildInfo{Version: "controller-test", Commit: "abc123", BuildDate: "2026-09-17T00:00:00Z"},
		SSH:   SSHConfig{Host: "pve.example", User: "root", Port: 22, KnownHostsFile: knownHosts},
	}
	report := workerReportFor(t, opts)
	report.PlanSHA256 = strings.Repeat("f", 64) // a worker's claim, never the controller's
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Report.PlanSHA256 != want {
		t.Fatalf("report plan_sha256 = %q, want the digest %s of the plan file", result.Report.PlanSHA256, want)
	}
	data, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, valid, err := attest.VerifyReportSignatureOnly(data)
	if err != nil || !valid {
		t.Fatalf("the saved report does not verify: valid=%v err=%v", valid, err)
	}
	if verified.PlanSHA256 != want {
		t.Fatalf("the signed report's plan_sha256 = %q, want %s", verified.PlanSHA256, want)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil || raw["plan_sha256"] != want {
		t.Fatalf("the saved JSON's plan_sha256 = %v (%v)", raw["plan_sha256"], err)
	}
}

// prepareReport takes the digest the caller gives it, whatever the worker
// wrote, and a run with no digest (none was read) leaves the field out.
func TestPrepareReportSetsThePlanDigestBeforeSigning(t *testing.T) {
	_, key, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("ab", 32)
	for name, given := range map[string]string{"a digest": digest, "no digest": ""} {
		report := &attest.Report{PlanID: "p", ReportID: "00000000-0000-4000-8000-000000000001", PlanSHA256: strings.Repeat("f", 64)}
		if _, err := prepareReport(report, "p", given, RunOptions{OutputDir: t.TempDir(), Signer: attesttest.NewSigner(key)}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if report.PlanSHA256 != given {
			t.Errorf("%s: plan_sha256 = %q", name, report.PlanSHA256)
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if _, valid, err := attest.VerifyReportSignatureOnly(data); err != nil || !valid {
			t.Errorf("%s: the signature does not cover the final report: valid=%v err=%v", name, valid, err)
		}
	}
}
