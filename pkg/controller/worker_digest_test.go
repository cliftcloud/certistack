// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	"github.com/google/uuid"
)

// Three build labels stamped into the executable are a build identity any
// binary can claim. The controller also signs the SHA-256 of the executable it
// uploaded to run as the worker, taken from the staged copy, so a report can be
// checked against the digest published for a release. A digest the caller
// supplies is replaced, and tampering with the recorded digest breaks the
// signature.
func TestSignedReportRecordsTheDigestOfTheUploadedWorker(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")
	t.Setenv("CERTISTACK_ALLOW_TEST_MODE", "1")

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0600); err != nil {
		t.Fatal(err)
	}
	absPlan, err := filepath.Abs(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	// The report a worker returns for this request, which the controller
	// checks against what it asked for before it signs.
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, RunOptions{PlanPath: absPlan, NodeName: "pve-01", SkipIntegrity: true})}}

	result, err := (&Executor{runner: fake}).Run(context.Background(), RunOptions{
		PlanPath:      absPlan,
		NodeName:      "pve-01",
		ScratchDir:    "/var/lib/certistack/scratch",
		StateDir:      "/var/lib/certistack",
		OutputDir:     t.TempDir(),
		Signer:        signer,
		SkipIntegrity: true,
		// A caller cannot choose what the report says was uploaded.
		Build: BuildInfo{Version: "controller-test", Commit: "abc123", BuildDate: "2026-09-17T00:00:00Z", ExecutableSHA256: strings.Repeat("f", 64)},
		SSH:   SSHConfig{Host: "pve.example", User: "root", Port: 22, KnownHostsFile: knownHosts},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	// The controller uploads its own executable, here the test binary.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	if result.Report.WorkerSHA256 != want {
		t.Fatalf("report worker_sha256 = %q, want the uploaded executable's %q", result.Report.WorkerSHA256, want)
	}

	reportJSON, err := json.Marshal(result.Report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reportJSON), `"worker_sha256":"`+want+`"`) {
		t.Fatalf("the signed JSON does not carry the digest: %s", reportJSON)
	}
	if _, valid, err := attest.VerifyReportSignatureOnly(reportJSON); err != nil || !valid {
		t.Fatalf("the report does not verify: valid=%v err=%v", valid, err)
	}
	tampered := strings.Replace(string(reportJSON), want, strings.Repeat("0", 64), 1)
	if _, valid, _ := attest.VerifyReportSignatureOnly([]byte(tampered)); valid {
		t.Fatal("a report whose recorded worker digest was changed still verifies: the digest is not signed")
	}
}

// prepareReport takes the digest from the build identity Run filled in, and
// an identity without one (a report signed outside a run) records none.
func TestPrepareReportRecordsOnlyAnExecutableDigestItWasGiven(t *testing.T) {
	output := t.TempDir()
	for _, digest := range []string{"", strings.Repeat("a", 64)} {
		report := &attest.Report{PlanID: "expected-plan", ReportID: uuid.NewString()}
		if _, err := prepareReport(report, "expected-plan", "", RunOptions{OutputDir: output, Build: BuildInfo{Version: "v1", ExecutableSHA256: digest}}); err != nil {
			t.Fatal(err)
		}
		if report.WorkerSHA256 != digest {
			t.Errorf("worker_sha256 = %q, want %q", report.WorkerSHA256, digest)
		}
	}
}
