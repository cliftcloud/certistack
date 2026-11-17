// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
)

// planWithSigningKeyPath is opts.PlanPath's plan with its sign_key_path
// replaced by path, or left out when path is empty, written to a new file.
func planWithSigningKeyPath(t *testing.T, opts RunOptions, path string) string {
	t.Helper()
	data, err := os.ReadFile(opts.PlanPath)
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`(?m)^( *)sign_key_path:.*\n`)
	if !line.Match(data) {
		t.Fatal("the fixture has no sign_key_path to replace")
	}
	replacement := ""
	if path != "" {
		replacement = "${1}sign_key_path: " + strconv.Quote(path) + "\n"
	}
	out := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(out, line.ReplaceAll(data, []byte(replacement)), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

func savedReportMembers(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatal(err)
	}
	return members
}

// Without a Signer, as in the Community Edition, the controller saves the
// worker's report unsigned, after every check it makes of it all the same: the
// report is bound to the plan file the controller read (plan_sha256) and to the
// executable it uploaded, carries the controller's build, and its cleanup is
// what the controller verified from the node's journal.
func TestRunWithoutASignerSavesAnUnsignedReportThatIsStillChecked(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	opts.Signer = nil
	opts.Build = BuildInfo{Version: "controller-test", Commit: "abc123", BuildDate: "2026-09-17T00:00:00Z"}
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("an unsigned run failed: %v", err)
	}
	if result == nil || result.ReportPath == "" || result.Report == nil {
		t.Fatalf("result = %+v, want a saved report", result)
	}
	if result.Report.Signature != "" || result.Report.PublicKey != "" || result.Report.SignerFingerprint != "" {
		t.Fatalf("the returned report is signed: %+v", result.Report)
	}
	members := savedReportMembers(t, result.ReportPath)
	for _, member := range attest.UnsignedReportMembers() {
		if _, present := members[member]; present {
			t.Errorf("the saved report has a %q member", member)
		}
	}
	// The checks and the controller's own evidence are the same as a signed run's.
	plan, digest, err := config.LoadFromFileWithDigest(opts.PlanPath)
	if err != nil || plan == nil {
		t.Fatal(err)
	}
	report := result.Report
	if report.PlanSHA256 != digest || report.EngineVersion != "controller-test" || report.GitCommit != "abc123" || report.WorkerSHA256 == "" {
		t.Errorf("the controller's evidence is missing: plan_sha256 %q (want %s), engine %q, commit %q, worker %q", report.PlanSHA256, digest, report.EngineVersion, report.GitCommit, report.WorkerSHA256)
	}
	if evidence := report.TeardownEvidence; evidence == nil || !evidence.AllCleaned || !evidence.JournalRecoveryVerified {
		t.Errorf("teardown evidence = %+v, want cleanup verified from the node's journal", evidence)
	}
}

// The controller's checks are not signing, and an unsigned run keeps them: a
// worker report that is of another plan, or that leaves out a VM the plan
// restores, is refused whether or not there is a Signer, and nothing is saved.
func TestRunRefusesAWorkerReportWithOrWithoutASigner(t *testing.T) {
	for _, withSigner := range []bool{false, true} {
		for name, damage := range map[string]func(*attest.Report){
			"another plan's report":            func(r *attest.Report) { r.PlanID = "someone-elses-plan" },
			"a report that lacks a planned VM": func(r *attest.Report) { r.VMRecords = nil },
		} {
			opts := completedWorkerTeardownOptions(t)
			if !withSigner {
				opts.Signer = nil
			}
			report := workerReportFor(t, opts)
			damage(report)
			var progress bytes.Buffer
			opts.Writer = &progress
			fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}
			result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil || (result != nil && result.ReportPath != "") {
				t.Errorf("%s, signer %v: the report was accepted: result %+v, err %v", name, withSigner, result, err)
				continue
			}
			if !strings.Contains(progress.String(), "no report was written") {
				t.Errorf("%s, signer %v: the operator is not told that nothing was written:\n%s", name, withSigner, progress.String())
			}
			if reports, _ := filepath.Glob(filepath.Join(opts.OutputDir, "*", "*.json")); len(reports) != 0 {
				t.Errorf("%s, signer %v: a report was saved: %v", name, withSigner, reports)
			}
		}
	}
}

// compliance.sign_key_path is the Enterprise Edition's field. The controller
// reads no key: a plan that names none, a placeholder that does not exist, or a
// file that does, all give the same unsigned report, and none stops the run.
func TestRunIgnoresThePlansSigningKeyPath(t *testing.T) {
	base := completedWorkerTeardownOptions(t)
	for name, planKey := range map[string]string{
		"the plan names no key":                            "",
		"the plan names a placeholder that does not exist": "/nonexistent/placeholder.ed25519",
		"the plan names a file that is not a key":          base.PlanPath,
	} {
		opts := base
		opts.Signer = nil
		opts.PlanPath = planWithSigningKeyPath(t, base, planKey)
		opts.OutputDir = t.TempDir()
		// The worker's report is of the unmodified plan: only sign_key_path differs.
		fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, base)}, journalPhase: "cleaned"}
		result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
		if err != nil || result == nil || result.ReportPath == "" {
			t.Errorf("%s: the run failed: %v (result %+v)", name, err, result)
			continue
		}
		if len(fake.calls) == 0 || result.Report.Signature != "" {
			t.Errorf("%s: calls %d, signature %q", name, len(fake.calls), result.Report.Signature)
		}
	}
}

// The preview needs no key either.
func TestPlanNeedsNoSigningKey(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	opts.Signer = nil
	opts.PlanPath = planWithSigningKeyPath(t, opts, "")
	opts.OutputDir = ""
	fake := &fakeCommandRunner{nodePlanOutput: `{"plan_id":"acme-erp-full-stack-dr","node":"pve-01","steps":[]}`}
	if _, err := (&Executor{runner: fake}).Plan(context.Background(), opts); err != nil || len(fake.calls) == 0 {
		t.Fatalf("a plan without a signing key: %v (calls %d)", err, len(fake.calls))
	}
}

// With a Signer the controller calls it exactly once, after its checks and
// before the report is saved; the saved report is the one it signed and
// verifies under the Signer's key, with the plan binding inside the signature.
func TestRunCallsTheSignerOnceAndSavesTheReportItSigned(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	signer := opts.Signer.(*attesttest.Signer)
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Calls() != 1 {
		t.Fatalf("the Signer was called %d times, want once", signer.Calls())
	}
	saved, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, valid, err := attest.VerifyReport(saved, []ed25519.PublicKey{signer.Public()})
	if err != nil || !valid {
		t.Fatalf("the saved report does not verify under the Signer's key: valid=%v err=%v", valid, err)
	}
	if verified.PlanSHA256 == "" || verified.PlanSHA256 != result.Report.PlanSHA256 {
		t.Errorf("the signature does not cover the plan binding: %q", verified.PlanSHA256)
	}
}

// A Signer that fails fails the run closed: no unsigned report is written in its
// place, the operator is told so, and the worker's raw result is kept for
// diagnosis. The node was cleaned up before the signing, so the workspace goes.
func TestRunFailsClosedWhenTheSignerFails(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	sentinel := errors.New("the signing service is down")
	signer := attesttest.NewFailingSigner(sentinel)
	opts.Signer = signer
	var progress bytes.Buffer
	opts.Writer = &progress
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "sign controller report") {
		t.Fatalf("err = %v, want the failure to sign, with its cause", err)
	}
	if result != nil {
		t.Errorf("a result was returned: %+v", result)
	}
	if signer.Calls() != 1 {
		t.Errorf("the Signer was called %d times, want once", signer.Calls())
	}
	if reports, _ := filepath.Glob(filepath.Join(opts.OutputDir, "*", "*.json")); len(reports) != 0 {
		t.Errorf("an unsigned report was written in place of the signed one: %v", reports)
	}
	for _, want := range []string{"The report could not be signed, so none was written", "the signing service is down", "is kept at"} {
		if !strings.Contains(progress.String(), want) {
			t.Errorf("the operator was not told %q:\n%s", want, progress.String())
		}
	}
	kept, _ := filepath.Glob(filepath.Join(opts.OutputDir, "refused", "*"))
	if len(kept) != 1 {
		t.Fatalf("the worker's raw result was not kept: %v", kept)
	}
	// The result passed every check of the controller; it is the
	// signer that failed. The kept file's first line says that, not that the
	// result "failed the controller's checks".
	text, err := os.ReadFile(kept[0])
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(text), "\n")
	if first != attest.UnsignedResultBanner {
		t.Errorf("the kept file starts with %q, want %q", first, attest.UnsignedResultBanner)
	}
	if strings.Contains(first, "failed the controller's checks") {
		t.Errorf("the banner says the result failed the controller's checks, which is not what happened: %q", first)
	}
	if !strings.Contains(string(text), "Reason: sign controller report: the signing service is down") {
		t.Errorf("the kept file does not carry the real reason:\n%.300s", text)
	}
	if !strings.Contains(progress.String(), "passed the controller's checks") {
		t.Errorf("the operator was not told that the result passed the checks and the signing failed:\n%s", progress.String())
	}
}

// A signer that returns without signing is no signer: the controller refuses to
// write what would pass for a signed report.
func TestRunRefusesASignerThatDoesNotSign(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	opts.Signer = noopSigner{}
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleaned"}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "returned without signing") {
		t.Fatalf("err = %v, want the signer's silence refused", err)
	}
}

type noopSigner struct{}

func (noopSigner) SignReport(*attest.Report) error { return nil }

// The same failure to save, with no Signer: the unsaved report is the unsigned
// one the controller checked, printed whole between the markers, and the
// operator is told to read it and to judge it as unsigned.
func TestRunKeepsAnUnsignedReportRecoverableWhenSaveFails(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	opts.Signer = nil
	var progress bytes.Buffer
	opts.Writer = &progress
	report := workerReportFor(t, opts)
	planDir := filepath.Join(opts.OutputDir, report.PlanID)
	fake := &fakeCommandRunner{
		nodeResult:   nodeapi.RunResult{Report: report},
		journalPhase: "cleaned",
		nodeRunHook: func() {
			if err := os.RemoveAll(planDir); err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(planDir, nil, 0o600); err != nil {
				t.Error(err)
			}
		},
	}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "save controller report") {
		t.Fatalf("Run error = %v, want the save failure", err)
	}
	if result == nil || result.Report == nil || result.Report.Signature != "" || result.ReportPath != "" {
		t.Fatalf("Run result = %+v, want the unsigned, unsaved report", result)
	}
	text := progress.String()
	begin := strings.Index(text, "-----BEGIN CERTISTACK REPORT-----\n")
	end := strings.Index(text, "\n-----END CERTISTACK REPORT-----")
	if begin < 0 || end < begin {
		t.Fatalf("progress did not carry the unsaved report between markers:\n%s", text)
	}
	printed := text[begin+len("-----BEGIN CERTISTACK REPORT-----\n") : end]
	decoded, err := attest.DecodeUnsignedReport([]byte(printed))
	if err != nil || decoded.ReportID != report.ReportID {
		t.Fatalf("the printed report is not the unsigned report: %v", err)
	}
	for _, want := range []string{"report show", "verify-report"} {
		if !strings.Contains(text, want) {
			t.Errorf("the operator is not told about %q:\n%s", want, text)
		}
	}
}
