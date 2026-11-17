// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// signingRun is the harness of a whole run with a stub orchestrator that passes:
// the report run builds, signs (or not) and saves, without a PVE node or a PBS
// repository.
type signingRun struct {
	plan    *config.Plan
	opts    Options
	out     *bytes.Buffer
	dir     string
	reports string
}

func newSigningRun(t *testing.T) *signingRun {
	t.Helper()
	origPrepare, origOrchestrate := prepareRunFn, orchestrate
	t.Cleanup(func() { prepareRunFn, orchestrate = origPrepare, origOrchestrate })
	prepareRunFn = func(context.Context, *config.Plan, Options, string) (*pve.Client, *pbs.Client, error) {
		return pve.NewClient(pve.Config{}), pbs.New(pbs.Config{}), nil
	}
	orchestrate = func(context.Context, *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
		return &orchestrator.ExecutionResult{AllPassed: true, RTO: time.Second}, nil
	}
	dir := t.TempDir()
	r := &signingRun{
		dir:     dir,
		reports: filepath.Join(dir, "reports"),
		out:     &bytes.Buffer{},
		plan: &config.Plan{
			PlanID:           "signing-hook",
			Compliance:       config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
			AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
			Tiers:            []config.Tier{{Level: 1}},
		},
	}
	r.opts = Options{NodeName: "pve1", StateDir: filepath.Join(dir, "state"), ScratchDir: filepath.Join(dir, "scratch"), OutputDir: r.reports, Writer: r.out}
	return r
}

func (r *signingRun) run(t *testing.T) (*attest.Report, error) {
	t.Helper()
	return run(context.Background(), r.plan, r.opts)
}

func (r *signingRun) savedReport(t *testing.T, report *attest.Report) []byte {
	t.Helper()
	data, err := os.ReadFile(attest.DefaultReportPath(r.reports, r.plan.PlanID, report.ReportID))
	if err != nil {
		t.Fatalf("the report was not saved: %v", err)
	}
	return data
}

func assertUnsigned(t *testing.T, what string, data []byte) {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	for _, member := range attest.UnsignedReportMembers() {
		if _, present := members[member]; present {
			t.Errorf("%s has a %q member", what, member)
		}
	}
}

// With no Signer, as in the Community Edition, the run writes the report of what
// it found and signs nothing: the file is the same document without the
// signature members, and the run succeeds.
func TestRunWithoutASignerWritesAnUnsignedReport(t *testing.T) {
	r := newSigningRun(t)
	report, err := r.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" {
		t.Fatalf("the returned report is signed: %+v", report)
	}
	assertUnsigned(t, "the saved report", r.savedReport(t, report))
	if !report.AllPassed || !strings.Contains(r.out.String(), "SUCCEEDED") {
		t.Errorf("the run did not succeed: passed=%v, output %q", report.AllPassed, r.out.String())
	}
}

// compliance.sign_key_path is the Enterprise Edition's field. A run of the
// Community engine reads no key: not for a path that does not exist, and not for
// one that does (it neither signs with it nor fails the run over it).
func TestRunIgnoresThePlansSigningKeyPath(t *testing.T) {
	_, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// A real, readable key file: the Community engine still does not look at it.
	keyFile := filepath.Join(t.TempDir(), "real.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"a path that does not exist": "/nonexistent/enterprise/signing.ed25519",
		"a file that is there":       keyFile,
		"a directory":                os.TempDir(),
	} {
		r := newSigningRun(t)
		r.plan.Compliance.SignKeyPath = path
		report, err := r.run(t)
		if err != nil {
			t.Errorf("%s: the run failed: %v", name, err)
			continue
		}
		assertUnsigned(t, name+": the saved report", r.savedReport(t, report))
	}
}

// A Signer is called exactly once, and the saved report is the one it signed:
// it verifies under the Signer's key, and what verify-report reads is what the
// run returned.
func TestRunCallsTheSignerOnceAndSavesTheReportItSigned(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer := attesttest.NewSigner(private)
	r := newSigningRun(t)
	r.opts.Signer = signer
	report, err := r.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Calls() != 1 {
		t.Fatalf("the Signer was called %d times, want once", signer.Calls())
	}
	saved := r.savedReport(t, report)
	verified, valid, err := attest.VerifyReport(saved, []ed25519.PublicKey{public})
	if err != nil || !valid || verified.ReportID != report.ReportID {
		t.Fatalf("the saved report does not verify under the Signer's key: valid=%v err=%v", valid, err)
	}
	returned, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := attest.VerifyReport(returned, []ed25519.PublicKey{public}); err != nil || !valid {
		t.Fatalf("the returned report does not verify: valid=%v err=%v", valid, err)
	}
}

// A Signer that fails fails the run closed: no unsigned fallback, no report in
// the store, and the error says what failed. The run's resources were cleaned up
// and its journal finalized before the report was signed, so the node is clean.
func TestRunFailsClosedWhenTheSignerFails(t *testing.T) {
	sentinel := errors.New("the signing service is down")
	signer := attesttest.NewFailingSigner(sentinel)
	r := newSigningRun(t)
	r.opts.Signer = signer
	report, err := r.run(t)
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "sign report") {
		t.Fatalf("run = %v, want a failure to sign the report that names its cause", err)
	}
	// The report the run had comes back with the error, as it does
	// for a report that could not be saved: unsigned, never saved, and not
	// evidence for a caller that sees the error.
	if report == nil || report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" || report.SignatureTimestamp != nil {
		t.Errorf("the returned report = %+v, want the run's own report with no signature member", report)
	}
	if signer.Calls() != 1 {
		t.Errorf("the Signer was called %d times, want once", signer.Calls())
	}
	if entries, _ := os.ReadDir(r.reports); len(entries) != 0 {
		t.Errorf("the report store is not empty: %v", entries)
	}
	if record, err := journal.Load(filepath.Join(r.dir, "state", "active.json")); err != nil || record.Phase != "cleaned" {
		t.Errorf("journal = %+v, %v; want the finished run's record", record, err)
	}
}

// A failed run whose signer also fails keeps both: the report with the failure
// the run recorded, and an error that carries the run's error as well as the
// signer's, so the validation's own failure_reason and error are not lost.
func TestRunKeepsTheRunsReportAndErrorWhenTheSignerFailsToo(t *testing.T) {
	sentinel := errors.New("the signing service is down")
	r := newSigningRun(t)
	orchestrate = func(context.Context, *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
		return &orchestrator.ExecutionResult{AllPassed: false, RTO: time.Second}, errors.New("probe 1 of VM 9001 failed")
	}
	r.opts.Signer = attesttest.NewFailingSigner(sentinel)
	report, err := r.run(t)
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "probe 1 of VM 9001 failed") || !strings.Contains(err.Error(), "sign report") {
		t.Fatalf("run = %v, want the run's failure and the signer's, both", err)
	}
	if report == nil || report.AllPassed || !strings.Contains(report.FailureReason, "probe 1 of VM 9001 failed") {
		t.Fatalf("report = %+v, want the run's failed report with its reason", report)
	}
	if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" {
		t.Errorf("the report carries signature members: %+v", report)
	}
	if entries, _ := os.ReadDir(r.reports); len(entries) != 0 {
		t.Errorf("the report store is not empty: %v", entries)
	}
	if text := r.out.String(); !strings.Contains(text, "DR VALIDATION FAILED") || strings.Contains(text, "SUCCEEDED") {
		t.Errorf("the operator was told %q", text)
	}
}

// A report that cannot be saved is marked failed after it was signed, so its
// signature no longer covers it. The Signer is not asked again, though: it is
// called once, and the report that comes back with the error carries no
// signature at all rather than one over the earlier, passing content (a second
// signature would make it verify).
func TestRunCallsTheSignerOnceWhenTheReportCannotBeSaved(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signer := attesttest.NewSigner(private)
	r := newSigningRun(t)
	occupied := filepath.Join(r.dir, "occupied")
	if err := os.WriteFile(occupied, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.opts.OutputDir = filepath.Join(occupied, "reports")
	r.opts.Signer = signer
	report, runErr := r.run(t)
	if runErr == nil || !strings.Contains(runErr.Error(), "save report") {
		t.Fatalf("run = %v, want the failure to save the report", runErr)
	}
	if report == nil || report.AllPassed || !strings.Contains(report.FailureReason, "save report") {
		t.Fatalf("report = %+v; want it failed, with the reason", report)
	}
	if signer.Calls() != 1 {
		t.Fatalf("the Signer was called %d times, want once", signer.Calls())
	}
	if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" {
		t.Fatalf("the failed report kept a signature that no longer covers it: %+v", report)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := attest.VerifyReport(data, []ed25519.PublicKey{public}); err == nil || valid {
		t.Errorf("the failed report verifies as signed: valid=%v err=%v", valid, err)
	}
	if text := r.out.String(); !strings.Contains(text, "DR VALIDATION FAILED") || strings.Contains(text, "SUCCEEDED") {
		t.Fatalf("the operator was told %q", text)
	}
	if record, err := journal.Load(filepath.Join(r.dir, "state", "active.json")); err != nil || record.Phase != "cleaned" {
		t.Fatalf("journal = %+v, %v; want the finished run's record", record, err)
	}
}

// The same without a Signer: the save failure is recorded the same way, and the
// report stays unsigned.
func TestRunRecordsASaveFailureWithoutASigner(t *testing.T) {
	r := newSigningRun(t)
	occupied := filepath.Join(r.dir, "occupied")
	if err := os.WriteFile(occupied, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.opts.OutputDir = filepath.Join(occupied, "reports")
	report, runErr := r.run(t)
	if runErr == nil || !strings.Contains(runErr.Error(), "save report") || report == nil || report.AllPassed {
		t.Fatalf("run = %v, report %+v", runErr, report)
	}
	if report.Signature != "" {
		t.Fatalf("an unsigned report became signed: %+v", report)
	}
}

func TestRecordSaveFailureDropsTheSignatureItNoLongerCovers(t *testing.T) {
	_, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		prior  error
		signed bool
	}{
		"a passing signed report":         {nil, true},
		"an already failed signed report": {errors.New("service readiness probe failed"), true},
		"an unsigned report":              {nil, false},
	} {
		report := &attest.Report{ReportSchemaVersion: attest.CurrentReportSchemaVersion, ReportID: "00000000-0000-4000-8000-000000000001", PlanID: "save-contract", NodeFQDN: "pve1", AllPassed: test.prior == nil}
		if test.prior != nil {
			report.FailureReason = test.prior.Error()
		}
		if test.signed {
			if err := attesttest.SignReport(report, private); err != nil {
				t.Fatal(err)
			}
		}
		runErr := recordSaveFailure(report, test.prior, errors.New("disk full"))
		if runErr == nil || !strings.Contains(runErr.Error(), "save report: disk full") || report.AllPassed || !strings.Contains(report.FailureReason, "save report: disk full") {
			t.Errorf("%s: err = %v, report = %+v; want a recorded failure", name, runErr, report)
		}
		if test.prior != nil && !strings.Contains(runErr.Error(), test.prior.Error()) {
			t.Errorf("%s: the earlier failure was lost: %v", name, runErr)
		}
		if report.Signature != "" || report.PublicKey != "" || report.SignerFingerprint != "" || report.SignatureTimestamp != nil {
			t.Errorf("%s: signature members are left: %+v", name, report)
		}
	}
}

// normalizeOptions gives a run its defaults. The plan's sign_key_path is not
// one of them: the options carry no key.
func TestNormalizeOptionsTakesNoSigningKeyFromThePlan(t *testing.T) {
	plan := &config.Plan{}
	plan.Compliance.SignKeyPath = "/keys/report.ed25519"
	opts := normalizeOptions(plan, Options{})
	if opts.Signer != nil {
		t.Fatalf("a Signer appeared from the plan's sign_key_path: %v", opts.Signer)
	}
	given := attesttest.NewFailingSigner(errors.New("x"))
	if got := normalizeOptions(plan, Options{Signer: given}).Signer; got != attest.Signer(given) {
		t.Fatalf("the Signer given was replaced: %v", got)
	}
}

// LoadAndRun, the library's entry point, loads the plan as a controller does and
// does not require it to name a signing key: a plan without sign_key_path loads,
// and the run fails later, for what this test environment lacks (a PVE node and
// a PBS repository), but not at the plan.
func TestLoadAndRunNeedsNoSigningKey(t *testing.T) {
	t.Setenv("PBS_REPOSITORY", "")
	t.Setenv("PVE_URL", "")
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	omitted := regexp.MustCompile(`(?m)^ *sign_key_path:.*\n`).ReplaceAll(data, nil)
	if len(omitted) == len(data) {
		t.Fatal("the fixture has no sign_key_path")
	}
	path := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(path, omitted, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{NodeName: "pve-01", OutputDir: t.TempDir(), StateDir: t.TempDir(), ScratchDir: filepath.Join(t.TempDir(), "scratch")}
	_, err = LoadAndRun(context.Background(), path, opts)
	if err == nil {
		t.Fatal("a run without PBS or PVE succeeded")
	}
	if strings.Contains(err.Error(), "compliance.sign_key_path") || strings.Contains(err.Error(), "load plan") {
		t.Fatalf("the plan was refused for naming no signing key: %v", err)
	}
}
