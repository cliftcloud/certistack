// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

func TestNormalizeOptionsUsesLocalDefaults(t *testing.T) {
	plan := &config.Plan{}

	opts := normalizeOptions(plan, Options{})

	if opts.NodeName != "localhost" {
		t.Fatalf("node name = %q, want localhost", opts.NodeName)
	}
	if opts.ScratchDir != sysutil.DefaultScratchDir {
		t.Fatalf("scratch directory = %q, want %s", opts.ScratchDir, sysutil.DefaultScratchDir)
	}
	if opts.OutputDir != "/var/lib/certistack/reports" {
		t.Fatalf("output directory = %q", opts.OutputDir)
	}
	if opts.StateDir != "/var/lib/certistack" {
		t.Fatalf("state directory = %q", opts.StateDir)
	}
	if opts.Writer != io.Discard {
		t.Fatal("writer should default to io.Discard")
	}
}

func TestEnforceRTOTargetFailsARunThatExceedsIt(t *testing.T) {
	plan := &config.Plan{}
	plan.Compliance.RTOTargetSeconds = 60
	report := &attest.Report{AllPassed: true, RTOSeconds: 90.5}

	err := enforceRTOTarget(report, plan)

	if err == nil || !strings.Contains(err.Error(), "recovery time objective exceeded") {
		t.Fatalf("enforceRTOTarget error = %v, want an RTO failure so the CLI, worker and daemon exit non-zero", err)
	}
	if report.AllPassed {
		t.Fatal("a run that exceeded its RTO target was still signed as passing")
	}
	if !strings.Contains(report.FailureReason, "recovery time objective exceeded") {
		t.Fatalf("failure reason = %q, want an RTO explanation", report.FailureReason)
	}
	if !strings.Contains(report.FailureReason, "90.5") || !strings.Contains(report.FailureReason, "60.0") {
		t.Fatalf("failure reason = %q, want both the actual and target RTO", report.FailureReason)
	}
}

func TestEnforceRTOTargetAppendsToAnExistingFailureReason(t *testing.T) {
	plan := &config.Plan{}
	plan.Compliance.RTOTargetSeconds = 60
	report := &attest.Report{AllPassed: false, RTOSeconds: 90, FailureReason: "probe timed out"}

	_ = enforceRTOTarget(report, plan)

	if !strings.Contains(report.FailureReason, "probe timed out") || !strings.Contains(report.FailureReason, "recovery time objective exceeded") {
		t.Fatalf("failure reason = %q, want both the original reason and the RTO explanation", report.FailureReason)
	}
}

func TestEnforceRTOTargetLeavesAPassingRunUntouchedWhenWithinTarget(t *testing.T) {
	plan := &config.Plan{}
	plan.Compliance.RTOTargetSeconds = 300
	report := &attest.Report{AllPassed: true, RTOSeconds: 42}

	if err := enforceRTOTarget(report, plan); err != nil {
		t.Fatalf("enforceRTOTarget returned %v for a run within its target", err)
	}

	if !report.AllPassed || report.FailureReason != "" {
		t.Fatalf("a run within its RTO target was modified: all_passed=%v failure_reason=%q", report.AllPassed, report.FailureReason)
	}
}

// A non-finite RTO target handed over without validation neither
// passes every run (+Inf) nor fails one for "exceeding NaN"; the objective
// is reported as not evaluated, and the run fails.
func TestEnforceRTOTargetRefusesANonFiniteTarget(t *testing.T) {
	for _, target := range []float64{math.NaN(), math.Inf(1)} {
		plan := &config.Plan{}
		plan.Compliance.RTOTargetSeconds = target
		report := &attest.Report{AllPassed: true, RTOSeconds: 42}
		err := enforceRTOTarget(report, plan)
		if err == nil || report.AllPassed || !strings.Contains(report.FailureReason, "not a finite number") {
			t.Fatalf("target %v: err %v, report %+v", target, err, report)
		}
	}
}

// guardedContext bounds a call that must be refused before it reaches any
// node: if the refusal under test were missing the run would start dialing
// the plan's PVE endpoint and retrying, so the test fails fast on the deadline
// (an error that does not name the field) instead of hanging.
func guardedContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// A plan handed to a run without the validating loader is refused before
// anything is created when a limit is not finite or a duration overflows.
// The plan carries valid compliance metadata, so the only fault in each case
// is the one named, and the refusal must name that field: a plan missing its
// frameworks would be refused anyway and prove nothing about the bound.
func TestRunRefusesUnboundedNumbersInAnUnvalidatedPlan(t *testing.T) {
	validPlan := func() *config.Plan {
		return &config.Plan{
			Compliance:       config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
			AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
			Tiers:            []config.Tier{{Level: 1}},
		}
	}
	// The control: every case below differs from this plan in one field.
	if err := requirePlanBounds(validPlan()); err != nil {
		t.Fatalf("the unmutated plan is refused: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*config.Plan)
		field  string
		reason string
	}{
		"NaN I/O wait limit":   {func(p *config.Plan) { p.AdmissionControl.MaxHostIOWaitPercent = math.NaN() }, "admission_control.max_host_iowait_percent", "must be a finite number"},
		"overflowing soak":     {func(p *config.Plan) { p.Tiers[0].SoakTimeSec = 9223372037 }, "tiers[0].soak_time_sec", "must be between 0 and"},
		"overflowing interval": {func(p *config.Plan) { p.AdmissionControl.DeferRetryIntervalSec = 9223372037 }, "admission_control.defer_retry_interval_sec", "must be between 1 and"},
	} {
		plan := validPlan()
		tc.mutate(plan)
		for entry, call := range map[string]func() error{
			"run":     func() error { _, err := run(guardedContext(t), plan, Options{}); return err },
			"PlanRun": func() error { _, err := PlanRun(guardedContext(t), plan, Options{}); return err },
		} {
			err := call()
			if err == nil || !strings.Contains(err.Error(), "invalid plan") || !strings.Contains(err.Error(), tc.field+": "+tc.reason) {
				t.Errorf("%s, %s: err %v, want the plan refused for %s (%s)", name, entry, err, tc.field, tc.reason)
			}
			if err != nil && strings.Contains(err.Error(), "compliance") {
				t.Errorf("%s, %s: refused for its compliance metadata, not the bound under test: %v", name, entry, err)
			}
		}
	}
}

// A plan handed to a run without the validating loader cannot carry
// a shell command to the guest under either spelling of the guest-agent
// probe: the run is refused before anything is created.
func TestRunRefusesAGuestCommandTheAllowlistRefuses(t *testing.T) {
	// The plan is valid in everything but the command: it carries compliance
	// metadata, so the command is the one thing refused, and
	// the test does not depend on which check requirePlanBounds runs first
	// (the error reports only the first of several).
	planWith := func(probeType, command string) *config.Plan {
		return &config.Plan{
			Compliance:       config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
			AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
			Tiers: []config.Tier{{Level: 1, VMs: []config.VM{{VMID: 9001, Probes: []config.Probe{
				{Type: probeType, Command: command, RequireQGA: true, TimeoutSec: 2},
			}}}}},
		}
	}
	for _, probeType := range []string{"qga", "qga_ping"} {
		if err := requirePlanBounds(planWith(probeType, "systemctl is-active sshd")); err != nil {
			t.Fatalf("%s: the control plan, with an allowed command, is refused: %v", probeType, err)
		}
		plan := planWith(probeType, "printf audit-qga-alias-marker")
		if err := requirePlanBounds(plan); err == nil || strings.Contains(err.Error(), "compliance") || strings.Contains(err.Error(), "validation errors occurred") {
			t.Fatalf("%s: requirePlanBounds = %v, want the guest command as the only fault", probeType, err)
		}
		for entry, call := range map[string]func() error{
			"run":     func() error { _, err := run(context.Background(), plan, Options{}); return err },
			"PlanRun": func() error { _, err := PlanRun(context.Background(), plan, Options{}); return err },
		} {
			if err := call(); err == nil || !strings.Contains(err.Error(), "invalid plan") || !strings.Contains(err.Error(), "arbitrary guest shell commands") {
				t.Errorf("%s, %s probe running printf: err %v, want the plan refused for its guest command", entry, probeType, err)
			}
		}
	}
}

// The frameworks and retention a report signs are checked on a plan handed to a
// run directly too, before anything is created: a plan with no framework, or a
// zero retention, is never signed into evidence.
func TestRunRefusesAPlanWithoutFrameworksOrRetention(t *testing.T) {
	for name, compliance := range map[string]config.Compliance{
		"no frameworks":  {RetentionDays: 90},
		"zero retention": {Frameworks: []string{"DORA"}},
		"neither":        {},
	} {
		plan := &config.Plan{
			Compliance:       compliance,
			AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
			Tiers:            []config.Tier{{Level: 1}},
		}
		for entry, call := range map[string]func() error{
			"run":     func() error { _, err := run(context.Background(), plan, Options{}); return err },
			"PlanRun": func() error { _, err := PlanRun(context.Background(), plan, Options{}); return err },
		} {
			if err := call(); err == nil || !strings.Contains(err.Error(), "invalid plan") || !strings.Contains(err.Error(), "compliance.") {
				t.Errorf("%s, %s: err %v, want the plan refused for its compliance metadata", name, entry, err)
			}
		}
	}
}

// A node name that is a list ("pve1,pve2") is refused before the
// scratch directory, the journal, PVE or PBS is touched, by a run and by a plan.
func TestRunAndPlanRunRefuseANodeListBeforeTouchingAnything(t *testing.T) {
	plan := &config.Plan{
		Compliance:       config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
		Tiers:            []config.Tier{{Level: 1}},
	}
	stateDir, scratchDir := t.TempDir(), filepath.Join(t.TempDir(), "scratch")
	opts := Options{NodeName: "pve1,pve2", StateDir: stateDir, ScratchDir: scratchDir}
	for entry, call := range map[string]func() error{
		"run":     func() error { _, err := run(context.Background(), plan, opts); return err },
		"PlanRun": func() error { _, err := PlanRun(context.Background(), plan, opts); return err },
	} {
		if err := call(); err == nil || !strings.Contains(err.Error(), "invalid PVE node name") {
			t.Errorf("%s: err %v, want the node refused", entry, err)
		}
	}
	if entries, _ := os.ReadDir(stateDir); len(entries) != 0 {
		t.Errorf("the state directory holds %d entries after a refused run", len(entries))
	}
	if _, err := os.Stat(scratchDir); !os.IsNotExist(err) {
		t.Errorf("the scratch directory was created for a refused run: %v", err)
	}
}
func TestEnforceRTOTargetIsANoOpWhenUnset(t *testing.T) {
	plan := &config.Plan{}
	report := &attest.Report{AllPassed: true, RTOSeconds: 1_000_000}

	if err := enforceRTOTarget(report, plan); err != nil {
		t.Fatalf("enforceRTOTarget returned %v with no target configured", err)
	}

	if !report.AllPassed || report.FailureReason != "" {
		t.Fatalf("an unset rto_target_seconds affected the report: all_passed=%v failure_reason=%q", report.AllPassed, report.FailureReason)
	}
}

func TestNormalizeOptionsFallsBackToPlanScratchDir(t *testing.T) {
	plan := &config.Plan{}
	plan.Storage.ScratchDir = "/var/lib/certistack/plan-scratch"

	opts := normalizeOptions(plan, Options{})

	if opts.ScratchDir != plan.Storage.ScratchDir {
		t.Fatalf("scratch directory = %q, want the plan's storage.scratch_dir %q", opts.ScratchDir, plan.Storage.ScratchDir)
	}
}

func TestNormalizeOptionsPrefersExplicitScratchDirOverPlan(t *testing.T) {
	plan := &config.Plan{}
	plan.Storage.ScratchDir = "/var/lib/certistack/plan-scratch"

	opts := normalizeOptions(plan, Options{ScratchDir: "/var/lib/certistack/operator-scratch"})

	if opts.ScratchDir != "/var/lib/certistack/operator-scratch" {
		t.Fatalf("scratch directory = %q, want the caller-provided value to win over the plan", opts.ScratchDir)
	}
}

func TestLoadAndRunRejectsEmptyPlanPath(t *testing.T) {
	_, err := LoadAndRun(context.Background(), "", Options{})
	if err == nil {
		t.Fatal("LoadAndRun accepted an empty plan path")
	}
}

func TestRunLockedRejectsNilPlanWithoutAcquiringAnotherLock(t *testing.T) {
	// This is the node-worker path: the caller already owns the host lock so
	// recovery, preflight, and the run are one mutually exclusive operation.
	// A nil plan exercises the function without contacting PBS or PVE.
	if _, err := RunLocked(context.Background(), nil, Options{}); err == nil || !strings.Contains(err.Error(), "plan is required") {
		t.Fatalf("RunLocked(nil) error = %v, want plan requirement", err)
	}
}

func TestRequireCleanJournalRejectsUnresolvedAndMalformedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	record := journal.Record{RunID: "unresolved-run", Phase: "cleanup_failed"}
	record.AddVM(9900, "node1", 0, "")
	if err := journal.Write(path, record); err != nil {
		t.Fatal(err)
	}
	if err := requireCleanJournal(path); err == nil || !strings.Contains(err.Error(), "refusing to start") || !strings.Contains(err.Error(), "cleanup_failed") {
		t.Fatalf("unresolved journal error = %v", err)
	}
	if err := os.WriteFile(path, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireCleanJournal(path); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("malformed journal error = %v", err)
	}
}

func TestRequireCleanJournalAllowsMissingAndTerminalCleanRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	if err := requireCleanJournal(path); err != nil {
		t.Fatalf("missing journal error = %v", err)
	}
	if err := journal.Write(path, journal.Record{RunID: "finished", Phase: "cleaned"}); err != nil {
		t.Fatal(err)
	}
	if err := requireCleanJournal(path); err != nil {
		t.Fatalf("clean journal error = %v", err)
	}
}

func TestMaintainedPlanFixturesPassRuntimePBSRoutingPreflight(t *testing.T) {
	for _, name := range []string{"valid_plan.yaml", "multi_tier_sandbox.yaml"} {
		t.Run(name, func(t *testing.T) {
			plan, err := config.LoadFromFile(filepath.Join("..", "..", "testdata", "plans", name))
			if err != nil {
				t.Fatalf("load maintained plan: %v", err)
			}
			if err := validatePBSRouting(plan, plan.Storage.PBSNamespace); err != nil {
				t.Fatalf("runtime PBS routing preflight: %v", err)
			}
		})
	}
}

func TestFinalizeJournalPreservesTrackedResourcesWhenTeardownIsUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	record := journal.Record{RunID: "journal-preserve", Phase: "running"}
	record.AddVM(9900, "node1", 0, "")
	if err := journal.Write(path, record); err != nil {
		t.Fatal(err)
	}

	if err := finalizeJournal(path, journal.Record{}, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := journal.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Phase != "cleanup_failed" || len(loaded.VMs) != 1 || loaded.VMs[0].VMID != 9900 {
		t.Fatalf("finalized journal lost recoverable state: %#v", loaded)
	}
}

func TestFinalizeJournalMarksResourceFreeRunCleaned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	record := journal.Record{RunID: "resource-free", Phase: "running"}
	if err := journal.Write(path, record); err != nil {
		t.Fatal(err)
	}
	if err := finalizeJournal(path, record, nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := journal.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Phase != "cleaned" {
		t.Fatalf("resource-free journal phase = %q, want cleaned", loaded.Phase)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("journal was not written: %v", err)
	}
}

func TestFinalizeJournalRejectsMissingActiveJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active.json")
	err := finalizeJournal(path, journal.Record{RunID: "lost-after-allocation", Phase: "running"}, nil)
	if err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("missing journal finalization error = %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing journal was recreated: %v", statErr)
	}
}

func TestRequireVerifiedTeardownFailsClosedForLocalRun(t *testing.T) {
	result := &orchestrator.ExecutionResult{
		AllPassed: true,
		TeardownEvidence: &attest.TeardownEvidence{
			AllCleaned:    false,
			CleanupErrors: []string{"cannot verify sandbox VM is absent"},
		},
	}
	err := requireVerifiedTeardown(result, nil)
	if err == nil || !strings.Contains(err.Error(), "cleanup could not be verified") {
		t.Fatalf("local unverified teardown error = %v", err)
	}
	if result.AllPassed || result.Error != err {
		t.Fatalf("local unverified teardown result = %+v", result)
	}
}

func TestRequireVerifiedTeardownPreservesValidationFailure(t *testing.T) {
	original := errors.New("service readiness probe failed")
	result := &orchestrator.ExecutionResult{
		AllPassed: false,
		TeardownEvidence: &attest.TeardownEvidence{
			AllCleaned: false,
		},
	}
	if got := requireVerifiedTeardown(result, original); got != original {
		t.Fatalf("existing validation failure = %v, want %v", got, original)
	}
}

func TestRecordDurabilityFailureFailsReportAndPreservesPriorError(t *testing.T) {
	report := &attest.Report{AllPassed: true}
	prior := errors.New("service readiness probe failed")
	got := recordDurabilityFailure(report, prior, "save signed report", errors.New("read-only filesystem"))
	if got == nil || !strings.Contains(got.Error(), "service readiness probe failed") || !strings.Contains(got.Error(), "save signed report") {
		t.Fatalf("durability failure = %v", got)
	}
	if report.AllPassed || !strings.Contains(report.FailureReason, "read-only filesystem") {
		t.Fatalf("report did not record durable evidence failure: %+v", report)
	}
}

func TestFinalizeJournalRejectsUnwritableParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parent, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := finalizeJournal(filepath.Join(parent, "active.json"), journal.Record{RunID: "no-write"}, nil); err == nil {
		t.Fatal("expected journal finalization to fail when its parent is not a directory")
	}
}

func TestSafeFailureReasonRedactsConfiguredSecretsAndBoundsOutput(t *testing.T) {
	sensitiveValues := map[string]string{
		"PVE_URL":                      "https://pve.internal:8006",
		"PVE_TOKEN_ID":                 "certistack@pve!automation",
		"PVE_TOKEN_SECRET":             "pve-sensitive",
		"CERTISTACK_PVE_CA_SOURCE":     "/secure/pve-ca.pem",
		"PBS_REPOSITORY":               "backup@pbs!nightly@pbs.internal:8007:datastore",
		"PBS_PASSWORD":                 "pbs-sensitive",
		"PBS_PASSWORD_FILE":            "/secure/pbs-password",
		"PBS_FINGERPRINT":              "SHA256:private-fingerprint",
		"PBS_ENCRYPTION_PASSWORD":      "encryption-sensitive",
		"PBS_ENCRYPTION_PASSWORD_FILE": "/secure/pbs-encryption-password",
		"CERTISTACK_SSH_IDENTITY":      "/secure/id_ed25519",
		"CERTISTACK_SSH_KNOWN_HOSTS":   "/secure/known_hosts",
	}
	var fragments []string
	for key, value := range sensitiveValues {
		t.Setenv(key, value)
		fragments = append(fragments, value)
	}
	reason := SafeFailureReason(fmt.Errorf("worker failed with %s\x00", strings.Join(fragments, " | ")))
	for _, value := range sensitiveValues {
		if strings.Contains(reason, value) {
			t.Fatalf("failure reason exposed configured sensitive value %q: %q", value, reason)
		}
	}
	if !strings.Contains(reason, "[REDACTED]") || strings.ContainsRune(reason, '\x00') {
		t.Fatalf("failure reason was not safely redacted: %q", reason)
	}
	if got := SafeFailureReason(fmt.Errorf("%s", strings.Repeat("x", 5000))); len(got) > 4096 || !strings.HasSuffix(got, " [truncated]") {
		t.Fatalf("failure reason was not bounded: length=%d", len(got))
	}
}

func TestSafeFailureReasonRedactsPVEHostWithTrailingSlash(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.internal:8006/")
	reason := SafeFailureReason(fmt.Errorf("request failed for https://pve.internal:8006/api2/json/version"))
	if strings.Contains(reason, "pve.internal") || strings.Contains(reason, "8006") {
		t.Fatalf("PVE host leaked from trailing-slash configuration: %q", reason)
	}
}

type fakeSnapshotResolver struct {
	resolved map[string]string
	calls    []string
}

func (r *fakeSnapshotResolver) ResolveSnapshot(_ context.Context, selector string, sourceVMID int) (string, error) {
	key := fmt.Sprintf("%s:%d", selector, sourceVMID)
	r.calls = append(r.calls, key)
	value, ok := r.resolved[key]
	if !ok {
		return "", fmt.Errorf("unexpected selector %s", key)
	}
	return value, nil
}

func TestResolveLatestSnapshotsPinsPerVMSnapshots(t *testing.T) {
	plan := &config.Plan{Tiers: []config.Tier{{VMs: []config.VM{
		{VMID: 9001, Name: "directory", SourceVMID: 100, SourcePBS: config.SourcePBS{Snapshot: "latest"}},
		{VMID: 9002, Name: "database", SourceVMID: 200, SourcePBS: config.SourcePBS{Snapshot: "latest"}},
	}}}}
	resolver := &fakeSnapshotResolver{resolved: map[string]string{
		"latest:100": "vm/100/2026-09-16T01:00:00Z",
		"latest:200": "vm/200/2026-09-16T01:05:00Z",
	}}

	if err := resolveLatestSnapshots(context.Background(), plan, resolver); err != nil {
		t.Fatal(err)
	}
	if got := plan.Tiers[0].VMs[0].SourcePBS.Snapshot; got != "vm/100/2026-09-16T01:00:00Z" {
		t.Fatalf("first VM snapshot = %q", got)
	}
	if got := plan.Tiers[0].VMs[1].SourcePBS.Snapshot; got != "vm/200/2026-09-16T01:05:00Z" {
		t.Fatalf("second VM snapshot = %q", got)
	}
}

// The real PBS resolver keeps a pinned path as it is, so the runner
// binds source_vmid to it: a pin of another VM's backup is refused, and a
// VM without source_vmid is reported under the VM whose backup it restores.
func TestResolvedSnapshotBindsTheSourceVMID(t *testing.T) {
	const snapshot = "vm/200/2026-09-27T03:00:09Z"
	contradiction := &config.Plan{Tiers: []config.Tier{{VMs: []config.VM{{VMID: 9001, Name: "db", SourceVMID: 100, SourcePBS: config.SourcePBS{Snapshot: snapshot}}}}}}
	err := resolveLatestSnapshots(context.Background(), contradiction, pbs.New(pbs.Config{}))
	if err == nil || !strings.Contains(err.Error(), "source_vmid 100") || !strings.Contains(err.Error(), "backup of VM 200") {
		t.Fatalf("contradictory source_vmid: err %v", err)
	}
	omitted := &config.Plan{Tiers: []config.Tier{{VMs: []config.VM{{VMID: 9001, Name: "db", SourcePBS: config.SourcePBS{Snapshot: snapshot}}}}}}
	if err := resolveLatestSnapshots(context.Background(), omitted, pbs.New(pbs.Config{})); err != nil {
		t.Fatal(err)
	}
	if vm := omitted.Tiers[0].VMs[0]; vm.SourceVMID != 200 || vm.SourcePBS.Snapshot != snapshot {
		t.Fatalf("omitted source_vmid: %d, %s; want 200 and the pin", vm.SourceVMID, vm.SourcePBS.Snapshot)
	}
}

type fakeBackupProfileResolver struct {
	profiles map[string]pbs.VMProfile
}

func (r fakeBackupProfileResolver) LoadVMProfile(_ context.Context, snapshot, _ string) (pbs.VMProfile, error) {
	profile, ok := r.profiles[snapshot]
	if !ok {
		return pbs.VMProfile{}, fmt.Errorf("unexpected snapshot %s", snapshot)
	}
	return profile, nil
}

func (r fakeBackupProfileResolver) LoadVMLayout(ctx context.Context, snapshot, scratchDir string) (pbs.VMLayout, error) {
	profile, err := r.LoadVMProfile(ctx, snapshot, scratchDir)
	return layoutOf(profile), err
}

func TestApplyBackupConfig_InheritsSafeFieldsAndAllDisks(t *testing.T) {
	plan := &config.Plan{UseBackupConfig: true, Tiers: []config.Tier{{VMs: []config.VM{{
		VMID: 9900, Name: "restore", SourcePBS: config.SourcePBS{Snapshot: "vm/7011/2026-09-16T00:00:00Z"},
	}}}}}
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/7011/2026-09-16T00:00:00Z": {
			Cores: 4, Sockets: 2, MemoryMB: 8192, BalloonMB: 4096, CPUWeight: 200,
			Machine: "pc-q35-8.1", OSType: "l26", BIOS: "seabios", SCSIHW: "virtio-scsi-single",
			MAC:        "00:11:22:33:44:55",
			NICModel:   "e1000",
			SourceTags: []string{"production", "postgres"},
			Drives:     []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}, {Slot: "scsi1", Archive: "drive-scsi1"}},
		},
	}}

	if err := applyBackupConfig(context.Background(), plan, resolver, "/tmp"); err != nil {
		t.Fatal(err)
	}
	vm := plan.Tiers[0].VMs[0]
	if vm.HardwareOverrides.Cores != 4 || vm.HardwareOverrides.Sockets != 2 || vm.HardwareOverrides.MemoryMB != 8192 {
		t.Fatalf("hardware not inherited: %+v", vm.HardwareOverrides)
	}
	if vm.Machine != "pc-q35-8.1" || vm.OSType != "l26" || vm.SCSIHW != "virtio-scsi-single" {
		t.Fatalf("runtime profile not inherited: %+v", vm)
	}
	if vm.MAC != "00:11:22:33:44:55" {
		t.Fatalf("source MAC was not inherited: %q", vm.MAC)
	}
	if vm.NICModel != "e1000" {
		t.Fatalf("source NIC model was not inherited: %q", vm.NICModel)
	}
	drives := vm.SourcePBS.RestoreDrives()
	if len(drives) != 2 || drives[1].Slot != "scsi1" {
		t.Fatalf("discovered drives = %+v", drives)
	}
	if len(vm.SourceTags) != 2 || vm.SourceTags[0] != "production" {
		t.Fatalf("source tag evidence = %v", vm.SourceTags)
	}
}

func uefiResolver() fakeBackupProfileResolver {
	return fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/7301/2026-09-27T03:00:00Z": {
			BIOS:   "ovmf",
			Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}},
			Firmware: []pbs.FirmwareImage{
				{Slot: "efidisk0", Archive: "drive-efidisk0", Options: "efitype=4m,pre-enrolled-keys=1"},
				{Slot: "tpmstate0", Archive: "drive-tpmstate0-backup", Options: "version=v2.0"},
			},
		},
	}}
}

func uefiPlan(useBackupConfig bool, bios string) *config.Plan {
	return &config.Plan{UseBackupConfig: useBackupConfig, Tiers: []config.Tier{{VMs: []config.VM{{
		VMID: 17301, Name: "uefi", BIOS: bios,
		SourcePBS: config.SourcePBS{Snapshot: "vm/7301/2026-09-27T03:00:00Z", Drives: []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}}},
	}}}}}
}

func TestSourceFirmwareFollowsEveryPlanStyle(t *testing.T) {
	want := []config.FirmwareDisk{
		{Slot: "efidisk0", Archive: "drive-efidisk0", Options: "efitype=4m,pre-enrolled-keys=1"},
		{Slot: "tpmstate0", Archive: "drive-tpmstate0-backup", Options: "version=v2.0"},
	}
	for name, apply := range map[string]func(*config.Plan) error{
		"use_backup_config": func(plan *config.Plan) error {
			return applyBackupConfig(context.Background(), plan, uefiResolver(), "/tmp")
		},
		"explicit drives": func(plan *config.Plan) error {
			return applyBackupLayout(context.Background(), plan, uefiResolver(), "/tmp")
		},
	} {
		plan := uefiPlan(name == "use_backup_config", "")
		if err := apply(plan); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		vm := plan.Tiers[0].VMs[0]
		if vm.BIOS != "ovmf" || !reflect.DeepEqual(vm.FirmwareDisks, want) {
			t.Fatalf("%s: bios %q firmware %+v, want ovmf and %+v", name, vm.BIOS, vm.FirmwareDisks, want)
		}
	}
}

func TestSourceFirmwareRefusesAContradictingPlan(t *testing.T) {
	plan := uefiPlan(false, "seabios")
	err := applyBackupLayout(context.Background(), plan, uefiResolver(), "/tmp")
	if err == nil || !strings.Contains(err.Error(), "UEFI (ovmf)") {
		t.Fatalf("seabios plan over a UEFI backup: err %v", err)
	}
	if err := applyBackupConfig(context.Background(), uefiPlan(true, "seabios"), uefiResolver(), "/tmp"); err == nil {
		t.Fatal("use_backup_config accepted a seabios plan over a UEFI backup")
	}
}

func multiBusResolver() fakeBackupProfileResolver {
	return fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/4100/2026-09-27T03:00:00Z": {
			BootOrder: []string{"virtio0", "net0"},
			Drives: []pbs.SourceDrive{
				{Slot: "sata1", Archive: "drive-sata1"},
				{Slot: "scsi0", Archive: "drive-scsi0"},
				{Slot: "virtio0", Archive: "drive-virtio0"},
			},
		},
	}}
}

func multiBusPlan(useBackupConfig bool, drives ...config.SourceDrive) *config.Plan {
	return &config.Plan{UseBackupConfig: useBackupConfig, Tiers: []config.Tier{{VMs: []config.VM{{
		VMID: 14100, Name: "legacy-virtio",
		SourcePBS: config.SourcePBS{Snapshot: "vm/4100/2026-09-27T03:00:00Z", Drives: drives},
	}}}}}
}

func TestSourceLayoutBootsTheSourceBootDiskOnAnyBus(t *testing.T) {
	plan := multiBusPlan(true)
	if err := applyBackupConfig(context.Background(), plan, multiBusResolver(), "/tmp"); err != nil {
		t.Fatal(err)
	}
	vm := plan.Tiers[0].VMs[0]
	if vm.BootDisk != "virtio0" || len(vm.SourcePBS.RestoreDrives()) != 3 || vm.OmittedDisks != nil {
		t.Fatalf("boot disk %q, drives %+v, omitted %v; want virtio0, all three, none", vm.BootDisk, vm.SourcePBS.RestoreDrives(), vm.OmittedDisks)
	}
}

func TestSourceLayoutRecordsDisksAPlanLeavesOut(t *testing.T) {
	plan := multiBusPlan(false, config.SourceDrive{Slot: "virtio0", Archive: "drive-virtio0"})
	if err := applyBackupLayout(context.Background(), plan, multiBusResolver(), "/tmp"); err != nil {
		t.Fatal(err)
	}
	vm := plan.Tiers[0].VMs[0]
	if vm.BootDisk != "virtio0" || !reflect.DeepEqual(vm.OmittedDisks, []string{"sata1", "scsi0"}) {
		t.Fatalf("boot disk %q, omitted %v; want virtio0 and [sata1 scsi0]", vm.BootDisk, vm.OmittedDisks)
	}
}

func TestSourceLayoutKeepsBootCriticalHardwareUnlessThePlanSetsIt(t *testing.T) {
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/4100/2026-09-27T03:00:00Z": {
			Machine: "pc-q35-8.1", SCSIHW: "lsi", OSType: "win10",
			Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}},
		},
	}}
	plan := multiBusPlan(false, config.SourceDrive{Slot: "scsi0", Archive: "drive-scsi0"})
	plan.Tiers[0].VMs[0].SCSIHW = "virtio-scsi-single" // the plan's explicit choice wins
	if err := applyBackupLayout(context.Background(), plan, resolver, "/tmp"); err != nil {
		t.Fatal(err)
	}
	vm := plan.Tiers[0].VMs[0]
	if vm.Machine != "pc-q35-8.1" || vm.OSType != "win10" || vm.SCSIHW != "virtio-scsi-single" {
		t.Fatalf("machine %q ostype %q scsihw %q", vm.Machine, vm.OSType, vm.SCSIHW)
	}
}

func TestSourceLayoutAttachesOtherNICsOnlyWhenAsked(t *testing.T) {
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/4100/2026-09-27T03:00:00Z": {
			Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}},
			NICs:   []pbs.SourceNIC{{Slot: "net1", Model: "virtio", MAC: "BC:24:11:00:00:02"}},
		},
	}}
	plan := multiBusPlan(false, config.SourceDrive{Slot: "scsi0", Archive: "drive-scsi0"})
	if err := applyBackupLayout(context.Background(), plan, resolver, "/tmp"); err != nil {
		t.Fatal(err)
	}
	if vm := plan.Tiers[0].VMs[0]; vm.AdditionalNICs != nil || !reflect.DeepEqual(vm.OmittedNICs, []string{"net1"}) {
		t.Fatalf("default: attached %+v, omitted %v; want net1 recorded as omitted", vm.AdditionalNICs, vm.OmittedNICs)
	}
	plan.Tiers[0].VMs[0].NetworkRecovery.AttachAllNICs = true
	if err := applyBackupLayout(context.Background(), plan, resolver, "/tmp"); err != nil {
		t.Fatal(err)
	}
	want := []config.SourceNIC{{Slot: "net1", Model: "virtio", MAC: "BC:24:11:00:00:02"}}
	if vm := plan.Tiers[0].VMs[0]; !reflect.DeepEqual(vm.AdditionalNICs, want) || vm.OmittedNICs != nil {
		t.Fatalf("attach_all_nics: attached %+v, omitted %v", vm.AdditionalNICs, vm.OmittedNICs)
	}
}

func TestSourceLayoutRefusesADiskTheBackupLacks(t *testing.T) {
	// The drive-scsi0 shorthand default on a VM whose disk is virtio-only.
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/4100/2026-09-27T03:00:00Z": {Drives: []pbs.SourceDrive{{Slot: "virtio0", Archive: "drive-virtio0"}}},
	}}
	plan := multiBusPlan(false, config.SourceDrive{Slot: "scsi0", Archive: "drive-scsi0"})
	err := applyBackupLayout(context.Background(), plan, resolver, "/tmp")
	if err == nil || !strings.Contains(err.Error(), "has no scsi0 disk") || !strings.Contains(err.Error(), "virtio0") {
		t.Fatalf("err = %v, want a refusal naming the backed-up virtio0", err)
	}
}

func TestSourceFirmwareLeavesSeaBIOSBackupsAlone(t *testing.T) {
	plan := &config.Plan{Tiers: []config.Tier{{VMs: []config.VM{{
		VMID: 17011, Name: "bios", SourcePBS: config.SourcePBS{Snapshot: "vm/7011/2026-09-16T00:00:00Z"},
	}}}}}
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{"vm/7011/2026-09-16T00:00:00Z": {BIOS: "seabios"}}}
	if err := applyBackupLayout(context.Background(), plan, resolver, "/tmp"); err != nil {
		t.Fatal(err)
	}
	if vm := plan.Tiers[0].VMs[0]; vm.BIOS != "" || vm.FirmwareDisks != nil {
		t.Fatalf("SeaBIOS backup changed the plan: bios %q firmware %+v", vm.BIOS, vm.FirmwareDisks)
	}
}

func TestApplyBackupConfig_RejectsPlanDiskMismatch(t *testing.T) {
	plan := &config.Plan{UseBackupConfig: true, Tiers: []config.Tier{{VMs: []config.VM{{
		VMID: 9900, Name: "restore", SourcePBS: config.SourcePBS{
			Snapshot: "vm/7011/2026-09-16T00:00:00Z",
			Drives:   []config.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}},
		},
	}}}}}
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/7011/2026-09-16T00:00:00Z": {Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}, {Slot: "scsi1", Archive: "drive-scsi1"}}},
	}}

	if err := applyBackupConfig(context.Background(), plan, resolver, "/tmp"); err == nil {
		t.Fatal("expected source drive mismatch to fail")
	}
}

func TestApplyBackupNetworkIdentity_InheritsOnlyNICIdentity(t *testing.T) {
	plan := &config.Plan{
		Network: config.Network{IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers: []config.Tier{{VMs: []config.VM{{
			VMID: 9900, Name: "restore", MAC: "", SourcePBS: config.SourcePBS{
				Snapshot: "vm/7011/2026-09-16T00:00:00Z", Drive: "drive-scsi0",
			},
			HardwareOverrides: config.HardwareOverrides{Cores: 7, MemoryMB: 7168},
			Probes:            []config.Probe{{Type: "tcp", TargetIP: "10.100.0.10"}},
		}}}},
	}
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/7011/2026-09-16T00:00:00Z": {
			Cores: 2, MemoryMB: 2048, MAC: "00:11:22:33:44:55", NICModel: "e1000",
			SourceTags: []string{"production"}, Drives: []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}, {Slot: "scsi1", Archive: "drive-scsi1"}},
		},
	}}

	if err := applyBackupNetworkIdentity(context.Background(), plan, resolver, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	vm := plan.Tiers[0].VMs[0]
	if vm.MAC != "00:11:22:33:44:55" || vm.NICModel != "e1000" || len(vm.SourceTags) != 1 {
		t.Fatalf("network identity not inherited: %+v", vm)
	}
	if vm.HardwareOverrides.Cores != 7 || vm.HardwareOverrides.MemoryMB != 7168 {
		t.Fatalf("network identity load changed compute overrides: %+v", vm.HardwareOverrides)
	}
	if drives := vm.SourcePBS.RestoreDrives(); len(drives) != 1 || drives[0].Slot != "scsi0" {
		t.Fatalf("network identity load changed configured disk layout: %+v", drives)
	}
}

// A preserve VM has no recovery address to derive (so a source without a
// net0 MAC is no error, as it is for the other modes), but it keeps the
// backup's net0 identity: the guest is left as backed up and nothing rewrites
// its network profile to follow a new MAC or model.
func TestApplyBackupNetworkIdentity_PreserveKeepsTheBackupsIdentity(t *testing.T) {
	plan := &config.Plan{
		Network: config.Network{IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers: []config.Tier{{VMs: []config.VM{{
			VMID: 9900, Name: "restore", NetworkRecovery: config.NetworkRecovery{Mode: "preserve"},
			SourcePBS: config.SourcePBS{Snapshot: "vm/7011/2026-09-16T00:00:00Z"},
			Probes:    []config.Probe{{Type: "tcp", TargetIP: "10.100.0.10"}},
		}}}},
	}
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/7011/2026-09-16T00:00:00Z": {MAC: "00:11:22:33:44:55", NICModel: "e1000", SourceTags: []string{"production"}},
	}}
	if err := applyBackupNetworkIdentity(context.Background(), plan, resolver, t.TempDir()); err != nil {
		t.Fatalf("preserve plan: %v", err)
	}
	vm := plan.Tiers[0].VMs[0]
	if vm.MAC != "00:11:22:33:44:55" || vm.NICModel != "e1000" {
		t.Fatalf("preserve did not keep the backup's net0 identity: MAC %q model %q", vm.MAC, vm.NICModel)
	}
	if len(vm.SourceTags) != 0 {
		t.Fatalf("preserve copied the source's tags: %v", vm.SourceTags)
	}

	// A source with no usable net0 leaves nothing to keep, and is no error.
	plan.Tiers[0].VMs[0].MAC, plan.Tiers[0].VMs[0].NICModel = "", ""
	empty := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{"vm/7011/2026-09-16T00:00:00Z": {}}}
	if err := applyBackupNetworkIdentity(context.Background(), plan, empty, t.TempDir()); err != nil {
		t.Fatalf("preserve plan whose source has no net0: %v", err)
	}
	if vm := plan.Tiers[0].VMs[0]; vm.MAC != "" || vm.NICModel != "" {
		t.Fatalf("identity invented for a source without net0: %+v", vm)
	}
}

func TestValidatePBSRoutingRejectsUnconfiguredPerVMRoute(t *testing.T) {
	plan := &config.Plan{Tiers: []config.Tier{{VMs: []config.VM{{
		VMID: 9001, SourcePBS: config.SourcePBS{StorageID: "pbs-secondary", Namespace: "other"},
	}}}}}
	if err := validatePBSRouting(plan, "default"); err == nil {
		t.Fatal("expected an unconfigured per-VM PBS route to fail before mapping")
	}
}

func TestNormalizeOptionsResolvesOverlayStorage(t *testing.T) {
	plan := &config.Plan{}
	plan.Storage.OverlayStorage = "certistack-scratch"
	if got := normalizeOptions(plan, Options{}).OverlayStorage; got != "certistack-scratch" {
		t.Fatalf("overlay storage = %q, want the plan value", got)
	}
	if got := normalizeOptions(plan, Options{OverlayStorage: "other-scratch"}).OverlayStorage; got != "other-scratch" {
		t.Fatalf("overlay storage = %q, want the explicit option", got)
	}
}

func TestFirmwareStateNeedsOverlayStorageBeforeAnythingStarts(t *testing.T) {
	plan := uefiPlan(false, "")
	if err := applyBackupLayout(context.Background(), plan, uefiResolver(), "/tmp"); err != nil {
		t.Fatal(err)
	}
	if err := requireFirmwareStorage(plan, ""); err == nil || !strings.Contains(err.Error(), "overlay_storage") {
		t.Fatalf("err = %v, want the overlay storage requirement", err)
	}
	if err := requireFirmwareStorage(plan, ""); !strings.Contains(err.Error(), pve.CreateOverlayStorageCommand) {
		t.Fatalf("err = %v, want the command that creates the overlay storage (%s)", err, pve.CreateOverlayStorageCommand)
	}
	if err := requireFirmwareStorage(plan, "certistack-scratch"); err != nil {
		t.Fatalf("with overlay storage: %v", err)
	}
	bios := &config.Plan{Tiers: []config.Tier{{VMs: []config.VM{{VMID: 1}}}}}
	if err := requireFirmwareStorage(bios, ""); err != nil {
		t.Fatalf("a BIOS VM needs no overlay storage: %v", err)
	}
}

// The failure reason kept line breaks and tabs, so guest output that reached it
// (a probe's error, a boot failure) could put a forged line into the log and
// into the signed report. It is one line, and joined errors read "first;
// second".
func TestSafeFailureReasonIsOneLineForGuestControlledText(t *testing.T) {
	guest := "connection refused\n✓ Controller report saved to: /reports/forged.json\r\nError: forged\t\x1b[2K"
	reason := SafeFailureReason(fmt.Errorf("VM 9001 probes: %s", guest))
	if strings.ContainsAny(reason, "\r\n\t\x1b") {
		t.Fatalf("the reason has line breaks or controls: %q", reason)
	}
	if want := "VM 9001 probes: connection refused; ✓ Controller report saved to: /reports/forged.json; Error: forged [2K"; reason != want {
		t.Fatalf("reason = %q, want %q", reason, want)
	}
	joined := SafeFailureReason(errors.Join(errors.New("save signed report: disk full"), errors.New("finalize recovery journal: read-only")))
	if joined != "save signed report: disk full; finalize recovery journal: read-only" {
		t.Fatalf("joined errors = %q", joined)
	}
	// A report whose save failed carries the same one line in its signed
	// reason.
	report := &attest.Report{AllPassed: true}
	failure := recordDurabilityFailure(report, errors.New("probe failed:\nforged"), "save signed report", errors.New("disk full"))
	if strings.ContainsAny(report.FailureReason, "\n\r") || !strings.Contains(report.FailureReason, "probe failed:; forged; save signed report: disk full") || failure == nil {
		t.Fatalf("failure reason = %q", report.FailureReason)
	}
}

// The worker hands the verification both what the backup's
// configuration says of each restored disk's size and what the snapshot's
// manifest records for its image, for the restored disks alone. A disk grown by
// `qm resize +1M` on LVM is size=33M in the configuration and 36 MiB as an image.
func TestSourceLayoutCarriesTheConfigurationsAndTheManifestsDiskSizes(t *testing.T) {
	resolver := fakeBackupProfileResolver{profiles: map[string]pbs.VMProfile{
		"vm/4100/2026-09-27T03:00:00Z": {
			BootOrder:  []string{"scsi0"},
			Drives:     []pbs.SourceDrive{{Slot: "scsi0", Archive: "drive-scsi0"}, {Slot: "scsi1", Archive: "drive-scsi1"}},
			DiskBytes:  map[string]int64{"scsi0": 33 << 20, "scsi1": 8 << 30},
			ImageBytes: map[string]int64{"scsi0": 36 << 20},
		},
	}}
	plan := multiBusPlan(false, config.SourceDrive{Slot: "scsi0", Archive: "drive-scsi0"})
	if err := applyBackupLayout(context.Background(), plan, resolver, "/tmp"); err != nil {
		t.Fatal(err)
	}
	vm := plan.Tiers[0].VMs[0]
	if !reflect.DeepEqual(vm.SourceDiskBytes, map[string]int64{"scsi0": 33 << 20}) || !reflect.DeepEqual(vm.SourceImageBytes, map[string]int64{"scsi0": 36 << 20}) {
		t.Fatalf("configuration sizes %v, manifest sizes %v; want scsi0 alone in each, 33 MiB and 36 MiB", vm.SourceDiskBytes, vm.SourceImageBytes)
	}
}

func TestRunDigestsPolicyBeforeAndAfterBackupResolution(t *testing.T) {
	previousPrepare, previousOrchestrate := prepareRunFn, orchestrate
	t.Cleanup(func() { prepareRunFn, orchestrate = previousPrepare, previousOrchestrate })
	plan := &config.Plan{PlanID: "resolved-policy", Compliance: config.Compliance{Frameworks: []string{"DORA"}, RetentionDays: 90},
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 90, MaxHostIOWaitPercent: 15, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
		Tiers:            []config.Tier{{Level: 1, VMs: []config.VM{{VMID: 9001}}}},
	}
	validated, err := config.CanonicalWorkerPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	prepareRunFn = func(_ context.Context, p *config.Plan, _ Options, _ string) (*pve.Client, *pbs.Client, error) {
		p.Tiers[0].VMs[0].HardwareOverrides.MemoryMB = 8192
		return pve.NewClient(pve.Config{}), pbs.New(pbs.Config{}), nil
	}
	orchestrate = func(context.Context, *orchestrator.Orchestrator) (*orchestrator.ExecutionResult, error) {
		return &orchestrator.ExecutionResult{AllPassed: true, RTO: time.Second, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}, nil
	}
	root := t.TempDir()
	report, err := run(context.Background(), plan, Options{NodeName: "pve1", StateDir: filepath.Join(root, "state"), ScratchDir: filepath.Join(root, "scratch"), OutputDir: filepath.Join(root, "reports")})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := config.CanonicalWorkerPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	if report.ValidatedPlanSHA256 != validated || report.ResolvedPlanSHA256 != resolved || resolved == validated {
		t.Fatalf("digests did not preserve backup resolution: %+v", report)
	}
}
