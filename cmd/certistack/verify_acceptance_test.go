// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

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

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/google/uuid"
)

// The fixture identity of the signed test reports. Release tooling outside this
// repository builds the CLI with these exact -ldflags values and checks the
// fixtures TestWriteCampaignEvidenceFixtures writes, so keep them in sync.
const (
	fixtureNode      = "node-a"
	fixtureVersion   = "v0.1.0-campaign-fixture"
	fixtureCommit    = "0123456789ab"
	fixtureBuildDate = "2026-09-29T00:00:00Z"
	fixturePlanPath  = "../../testdata/plans/valid_plan.yaml"
)

// campaignFixture is one signed report variant. Mode is the campaign mode
// (and verify-report --expect-outcome) that evaluates it; accepted is the
// correct verdict. The first thirteen are the basic campaign cases, built as
// the controller really builds reports: a fault drill's target VM is "failed"
// and its later tiers never start.
type campaignFixture struct {
	name      string
	mode      string
	accepted  bool
	testMode  bool
	untrusted bool
	// unbound is a report verify-report accepts on what it records while its
	// verdict lists a NOT BOUND entry (an earlier schema, or no plan digest):
	// a campaign must not credit it.
	unbound bool
	// reason is the signed failure reason of a denied (capacity guard) fixture.
	reason string
	mutate func(report *attest.Report)
}

// The signed failure reasons the product gives a capacity refusal, and one it
// gives a run that failed for another reason before any VM was restored.
const (
	fixtureAdmissionReason = "admission control guardrail triggered: max admission retries exceeded"
	fixturePreflightReason = "node preflight failed: memory: available RAM 512 MB is below required 4096 MB"
	fixtureSDNFailure      = "SDN sandbox setup failed: create zone csSb01: 500 zone already exists"
)

var campaignFixtures = []campaignFixture{
	{name: "matching_control", mode: accept.OutcomePass, accepted: true},
	{name: "wrong_build", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.EngineVersion, r.GitCommit = "v0.0.9", "1111111" }},
	{name: "wrong_node", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.NodeFQDN = "unrequested-node" }},
	{name: "no_vms", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.VMRecords = nil }},
	{name: "failed_probe_under_pass", mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		r.VMRecords[0].ProbeResults[0].Passed = false
		r.VMRecords[0].AllPassed = false
	}},
	{name: "incomplete_vm", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.VMRecords[0].VerificationStatus = "incomplete" }},
	{name: "wrong_plan_control", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.PlanID = "different-plan" }},
	{name: "unclean_control", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.TeardownEvidence.AllCleaned = false }},
	{name: "untrusted_control", mode: accept.OutcomePass, untrusted: true},
	{name: "fault_exact_control", mode: accept.OutcomeFault, accepted: true},
	{name: "fault_vmid_prefix", mode: accept.OutcomeFault, mutate: func(r *attest.Report) { r.VMRecords[0].VMID = 90010 }},
	{name: "fault_wrong_vm_control", mode: accept.OutcomeFault, mutate: func(r *attest.Report) {
		// Tier 1 passed; the failure is on VM 9002 in tier 2.
		r.VMRecords[0] = passedRecord(r.VMRecords[0])
		failed := failedRecord(r.VMRecords[0])
		failed.VMID, failed.SourceVMID, failed.Name = 9002, 200, "cs-test-db01"
		failed.ProbeResults = []probe.Result{
			{Type: "tcp", Target: "192.0.2.20:5432", Description: "LDAP TCP handshake on domain controller", Error: "synthetic fault"},
			{Type: "qga", Target: "systemctl is-active postgresql@16-main", Description: "Verify PostgreSQL service is active via guest agent", Passed: true},
		}
		r.VMRecords = append(r.VMRecords, failed)
	}},
	{name: "fault_protocol_control", mode: accept.OutcomeFault, mutate: func(r *attest.Report) { r.VMRecords[0].ProbeResults[0].Type = "http" }},

	// Further cases the campaign must reject.
	{name: "fault_collateral_failure", mode: accept.OutcomeFault, mutate: func(r *attest.Report) {
		r.VMRecords[0].ProbeResults[1].Passed = false
		r.VMRecords[0].ProbeResults[1].Error = "unexpected second failure"
	}},
	{name: "fault_other_description", mode: accept.OutcomeFault, mutate: func(r *attest.Report) {
		r.VMRecords[0].ProbeResults[0].Description = "DNS TCP listener on domain controller"
	}},
	{name: "fault_unclean", mode: accept.OutcomeFault, mutate: func(r *attest.Report) { r.TeardownEvidence.AllCleaned = false }},
	{name: "fault_later_tier_started", mode: accept.OutcomeFault, mutate: func(r *attest.Report) {
		r.VMRecords = append(r.VMRecords, passedRecordFor(mustLoadFixturePlan(), 9002))
	}},
	{name: "optional_qga_skipped", mode: accept.OutcomePass, accepted: true, mutate: func(r *attest.Report) {
		r.VMRecords[0].ProbeResults[2].Skipped = true
	}},
	{name: "required_probe_skipped", mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		r.VMRecords[0].ProbeResults[0].Skipped = true
	}},
	{name: "missing_probe_result", mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		r.VMRecords[1].ProbeResults = r.VMRecords[1].ProbeResults[:1]
	}},
	{name: "extra_vm", mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		extra := passedRecord(r.VMRecords[2])
		extra.VMID, extra.SourceVMID, extra.SourceSnapshot = 9004, 400, "vm/400/2026-09-27T03:12:59Z"
		r.VMRecords = append(r.VMRecords, extra)
	}},
	{name: "duplicate_vm", mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		r.VMRecords[2] = r.VMRecords[1]
	}},
	{name: "wrong_source_vm", mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		r.VMRecords[0].SourceVMID, r.VMRecords[0].SourceSnapshot = 101, "vm/101/2026-09-27T03:12:59Z"
	}},
	// A record that names no backup, or a snapshot of another VM than
	// its own source, contradicts itself and needs no request to be refused.
	{name: "no_source_snapshot", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "" }},
	{name: "snapshot_of_another_vm", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.VMRecords[0].SourceSnapshot = "vm/999/2026-09-27T03:12:59Z" }},
	{name: "integrity_skipped_in_full_mode", mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		r.VMRecords[1].SourceDisks[0].IntegrityStatus = "skipped_test_mode"
		r.VMRecords[1].SourceDisks[0].ImageDigest = ""
	}},
	{name: "journal_not_verified", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.TeardownEvidence.JournalRecoveryVerified = false }},
	{name: "test_mode_report", mode: accept.OutcomePass, testMode: true},

	// Gates on the evidence itself.
	{name: "probe_target_mismatch", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.VMRecords[0].ProbeResults[0].Target = "203.0.113.99:22" }},
	{name: "duplicate_disk_slot", mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		r.VMRecords[0].SourceDisks = append(r.VMRecords[0].SourceDisks, r.VMRecords[0].SourceDisks[0])
	}},
	{name: "boot_disk_without_evidence", mode: accept.OutcomePass, mutate: func(r *attest.Report) {
		r.VMRecords[0].RestoredHardware = &probe.RestoredHardware{BootDisk: "scsi9"}
	}},
	{name: "boot_disk_recorded", mode: accept.OutcomePass, accepted: true, mutate: func(r *attest.Report) {
		r.VMRecords[0].RestoredHardware = &probe.RestoredHardware{BootDisk: "scsi0"}
	}},
	{name: "schema_newer_minor", mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.ReportSchemaVersion = "1.99" }},
	// An accepted verdict is not necessarily a bound one: a report that predates
	// the evidence is accepted on what it records, and the campaign helper must
	// not credit it.
	{name: "unbound_older_schema", mode: accept.OutcomePass, accepted: true, unbound: true, mutate: func(r *attest.Report) {
		r.ReportSchemaVersion, r.PlanSHA256 = "1.5", ""
	}},
	{name: "unbound_no_plan_digest", mode: accept.OutcomePass, accepted: true, unbound: true, mutate: func(r *attest.Report) { r.PlanSHA256 = "" }},
	{name: "unbound_fault_older_schema", mode: accept.OutcomeFault, accepted: true, unbound: true, mutate: func(r *attest.Report) {
		r.ReportSchemaVersion = "1.5"
	}},
	{name: "guard_admission_control", mode: accept.OutcomeDenied, accepted: true, reason: fixtureAdmissionReason},
	{name: "guard_preflight_memory", mode: accept.OutcomeDenied, accepted: true, reason: fixturePreflightReason},
	{name: "guard_sdn_failure", mode: accept.OutcomeDenied, reason: fixtureSDNFailure},
	{name: "guard_unclean", mode: accept.OutcomeDenied, reason: fixtureAdmissionReason, mutate: func(r *attest.Report) { r.TeardownEvidence.AllCleaned = false }},
	{name: "guard_started_a_vm", mode: accept.OutcomeDenied, reason: fixtureAdmissionReason, mutate: func(r *attest.Report) {
		r.VMRecords = append(r.VMRecords, passedRecordFor(mustLoadFixturePlan(), 9001))
	}},
}

func mustLoadFixturePlan() *config.Plan {
	plan, err := config.LoadFromFileForWorker(fixturePlanPath)
	if err != nil {
		panic(fmt.Sprintf("load fixture plan: %v", err))
	}
	return plan
}

// fixtureSnapshot is the snapshot a worker records for a planned VM: the one
// the plan pins, or the latest of the source VM's group as the worker resolved it.
func fixtureSnapshot(vm config.VM) string {
	if pinned := strings.TrimSpace(vm.SourcePBS.Snapshot); strings.Count(pinned, "/") == 2 {
		return pinned
	}
	return fmt.Sprintf("vm/%d/2026-09-27T03:12:59Z", attest.ExpectedSourceVMID(vm))
}

func fixtureDigest(vmid int, slot string) string {
	return fmt.Sprintf("%064x", vmid)[:56] + hex.EncodeToString([]byte(slot))[:8]
}

// passedRecordFor is a verified VM record for one planned VM, as the
// orchestrator writes it after every configured probe passed.
func passedRecordFor(plan *config.Plan, vmid int) probe.VMValidationRecord {
	vm := findPlanVM(plan, vmid)
	record := probe.VMValidationRecord{
		VMID:               vm.VMID,
		SourceVMID:         vm.SourceVMID,
		Name:               vm.Name,
		VerificationStatus: "verified",
		AllPassed:          true,
		SourceSnapshot:     fixtureSnapshot(*vm),
		SourceDisks: []probe.SourceDiskEvidence{{
			Slot:              "scsi0",
			Archive:           "drive-scsi0",
			ManifestReference: "drive-scsi0.img.fidx",
			IntegrityStatus:   "verified",
			ImageDigest:       fixtureDigest(vm.VMID, "scsi0"),
		}},
	}
	for _, configured := range vm.Probes {
		record.ProbeResults = append(record.ProbeResults, recordedResult(plan, configured))
	}
	if soakSec := planSoakSec(plan, vm.VMID); soakSec > 0 {
		record.Soak = fixtureSoak(record, *vm, soakSec)
	}
	return record
}

// fixtureSoak is the summary of the service checks an honest worker records
// for a VM whose tier held it for soakSec seconds (schema 1.7): a check every
// 30 s and one when the period ends, all passed.
func fixtureSoak(record probe.VMValidationRecord, vm config.VM, soakSec int) *probe.SoakEvidence {
	started := time.Date(2026, 9, 29, 11, 0, 0, 0, time.UTC)
	samples := soakSec/30 + 1
	soak := &probe.SoakEvidence{
		ConfiguredSec: soakSec, IntervalSec: 30, Samples: samples, StatusReads: samples + 1,
		StartedAt:     started.Format(time.RFC3339),
		FirstSampleAt: started.Add(time.Duration(min(30, soakSec)) * time.Second).Format(time.RFC3339),
		LastSampleAt:  started.Add(time.Duration(soakSec) * time.Second).Format(time.RFC3339),
	}
	for index, configured := range vm.Probes {
		if config.IsGuestLevelProbe(configured.Type) {
			soak.Probes = append(soak.Probes, probe.SoakProbeEvidence{
				Probe: index + 1, Type: record.ProbeResults[index].Type, Description: record.ProbeResults[index].Description,
				Passed: samples, WorstDuration: 5 * time.Millisecond,
			})
		}
	}
	return soak
}

// recordedResult is the passing result of a probe that ran once under its
// plan, as the orchestrator's probe stage records it in report schema 1.6:
// the target the prober builds, and the policy the probe ran under.
func recordedResult(plan *config.Plan, configured config.Probe) probe.Result {
	target, _ := attest.ExpectedProbeTarget(configured)
	result := probe.Result{
		Type: configured.Type, Target: target, Description: configured.Description, Passed: true,
		TimeoutSec: configured.TimeoutSec, Retries: max(configured.Retries, 0), Attempts: 1,
	}
	switch configured.Type {
	case "qga":
		result.RequireQGA = configured.RequireQGA
	case "http", "mssql":
		result.ServerName = configured.ServerName
	case "screendump":
		result.ImageSHA256 = strings.Repeat("ab", 32)
	}
	if config.IsWireProbe(configured.Type) {
		result.SourceInterface, result.SourceAddress = plan.Network.VNetID, strings.TrimSpace(plan.Network.ProbeIP)
	}
	return result
}

// fixturePlanDigest is plan_sha256 of the fixture plan: the digest of its file.
func fixturePlanDigest() string {
	data, err := os.ReadFile(fixturePlanPath)
	if err != nil {
		panic(fmt.Sprintf("read fixture plan: %v", err))
	}
	return config.PlanDigest(data)
}

func passedRecord(record probe.VMValidationRecord) probe.VMValidationRecord {
	record.VerificationStatus = "verified"
	record.AllPassed = true
	record.ProbeResults = append([]probe.Result(nil), record.ProbeResults...)
	for index := range record.ProbeResults {
		record.ProbeResults[index].Passed = true
		record.ProbeResults[index].Error = ""
	}
	return record
}

func failedRecord(record probe.VMValidationRecord) probe.VMValidationRecord {
	record.VerificationStatus = "failed"
	record.AllPassed = false
	record.ProbeResults = append([]probe.Result(nil), record.ProbeResults...)
	record.ProbeResults[0].Passed = false
	record.ProbeResults[0].Error = "synthetic fault"
	return record
}

// campaignFixtureReport builds the unsigned report for one fixture. A pass
// fixture records every planned VM verified; a fault fixture records the
// fault plan's target (VM 9001, first probe) failed and, as the orchestrator
// stops at a failing tier, nothing from later tiers.
func campaignFixtureReport(plan *config.Plan, fixture campaignFixture) *attest.Report {
	report := &attest.Report{
		ReportSchemaVersion: attest.CurrentReportSchemaVersion,
		ReportID:            uuid.NewString(),
		Timestamp:           "2026-09-29T12:00:00Z",
		PlanID:              plan.PlanID,
		PlanName:            plan.Name,
		PlanSHA256:          fixturePlanDigest(),
		ValidationMode:      attest.ValidationModeFullIntegrity,
		NodeFQDN:            fixtureNode,
		EngineVersion:       fixtureVersion,
		GitCommit:           fixtureCommit,
		BuildDate:           fixtureBuildDate,
		Frameworks:          plan.Compliance.Frameworks,
		RetentionDays:       plan.Compliance.RetentionDays,
		RTOTargetSeconds:    attest.RTOObjective(plan),
		Admission:           attest.NewAdmissionEvidence(plan),
		AllPassed:           true,
		TeardownEvidence: &attest.TeardownEvidence{
			VMStoppedAndDestroyed:   true,
			SDNProvisioning:         "preprovisioned",
			SDNZoneValidated:        plan.Network.ZoneID,
			SDNVNetValidated:        plan.Network.VNetID,
			OrphanSweepClean:        true,
			AllCleaned:              true,
			JournalRecoveryVerified: true,
			VerifiedAt:              "2026-09-29T12:00:01Z",
		},
	}
	switch fixture.mode {
	case accept.OutcomeFault:
		report.AllPassed = false
		report.FailureReason = "recovery tier 1 failed: VM 9001 probes: synthetic fault"
		report.VMRecords = []probe.VMValidationRecord{failedRecord(passedRecordFor(plan, 9001))}
	case accept.OutcomeDenied:
		// A refusal before any VM was restored, as the node worker's report
		// for a preflight refusal or the orchestrator's for an admission denial.
		report.AllPassed = false
		report.FailureReason = fixture.reason
	default:
		for _, tier := range plan.Tiers {
			for _, vm := range tier.VMs {
				report.VMRecords = append(report.VMRecords, passedRecordFor(plan, vm.VMID))
			}
		}
	}
	if fixture.mode != accept.OutcomeDenied {
		// A run that restored VMs was admitted: its one check granted it.
		report.Admission = fixtureGrantedAdmission(report.Admission)
	}
	if fixture.testMode {
		report.ValidationMode = attest.ValidationModeTestSkipIntegrity
		for vmIndex := range report.VMRecords {
			for diskIndex := range report.VMRecords[vmIndex].SourceDisks {
				report.VMRecords[vmIndex].SourceDisks[diskIndex].IntegrityStatus = "skipped_test_mode"
				report.VMRecords[vmIndex].SourceDisks[diskIndex].ImageDigest = ""
			}
		}
	}
	if fixture.mutate != nil {
		fixture.mutate(report)
	}
	return report
}

func fixtureExpectations(plan *config.Plan, outcome string) accept.Expectations {
	node, version, commit, buildDate, mode := fixtureNode, fixtureVersion, fixtureCommit, fixtureBuildDate, attest.ValidationModeFullIntegrity
	return accept.Expectations{Outcome: outcome, Plan: plan, PlanSHA256: fixturePlanDigest(), Node: &node, Version: &version, Commit: &commit, BuildDate: &buildDate, ValidationMode: &mode}
}

// Each campaign fixture receives the correct verdict when bound to the
// requested plan, node, build, and mode.
func TestReportAcceptanceCampaignFixtures(t *testing.T) {
	plan := mustLoadFixturePlan()
	for _, fixture := range campaignFixtures {
		if fixture.untrusted {
			continue // A signature failure, covered by TestVerifyReportAcceptanceCLI.
		}
		t.Run(fixture.name, func(t *testing.T) {
			report := campaignFixtureReport(plan, fixture)
			acceptance := accept.Evaluate(report, fixtureExpectations(plan, fixture.mode))
			if accepted := acceptance.Verdict == accept.Accepted; accepted != fixture.accepted {
				t.Fatalf("verdict = %s, want accepted=%v; reasons: %q", acceptance.Verdict, fixture.accepted, acceptance.Reasons)
			}
			if fixture.accepted && len(acceptance.Reasons) != 0 {
				t.Fatalf("accepted verdict carries reasons: %q", acceptance.Reasons)
			}
			if !fixture.accepted && len(acceptance.Reasons) == 0 {
				t.Fatal("rejected verdict has no reason")
			}
			if fixture.unbound {
				// Accepted on what it records, and the verdict says what it
				// could not check, so a campaign does not credit it.
				unbound := 0
				for _, binding := range acceptance.Bindings {
					if strings.HasPrefix(binding, accept.UnboundPrefix) {
						unbound++
					}
				}
				if unbound == 0 {
					t.Fatalf("an unbound fixture lists no %q entry: %q", accept.UnboundPrefix, acceptance.Bindings)
				}
				return
			}
			if strings.Join(acceptance.Bindings, ",") != "plan,plan_sha256,probe_policy,rto_objective,admission_policy,node,build,validation_mode" {
				t.Fatalf("bindings = %q", acceptance.Bindings)
			}
		})
	}
}

// A failed probe on VM 90010 must never satisfy an expected VM 9001
// through a numeric prefix; the reasons name both VMs as integers.
func TestReportAcceptanceFaultComparesVMIDsAsIntegers(t *testing.T) {
	plan := mustLoadFixturePlan()
	for _, fixture := range campaignFixtures {
		if fixture.name != "fault_vmid_prefix" {
			continue
		}
		acceptance := accept.Evaluate(campaignFixtureReport(plan, fixture), fixtureExpectations(plan, accept.OutcomeFault))
		joined := strings.Join(acceptance.Reasons, "\n")
		if acceptance.Verdict != accept.Rejected || !strings.Contains(joined, "the failed probe is on VM 90010, not the fault plan's target VM 9001") {
			t.Fatalf("VM 90010 fault was not rejected for its VM: %s %q", acceptance.Verdict, acceptance.Reasons)
		}
		return
	}
	t.Fatal("fault_vmid_prefix fixture is missing")
}

// Build and node mismatches are named, not just counted.
func TestReportAcceptanceNamesIdentityMismatches(t *testing.T) {
	plan := mustLoadFixturePlan()
	cases := map[string]string{
		"wrong_build":        `the report was produced by CertiStack version "v0.0.9", not the expected "v0.1.0-campaign-fixture"`,
		"wrong_node":         `the report was produced on node "unrequested-node", not the expected node "node-a"`,
		"no_vms":             "the report records no VM",
		"incomplete_vm":      `VM 9001 verification_status is "incomplete", not "verified"`,
		"wrong_plan_control": `the report is for plan "different-plan", not the expected plan "acme-erp-full-stack-dr"`,
		"unclean_control":    "teardown_evidence.all_cleaned is false",
	}
	for _, fixture := range campaignFixtures {
		want, ok := cases[fixture.name]
		if !ok {
			continue
		}
		acceptance := accept.Evaluate(campaignFixtureReport(plan, fixture), fixtureExpectations(plan, fixture.mode))
		if !strings.Contains(strings.Join(acceptance.Reasons, "\n"), want) {
			t.Errorf("%s: reasons %q do not include %q", fixture.name, acceptance.Reasons, want)
		}
	}
	for _, fixture := range campaignFixtures {
		if fixture.name == "failed_probe_under_pass" {
			acceptance := accept.Evaluate(campaignFixtureReport(plan, fixture), fixtureExpectations(plan, fixture.mode))
			if !strings.Contains(strings.Join(acceptance.Reasons, "\n"), "top-level all_passed contradicts") {
				t.Errorf("failed probe under all_passed=true was not called a contradiction: %q", acceptance.Reasons)
			}
		}
	}
}

// Without expectations the verdict still rejects incomplete or
// contradictory evidence, and says that it bound nothing.
func TestReportAcceptanceWithoutExpectations(t *testing.T) {
	plan := mustLoadFixturePlan()
	for _, fixture := range campaignFixtures {
		if fixture.mode != accept.OutcomePass || fixture.untrusted {
			continue
		}
		acceptance := accept.Evaluate(campaignFixtureReport(plan, fixture), accept.Expectations{})
		wantAccepted := fixture.accepted
		switch fixture.name {
		case "wrong_build", "wrong_node", "wrong_plan_control", "missing_probe_result", "wrong_source_vm", "probe_target_mismatch":
			// Only a binding to the request can reveal these.
			wantAccepted = true
		case "extra_vm":
			// The extra record copies VM 9003's, probe results included, so two
			// VM records name one wire target: the report is its own evidence
			// that one answer is credited twice.
			wantAccepted = false
		}
		if accepted := acceptance.Verdict == accept.Accepted; accepted != wantAccepted {
			t.Errorf("%s: verdict %s without expectations; reasons %q", fixture.name, acceptance.Verdict, acceptance.Reasons)
		}
		if len(acceptance.Bindings) != 0 || acceptance.Outcome != accept.OutcomePass {
			t.Errorf("%s: unbound verdict reports bindings %q, outcome %q", fixture.name, acceptance.Bindings, acceptance.Outcome)
		}
	}
}

func TestReportAcceptanceTestModeAndDenied(t *testing.T) {
	plan := mustLoadFixturePlan()
	testMode := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass, testMode: true})
	lab := attest.ValidationModeTestSkipIntegrity
	exp := fixtureExpectations(plan, accept.OutcomePass)
	exp.ValidationMode, exp.AllowTestMode = &lab, true
	if acceptance := accept.Evaluate(testMode, exp); acceptance.Verdict != accept.Accepted {
		t.Fatalf("allowed test-mode report was rejected: %q", acceptance.Reasons)
	}
	full := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass})
	if acceptance := accept.Evaluate(full, exp); acceptance.Verdict != accept.Rejected {
		t.Fatal("a full-integrity report was accepted for a test-mode campaign")
	}

	denied := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass})
	denied.AllPassed, denied.VMRecords = false, nil
	denied.FailureReason = fixtureAdmissionReason
	if acceptance := accept.Evaluate(denied, fixtureExpectations(plan, accept.OutcomeDenied)); acceptance.Verdict != accept.Accepted {
		t.Fatalf("clean denial was rejected: %q", acceptance.Reasons)
	}
	started := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomeFault})
	if acceptance := accept.Evaluate(started, fixtureExpectations(plan, accept.OutcomeDenied)); acceptance.Verdict != accept.Rejected {
		t.Fatal("a run that restored a VM was accepted as a denial")
	}

	unsupported := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass})
	unsupported.ReportSchemaVersion = "2.0"
	if acceptance := accept.Evaluate(unsupported, fixtureExpectations(plan, accept.OutcomePass)); acceptance.Verdict != accept.Rejected {
		t.Fatal("an unsupported report schema was accepted")
	}
}

// A VM whose every result is a skipped optional guest-agent probe
// proved nothing about its service, even though no probe failed.
func TestReportAcceptanceRequiresAProbeThatRan(t *testing.T) {
	report := campaignFixtureReport(mustLoadFixturePlan(), campaignFixture{mode: accept.OutcomePass})
	report.VMRecords[0].ProbeResults = []probe.Result{{Type: "qga", Target: "ping", Description: "qga verification probe", Passed: true, Skipped: true}}
	acceptance := accept.Evaluate(report, accept.Expectations{})
	if acceptance.Verdict != accept.Rejected || !strings.Contains(strings.Join(acceptance.Reasons, "\n"), "VM 9001 has no guest-level assertion that ran") {
		t.Fatalf("skipped-only VM was not rejected: %s %q", acceptance.Verdict, acceptance.Reasons)
	}
}

func writeSignedFixture(t *testing.T, dir string, report *attest.Report, key ed25519.PrivateKey) string {
	t.Helper()
	if err := attesttest.SignReport(report, key); err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, report.ReportID+".json")
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runVerifyReport(args ...string) (string, error) {
	cmd := verifyReportCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), err
}

// The CLI prints the additive verdict and build/node facts, exits 1 for a
// rejected report when an expectation was given, and keeps its usual exit
// status without one.
func TestVerifyReportAcceptanceCLI(t *testing.T) {
	plan := mustLoadFixturePlan()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	trusted := hex.EncodeToString(public)
	expectArgs := []string{"--expect-plan", fixturePlanPath, "--expect-node", fixtureNode, "--expect-version", fixtureVersion, "--expect-commit", fixtureCommit, "--expect-build-date", fixtureBuildDate, "--expect-validation-mode", attest.ValidationModeFullIntegrity}

	for _, fixture := range campaignFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			key := private
			if fixture.untrusted {
				if _, key, err = attesttest.GenerateKeyPair(); err != nil {
					t.Fatal(err)
				}
			}
			path := writeSignedFixture(t, dir, campaignFixtureReport(plan, fixture), key)
			args := append([]string{"--format", "json", "--trusted-key", trusted, "--expect-outcome", fixture.mode}, expectArgs...)
			output, err := runVerifyReport(append(args, path)...)
			if fixture.untrusted {
				if err == nil || exitCodeForError(err) != exitCodeInfrastructure || output != "" {
					t.Fatalf("untrusted signer: err=%v output=%q", err, output)
				}
				return
			}
			var summary reportVerificationSummary
			if decodeErr := json.Unmarshal([]byte(output), &summary); decodeErr != nil {
				t.Fatalf("decode summary: %v; output=%q", decodeErr, output)
			}
			if !summary.SignatureValid {
				t.Fatal("trusted signature not reported valid")
			}
			if fixture.accepted {
				if err != nil || summary.Acceptance.Verdict != accept.Accepted {
					t.Fatalf("accepted fixture: err=%v acceptance=%+v", err, summary.Acceptance)
				}
				return
			}
			if fixture.testMode {
				// Without --allow-test-mode the test-mode refusal (exit 2)
				// applies, and the verdict says why.
				if err == nil || summary.Acceptance.Verdict != accept.Rejected || summary.AllPassed {
					t.Fatalf("test-mode fixture: err=%v summary=%+v", err, summary)
				}
				return
			}
			var coded *exitCodeError
			if err == nil || !errors.As(err, &coded) || coded.code != exitCodeValidationFailed || summary.Acceptance.Verdict != accept.Rejected {
				t.Fatalf("rejected fixture: err=%v acceptance=%+v", err, summary.Acceptance)
			}
		})
	}

	// The summary exposes the signed build and node identity.
	path := writeSignedFixture(t, dir, campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass}), private)
	output, err := runVerifyReport("--format", "json", "--trusted-key", trusted, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"node_fqdn":"node-a"`, `"engine_version":"v0.1.0-campaign-fixture"`, `"git_commit":"0123456789ab"`, `"build_date":"2026-09-29T00:00:00Z"`, `"acceptance":{"verdict":"accepted","expected_outcome":"pass","bindings":[],"authenticated":true}`} {
		if !strings.Contains(output, want) {
			t.Fatalf("summary lacks %s: %s", want, output)
		}
	}

	// Without an expectation, a rejected verdict keeps the usual exit status:
	// the signature is valid, and the verdict is informational.
	rejected := campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass, mutate: func(r *attest.Report) { r.VMRecords = nil }})
	path = writeSignedFixture(t, dir, rejected, private)
	output, err = runVerifyReport("--trusted-key", trusted, path)
	if err != nil {
		t.Fatalf("unbound rejected verdict changed the exit status: %v", err)
	}
	if !strings.Contains(output, "Acceptance:  REJECTED as pass evidence (internal consistency only") || !strings.Contains(output, "- the report records no VM") {
		t.Fatalf("text output does not show the rejected verdict: %q", output)
	}
	if _, err = runVerifyReport("--trusted-key", trusted, "--expect-outcome", "pass", path); err == nil {
		t.Fatal("an explicit --expect-outcome did not make a rejected verdict fail")
	}
}

func TestVerifyReportRejectsUnusableExpectations(t *testing.T) {
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plan := mustLoadFixturePlan()
	path := writeSignedFixture(t, t.TempDir(), campaignFixtureReport(plan, campaignFixture{mode: accept.OutcomePass}), private)
	trusted := hex.EncodeToString(public)
	cases := map[string][]string{
		"empty node":               {"--expect-node", ""},
		"blank commit":             {"--expect-commit", "  "},
		"unknown outcome":          {"--expect-outcome", "passed"},
		"fault without plan":       {"--expect-outcome", "fault"},
		"unknown validation mode":  {"--expect-validation-mode", "full"},
		"test mode without opt-in": {"--expect-validation-mode", attest.ValidationModeTestSkipIntegrity},
		"missing plan":             {"--expect-plan", filepath.Join(t.TempDir(), "absent.yaml")},
	}
	for name, flags := range cases {
		args := append([]string{"--format", "json", "--trusted-key", trusted}, flags...)
		output, err := runVerifyReport(append(args, path)...)
		if err == nil || output != "" {
			t.Errorf("%s: err=%v output=%q", name, err, output)
		}
	}
}

// TestWriteCampaignEvidenceFixtures writes signed fixture reports for release
// tooling that runs them through the real verifier. It is skipped unless
// CERTISTACK_CAMPAIGN_FIXTURES names an output directory. The signing key is
// generated here and never written.
func TestWriteCampaignEvidenceFixtures(t *testing.T) {
	dir := os.Getenv("CERTISTACK_CAMPAIGN_FIXTURES")
	if dir == "" {
		t.Skip("CERTISTACK_CAMPAIGN_FIXTURES is not set")
	}
	plan := mustLoadFixturePlan()
	public, private, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trusted.pub"), []byte(hex.EncodeToString(public)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var index strings.Builder
	for _, fixture := range campaignFixtures {
		key := private
		if fixture.untrusted {
			if _, key, err = attesttest.GenerateKeyPair(); err != nil {
				t.Fatal(err)
			}
		}
		report := campaignFixtureReport(plan, fixture)
		// The executable the campaign helper runs and hashes; a real report
		// signs the digest of the controller that produced it.
		if digest := os.Getenv("CERTISTACK_CAMPAIGN_WORKER_SHA256"); digest != "" {
			report.WorkerSHA256 = digest
		}
		if err := attesttest.SignReport(report, key); err != nil {
			t.Fatal(err)
		}
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fixture.name+".json"), append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		// What the campaign helper must do with it: the verifier's acceptance,
		// unless the verdict is not a bound one.
		verdict := "reject"
		if fixture.accepted && !fixture.unbound {
			verdict = "accept"
		}
		// The campaign mode that evaluates the fixture: a pass is a positive
		// case, a denial a capacity guard.
		mode := fixture.mode
		switch mode {
		case accept.OutcomePass:
			mode = "positive"
		case accept.OutcomeDenied:
			mode = "guard"
		}
		testMode := "full"
		if fixture.testMode {
			testMode = "test"
		}
		fmt.Fprintf(&index, "%s\t%s\t%s\t%s\t%s\n", fixture.name, mode, verdict, testMode, fixture.reason)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixtures.tsv"), []byte(index.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

// fixtureGrantedAdmission is the admission evidence of a worker whose single
// check admitted the plan's run on a node of 1 000 000 MiB with 900 000 MiB
// free: the policy and the reservation are the plan's, and the measurements
// add up.
func fixtureGrantedAdmission(evidence *attest.AdmissionEvidence) *attest.AdmissionEvidence {
	const total, available = 1_000_000.0, 900_000.0
	return evidence.WithEvaluation(admission.Evaluation{
		Checks: 1, Decision: admission.DecisionGranted,
		HostTotalMiB: total, HostAvailableMiB: available,
		HostRAMPercent: (total - available) / total * 100, HostIOWaitPercent: 0.5,
		ProjectedRAMPercent: (total - available + float64(evidence.RecoveryReservationMiB)) / total * 100,
	})
}
