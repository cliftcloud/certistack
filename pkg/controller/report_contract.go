// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	progresspkg "github.com/cliftcloud/certistack/pkg/progress"
)

// reportClockSkew is how far a report's timestamp may lie outside the
// controller's own run: the node's clock and the controller's are two
// clocks, and a difference of minutes is ordinary. More than this says the
// node's clock is wrong, or the report is not from this run.
const reportClockSkew = 10 * time.Minute

// maxReportProblems bounds how many contradictions an error lists.
const maxReportProblems = 12

// reportExpectation is what the controller asked for, and can therefore hold
// a worker's report to.
type reportExpectation struct {
	plan          *config.Plan
	node          string
	runID         string
	skipIntegrity bool
	// startedAt is when the controller began the run, and now is when it
	// checks the report.
	startedAt time.Time
	now       time.Time
	// workerError is the error the worker's result carried with the report:
	// a validation that failed, or a run a signal interrupted.
	workerError string
}

// checkWorkerReport holds a worker's report to what the controller requested
// before it signs it: the run, node, mode and plan it asked for, a timestamp
// from its own run, the population of VMs and probes the plan defines, and
// the report's own consistency. The worker is the less-trusted tier, and a
// signature over its words certifies them as the controller's: a report that
// names another node or run, comes from another time, relabels its mode, or
// omits, adds or contradicts the work requested is refused, never repaired
// by overwriting what it says. What the worker observed on
// the node, such as a probe's result or an image digest, is still its
// observation, which no check here can independently confirm.
//
// A report that does not claim a pass is checked for identity and
// consistency, and for the backup each of its VM records names,
// only: a run that failed partway legitimately has a partial population, and
// partial probe results.
//
// The report's schema is exactly the one this build writes. The worker is the
// controller's own executable, uploaded for the run, so a worker that declares
// another schema is not that executable, and an older schema would be signed
// as a report that never recorded the evidence this build's verifier holds a
// report to.
func checkWorkerReport(report *attest.Report, want reportExpectation) error {
	var problems []string
	problem := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	if report.ReportSchemaVersion != attest.CurrentReportSchemaVersion {
		problem("report_schema_version %q is not the schema %s this controller's worker writes", boundedText(report.ReportSchemaVersion), attest.CurrentReportSchemaVersion)
	}
	// The worker never signs: only a controller's Signer does, after these checks.
	// A report that comes back carrying a signature, a key, a fingerprint or a
	// timestamp of one is not the report of the executable that was uploaded, and
	// without a Signer nothing would overwrite the members, so they would be saved
	// as if the run had signed.
	for _, member := range signatureMembersOf(report) {
		problem("the report carries a signature member (%q), and the worker never signs: it is not the report of the worker that was started", member)
	}
	if report.ValidatedPlanSHA256 == "" || report.ResolvedPlanSHA256 == "" {
		problem("the report records no complete validated and resolved worker-plan digests")
	}
	if report.NodeFQDN != want.node {
		problem("the report names node %q, and the run was on node %q", boundedText(report.NodeFQDN), want.node)
	}
	switch {
	case report.RunID == "":
		problem("the report names no run, so it cannot be tied to this invocation")
	case report.RunID != want.runID:
		problem("the report names run %q, and this run is %q", boundedText(report.RunID), want.runID)
	}
	wantMode := attest.ValidationModeFullIntegrity
	if want.skipIntegrity {
		wantMode = attest.ValidationModeTestSkipIntegrity
	}
	if report.ValidationMode != wantMode {
		problem("the report's validation mode is %q, and %q was requested", boundedText(report.ValidationMode), wantMode)
	}
	if stamp, err := time.Parse(time.RFC3339, report.Timestamp); err != nil {
		problem("the report's timestamp %q is not an RFC 3339 time", boundedText(report.Timestamp))
	} else if stamp.Before(want.startedAt.Add(-reportClockSkew)) || stamp.After(want.now.Add(reportClockSkew)) {
		problem("the report's timestamp %s is not from this run (it ran from %s to %s, allowing %s of difference between the node's clock and the controller's); check the node's clock",
			stamp.UTC().Format(time.RFC3339), want.startedAt.UTC().Format(time.RFC3339), want.now.UTC().Format(time.RFC3339), reportClockSkew)
	}
	plan := want.plan
	if report.PlanID != plan.PlanID {
		problem("the report is for plan %q, not %q", boundedText(report.PlanID), plan.PlanID)
	}
	if report.PlanName != plan.Name {
		problem("the report names plan %q, and the plan is named %q", boundedText(report.PlanName), plan.Name)
	}
	if !sameStrings(report.Frameworks, plan.Compliance.Frameworks) {
		problem("the report's compliance frameworks %q are not the plan's %q", report.Frameworks, plan.Compliance.Frameworks)
	}
	if report.RetentionDays != plan.Compliance.RetentionDays {
		problem("the report's retention_days %d is not the plan's %d", report.RetentionDays, plan.Compliance.RetentionDays)
	}
	// The objective and the host admission policy the run was held to are the
	// plan's, and what the admission check decided is consistent with them
	// (the verifier applies the same rules).
	for _, message := range attest.PolicyEvidenceProblems(report, plan) {
		problem("%s", boundedMessage(message))
	}
	if report.AllPassed && want.workerError != "" {
		problem("the report claims a pass, and the worker's result reports an error (%s)", boundedText(want.workerError))
	}
	checkReportPopulation(report, plan, wantMode, problem)
	if len(problems) == 0 {
		return nil
	}
	shown := problems
	more := ""
	if len(shown) > maxReportProblems {
		shown, more = shown[:maxReportProblems], fmt.Sprintf("; and %d more", len(problems)-maxReportProblems)
	}
	return fmt.Errorf("the node worker's report contradicts what was requested: %s%s", strings.Join(shown, "; "), more)
}

// signatureMembersOf names the signature members a report carries.
func signatureMembersOf(report *attest.Report) []string {
	var members []string
	if report.Signature != "" {
		members = append(members, "signature")
	}
	if report.PublicKey != "" {
		members = append(members, "public_key")
	}
	if report.SignerFingerprint != "" {
		members = append(members, "signer_fingerprint")
	}
	if report.SignatureTimestamp != nil {
		members = append(members, attest.TimestampMember)
	}
	return members
}

// checkReportPopulation checks the VM records against the plan's VMs and
// probes, and the report's pass against them.
func checkReportPopulation(report *attest.Report, plan *config.Plan, wantMode string, problem func(string, ...any)) {
	planned := make(map[int]config.VM)
	soakSec := make(map[int]int)
	var order []int
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			planned[vm.VMID] = vm
			soakSec[vm.VMID] = tier.SoakTimeSec
			order = append(order, vm.VMID)
		}
	}
	recorded := make(map[int]probe.VMValidationRecord)
	for _, record := range report.VMRecords {
		if _, twice := recorded[record.VMID]; twice {
			problem("VM %d is recorded more than once", record.VMID)
			continue
		}
		recorded[record.VMID] = record
		vm, known := planned[record.VMID]
		if !known {
			problem("VM %d is recorded, and is not in the plan", record.VMID)
			continue
		}
		want := expectedSourceVMID(vm)
		switch {
		case vm.SourceVMID > 0 && record.SourceVMID != vm.SourceVMID:
			problem("VM %d records source VM %d, and the plan restores source VM %d", record.VMID, record.SourceVMID, vm.SourceVMID)
		case vm.SourceVMID <= 0 && want > 0 && record.SourceVMID != 0 && record.SourceVMID != want:
			problem("VM %d records source VM %d, and the plan restores source VM %d", record.VMID, record.SourceVMID, want)
		}
		// Whatever way a VM's restore ended, its record says which backup it
		// restored and which disks it was to restore: a worker starts
		// the record with them, so a failed or an incomplete VM has them too,
		// and a record that names another backup, or another layout, than the
		// plan's is not signed as this run's.
		for _, message := range attest.SourceProblems(record, &vm) {
			problem("%s", boundedMessage(message))
		}
		for _, message := range attest.DiskProblems(record, &vm) {
			problem("%s", boundedMessage(message))
		}
		// The summary of the service checks a tier's soak ran must add up for
		// any record that carries one, and a VM of a report that claims a pass
		// must carry the one its tier's soak asks for. A VM that
		// verified in a run that failed elsewhere may belong to a tier that
		// failed before its soak began, so it is not required to carry one.
		for _, message := range attest.SoakProblems(record, &vm, soakSec[record.VMID], report.AllPassed) {
			problem("%s", boundedMessage(message))
		}
		// A VM the report calls verified, or any VM of a report that claims a
		// pass, ran the plan's probes under the plan's policy: what the
		// results say is held to the plan, by the rules verify-report applies
		// to a report too (pkg/attest planrules.go). A VM of a run that failed
		// partway has partial results and is not.
		if report.AllPassed || record.VerificationStatus == "verified" {
			for _, message := range attest.ProbeProblems(record, &vm, -1) {
				problem("%s", boundedMessage(message))
			}
			for _, message := range attest.ProbePolicyProblems(record, &vm, plan) {
				problem("%s", boundedMessage(message))
			}
			// A report that claims a pass is held to the integrity evidence of
			// its mode for every planned VM below; a VM that verified in a run
			// that failed elsewhere is held to it here.
			if !report.AllPassed {
				checkIntegrityEvidence(record.VMID, record.SourceDisks, wantMode, problem)
			}
		} else if record.AllPassed {
			failed := 0
			for _, result := range record.ProbeResults {
				if !result.Passed {
					failed++
				}
			}
			if failed > 0 {
				problem("VM %d claims a pass with %d failed probe(s)", record.VMID, failed)
			}
		}
		// The branch above holds a VM of a passing report, or one that
		// verified, to the integrity evidence of the report's mode. Any other
		// record is not, but a disk of it that says "verified" is still held to
		// what that word stands for, whatever its VM's own status: a failed
		// record that kept the label without its digest or manifest reference
		// would otherwise be signed, and shown, as a checked disk.
		if !report.AllPassed && record.VerificationStatus != "verified" {
			for _, disk := range record.SourceDisks {
				if disk.IntegrityStatus == probe.DiskVerified {
					checkVerifiedDiskEvidence(record.VMID, disk, problem)
				}
			}
		}
	}
	// One address cannot be two VMs' services: the plan the loader
	// accepted never names one on two VMs, and the report is held to it too.
	for _, message := range attest.SharedWireTargetProblems(report.VMRecords) {
		problem("%s", boundedMessage(message))
	}
	if !report.AllPassed {
		return
	}
	if report.FailureReason != "" {
		problem("the report claims a pass and also records a failure (%s)", boundedText(report.FailureReason))
	}
	if len(report.VMRecords) == 0 {
		problem("the report claims a pass and records no VM, so no recovery was validated")
	}
	for _, id := range order {
		record, present := recorded[id]
		if !present {
			problem("the report claims a pass, and planned VM %d has no record", id)
			continue
		}
		if !record.AllPassed {
			problem("the report claims a pass, and VM %d does not", id)
		}
		if record.VerificationStatus != "verified" {
			problem("the report claims a pass, and VM %d's verification_status is %q, not \"verified\"", id, boundedText(record.VerificationStatus))
		}
		checkIntegrityEvidence(id, record.SourceDisks, wantMode, problem)
	}
}

// checkIntegrityEvidence requires, of a VM that passed, the integrity
// evidence its mode stands for. A full-integrity report needs a verified
// SHA-256 image digest of every restored disk, and a disk the worker says it
// skipped is a contradiction of the mode, not an evidence of it. A test-mode
// report may record the test-mode skip instead.
func checkIntegrityEvidence(vmid int, disks []probe.SourceDiskEvidence, mode string, problem func(string, ...any)) {
	if len(disks) == 0 {
		problem("VM %d passed with no source-disk integrity evidence", vmid)
		return
	}
	for _, disk := range disks {
		switch {
		case disk.IntegrityStatus == "verified":
			checkVerifiedDiskEvidence(vmid, disk, problem)
		case disk.IntegrityStatus == "skipped_test_mode" && mode == attest.ValidationModeTestSkipIntegrity:
		default:
			problem("VM %d disk %q has integrity_status %q, which a %s report cannot pass with", vmid, boundedText(disk.Slot), boundedText(disk.IntegrityStatus), mode)
		}
	}
}

// checkVerifiedDiskEvidence holds a disk that says "verified" to what that
// word stands for: a SHA-256 image digest and a PBS manifest reference. It
// applies to every disk that makes the claim, whatever the status of its VM.
func checkVerifiedDiskEvidence(vmid int, disk probe.SourceDiskEvidence, problem func(string, ...any)) {
	if !isSHA256Hex(disk.ImageDigest) {
		problem("VM %d disk %q is marked verified without a SHA-256 image digest", vmid, boundedText(disk.Slot))
	}
	if disk.ManifestReference == "" {
		problem("VM %d disk %q is marked verified without a PBS manifest reference", vmid, boundedText(disk.Slot))
	}
}

// expectedSourceVMID is the source VM a planned VM restores: its explicit
// source_vmid, or the group of a vm/<id>/... snapshot selector. Zero means
// the plan does not name one.
func expectedSourceVMID(vm config.VM) int { return attest.ExpectedSourceVMID(vm) }

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// sameStrings compares two lists as written: nil and empty are the same.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// boundedMessage is boundedText for a whole message that quotes what a worker
// supplied, such as one of the plan rules' contradictions.
func boundedMessage(text string) string {
	text = progresspkg.SingleLine(text)
	const limit = 400
	if utf8.RuneCountInString(text) <= limit {
		return text
	}
	return string([]rune(text)[:limit]) + "…"
}

// boundedText keeps text a worker supplied to one line, short enough for an
// error.
func boundedText(text string) string {
	text = progresspkg.SingleLine(text)
	const limit = 120
	if utf8.RuneCountInString(text) <= limit {
		return text
	}
	return string([]rune(text)[:limit]) + "…"
}
