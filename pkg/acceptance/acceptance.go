// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

// Package acceptance judges whether a decoded report is acceptable evidence.
//
// It is the one acceptance rule of the project: `certistack verify-report` (the
// Community Edition) and the Enterprise Edition both call Evaluate, so what one
// accepts the other accepts. The rule does not look at a signature. A valid
// signature from a trusted signer proves who signed a report and that it is
// unchanged; it does not prove that the report records a complete, successful
// recovery of what was requested: a trusted signer can sign a report with no VM
// records, a failed probe beneath a top-level pass, an unverified teardown, or
// another plan, node, or build. A report the Community Edition wrote carries no
// signature at all, and is judged by the same rules: its contents are the run's
// own claim, and the verdict says whether that claim is complete and coherent.
// Whether the report is authentic is the caller's separate question, answered
// with attest.VerifyReport. The expectations bind the verdict to the request the
// caller actually made.
package acceptance

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// The two verdicts of Result.Verdict.
const (
	Accepted = "accepted"
	Rejected = "rejected"
)

// The outcomes a caller can expect (Expectations.Outcome).
const (
	// OutcomePass accepts a complete, clean, passing recovery.
	OutcomePass = "pass"
	// OutcomeFault accepts a fault drill: exactly one probe failed, and
	// it is the first probe of the plan's first VM, the injected fault.
	OutcomeFault = "fault"
	// OutcomeDenied accepts a run refused before any VM was restored,
	// such as a capacity guard.
	OutcomeDenied = "denied"
)

// Result is the verdict verify-report adds to its summary.
// Bindings names the caller's expectations that were checked; with none, the
// verdict establishes only that the report is internally complete and
// coherent, not that it answers the caller's request. An expectation that was
// given but could not be checked against this report, because the report
// predates the evidence it needs, is listed too, with the prefix
// UnboundPrefix, so a reader never takes a missing check for a passed one.
type Result struct {
	Verdict  string   `json:"verdict"`
	Outcome  string   `json:"expected_outcome"`
	Bindings []string `json:"bindings"`
	Reasons  []string `json:"reasons,omitempty"`
	// Authenticated is whether the caller authenticated the report before it
	// judged it (Expectations.Authenticated): false is a verdict on the contents
	// of a file that anyone may have written, which is all an unsigned report
	// is. It is the last member, so a consumer that matches the start of the
	// object is not disturbed.
	Authenticated bool `json:"authenticated"`
}

// UnboundPrefix starts a binding that was requested and could not be checked.
const UnboundPrefix = "NOT BOUND: "

// probePolicySchemaMinor is the first report schema minor (1.6) whose probe
// results record the policy they ran under: timeout, retries, attempts, the
// guest-agent requirement, the virtual host and the bound source. A report of
// an earlier schema cannot be held to the plan on those.
const probePolicySchemaMinor = 6

// PolicyEvidenceSchemaMinor is the first report schema minor (1.7) that records
// the recovery time objective a run was held to and its host admission policy
// and check. A report of an earlier schema cannot say what it
// passed under, and a missing member there is not "no objective".
const PolicyEvidenceSchemaMinor = 7

// Expectations is what the caller requested. A nil pointer is an
// expectation the caller did not state.
type Expectations struct {
	// Outcome is OutcomePass, OutcomeFault or OutcomeDenied; empty means
	// OutcomePass.
	Outcome string
	// Plan is the expected plan: the report must be of exactly its VMs and
	// probes.
	Plan *config.Plan
	// PlanSHA256 is the SHA-256 (lower-case hex) of the expected plan file's
	// bytes, which the report's plan_sha256 must equal. Empty when the caller
	// has no plan file bytes to give.
	PlanSHA256     string
	Node           *string
	Version        *string
	Commit         *string
	BuildDate      *string
	WorkerSHA256   *string
	ValidationMode *string
	// VersionSupport is "tested" or "untested": the report's version_support
	// must be exactly it (a release lane asks for tested).
	VersionSupport *string
	// AllowTestMode accepts a test-mode report (validation mode
	// test_skip_integrity) as lab evidence.
	AllowTestMode bool
	// Authenticated says the caller verified the report's signature against a
	// signer it trusts before calling Evaluate. Evaluate reads the contents only
	// and cannot tell; it records what it was told in Result.Authenticated, and a
	// caller that says nothing gets false, the safe reading (review R1-04).
	Authenticated bool
}

// Evaluate judges report against exp. It reads the report's contents only; it
// neither verifies nor requires a signature (see the package comment).
func Evaluate(report *attest.Report, exp Expectations) Result {
	outcome := exp.Outcome
	if outcome == "" {
		outcome = OutcomePass
	}
	check := acceptanceCheck{acceptance: Result{Outcome: outcome, Bindings: []string{}, Authenticated: exp.Authenticated}}
	check.identity(report, exp)
	check.teardown(report.TeardownEvidence)
	switch outcome {
	case OutcomePass:
		check.pass(report, exp)
	case OutcomeFault:
		check.fault(report, exp)
	case OutcomeDenied:
		check.denied(report)
	default:
		check.reject("unsupported expected outcome %q", outcome)
	}
	check.acceptance.Verdict = Accepted
	if len(check.acceptance.Reasons) > 0 {
		check.acceptance.Verdict = Rejected
	}
	return check.acceptance
}

type acceptanceCheck struct {
	acceptance Result
	// policyRecorded is whether the report's schema records each probe's
	// policy (probePolicySchemaMinor), and plan the expected plan the probes
	// are held to; both are set by identity, which runs first.
	policyRecorded bool
	plan           *config.Plan
	// soakRecorded is whether the report's schema records the service checks
	// of a tier's soak (attest.SoakSchemaMinor).
	soakRecorded bool
}

func (c *acceptanceCheck) reject(format string, args ...any) {
	c.acceptance.Reasons = append(c.acceptance.Reasons, fmt.Sprintf(format, args...))
}

func (c *acceptanceCheck) bind(name string) {
	c.acceptance.Bindings = append(c.acceptance.Bindings, name)
}

// unbound says an expectation the caller gave could not be checked.
func (c *acceptanceCheck) unbound(what string) {
	c.acceptance.Bindings = append(c.acceptance.Bindings, UnboundPrefix+what)
}

// ValidationModeProblem is why a report's validation mode cannot be accepted,
// or "" when it can. The mode is an allowlist of exactly two values:
// full_integrity, and test_skip_integrity for a caller who allowed test mode.
// Anything else, an empty or missing mode, another case, a spelling a later
// release might add, is refused, not read as full integrity: only a mode this
// verifier understands says what the run proved. verify-report applies it to
// every report, with or without an --expect-* flag.
func ValidationModeProblem(mode string, allowTestMode bool) string {
	switch mode {
	case attest.ValidationModeFullIntegrity:
		return ""
	case attest.ValidationModeTestSkipIntegrity:
		if allowTestMode {
			return ""
		}
		return "the report skipped full mapped-image integrity verification (test mode) and is not production evidence"
	}
	return fmt.Sprintf("the report records no supported validation mode (%q)", mode)
}

// versionSupportProblem is why the Proxmox version members of a report
// contradict themselves, or "" when they do not or when the report records
// none (a report of an earlier build, or a run refused before it read the
// versions, says nothing of them and is judged as before). version_support is
// tested, untested or unknown: a run of an unsupported pair is refused before
// it creates anything, so no report of one is signed, and a tested pair names
// the three versions it was judged on.
func versionSupportProblem(report *attest.Report) string {
	switch report.VersionSupport {
	case "", "untested", "unknown":
		return ""
	case "tested":
		if report.PVEVersion == "" || report.PBSVersion == "" || report.PBSClientVersion == "" {
			return "the report says its Proxmox versions are tested but does not record all of pve_version, pbs_version and pbs_client_version"
		}
		return ""
	}
	return fmt.Sprintf("the report records version_support %q, which is none of tested, untested or unknown (a run of an unsupported pair is refused before it creates anything)", BoundedReason(report.VersionSupport))
}

// identity checks the schema and validation mode, and binds the report to the
// expected plan, node, build, and validation mode.
func (c *acceptanceCheck) identity(report *attest.Report, exp Expectations) {
	if problem := SchemaProblem(report.ReportSchemaVersion); problem != "" {
		c.reject("%s", problem)
	}
	c.policyRecorded = SchemaMinor(report.ReportSchemaVersion) >= probePolicySchemaMinor
	c.soakRecorded = SchemaMinor(report.ReportSchemaVersion) >= attest.SoakSchemaMinor
	c.plan = exp.Plan
	// A report that records the objective and the admission policy it was judged
	// by is held to them: to the plan's when there is one, and to itself always
	// (a pass inside its own objective, a grant inside its own limits). These
	// are the controller's rules too (attest.PolicyEvidenceProblems). An earlier
	// schema recorded neither, so nothing is said of them, and with a plan the
	// verdict says they were not bound.
	objectiveRecorded := SchemaMinor(report.ReportSchemaVersion) >= PolicyEvidenceSchemaMinor
	if objectiveRecorded {
		for _, problem := range attest.PolicyEvidenceProblems(report, exp.Plan) {
			c.reject("%s", problem)
		}
	}
	if report.PlanSHA256 != "" && !isSHA256Hex(report.PlanSHA256) {
		c.reject("the report's plan_sha256 %q is not a SHA-256 digest", BoundedReason(report.PlanSHA256))
	}
	if problem := versionSupportProblem(report); problem != "" {
		c.reject("%s", problem)
	}
	if problem := ValidationModeProblem(report.ValidationMode, exp.AllowTestMode); problem != "" {
		c.reject("%s", problem)
	}
	if exp.Plan != nil {
		c.bind("plan")
		if report.PlanID != exp.Plan.PlanID {
			c.reject("the report is for plan %q, not the expected plan %q", report.PlanID, exp.Plan.PlanID)
		}
		c.planDigest(report, exp)
		if c.policyRecorded {
			c.bind("probe_policy")
		} else {
			c.unbound(fmt.Sprintf("probe policy (report schema %q predates 1.%d, which records each probe's timeout, retries, guest-agent requirement, virtual host and source)", BoundedReason(report.ReportSchemaVersion), probePolicySchemaMinor))
		}
		switch {
		case !planHasSoak(exp.Plan):
		case c.soakRecorded:
			c.bind("soak_checks")
		default:
			c.unbound(fmt.Sprintf("soak service checks (report schema %q predates 1.%d; its soak held the tier while PVE reported the VMs running and did not repeat any service probe, so it does not show that a service stayed up)", BoundedReason(report.ReportSchemaVersion), attest.SoakSchemaMinor))
		}
		if objectiveRecorded {
			c.bind("rto_objective")
			c.bind("admission_policy")
		} else {
			c.unbound(fmt.Sprintf("RTO objective and admission policy (report schema %q predates 1.%d, which records the recovery time objective and the host admission limits)", BoundedReason(report.ReportSchemaVersion), PolicyEvidenceSchemaMinor))
		}
	}
	if exp.Node != nil {
		c.bind("node")
		if report.NodeFQDN != *exp.Node {
			c.reject("the report was produced on node %q, not the expected node %q", report.NodeFQDN, *exp.Node)
		}
	}
	if exp.Version != nil || exp.Commit != nil || exp.BuildDate != nil || exp.WorkerSHA256 != nil {
		c.bind("build")
		if exp.WorkerSHA256 != nil {
			switch {
			case report.WorkerSHA256 == "":
				c.reject("the report records no worker executable digest (it was written by a build that did not record one), so it cannot be tied to the expected executable %q", *exp.WorkerSHA256)
			case report.WorkerSHA256 != *exp.WorkerSHA256:
				c.reject("the report was produced by executable %q, not the expected %q", report.WorkerSHA256, *exp.WorkerSHA256)
			}
		}
		if exp.Version != nil && report.EngineVersion != *exp.Version {
			c.reject("the report was produced by CertiStack version %q, not the expected %q", report.EngineVersion, *exp.Version)
		}
		if exp.Commit != nil && report.GitCommit != *exp.Commit {
			c.reject("the report was produced by commit %q, not the expected %q", report.GitCommit, *exp.Commit)
		}
		if exp.BuildDate != nil && report.BuildDate != *exp.BuildDate {
			c.reject("the report was produced by a build dated %q, not the expected %q", report.BuildDate, *exp.BuildDate)
		}
	}
	if exp.ValidationMode != nil {
		c.bind("validation_mode")
		if report.ValidationMode != *exp.ValidationMode {
			c.reject("the report's validation mode is %q, not the expected %q", report.ValidationMode, *exp.ValidationMode)
		}
	}
	if exp.VersionSupport != nil {
		c.bind("version_support")
		switch report.VersionSupport {
		case *exp.VersionSupport:
		case "":
			c.reject("the report records no version_support (a build or a run that did not record the Proxmox versions), so it cannot be held to the expected %q", *exp.VersionSupport)
		default:
			c.reject("the report records version_support %q, not the expected %q", BoundedReason(report.VersionSupport), *exp.VersionSupport)
		}
	}
}

// planDigest binds the report to the exact bytes of the expected plan file.
// The controller records the SHA-256 of the plan file it read (plan_sha256),
// so a plan that reads the same to the loader but is another file, or a
// changed timeout, expected status or expected output, no longer matches. A
// report without the digest (one of an earlier schema, or one signed with no
// controller) is still judged on its plan ID, VMs and probes, and the verdict
// says the digest was not bound.
func (c *acceptanceCheck) planDigest(report *attest.Report, exp Expectations) {
	switch {
	case report.PlanSHA256 == "":
		c.unbound("plan digest (the report carries no plan_sha256, so the plan file's exact bytes are not compared)")
	case exp.PlanSHA256 == "":
		c.unbound("plan digest (no digest of the expected plan file was given)")
	default:
		c.bind("plan_sha256")
		if report.PlanSHA256 != exp.PlanSHA256 {
			c.reject("the report is for a plan file with SHA-256 %s, not the expected plan file's %s", report.PlanSHA256, exp.PlanSHA256)
		}
	}
}

// teardown requires cleanup that the controller established from the node's
// journal. A report whose cleanup was not verified is never acceptable
// evidence, whatever its outcome.
func (c *acceptanceCheck) teardown(evidence *attest.TeardownEvidence) {
	if evidence == nil {
		c.reject("the report has no teardown evidence, so cleanup of the run's temporary resources is unknown")
		return
	}
	if !evidence.AllCleaned {
		c.reject("teardown_evidence.all_cleaned is false: cleanup of the run's temporary resources was not verified")
	}
	if !evidence.OrphanSweepClean {
		c.reject("teardown_evidence.orphan_sweep_clean is false: not every resource the run owned was confirmed removed")
	}
	if len(evidence.CleanupErrors) > 0 {
		c.reject("teardown_evidence lists %d unresolved cleanup error(s)", len(evidence.CleanupErrors))
	}
	if !evidence.JournalRecoveryVerified {
		c.reject("teardown_evidence.journal_recovery_verified is false: the controller did not confirm cleanup from the node's journal")
	}
}

func (c *acceptanceCheck) pass(report *attest.Report, exp Expectations) {
	switch {
	case !report.AllPassed && report.FailureReason != "":
		c.reject("the report does not record a pass: %q", BoundedReason(report.FailureReason))
	case !report.AllPassed:
		c.reject("the report does not record a pass (all_passed is false)")
	case report.FailureReason != "":
		c.reject("the report records all_passed but also a failure: %q", BoundedReason(report.FailureReason))
	}
	records := report.VMRecords
	if len(records) == 0 {
		c.reject("the report records no VM, so no recovery was validated")
	}
	c.uniqueRecords(records)
	c.sharedTargets(records)
	contradicted := false
	for _, record := range records {
		if record.VerificationStatus != "verified" {
			c.reject("VM %d verification_status is %q, not \"verified\"", record.VMID, record.VerificationStatus)
			contradicted = true
		}
		if !record.AllPassed {
			c.reject("VM %d does not record a pass", record.VMID)
			contradicted = true
		}
		var planned *config.VM
		if exp.Plan != nil {
			planned = findPlanVM(exp.Plan, record.VMID)
		}
		if c.probes(record, planned, -1) {
			contradicted = true
		}
		if c.soak(record, planned, exp.Plan, true) {
			contradicted = true
		}
		c.integrity(record, planned, report.ValidationMode, exp.AllowTestMode)
	}
	if exp.Plan != nil {
		c.population(records, exp.Plan, 0, false)
	}
	if report.AllPassed && contradicted {
		c.reject("the report's top-level all_passed contradicts its VM and probe results")
	}
}

// fault accepts exactly one failed probe: the first probe of the fault plan's
// first VM, as the plan is written. Every other probe that ran must have
// passed, so a collateral failure is never credited as the injected fault.
func (c *acceptanceCheck) fault(report *attest.Report, exp Expectations) {
	plan := exp.Plan
	if plan == nil {
		c.reject("a fault drill can be accepted only against its plan (--expect-plan)")
		return
	}
	if len(plan.Tiers) == 0 || len(plan.Tiers[0].VMs) == 0 || len(plan.Tiers[0].VMs[0].Probes) == 0 {
		c.reject("the fault plan names no VM probe to expect as the injected failure")
		return
	}
	target := plan.Tiers[0].VMs[0]
	targetProbe := target.Probes[0]
	if report.AllPassed {
		c.reject("the report records a pass; a fault drill must record the injected failure")
	}

	type failedProbe struct {
		record probe.VMValidationRecord
		index  int
	}
	var failures []failedProbe
	for _, record := range report.VMRecords {
		for index, result := range record.ProbeResults {
			if !result.Passed {
				failures = append(failures, failedProbe{record: record, index: index})
			}
		}
	}
	if len(failures) != 1 {
		c.reject("the report records %d failed probes; a fault drill must record exactly one, on the fault plan's first VM and probe", len(failures))
	} else {
		failed := failures[0]
		result := failed.record.ProbeResults[failed.index]
		if failed.record.VMID != target.VMID {
			c.reject("the failed probe is on VM %d, not the fault plan's target VM %d", failed.record.VMID, target.VMID)
		}
		if result.Type != targetProbe.Type {
			c.reject("the failed probe is a %s probe, not the fault plan's %s probe", result.Type, targetProbe.Type)
		}
		if result.Description != targetProbe.Description {
			c.reject("the failed probe is %q, not the fault plan's %q", result.Description, targetProbe.Description)
		}
		if failed.index != 0 {
			c.reject("the failed probe is probe %d of VM %d; the fault plan expects its first probe", failed.index+1, failed.record.VMID)
		}
	}

	records := report.VMRecords
	c.uniqueRecords(records)
	c.sharedTargets(records)
	for _, record := range records {
		planned := findPlanVM(plan, record.VMID)
		expectedIndex := -1
		if record.VMID == target.VMID {
			expectedIndex = 0
			if record.VerificationStatus != "failed" {
				c.reject("fault target VM %d verification_status is %q, not \"failed\"", record.VMID, record.VerificationStatus)
			}
			if record.AllPassed {
				c.reject("fault target VM %d records a pass", record.VMID)
			}
		} else {
			if record.VerificationStatus != "verified" {
				c.reject("VM %d verification_status is %q, not \"verified\"; only the fault target may fail", record.VMID, record.VerificationStatus)
			}
			if !record.AllPassed {
				c.reject("VM %d does not record a pass; only the fault target may fail", record.VMID)
			}
		}
		c.probes(record, planned, expectedIndex)
		// The target's tier fails before any soak begins, so a drill's VMs
		// are not required to carry one; a summary they do carry must add up.
		c.soak(record, planned, plan, false)
		c.integrity(record, planned, report.ValidationMode, exp.AllowTestMode)
	}
	c.population(records, plan, plan.Tiers[0].Level, true)
}

// denied accepts a capacity refusal: the run failed before any VM was
// restored, and its signed failure reason is the admission or preflight
// capacity denial the product emits. Any other failure before a restore (SDN
// setup, storage, PBS access) is a failed run, not a guard denial.
func (c *acceptanceCheck) denied(report *attest.Report) {
	if report.AllPassed {
		c.reject("the report records a pass; a denied run must record a failed validation")
	}
	switch {
	case report.FailureReason == "":
		c.reject("the report records no failure reason for the denial")
	case !CapacityDenial(report.FailureReason):
		c.reject("the failure reason is not an admission or preflight capacity denial: %q", BoundedReason(report.FailureReason))
	}
	if len(report.VMRecords) > 0 {
		c.reject("the report records %d VM(s); a denied run must stop before any VM is restored", len(report.VMRecords))
	}
}

// The capacity denials, one place. A run is refused for capacity in two
// places, and each starts its failure reason with these words:
//   - the orchestrator's admission control (pkg/orchestrator) prefixes the
//     admission package's admission-denied, retries-exhausted and
//     never-admissible errors with AdmissionDenialPrefix;
//   - the node worker's preflight (cmd/certistack node-run, which starts its
//     reason with PreflightFailurePrefix) lists its failed checks, and the
//     memory check's two failures are a shortage of available RAM and a plan
//     no wait can admit.
//
// Tests build these from the product's own errors and pin the orchestrator's
// prefix, so a change to any of them fails there rather than silently
// rejecting every guard.
const AdmissionDenialPrefix = "admission control guardrail triggered: "

// PreflightFailurePrefix starts the failure reason of a node preflight
// refusal. Evaluate recognizes a capacity denial by it (see CapacityDenial), so
// it is named once, here, and the node worker writes it from here.
const PreflightFailurePrefix = "node preflight failed: "

var preflightMemoryShortage = regexp.MustCompile(`^memory: available RAM [0-9]+ MB is below required [0-9]+ MB`)

// CapacityDenial reports whether a signed failure reason is a capacity
// denial. It anchors at the start of the reason, so text the plan or a guest
// controls further in (a plan ID, a probe error) can never satisfy it, and a
// preflight refusal must name the memory check first: an earlier failed check
// (privileges, KVM, a missing tool) is a broken node, not a full one.
func CapacityDenial(reason string) bool {
	if rest, found := strings.CutPrefix(reason, AdmissionDenialPrefix); found {
		for _, denial := range []error{admission.ErrAdmissionDenied, admission.ErrMaxRetriesExceeded, admission.ErrNeverAdmissible} {
			if strings.HasPrefix(rest, denial.Error()) {
				return true
			}
		}
		return false
	}
	if rest, found := strings.CutPrefix(reason, PreflightFailurePrefix); found {
		return preflightMemoryShortage.MatchString(rest) || strings.HasPrefix(rest, "memory: "+admission.ErrNeverAdmissible.Error())
	}
	return false
}

// uniqueRecords requires each sandbox VM to be recorded once. The population
// is the set of (sandbox VM, source VM) pairs, so a plan that restores one
// source into two sandbox VMs is not a duplicate: the same source under two
// sandbox VMIDs is two pairs, and only the same sandbox VMID twice is one.
func (c *acceptanceCheck) uniqueRecords(records []probe.VMValidationRecord) {
	seenVMIDs := make(map[int]bool, len(records))
	for _, record := range records {
		if record.VMID <= 0 {
			c.reject("a VM record has no VM ID")
			continue
		}
		if seenVMIDs[record.VMID] {
			c.reject("VM %d is recorded more than once", record.VMID)
		}
		seenVMIDs[record.VMID] = true
	}
}

// probes checks one VM's probe results and reports whether any contradicts a
// pass. With the planned VM, the results must be the plan's probes in order:
// the same type, description, and, where the report carries it, target (see
// expectedProbeTarget), and in a report that records them, the policy each ran
// under (see attest.ProbePolicyProblems). A required probe must have run and passed, and only
// an optional guest-agent probe may be skipped. expectedFailure is the index of
// the one probe allowed to fail (the fault drill's injected failure), or -1.
// A VM that does not fail must have at least one guest-level assertion that
// ran and passed: QMP and screendump probes show that the VM is running, not
// that a service in it works, so they never count as one.
func (c *acceptanceCheck) probes(record probe.VMValidationRecord, planned *config.VM, expectedFailure int) bool {
	problems := attest.ProbeProblems(record, planned, expectedFailure)
	for _, problem := range problems {
		c.reject("%s", problem)
	}
	contradicted := len(problems) > 0
	// In a report whose schema records each probe's policy (policyRecorded),
	// a result is also held to the policy its plan configures and to the
	// evidence it must carry; a result that says its guest-agent probe was
	// required cannot be a skip, with a plan or without one. These rules are
	// the controller's too (attest.ProbePolicyProblems), so a report the
	// controller signed never fails them here. They need the report's schema,
	// which is why they are not part of attest.ProbeProblems.
	if c.policyRecorded {
		policy := attest.ProbePolicyProblems(record, planned, c.plan)
		for _, problem := range policy {
			c.reject("%s", problem)
		}
		contradicted = contradicted || len(policy) > 0
	}
	return contradicted
}

// soak checks the summary of the service checks a tier's soak ran on one VM
// (attest.SoakProblems, the controller's rule too), and reports whether any
// contradicts a pass. A report of a schema that does not record them cannot
// carry one; with a plan and require, a VM whose tier holds a soak must have
// been checked during it.
func (c *acceptanceCheck) soak(record probe.VMValidationRecord, planned *config.VM, plan *config.Plan, require bool) bool {
	if !c.soakRecorded {
		if record.Soak != nil {
			c.reject("VM %d carries a soak summary, which the report's schema does not define (it records the service checks from 1.%d)", record.VMID, attest.SoakSchemaMinor)
			return true
		}
		return false
	}
	problems := attest.SoakProblems(record, planned, planSoakSec(plan, record.VMID), require)
	for _, problem := range problems {
		c.reject("%s", problem)
	}
	return len(problems) > 0
}

// planSoakSec is the soak_time_sec of the tier that holds the VM, or zero.
func planSoakSec(plan *config.Plan, vmid int) int {
	if plan == nil {
		return 0
	}
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			if vm.VMID == vmid {
				return tier.SoakTimeSec
			}
		}
	}
	return 0
}

// planHasSoak is whether any tier of the plan holds its VMs for a soak.
func planHasSoak(plan *config.Plan) bool {
	for _, tier := range plan.Tiers {
		if tier.SoakTimeSec > 0 {
			return true
		}
	}
	return false
}

// probeIsGuestLevel, expectedProbeTarget and probeIsOptional are the rules the
// controller applies before it signs a report (pkg/attest planrules.go), so
// that what it refuses and what this verifier refuses cannot differ.
func probeIsGuestLevel(probeType string) bool { return attest.ProbeIsGuestLevel(probeType) }

func expectedProbeTarget(p config.Probe) (string, bool) { return attest.ExpectedProbeTarget(p) }

func probeIsOptional(configured config.Probe) bool { return attest.ProbeIsOptional(configured) }

// integrity checks the backup a VM record names (the snapshot, which must be
// the plan's and the source VM's; see attest.SourceProblems) and its disk
// evidence: every disk the report records is
// verified with a digest and manifest reference (a test-mode report accepted
// with --allow-test-mode may instead record the explicit test-mode skip), no
// slot is recorded twice, the boot disk the report names is among them, and
// every disk the plan names is among them. A plan that names no drives (it
// takes them from the backup's configuration) cannot say what the layout
// should be, so its disks are checked only for what they record.
func (c *acceptanceCheck) integrity(record probe.VMValidationRecord, planned *config.VM, validationMode string, allowTestMode bool) {
	for _, problem := range attest.SourceProblems(record, planned) {
		c.reject("%s", problem)
	}
	if len(record.SourceDisks) == 0 {
		c.reject("VM %d records no source-disk integrity evidence", record.VMID)
		return
	}
	testMode := validationMode == attest.ValidationModeTestSkipIntegrity && allowTestMode
	recordedSlots := make(map[string]bool, len(record.SourceDisks))
	for _, disk := range record.SourceDisks {
		recordedSlots[disk.Slot] = true
	}
	for _, problem := range attest.DiskProblems(record, planned) {
		c.reject("%s", problem)
	}
	if hardware := record.RestoredHardware; hardware != nil && hardware.BootDisk != "" && !recordedSlots[hardware.BootDisk] {
		c.reject("VM %d booted disk %q, which has no integrity evidence", record.VMID, hardware.BootDisk)
	}
	// The boot order (reports of schema 1.7 and later) lists only restored disks,
	// the boot disk first: a disk with no evidence in it, or a boot order that
	// does not lead with the disk the report says booted, contradicts itself.
	if hardware := record.RestoredHardware; hardware != nil && len(hardware.BootOrder) > 0 {
		for _, slot := range hardware.BootOrder {
			if !recordedSlots[slot] {
				c.reject("VM %d boot order names disk %q, which has no integrity evidence", record.VMID, slot)
			}
		}
		if hardware.BootDisk != "" && hardware.BootOrder[0] != hardware.BootDisk {
			c.reject("VM %d booted disk %q, but its boot order starts with %q", record.VMID, hardware.BootDisk, hardware.BootOrder[0])
		}
	}
	for _, disk := range record.SourceDisks {
		switch {
		case disk.IntegrityStatus == "verified":
			if !isSHA256Hex(disk.ImageDigest) {
				c.reject("VM %d disk %q is marked verified without a SHA-256 image digest", record.VMID, disk.Slot)
			}
			if disk.ManifestReference == "" {
				c.reject("VM %d disk %q is marked verified without a PBS manifest reference", record.VMID, disk.Slot)
			}
		case disk.IntegrityStatus == "skipped_test_mode" && testMode:
		default:
			c.reject("VM %d disk %q integrity_status is %q, not \"verified\"", record.VMID, disk.Slot, disk.IntegrityStatus)
		}
	}
}

// population requires the report's VM records to be exactly the plan's VMs,
// each restored from the source the plan names. For a fault drill (partial),
// a failing tier stops the run, so VMs in tiers after the fault target's tier
// must be absent and every other planned VM present.
func (c *acceptanceCheck) population(records []probe.VMValidationRecord, plan *config.Plan, faultTierLevel int, partial bool) {
	recorded := make(map[int]probe.VMValidationRecord, len(records))
	for _, record := range records {
		recorded[record.VMID] = record
	}
	planned := make(map[int]bool)
	for _, tier := range plan.Tiers {
		for _, vm := range tier.VMs {
			planned[vm.VMID] = true
			record, present := recorded[vm.VMID]
			switch {
			case partial && tier.Level > faultTierLevel:
				if present {
					c.reject("VM %d is recorded, but its tier %d runs after the fault target's tier %d and must not have started", vm.VMID, tier.Level, faultTierLevel)
				}
				continue
			case !present:
				c.reject("planned VM %d (source %s) has no record in the report", vm.VMID, sourceDescription(vm))
				continue
			}
			// A plan without source_vmid has records without one; when the
			// record names a source anyway, it must be the snapshot's group.
			want := expectedSourceVMID(vm)
			switch {
			case vm.SourceVMID > 0 && record.SourceVMID != vm.SourceVMID:
				c.reject("VM %d records source VM %d; the plan restores source VM %d", vm.VMID, record.SourceVMID, vm.SourceVMID)
			case vm.SourceVMID <= 0 && record.SourceVMID != 0 && record.SourceVMID != want:
				c.reject("VM %d records source VM %d; the plan restores source %s", vm.VMID, record.SourceVMID, sourceDescription(vm))
			}
		}
	}
	for _, record := range records {
		if record.VMID > 0 && !planned[record.VMID] {
			c.reject("VM %d is recorded but is not in the expected plan", record.VMID)
		}
	}
}

func findPlanVM(plan *config.Plan, vmid int) *config.VM {
	for tierIndex := range plan.Tiers {
		for vmIndex := range plan.Tiers[tierIndex].VMs {
			if plan.Tiers[tierIndex].VMs[vmIndex].VMID == vmid {
				return &plan.Tiers[tierIndex].VMs[vmIndex]
			}
		}
	}
	return nil
}

// expectedSourceVMID is the source VM a planned VM restores: its explicit
// source_vmid, or the group of a vm/<id>/... snapshot selector. Zero means the
// plan does not name one.
func expectedSourceVMID(vm config.VM) int { return attest.ExpectedSourceVMID(vm) }

func sourceDescription(vm config.VM) string {
	if want := expectedSourceVMID(vm); want > 0 {
		return strconv.Itoa(want)
	}
	return "unspecified"
}

// SchemaProblem is why a report's schema version cannot be judged by
// this verifier, or "" when it can: schema 1.x up to the highest minor this
// build knows (attest.CurrentReportSchemaVersion). A newer minor may add
// evidence that changes what acceptable means, so it is refused, not guessed.
func SchemaProblem(version string) string {
	known := SchemaMinor(attest.CurrentReportSchemaVersion)
	minor := SchemaMinor(version)
	switch {
	case minor < 0:
		return fmt.Sprintf("report schema version %q is not a supported 1.x schema", version)
	case minor > known:
		return fmt.Sprintf("report schema version %q is newer than this verifier understands (1.%d); verify it with CertiStack of the same or a later release", version, known)
	}
	return ""
}

// SchemaMinor is the minor number of a canonical "1.<minor>" version
// (digits only, no leading zero), or -1.
func SchemaMinor(version string) int {
	major, minor, found := strings.Cut(version, ".")
	if !found || major != "1" || minor == "" || len(minor) > 4 || (len(minor) > 1 && minor[0] == '0') {
		return -1
	}
	number, err := strconv.Atoi(minor)
	if err != nil || number < 0 || strconv.Itoa(number) != minor {
		return -1
	}
	return number
}

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

// BoundedReason keeps a quoted failure reason readable in a verdict.
func BoundedReason(reason string) string {
	const limit = 240
	if utf8.RuneCountInString(reason) <= limit {
		return reason
	}
	runes := []rune(reason)
	return string(runes[:limit]) + "…"
}
