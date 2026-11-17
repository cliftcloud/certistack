// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// Schema 1.7 signs the policy a run was judged by: the recovery time objective
// and the host admission limits, reservation and last check.

// policyPlan is the test plan: complete apart from the objective (target <=
// 0 leaves it out) and the RAM limit it is built with.
func policyPlan(target, maxRAM float64) *config.Plan {
	return &config.Plan{
		Version: "v1", PlanID: "audit-policy", Name: "Audit policy",
		Compliance: config.Compliance{
			Frameworks: []string{"DORA-Article-12"}, RetentionDays: 90,
			SignKeyPath: "/synthetic/controller-signing.ed25519", RTOTargetSeconds: target,
		},
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: maxRAM, MaxHostIOWaitPercent: 50, DeferRetryIntervalSec: 5, MaxDeferRetries: 3},
		Network:          config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", Tag: 100, IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
		Tiers: []config.Tier{{
			Level: 1, Name: "Audit tier",
			VMs: []config.VM{{
				VMID: 9001, Name: "audit-vm",
				SourcePBS: config.SourcePBS{StorageID: "pbs", Snapshot: "vm/100/2026-03-30T02:00:00Z", Drive: "drive-scsi0"},
				Probes:    []config.Probe{{Type: "tcp", TargetIP: "10.100.0.10", Port: 443, TimeoutSec: 1, Description: "Audit TCP probe"}},
			}},
		}},
	}
}

// granted is a check that admitted the plan's run on a 1 000 000 MiB node with
// 900 000 MiB free, with arithmetic that holds.
func granted(evidence *AdmissionEvidence) *AdmissionEvidence {
	const total, available = 1_000_000.0, 900_000.0
	return evidence.WithEvaluation(admission.Evaluation{
		Checks: 1, Decision: admission.DecisionGranted,
		HostTotalMiB: total, HostAvailableMiB: available,
		HostRAMPercent: (total - available) / total * 100, HostIOWaitPercent: 0.5,
		ProjectedRAMPercent: (total - available + float64(evidence.RecoveryReservationMiB)) / total * 100,
	})
}

// signedPolicyReport is a passing report of plan with the identity and time
// fixed, signed by key.
func signedPolicyReport(t *testing.T, plan *config.Plan, key ed25519.PrivateKey) (*Report, []byte) {
	t.Helper()
	report := BuildReport(plan, "pve1.example.invalid", 42*time.Second, true, nil, "")
	report.ReportID = "00000000-0000-4000-8000-000000000193"
	report.Timestamp = "2026-09-30T18:00:00Z"
	report.PhaseTimings = &PhaseTimings{AdmissionCheckSec: 0.5, TotalRTOSec: 42}
	report.Admission = granted(report.Admission)
	if err := report.SignReport(key); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return report, data
}

func policyKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x93}, ed25519.SeedSize))
}

func TestSchema17PolicyEvidenceIsTheCurrentSchema(t *testing.T) {
	if CurrentReportSchemaVersion != "1.7" {
		t.Fatalf("CurrentReportSchemaVersion = %q; the policy evidence (rto_target_seconds, admission) is schema 1.7, and a new minor must say what it adds in its doc comment and in the schema history", CurrentReportSchemaVersion)
	}
	if got := BuildReport(policyPlan(60, 85), "n", 0, true, nil, "").ReportSchemaVersion; got != "1.7" {
		t.Fatalf("a built report says schema %q", got)
	}
}

// Targets 60 and 300 with the same 42-second pass give different canonical
// payloads and signatures: the report says which objective it passed under, a
// verifier reads it back from the signed bytes, and the same plan twice is
// byte-identical.
func TestDistinctPassingRTOTargetsSignDifferentReports(t *testing.T) {
	key := policyKey()
	public := key.Public().(ed25519.PublicKey)
	strict, strictJSON := signedPolicyReport(t, policyPlan(60, 85), key)
	permissive, permissiveJSON := signedPolicyReport(t, policyPlan(300, 85), key)
	again, againJSON := signedPolicyReport(t, policyPlan(60, 85), key)

	if bytes.Equal(strictJSON, permissiveJSON) || strict.Signature == permissive.Signature {
		t.Fatal("a pass under an objective of 60 seconds and one under 300 seconds are the same signed report")
	}
	strictCanonical, _ := CanonicalizeReportJSON(strictJSON)
	permissiveCanonical, _ := CanonicalizeReportJSON(permissiveJSON)
	if bytes.Equal(strictCanonical, permissiveCanonical) {
		t.Fatal("the canonical payloads of the two objectives are identical")
	}
	if !bytes.Equal(strictJSON, againJSON) || strict.Signature != again.Signature {
		t.Fatal("the same plan and result do not sign to the same bytes")
	}
	for label, tc := range map[string]struct {
		data []byte
		want float64
	}{"strict": {strictJSON, 60}, "permissive": {permissiveJSON, 300}} {
		verified, valid, err := VerifyReport(tc.data, []ed25519.PublicKey{public})
		if err != nil || !valid {
			t.Fatalf("%s: valid=%v err=%v", label, valid, err)
		}
		if verified.RTOTargetSeconds == nil || *verified.RTOTargetSeconds != tc.want {
			t.Errorf("%s: the verified report names objective %v, want %v", label, verified.RTOTargetSeconds, tc.want)
		}
	}
	// The objective is inside the signature: changing it, or taking it out, breaks it.
	for _, tamper := range []struct{ from, to string }{
		{`"rto_target_seconds":60`, `"rto_target_seconds":600`},
		{`"rto_target_seconds":60,`, ``},
	} {
		if !bytes.Contains(strictJSON, []byte(tamper.from)) {
			t.Fatalf("test bug: %s is not in %s", tamper.from, strictJSON)
		}
		if _, _, err := VerifyReportSignatureOnly(bytes.Replace(strictJSON, []byte(tamper.from), []byte(tamper.to), 1)); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("changing %s: err = %v, want an invalid signature", tamper.from, err)
		}
	}
}

// A plan with no objective writes no member, which is how a verifier tells "no
// objective" from a report that never recorded one (its schema says which).
func TestAReportOfAPlanWithoutAnObjectiveWritesNone(t *testing.T) {
	_, data := signedPolicyReport(t, policyPlan(0, 85), policyKey())
	if bytes.Contains(data, []byte("rto_target_seconds")) {
		t.Fatalf("a plan with no objective wrote one: %s", data)
	}
	verified, valid, err := VerifyReportSignatureOnly(data)
	if err != nil || !valid || verified.RTOTargetSeconds != nil {
		t.Fatalf("valid=%v err=%v objective=%v", valid, err, verified.RTOTargetSeconds)
	}
	for _, unusable := range []float64{math.NaN(), math.Inf(1), -5} {
		if got := RTOObjective(policyPlan(unusable, 85)); got != nil {
			t.Errorf("an objective of %v is recorded as %v", unusable, *got)
		}
	}
}

// Limits of 70 and 90 that admit the same reservation sign different reports:
// each admission policy member changes the signed content, and an identical
// policy does not.
func TestEachAdmissionPolicyChangesTheSignedReport(t *testing.T) {
	key := policyKey()
	base := policyPlan(60, 70)
	_, baseJSON := signedPolicyReport(t, base, key)
	_, repeatJSON := signedPolicyReport(t, policyPlan(60, 70), key)
	if !bytes.Equal(baseJSON, repeatJSON) {
		t.Fatal("an identical policy does not sign to identical bytes")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*config.Plan)
		member string
	}{
		{"the RAM limit", func(p *config.Plan) { p.AdmissionControl.MaxHostRAMPercent = 90 }, `"max_host_ram_percent":90`},
		{"the I/O wait limit", func(p *config.Plan) { p.AdmissionControl.MaxHostIOWaitPercent = 20 }, `"max_host_iowait_percent":20`},
		{"the retry interval", func(p *config.Plan) { p.AdmissionControl.DeferRetryIntervalSec = 9 }, `"defer_retry_interval_sec":9`},
		{"the retry count", func(p *config.Plan) { p.AdmissionControl.MaxDeferRetries = 7 }, `"max_defer_retries":7`},
		{"the boot gate", func(p *config.Plan) { p.AdmissionControl.MaxConcurrentBoots = 2 }, `"max_concurrent_boots":2`},
		{"the boot settle time", func(p *config.Plan) { p.AdmissionControl.MaxConcurrentBoots, p.AdmissionControl.BootSettleSec = 2, 90 }, `"boot_settle_sec":90`},
		{"a VM's memory (the reservation)", func(p *config.Plan) { p.Tiers[0].VMs[0].HardwareOverrides.MemoryMB = 8192 }, `"recovery_reservation_mib":8448`},
		{"a second VM (the reservation)", func(p *config.Plan) {
			second := p.Tiers[0].VMs[0]
			second.VMID, second.Name = 9002, "audit-vm-2"
			p.Tiers[0].VMs = append(p.Tiers[0].VMs, second)
		}, `"recovery_reservation_vms":2`},
	} {
		plan := policyPlan(60, 70)
		tc.mutate(plan)
		_, changed := signedPolicyReport(t, plan, key)
		if bytes.Equal(baseJSON, changed) {
			t.Errorf("changing %s leaves the signed report unchanged", tc.name)
		}
		if !bytes.Contains(changed, []byte(tc.member)) {
			t.Errorf("changing %s: the signed report lacks %s: %s", tc.name, tc.member, changed)
		}
	}
	if !bytes.Contains(baseJSON, []byte(`"recovery_reservation_mib":2304`)) {
		t.Errorf("the reservation of one default VM (2048 MiB and 256 MiB of overhead) is not recorded: %s", baseJSON)
	}
}

// The admission evidence is signed: any member changed, or the evaluation
// removed, breaks the signature.
func TestAdmissionEvidenceIsCoveredByTheSignature(t *testing.T) {
	_, signed := signedPolicyReport(t, policyPlan(60, 70), policyKey())
	for _, tamper := range []struct{ from, to string }{
		{`"max_host_ram_percent":70`, `"max_host_ram_percent":90`},
		{`"decision":"granted"`, `"decision":"denied_ram"`},
		{`"checks":1`, `"checks":2`},
		{`"host_iowait_percent":0.5`, `"host_iowait_percent":0.1`},
		{`"recovery_reservation_mib":2304`, `"recovery_reservation_mib":230`},
	} {
		if !bytes.Contains(signed, []byte(tamper.from)) {
			t.Fatalf("test bug: %s is not in %s", tamper.from, signed)
		}
		if _, _, err := VerifyReportSignatureOnly(bytes.Replace(signed, []byte(tamper.from), []byte(tamper.to), 1)); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("changing %s: err = %v, want an invalid signature", tamper.from, err)
		}
	}
}

// A schema 1.6 report, which never recorded either, still verifies.
func TestASchema16ReportStillVerifies(t *testing.T) {
	report := BuildReport(policyPlan(60, 70), "n", 42*time.Second, true, nil, "")
	report.ReportSchemaVersion, report.RTOTargetSeconds, report.Admission = "1.6", nil, nil
	if err := report.SignReport(policyKey()); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(report)
	if _, valid, err := VerifyReportSignatureOnly(data); err != nil || !valid {
		t.Fatalf("a schema 1.6 report does not verify: valid=%v err=%v", valid, err)
	}
}

// consistentReport is a passing report whose policy evidence holds.
func consistentReport(plan *config.Plan) *Report {
	report := BuildReport(plan, "n", 42*time.Second, true, []probe.VMValidationRecord{{VMID: 9001}}, "")
	report.Admission = granted(report.Admission)
	return report
}

// What the controller and the verifier hold a report to, one rule at a time.
func TestPolicyEvidenceProblems(t *testing.T) {
	plan := policyPlan(60, 70)
	if problems := PolicyEvidenceProblems(consistentReport(plan), plan); len(problems) != 0 {
		t.Fatalf("a consistent report is refused: %v", problems)
	}
	if problems := PolicyEvidenceProblems(consistentReport(plan), nil); len(problems) != 0 {
		t.Fatalf("a consistent report without a plan is refused: %v", problems)
	}
	denied := func(r *Report, decision string, mutate func(*AdmissionEvaluation)) {
		r.AllPassed, r.VMRecords, r.RTOSeconds = false, nil, 0
		r.Admission.Evaluation.Decision = decision
		mutate(r.Admission.Evaluation)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Report)
		plan   *config.Plan
		want   string
	}{
		{"a pass over its own objective", func(r *Report) { r.RTOSeconds = 61 }, nil, "over its own objective of 60.0s"},
		{"an objective of zero", func(r *Report) { zero := 0.0; r.RTOTargetSeconds = &zero }, nil, "is not a number of seconds above 0"},
		{"a non-finite objective", func(r *Report) { nan := math.NaN(); r.RTOTargetSeconds = &nan }, nil, "is not a number of seconds above 0"},
		{"an objective the plan does not set", func(r *Report) {}, policyPlan(0, 70), "records a recovery time objective of 60s, and the plan sets none"},
		{"no objective for a plan that sets one", func(r *Report) { r.RTOTargetSeconds = nil }, plan, "records no recovery time objective, and the plan's is 60s"},
		{"another objective", func(r *Report) { r.RTOTargetSeconds = new(float64); *r.RTOTargetSeconds = 300 }, plan, "objective of 300s, and the plan's is 60s"},
		{"no admission policy", func(r *Report) { r.Admission = nil }, nil, "records no host admission policy"},
		{"a RAM limit above 100", func(r *Report) { r.Admission.MaxHostRAMPercent = 150 }, nil, "max_host_ram_percent 150 is not above 0 and at most 100"},
		{"another RAM limit than the plan's", func(r *Report) { r.Admission.MaxHostRAMPercent = 90 }, plan, "admission max_host_ram_percent is 90, and the plan's is 70"},
		{"another I/O wait limit", func(r *Report) { r.Admission.MaxHostIOWaitPercent = 10 }, plan, "max_host_iowait_percent is 10, and the plan's is 50"},
		{"another retry interval", func(r *Report) { r.Admission.DeferRetryIntervalSec = 99 }, plan, "defer_retry_interval_sec is 99"},
		{"another retry count", func(r *Report) { r.Admission.MaxDeferRetries = 9 }, plan, "max_defer_retries is 9"},
		{"a boot gate the plan lacks", func(r *Report) { r.Admission.MaxConcurrentBoots = 3 }, plan, "max_concurrent_boots is 3, and the plan's is 0"},
		{"another reservation", func(r *Report) { r.Admission.RecoveryReservationMiB = 1 }, plan, "recovery_reservation_mib is 1, and the plan's is 2304"},
		{"a pass with no check", func(r *Report) { r.Admission.Evaluation = nil }, nil, "no admission check that let the run start"},
		{"VMs with no check", func(r *Report) { r.AllPassed, r.Admission.Evaluation = false, nil }, nil, "no admission check that let the run start"},
		{"zero checks", func(r *Report) { r.Admission.Evaluation.Checks = 0 }, nil, "records 0 checks"},
		{"more checks than the retries allow", func(r *Report) { r.Admission.Evaluation.Checks = 5 }, nil, "5 checks, more than max_defer_retries 3 allows"},
		{"an unknown decision", func(r *Report) { r.Admission.Evaluation.Decision = "approved\x1b[31m" }, nil, `decision "approved`},
		{"a pass after a denial", func(r *Report) { r.Admission.Evaluation.Decision = admission.DecisionDeniedRAM }, nil, "decided denied_ram, and the report records VMs or claims a pass"},
		{"a grant over the RAM limit", func(r *Report) { r.Admission.Evaluation.HostRAMPercent = 71 }, nil, "granted with host RAM at 71.00%, over the limit of 70.00%"},
		{"a grant over the I/O wait limit", func(r *Report) { r.Admission.Evaluation.HostIOWaitPercent = 51 }, nil, "granted with I/O wait at 51.00%"},
		{"a grant over the projected limit", func(r *Report) { r.Admission.Evaluation.ProjectedRAMPercent = 71 }, nil, "granted with projected RAM at 71.00%"},
		{"a grant for a reservation that cannot fit", func(r *Report) { r.Admission.RecoveryReservationMiB = 800_000 }, nil, "granted for a reservation of 800000 MiB, more than 70.00%"},
		{"a grant with no total memory", func(r *Report) { r.Admission.Evaluation.HostTotalMiB = 0 }, nil, "which is not a measurement"},
		{"a projection that does not add up", func(r *Report) { r.Admission.Evaluation.ProjectedRAMPercent = 12 }, nil, "its memory figures and reservation give"},
		{"a negative measurement", func(r *Report) { r.Admission.Evaluation.HostIOWaitPercent = -1 }, nil, "host_iowait_percent -1 is not a measurement"},
		{"a RAM denial within the limit", func(r *Report) { denied(r, admission.DecisionDeniedRAM, func(e *AdmissionEvaluation) {}) }, nil, "denied for RAM at 10.00%, which is within the limit"},
		{"an I/O wait denial within the limit", func(r *Report) { denied(r, admission.DecisionDeniedIOWait, func(e *AdmissionEvaluation) {}) }, nil, "denied for I/O wait of 0.50%, which is within the limit"},
		{"a projected RAM denial within the limit", func(r *Report) { denied(r, admission.DecisionDeniedProjectedRAM, func(e *AdmissionEvaluation) {}) }, nil, "denied for projected RAM"},
		{"a never-admissible refusal of a reservation that fits", func(r *Report) { denied(r, admission.DecisionNeverAdmissible, func(e *AdmissionEvaluation) {}) }, nil, "never admissible, and a reservation of 2304 MiB fits"},
	} {
		report := consistentReport(plan)
		tc.mutate(report)
		problems := PolicyEvidenceProblems(report, tc.plan)
		if !containsAny(problems, tc.want) {
			t.Errorf("%s: problems %q, want one containing %q", tc.name, problems, tc.want)
		}
	}
}

// The ways a run is refused are all consistent when their numbers are.
func TestPolicyEvidenceAcceptsEachKindOfRefusal(t *testing.T) {
	plan := policyPlan(60, 70)
	for _, tc := range []struct {
		decision string
		set      func(*AdmissionEvaluation)
	}{
		{admission.DecisionDeniedRAM, func(e *AdmissionEvaluation) { e.HostRAMPercent = 71 }},
		{admission.DecisionDeniedIOWait, func(e *AdmissionEvaluation) { e.HostIOWaitPercent = 60 }},
		{admission.DecisionDeniedIOWaitUnmeasured, func(e *AdmissionEvaluation) { e.HostIOWaitPercent = 0 }},
		{admission.DecisionDeniedProjectedRAM, func(e *AdmissionEvaluation) { e.ProjectedRAMPercent = 71 }},
		{admission.DecisionNeverAdmissible, func(e *AdmissionEvaluation) { e.HostTotalMiB, e.HostAvailableMiB = 3000, 0 }},
		{admission.DecisionMetricsUnavailable, func(e *AdmissionEvaluation) { *e = AdmissionEvaluation{Checks: 1} }},
	} {
		report := BuildReport(plan, "n", 3*time.Second, false, nil, "")
		report.Admission = granted(report.Admission)
		report.Admission.Evaluation.Decision = tc.decision
		tc.set(report.Admission.Evaluation)
		report.Admission.Evaluation.Decision = tc.decision
		if problems := PolicyEvidenceProblems(report, plan); len(problems) != 0 {
			t.Errorf("a run refused with %s is contradicted: %v", tc.decision, problems)
		}
	}
	// A run that ended before admission was evaluated records the policy only.
	early := BuildReport(plan, "n", 0, false, nil, "")
	if early.Admission == nil || early.Admission.Evaluation != nil {
		t.Fatalf("an early failure's admission evidence: %+v", early.Admission)
	}
	if problems := PolicyEvidenceProblems(early, plan); len(problems) != 0 {
		t.Errorf("a run that ended before admission is contradicted: %v", problems)
	}
}

func containsAny(problems []string, want string) bool {
	for _, problem := range problems {
		if strings.Contains(problem, want) {
			return true
		}
	}
	return false
}

// With use_backup_config the node reads a VM's memory from its backup before it
// runs (the runner fills hardware_overrides.memory_mb from the backup's
// profile), so the reservation of its admission is not one the controller can
// recompute from the plan it read: holding an honest report to the plan's
// default would refuse every run of the recommended configuration. The plan
// then fixes the number of VMs, the tier and a floor (the memory it does give and
// the host overhead of each VM); a plan that fixes every VM's memory is held to
// it exactly.
func TestAReportOfABackupConfigPlanIsHeldToTheReservationTheBackupGives(t *testing.T) {
	controllersPlan := policyPlan(60, 70)
	controllersPlan.UseBackupConfig = true // no memory_mb: the backup says
	onNode := policyPlan(60, 70)
	onNode.UseBackupConfig = true
	onNode.Tiers[0].VMs[0].HardwareOverrides.MemoryMB = 8192 // what applyBackupConfig read
	report := consistentReport(onNode)
	report.ValidatedPlanSHA256, _ = config.CanonicalWorkerPlanSHA256(controllersPlan)
	if report.Admission.RecoveryReservationMiB != 8192+256 {
		t.Fatalf("test bug: the node's reservation is %d", report.Admission.RecoveryReservationMiB)
	}
	if problems := PolicyEvidenceProblems(report, controllersPlan); len(problems) != 0 {
		t.Fatalf("an honest report of a plan that takes its VMs' memory from the backup is refused: %v", problems)
	}

	below := consistentReport(onNode)
	below.Admission.RecoveryReservationMiB = 100
	if problems := PolicyEvidenceProblems(below, controllersPlan); !containsAny(problems, "below the 256 the plan itself reserves") {
		t.Errorf("a reservation below the host overhead of the plan's VMs: %v", problems)
	}
	extra := consistentReport(onNode)
	extra.Admission.RecoveryReservationVMs = 2
	if problems := PolicyEvidenceProblems(extra, controllersPlan); !containsAny(problems, "recovery_reservation_vms is 2, and the plan's is 1") {
		t.Errorf("a reservation for more VMs than the plan has: %v", problems)
	}

	// The plan fixes the memory of every VM: the figure is exact, with the
	// backup's configuration or without it.
	for _, useBackup := range []bool{true, false} {
		fixed := policyPlan(60, 70)
		fixed.UseBackupConfig = useBackup
		fixed.Tiers[0].VMs[0].HardwareOverrides.MemoryMB = 4096
		if problems := PolicyEvidenceProblems(consistentReport(fixed), fixed); len(problems) != 0 {
			t.Errorf("use_backup_config %v: a report of a plan with its memory set is refused: %v", useBackup, problems)
		}
		if problems := PolicyEvidenceProblems(consistentReport(onNode), fixed); !containsAny(problems, "recovery_reservation_mib is 8448, and the plan's is 4352") {
			t.Errorf("use_backup_config %v: another reservation than the plan's own: %v", useBackup, problems)
		}
	}
	// Without the backup's configuration the default of 2048 MiB is the plan's.
	defaulted := policyPlan(60, 70)
	if problems := PolicyEvidenceProblems(consistentReport(onNode), defaulted); !containsAny(problems, "recovery_reservation_mib is 8448, and the plan's is 2304") {
		t.Errorf("a backup-derived reservation for a plan that does not use the backup's configuration: %v", problems)
	}
}

func TestCanonicalPlanDigestsAreSignedAndCheckedAgainstExpectedPolicy(t *testing.T) {
	plan := policyPlan(60, 85)
	report, data := signedPolicyReport(t, plan, policyKey())
	if report.ValidatedPlanSHA256 == "" || report.ResolvedPlanSHA256 != report.ValidatedPlanSHA256 {
		t.Fatal("complete plan digests missing")
	}
	if _, valid, err := VerifyReportSignatureOnly(data); err != nil || !valid {
		t.Fatalf("valid signature: %v %v", valid, err)
	}
	report.ResolvedPlanSHA256 = strings.Repeat("0", 64)
	changed, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, _ := VerifyReportSignatureOnly(changed); valid {
		t.Fatal("resolved policy digest was not authenticated")
	}
	plan.Tiers[0].StartupGracePeriodSec++
	problems := PolicyEvidenceProblems(report, plan)
	if !strings.Contains(strings.Join(problems, "\n"), "validated_plan_sha256 differs") {
		t.Fatalf("different startup policy accepted: %v", problems)
	}
}

func TestPreflightMemoryEvidenceRefusesContradictoryMeasurements(t *testing.T) {
	plan := policyPlan(60, 85)
	report := BuildReport(plan, "node", 0, false, nil, "")
	required := float64(report.Admission.RecoveryReservationMiB)
	report.Admission = report.Admission.WithEvaluation(admission.Evaluation{
		Checks: 1, Decision: admission.DecisionPreflightDeniedMemory,
		HostTotalMiB: 10000, HostAvailableMiB: required - 1, RequiredAvailableMiB: required,
	})
	if problems := PolicyEvidenceProblems(report, plan); len(problems) != 0 {
		t.Fatalf("valid refusal rejected: %v", problems)
	}
	report.Admission.Evaluation.HostAvailableMiB = required + 1
	if problems := PolicyEvidenceProblems(report, plan); len(problems) == 0 {
		t.Fatal("refusal with sufficient memory accepted")
	}
}
