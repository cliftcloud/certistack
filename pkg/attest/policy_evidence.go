// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/config"
)

// The policy a run is judged by is recorded with its result (schema 1.7). A
// pass that does not say which recovery time objective or which host admission
// limits it passed under cannot be told from a pass under much looser ones.

// AdmissionEvidence is the host admission policy a run was held to, the
// recovery memory it had to reserve, and what the last admission check
// measured and decided. All memory is in MiB (1024*1024 bytes) and all
// percentages are 0 to 100.
//
// The policy, and the count of VMs and the tier of the reservation, are
// functions of the plan, so a controller or a verifier that has the plan
// recomputes them (PolicyEvidenceProblems). So is the reserved memory, unless
// the plan has the node take a VM's memory from its backup (use_backup_config
// with no memory_mb for it): the node reads that from the backup, and the plan
// fixes only a floor. The evaluation is the node's own observation, which
// nothing can recheck afterwards; it is held only to its own limits and
// arithmetic.
type AdmissionEvidence struct {
	// MaxHostRAMPercent and MaxHostIOWaitPercent are the plan's
	// admission_control limits as the run enforced them (the aliases the plan
	// may use are already resolved).
	MaxHostRAMPercent    float64 `json:"max_host_ram_percent"`
	MaxHostIOWaitPercent float64 `json:"max_host_iowait_percent"`
	// DeferRetryIntervalSec and MaxDeferRetries bound how long a run waits for
	// the node to fall under the limits: the interval in seconds between
	// checks, and how many more checks follow the first.
	DeferRetryIntervalSec int `json:"defer_retry_interval_sec"`
	MaxDeferRetries       int `json:"max_defer_retries"`
	// MaxConcurrentBoots and BootSettleSec are the plan's boot gate: how many
	// sandbox VMs may be booting at once (0, and absent here, is unlimited) and
	// for how many seconds after its start a VM counts as booting (the plan's,
	// or the default when it gave none; absent without a gate).
	MaxConcurrentBoots int `json:"max_concurrent_boots,omitempty"`
	BootSettleSec      int `json:"boot_settle_sec,omitempty"`
	// RecoveryReservationMiB is the memory the plan's sandbox VMs reserve at
	// the peak: every tier stays up until teardown, so the last tier boots
	// beside all the earlier ones. It counts each VM's memory and a fixed host
	// overhead for it. RecoveryReservationVMs is how many VMs that is, and
	// RecoveryReservationTier the highest tier level included.
	RecoveryReservationMiB  int `json:"recovery_reservation_mib"`
	RecoveryReservationVMs  int `json:"recovery_reservation_vms"`
	RecoveryReservationTier int `json:"recovery_reservation_tier"`
	// Evaluation is the last admission check. It is absent when the run ended
	// before admission was evaluated (a refused plan, or a failed non-memory node preflight).
	Evaluation *AdmissionEvaluation `json:"evaluation,omitempty"`
}

// AdmissionEvaluation is what the last admission check of a run measured and
// decided. A run that is deferred is checked again after each retry interval:
// Checks counts the checks, and the measurements are those of the last, the one
// that granted the run or the one that refused it last.
//
// A measurement the check did not reach is 0 and Decision says which were
// taken: never_admissible read only the node's memory,
// denied_iowait_unmeasured has no I/O wait, and metrics_unavailable has none.
type AdmissionEvaluation struct {
	// Checks is how many admission checks ran, at least 1.
	Checks int `json:"checks"`
	// Decision is the outcome of the last check: granted, denied_ram,
	// denied_iowait, denied_iowait_unmeasured, denied_projected_ram,
	// never_admissible, preflight_denied_memory or metrics_unavailable.
	Decision string `json:"decision"`
	// HostTotalMiB and HostAvailableMiB are MemTotal and MemAvailable of the
	// node at the check that held the reservation to the limit. They are read
	// after the I/O wait sample, about half a second after HostRAMPercent.
	HostTotalMiB         float64 `json:"host_total_mib"`
	HostAvailableMiB     float64 `json:"host_available_mib"`
	RequiredAvailableMiB float64 `json:"required_available_mib,omitempty"`
	// HostRAMPercent is the share of memory in use when the check first read
	// it: (MemTotal-MemAvailable)/MemTotal.
	HostRAMPercent float64 `json:"host_ram_percent"`
	// HostIOWaitPercent is the share of all CPU time spent waiting for I/O
	// over one sampling interval of /proc/stat (half a second; a sample that is
	// not usable is taken again, up to three intervals).
	HostIOWaitPercent float64 `json:"host_iowait_percent"`
	// ProjectedRAMPercent is the share of memory that would be in use once the
	// recovery reservation is added to the use at the second memory reading:
	// (MemTotal-MemAvailable+reservation)/MemTotal. It is what is held to
	// max_host_ram_percent.
	ProjectedRAMPercent float64 `json:"projected_ram_percent"`
}

// RTOObjective is the recovery time objective a plan sets, as a report
// records it: nil when the plan sets none (omitting the key is the only way to
// say so), the target in seconds otherwise.
func RTOObjective(plan *config.Plan) *float64 {
	if plan == nil {
		return nil
	}
	target := plan.Compliance.RTOTargetSeconds
	if math.IsNaN(target) || math.IsInf(target, 0) || target <= 0 {
		return nil
	}
	return &target
}

// NewAdmissionEvidence is the policy and reservation the plan implies, with no
// evaluation. A run that reaches admission adds the evaluation to it
// (WithEvaluation).
func NewAdmissionEvidence(plan *config.Plan) *AdmissionEvidence {
	if plan == nil {
		return nil
	}
	control := plan.AdmissionControl
	evidence := &AdmissionEvidence{
		MaxHostRAMPercent:     control.MaxHostRAMPercent,
		MaxHostIOWaitPercent:  control.MaxHostIOWaitPercent,
		DeferRetryIntervalSec: control.DeferRetryIntervalSec,
		MaxDeferRetries:       control.MaxDeferRetries,
		MaxConcurrentBoots:    control.MaxConcurrentBoots,
	}
	if control.MaxConcurrentBoots > 0 {
		evidence.BootSettleSec = int(control.BootSettle().Seconds())
	}
	// An overflowing reservation is refused by the run itself; the evidence of
	// that refusal then has no reservation to state.
	if memory, vms, tier, err := admission.RecoveryMemoryReservation(plan); err == nil {
		evidence.RecoveryReservationMiB, evidence.RecoveryReservationVMs, evidence.RecoveryReservationTier = memory, vms, tier
	}
	return evidence
}

// planReservation is what the plan fixes of the recovery reservation: its
// exact value in MiB when every VM's memory is known from the plan (set in the
// plan, or the default a plan that does not use the backup's configuration
// gets), or -1 and a floor when the node reads some VM's memory from its backup
// (use_backup_config, no memory_mb): the memory the plan does give, and the host
// overhead of every VM.
func planReservation(plan *config.Plan) (exact, floor int) {
	memory, vms, _, err := admission.RecoveryMemoryReservation(plan)
	if err != nil {
		return -1, 0
	}
	floor = vms * admission.SandboxVMHostOverheadMB
	fixed := true
	if plan.UseBackupConfig {
		for _, tier := range plan.Tiers {
			for _, vm := range tier.VMs {
				if vm.HardwareOverrides.MemoryMB <= 0 {
					fixed = false // the node reads it from the backup
				} else {
					floor += vm.HardwareOverrides.MemoryMB
				}
			}
		}
	}
	if fixed {
		return memory, floor
	}
	return -1, floor
}

// WithEvaluation returns a copy of the evidence with the last admission
// check's measurements and decision, or the evidence itself when no check ran.
func (e *AdmissionEvidence) WithEvaluation(last admission.Evaluation) *AdmissionEvidence {
	if e == nil || last.Checks == 0 {
		return e
	}
	withEvaluation := *e
	withEvaluation.Evaluation = &AdmissionEvaluation{
		Checks:               last.Checks,
		Decision:             last.Decision,
		HostTotalMiB:         last.HostTotalMiB,
		HostAvailableMiB:     last.HostAvailableMiB,
		RequiredAvailableMiB: last.RequiredAvailableMiB,
		HostRAMPercent:       last.HostRAMPercent,
		HostIOWaitPercent:    last.HostIOWaitPercent,
		ProjectedRAMPercent:  last.ProjectedRAMPercent,
	}
	return &withEvaluation
}

// projectionTolerance is how far the projected share of memory may differ from
// the one recomputed from the memory figures beside it: the figures are the
// node's own, written as read, so the difference is rounding only.
const projectionTolerance = 0.01

// PolicyEvidenceProblems are the ways a report of schema 1.7 or later
// contradicts itself, or the plan when one is given, about the recovery time
// objective and the host admission policy it was judged by. The caller decides
// that the report's schema records them. The controller applies it to a
// worker's report before it signs one and verify-report applies it to a signed
// report, so the two cannot disagree about what is acceptable.
//
// Without a plan, the objective and the admission evidence are held to
// themselves: an objective of a passing report is met, a granted admission
// satisfies its own limits, no VM is recorded for a run that was refused, and a
// pass was admitted. With a plan they must also be the plan's.
func PolicyEvidenceProblems(report *Report, plan *config.Plan) []string {
	var problems []string
	problem := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	// These digests cover every policy and resolved backup setting, rather
	// than only the individually displayed objective and admission fields.
	for _, entry := range []struct{ name, digest string }{
		{"validated_plan_sha256", report.ValidatedPlanSHA256},
		{"resolved_plan_sha256", report.ResolvedPlanSHA256},
	} {
		name, digest := entry.name, entry.digest
		if digest == "" {
			continue // older reports omit these additive members
		}
		if decoded, err := hex.DecodeString(digest); err != nil || len(decoded) != 32 || strings.ToLower(digest) != digest {
			problem("the report's %s is not a canonical SHA-256 digest", name)
		}
	}
	if (report.ValidatedPlanSHA256 != "" || report.ResolvedPlanSHA256 != "") && report.PlanDigestFormat != config.WorkerPlanDigestFormat {
		problem("the report's plan_digest_format is not supported")
	}
	if plan != nil && report.ValidatedPlanSHA256 != "" {
		if expected, err := config.CanonicalWorkerPlanSHA256(plan); err != nil || report.ValidatedPlanSHA256 != expected {
			problem("the report's validated_plan_sha256 differs from the expected worker plan")
		}
	}

	// The recovery time objective.
	if target := report.RTOTargetSeconds; target != nil {
		switch {
		case math.IsNaN(*target) || math.IsInf(*target, 0) || *target <= 0:
			problem("the report's rto_target_seconds %v is not a number of seconds above 0", *target)
		case report.AllPassed && report.RTOSeconds > *target:
			problem("the report claims a pass with a recovery time of %.1fs, over its own objective of %.1fs", report.RTOSeconds, *target)
		}
	}
	if plan != nil {
		switch want, got := RTOObjective(plan), report.RTOTargetSeconds; {
		case want == nil && got != nil:
			problem("the report records a recovery time objective of %vs, and the plan sets none", *got)
		case want != nil && got == nil:
			problem("the report records no recovery time objective, and the plan's is %vs", *want)
		case want != nil && got != nil && *want != *got:
			problem("the report records a recovery time objective of %vs, and the plan's is %vs", *got, *want)
		}
	}

	// The host admission policy.
	admitted := report.Admission
	if admitted == nil {
		problem("the report records no host admission policy")
		return problems
	}
	for _, limit := range []struct {
		name  string
		value float64
	}{{"max_host_ram_percent", admitted.MaxHostRAMPercent}, {"max_host_iowait_percent", admitted.MaxHostIOWaitPercent}} {
		if math.IsNaN(limit.value) || math.IsInf(limit.value, 0) || limit.value <= 0 || limit.value > 100 {
			problem("the report's admission %s %v is not above 0 and at most 100", limit.name, limit.value)
		}
	}
	if plan != nil {
		want := NewAdmissionEvidence(plan)
		for _, field := range []struct {
			name      string
			got, want float64
		}{
			{"max_host_ram_percent", admitted.MaxHostRAMPercent, want.MaxHostRAMPercent},
			{"max_host_iowait_percent", admitted.MaxHostIOWaitPercent, want.MaxHostIOWaitPercent},
			{"defer_retry_interval_sec", float64(admitted.DeferRetryIntervalSec), float64(want.DeferRetryIntervalSec)},
			{"max_defer_retries", float64(admitted.MaxDeferRetries), float64(want.MaxDeferRetries)},
			{"max_concurrent_boots", float64(admitted.MaxConcurrentBoots), float64(want.MaxConcurrentBoots)},
			{"boot_settle_sec", float64(admitted.BootSettleSec), float64(want.BootSettleSec)},
			{"recovery_reservation_vms", float64(admitted.RecoveryReservationVMs), float64(want.RecoveryReservationVMs)},
			{"recovery_reservation_tier", float64(admitted.RecoveryReservationTier), float64(want.RecoveryReservationTier)},
		} {
			if field.got != field.want {
				problem("the report's admission %s is %v, and the plan's is %v", field.name, field.got, field.want)
			}
		}
		// The reserved memory is the plan's exactly, unless the node reads a
		// VM's memory from its backup: then the plan fixes a floor, and the
		// node's figure may not be below it.
		if exact, floor := planReservation(plan); exact >= 0 {
			if admitted.RecoveryReservationMiB != exact {
				problem("the report's admission recovery_reservation_mib is %d, and the plan's is %d", admitted.RecoveryReservationMiB, exact)
			}
		} else if admitted.RecoveryReservationMiB < floor {
			problem("the report's admission recovery_reservation_mib is %d, below the %d the plan itself reserves (its VMs' own memory and the host overhead of each)", admitted.RecoveryReservationMiB, floor)
		}
	}

	// What the last admission check measured and decided.
	evaluation := admitted.Evaluation
	switch {
	case evaluation == nil:
		if report.AllPassed || len(report.VMRecords) > 0 {
			problem("the report records VMs or claims a pass, and no admission check that let the run start")
		}
		return problems
	case evaluation.Checks < 1:
		problem("the report's admission records %d checks; a run that was evaluated was checked at least once", evaluation.Checks)
	case admitted.MaxDeferRetries >= 0 && evaluation.Checks > admitted.MaxDeferRetries+1:
		problem("the report's admission records %d checks, more than max_defer_retries %d allows", evaluation.Checks, admitted.MaxDeferRetries)
	}
	if !admission.KnownDecision(evaluation.Decision) {
		problem("the report's admission decision %q is not one this release records", clipPolicyText(evaluation.Decision))
		return problems
	}
	if evaluation.Decision != admission.DecisionGranted && (report.AllPassed || len(report.VMRecords) > 0) {
		problem("the report's last admission check decided %s, and the report records VMs or claims a pass", evaluation.Decision)
	}
	for _, measured := range []struct {
		name  string
		value float64
	}{
		{"host_total_mib", evaluation.HostTotalMiB}, {"host_available_mib", evaluation.HostAvailableMiB},
		{"host_ram_percent", evaluation.HostRAMPercent}, {"host_iowait_percent", evaluation.HostIOWaitPercent},
		{"projected_ram_percent", evaluation.ProjectedRAMPercent},
		{"required_available_mib", evaluation.RequiredAvailableMiB},
	} {
		if math.IsNaN(measured.value) || math.IsInf(measured.value, 0) || measured.value < 0 {
			problem("the report's admission %s %v is not a measurement", measured.name, measured.value)
			return problems
		}
	}
	limitRAM, limitIOWait := admitted.MaxHostRAMPercent, admitted.MaxHostIOWaitPercent
	reservation := float64(admitted.RecoveryReservationMiB)
	switch evaluation.Decision {
	case admission.DecisionPreflightDeniedMemory:
		if evaluation.HostTotalMiB <= 0 || evaluation.HostAvailableMiB > evaluation.HostTotalMiB || evaluation.RequiredAvailableMiB <= evaluation.HostAvailableMiB || evaluation.RequiredAvailableMiB != reservation {
			problem("preflight memory denial does not match the measured available memory and recovery reservation")
		}
	case admission.DecisionGranted:
		if evaluation.HostRAMPercent > limitRAM {
			problem("admission was granted with host RAM at %.2f%%, over the limit of %.2f%%", evaluation.HostRAMPercent, limitRAM)
		}
		if evaluation.HostIOWaitPercent > limitIOWait {
			problem("admission was granted with I/O wait at %.2f%%, over the limit of %.2f%%", evaluation.HostIOWaitPercent, limitIOWait)
		}
		if evaluation.ProjectedRAMPercent > limitRAM {
			problem("admission was granted with projected RAM at %.2f%%, over the limit of %.2f%%", evaluation.ProjectedRAMPercent, limitRAM)
		}
		if reservation > 0 {
			switch {
			case evaluation.HostTotalMiB <= 0 || evaluation.HostAvailableMiB > evaluation.HostTotalMiB:
				problem("admission was granted with host memory of %.1f MiB total and %.1f MiB available, which is not a measurement", evaluation.HostTotalMiB, evaluation.HostAvailableMiB)
			case reservation > evaluation.HostTotalMiB*limitRAM/100:
				problem("admission was granted for a reservation of %.0f MiB, more than %.2f%% of the node's %.1f MiB", reservation, limitRAM, evaluation.HostTotalMiB)
			default:
				projected := (evaluation.HostTotalMiB - evaluation.HostAvailableMiB + reservation) / evaluation.HostTotalMiB * 100
				if math.Abs(projected-evaluation.ProjectedRAMPercent) > projectionTolerance {
					problem("the report's projected RAM is %.2f%%, and its memory figures and reservation give %.2f%%", evaluation.ProjectedRAMPercent, projected)
				}
			}
		}
	case admission.DecisionDeniedRAM:
		if evaluation.HostRAMPercent <= limitRAM {
			problem("admission was denied for RAM at %.2f%%, which is within the limit of %.2f%%", evaluation.HostRAMPercent, limitRAM)
		}
	case admission.DecisionDeniedIOWait:
		if evaluation.HostIOWaitPercent <= limitIOWait {
			problem("admission was denied for I/O wait of %.2f%%, which is within the limit of %.2f%%", evaluation.HostIOWaitPercent, limitIOWait)
		}
	case admission.DecisionDeniedProjectedRAM:
		if evaluation.ProjectedRAMPercent <= limitRAM {
			problem("admission was denied for projected RAM of %.2f%%, which is within the limit of %.2f%%", evaluation.ProjectedRAMPercent, limitRAM)
		}
	case admission.DecisionNeverAdmissible:
		if evaluation.HostTotalMiB <= 0 || reservation <= evaluation.HostTotalMiB*limitRAM/100 {
			problem("admission was refused as never admissible, and a reservation of %.0f MiB fits %.2f%% of the node's %.1f MiB", reservation, limitRAM, evaluation.HostTotalMiB)
		}
	}
	return problems
}

// clipPolicyText keeps a value a worker supplied short and on one line, for a
// message.
func clipPolicyText(text string) string {
	text = strings.Join(strings.FieldsFunc(text, func(r rune) bool { return r < 0x20 || r == 0x7f }), " ")
	const limit = 60
	if utf8.RuneCountInString(text) <= limit {
		return text
	}
	return string([]rune(text)[:limit]) + "…"
}
