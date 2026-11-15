// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"io"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
)

// writeRTOTarget prints the recovery time objective a report was judged by,
// beside the achieved recovery time, so the default view says what the pass was
// a pass of.
func writeRTOTarget(out io.Writer, report *attest.Report) {
	if accept.SchemaMinor(report.ReportSchemaVersion) < accept.PolicyEvidenceSchemaMinor {
		fmt.Fprintf(out, "  RTO Target:  not recorded (schema %s predates 1.%d, which records the objective)\n",
			sanitizeVerifyText(report.ReportSchemaVersion), accept.PolicyEvidenceSchemaMinor)
		return
	}
	switch target := report.RTOTargetSeconds; {
	case target == nil:
		fmt.Fprintln(out, "  RTO Target:  none set (the plan sets no recovery time objective)")
	case report.RTOSeconds <= *target:
		fmt.Fprintf(out, "  RTO Target:  %.2f seconds (met)\n", *target)
	default:
		fmt.Fprintf(out, "  RTO Target:  %.2f seconds (EXCEEDED)\n", *target)
	}
}

// writeAdmissionPolicy prints the host admission limits a report was held to,
// the recovery memory it reserved and what the last admission check measured.
// Every number is the report's own; the decision is a name from a fixed list,
// printed through the same sanitizer as everything else a signed report
// supplies.
func writeAdmissionPolicy(out io.Writer, report *attest.Report) {
	if accept.SchemaMinor(report.ReportSchemaVersion) < accept.PolicyEvidenceSchemaMinor {
		return
	}
	admitted := report.Admission
	if admitted == nil {
		fmt.Fprintln(out, "\n  Admission Policy: not recorded")
		return
	}
	fmt.Fprintln(out, "\n  Admission Policy:")
	fmt.Fprintf(out, "    - Limits:                RAM %.1f%%, I/O wait %.1f%%\n", admitted.MaxHostRAMPercent, admitted.MaxHostIOWaitPercent)
	fmt.Fprintf(out, "    - Waits:                 a check every %d s, up to %d more\n", admitted.DeferRetryIntervalSec, admitted.MaxDeferRetries)
	if admitted.MaxConcurrentBoots > 0 {
		fmt.Fprintf(out, "    - Boot Gate:             %d concurrent boot(s), each counted for %d s\n", admitted.MaxConcurrentBoots, admitted.BootSettleSec)
	}
	fmt.Fprintf(out, "    - Recovery Reservation:  %d MiB for %d VM(s) through tier %d\n", admitted.RecoveryReservationMiB, admitted.RecoveryReservationVMs, admitted.RecoveryReservationTier)
	evaluation := admitted.Evaluation
	if evaluation == nil {
		fmt.Fprintln(out, "    - Last Check:            none (the run ended before admission was evaluated)")
		return
	}
	fmt.Fprintf(out, "    - Last Check:            %s (check %d)\n", sanitizeVerifyText(evaluation.Decision), evaluation.Checks)
	fmt.Fprintf(out, "    - Measured:              RAM %.1f%% in use, I/O wait %.1f%%, projected RAM %.1f%% of %.0f MiB (%.0f MiB available)\n",
		evaluation.HostRAMPercent, evaluation.HostIOWaitPercent, evaluation.ProjectedRAMPercent, evaluation.HostTotalMiB, evaluation.HostAvailableMiB)
}
