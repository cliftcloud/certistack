// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"fmt"
	"io"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
)

// writeSoakSummary prints, for each VM whose tier held it for a soak, what the
// soak checked: how many times its service probes ran, how many of those runs
// failed, the slowest probe, and how many times PVE was asked whether the VM
// still ran. A report of an earlier schema, or a tier with no
// soak, has nothing to print.
func writeSoakSummary(out io.Writer, report *attest.Report) {
	printed := false
	for _, vm := range report.VMRecords {
		soak := vm.Soak
		if soak == nil {
			continue
		}
		if !printed {
			fmt.Fprintln(out, "\n  Tier Soak Service Checks:")
			printed = true
		}
		var worst time.Duration
		for _, row := range soak.Probes {
			worst = max(worst, row.WorstDuration)
		}
		fmt.Fprintf(out, "    - VM %d: %d check(s) of %d probe(s) over %ds (every %ds), %d failed, slowest %s; PVE state read %d time(s), %d failed\n",
			vm.VMID, soak.Samples, len(soak.Probes), soak.ConfiguredSec, soak.IntervalSec, soak.FailedSamples, worst.Round(time.Microsecond), soak.StatusReads, soak.StatusReadFailures)
		for _, row := range soak.Probes {
			if row.Failed > 0 {
				fmt.Fprintf(out, "      probe %d (%s %q) failed %d time(s): %s\n", row.Probe, sanitizeVerifyText(row.Type), sanitizeVerifyText(row.Description), row.Failed, sanitizeVerifyText(row.FirstError))
			}
		}
		if soak.StatusReadFailures > 0 {
			fmt.Fprintf(out, "      first PVE status error: %s\n", sanitizeVerifyText(soak.FirstStatusError))
		}
	}
}
