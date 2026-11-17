// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"fmt"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// MaxSoakErrorBytes bounds the failure text a soak summary keeps for a probe,
// so the summary is the same size however long the soak ran.
const MaxSoakErrorBytes = 512

// SoakSchemaMinor is the first report schema minor (1.7) whose VM records say
// what their tier's soak checked. A report of an earlier minor records no
// service checks of its soak (that soak only asked PVE whether each VM still
// ran), so it is not held to them.
const SoakSchemaMinor = 7

// SoakProblems is what contradicts the plan, or the record itself, in the soak
// summary of one VM record. A summary, whatever the VM's outcome, must
// add up: counts that agree, timestamps that parse and run forward, one entry
// per repeated probe, each of them the record's own probe at that position.
//
// planned is the VM the plan configures (nil when the report is checked
// without a plan) and soakSec its tier's soak_time_sec. With a plan, the
// summary must be of that soak, over exactly the plan's service probes, and a
// VM whose tier has no soak records none. A VM the report calls a pass was
// checked throughout: at least one check, none failed, and the last one at or
// after the end of the configured period. require is whether the VM must
// carry a summary at all: true for a VM of a report that claims a pass, whose
// tier held it for a soak (a VM of a run that failed elsewhere may belong to a
// tier that failed before its soak began).
func SoakProblems(record probe.VMValidationRecord, planned *config.VM, soakSec int, require bool) []string {
	var problems []string
	problem := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf("VM %d soak: ", record.VMID)+fmt.Sprintf(format, args...))
	}
	soak := record.Soak
	if soak == nil {
		if require && planned != nil && soakSec > 0 {
			problems = append(problems, fmt.Sprintf("VM %d passed without a record of its services being checked during its tier's %d s soak", record.VMID, soakSec))
		}
		return problems
	}
	if planned != nil && soakSec <= 0 {
		problem("the record carries a soak summary, and the plan holds its tier for no soak")
	}
	if planned != nil && soakSec > 0 && soak.ConfiguredSec != soakSec {
		problem("records a soak of %d s; the plan holds the tier for %d s", soak.ConfiguredSec, soakSec)
	}
	if soak.ConfiguredSec <= 0 || soak.IntervalSec <= 0 {
		problem("records a period of %d s and a check interval of %d s; both must be positive", soak.ConfiguredSec, soak.IntervalSec)
	}
	// A plan cannot ask for more than config.MaxDurationSec, and a count of
	// seconds beyond about 292 years wraps negative as a time.Duration, which
	// would turn the period check below into one no check can fail.
	if soak.ConfiguredSec > config.MaxDurationSec || soak.IntervalSec > config.MaxDurationSec {
		problem("records a period of %d s and a check interval of %d s; neither may exceed %d s (7 days), the longest a plan allows", soak.ConfiguredSec, soak.IntervalSec, config.MaxDurationSec)
	}
	if soak.Samples < 0 || soak.FailedSamples < 0 || soak.FailedSamples > soak.Samples {
		problem("records %d failed check(s) of %d", soak.FailedSamples, soak.Samples)
	}

	started, startedOK := soakTime(soak.StartedAt)
	if !startedOK {
		problem("started_at %q is not an RFC 3339 time", boundedSoakText(soak.StartedAt))
	}
	first, firstOK := soakTime(soak.FirstSampleAt)
	last, lastOK := soakTime(soak.LastSampleAt)
	switch {
	case soak.Samples > 0 && (!firstOK || !lastOK):
		problem("records %d check(s) without an RFC 3339 first_sample_at and last_sample_at", soak.Samples)
	case soak.Samples == 0 && (soak.FirstSampleAt != "" || soak.LastSampleAt != ""):
		problem("records no check, and the time of one")
	case soak.Samples > 0 && (last.Before(first) || (startedOK && first.Before(started))):
		problem("its first check (%s) and last check (%s) do not run forward from its start (%s)", soak.FirstSampleAt, soak.LastSampleAt, soak.StartedAt)
	}

	rowFailures, mostFailed := 0, 0
	previous := 0
	for index, row := range soak.Probes {
		rowProblem := func(format string, args ...any) {
			problem("probe entry %d (%s %q) %s", index+1, boundedSoakText(row.Type), boundedSoakText(row.Description), fmt.Sprintf(format, args...))
		}
		switch {
		case row.Probe < 1 || row.Probe <= previous:
			rowProblem("names probe position %d, which is not after the entry before it", row.Probe)
		case row.Probe > len(record.ProbeResults):
			rowProblem("names probe position %d, and the record has %d probe result(s)", row.Probe, len(record.ProbeResults))
		default:
			result := record.ProbeResults[row.Probe-1]
			if result.Type != row.Type || result.Description != row.Description {
				rowProblem("is not the record's probe %d (%s %q)", row.Probe, boundedSoakText(result.Type), boundedSoakText(result.Description))
			}
			if row.Skipped > 0 && !result.Skipped {
				rowProblem("was skipped in %d check(s), and it was not skipped in the probe stage", row.Skipped)
			}
			if !probeIsServiceCheck(result.Type) {
				rowProblem("is not a service probe, which are the only probes a soak repeats")
			}
		}
		previous = row.Probe
		if row.Passed < 0 || row.Skipped < 0 || row.Failed < 0 || row.Passed+row.Skipped+row.Failed != soak.Samples {
			rowProblem("records %d passed, %d skipped and %d failed check(s), and the soak has %d", row.Passed, row.Skipped, row.Failed, soak.Samples)
		}
		if row.WorstDuration < 0 {
			rowProblem("records a negative worst duration")
		}
		if (row.Failed > 0) != (row.FirstError != "") {
			rowProblem("records %d failed check(s) and an error text of %d byte(s); a failure has its error, and only a failure does", row.Failed, len(row.FirstError))
		}
		if len(row.FirstError) > MaxSoakErrorBytes {
			rowProblem("records an error text of %d bytes, more than the %d a summary keeps", len(row.FirstError), MaxSoakErrorBytes)
		}
		rowFailures += row.Failed
		mostFailed = max(mostFailed, row.Failed)
	}
	// Every failed check failed at least one probe, and a probe fails a check
	// at most once, so the per-probe failures bracket the number of failed checks.
	if soak.FailedSamples > rowFailures || soak.FailedSamples < mostFailed {
		problem("records %d failed check(s), and its probes failed %d time(s), at most %d each", soak.FailedSamples, rowFailures, mostFailed)
	}

	if soak.StatusReads < 0 || soak.StatusReadFailures < 0 || soak.StatusReadFailures > soak.StatusReads {
		problem("records %d failed status read(s) of %d", soak.StatusReadFailures, soak.StatusReads)
	}
	if (soak.StatusReadFailures > 0) != (soak.FirstStatusError != "") || len(soak.FirstStatusError) > MaxSoakErrorBytes {
		problem("records %d failed status read(s) and a status error text of %d byte(s); a failure has its error (at most %d bytes), and only a failure does", soak.StatusReadFailures, len(soak.FirstStatusError), MaxSoakErrorBytes)
	}

	if planned != nil && soakSec > 0 {
		want := 0
		for _, configured := range planned.Probes {
			if probeIsServiceCheck(configured.Type) {
				want++
			}
		}
		if len(soak.Probes) != want {
			problem("repeats %d probe(s); the plan has %d service probe(s) to repeat", len(soak.Probes), want)
		}
	}

	if record.VerificationStatus == "verified" && record.AllPassed {
		switch {
		case soak.Samples < 1:
			problem("the VM is recorded as a pass, and no service check ran during its soak")
		case soak.FailedSamples > 0:
			problem("the VM is recorded as a pass, and %d of its %d service check(s) failed", soak.FailedSamples, soak.Samples)
		case soak.StatusReads-soak.StatusReadFailures < 1:
			problem("the VM is recorded as a pass, and PVE never reported its state during the soak (%d of %d status read(s) failed), so a stop could have gone unseen", soak.StatusReadFailures, soak.StatusReads)
		case startedOK && lastOK && soak.ConfiguredSec > 0 && last.Sub(started) < time.Duration(min(soak.ConfiguredSec, config.MaxDurationSec))*time.Second:
			problem("the VM is recorded as a pass, and its last service check ran %s after the soak began, before the configured %d s were over", last.Sub(started), soak.ConfiguredSec)
		}
	}
	return problems
}

// probeIsServiceCheck reports whether a soak repeats a probe of this type: the
// probes that assert something in the guest. A qmp or screendump probe shows
// only that QEMU runs the VM, which the soak asks PVE about directly, and a
// screendump captures an image each time.
// The orchestrator selects the probes to repeat with the same predicate
// (config.IsGuestLevelProbe), so what it repeats and what these rules expect
// are one rule.
func probeIsServiceCheck(probeType string) bool { return config.IsGuestLevelProbe(probeType) }

func soakTime(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil
}

// boundedSoakText keeps report text quoted in a message short.
func boundedSoakText(value string) string {
	const limit = 80
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
