// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// soakPlannedVM is a VM with one hypervisor probe and two service probes.
func soakPlannedVM() config.VM {
	return config.VM{VMID: 9001, Name: "app", Probes: []config.Probe{
		{Type: "qmp", Description: "VM is running"},
		{Type: "tcp", TargetIP: "10.100.0.10", Port: 5432, Description: "database"},
		{Type: "qga", Command: "ping", Description: "agent", RequireQGA: true},
	}}
}

// soakRecord is the record an honest worker writes for soakPlannedVM after a
// 60 s soak checked at 30 s: three checks, none failed.
func soakRecord() probe.VMValidationRecord {
	return probe.VMValidationRecord{
		VMID: 9001, Name: "app", VerificationStatus: "verified", AllPassed: true,
		ProbeResults: []probe.Result{
			{Type: "qmp", Description: "VM is running", Passed: true},
			{Type: "tcp", Target: "10.100.0.10:5432", Description: "database", Passed: true},
			{Type: "qga", Target: "ping", Description: "agent", Passed: true},
		},
		Soak: &probe.SoakEvidence{
			ConfiguredSec: 60, IntervalSec: 30,
			StartedAt: "2026-09-30T10:00:00Z", FirstSampleAt: "2026-09-30T10:00:30Z", LastSampleAt: "2026-09-30T10:01:00Z",
			Samples: 3, FailedSamples: 0,
			Probes: []probe.SoakProbeEvidence{
				{Probe: 2, Type: "tcp", Description: "database", Passed: 3, WorstDuration: 4 * time.Millisecond},
				{Probe: 3, Type: "qga", Description: "agent", Passed: 3, WorstDuration: 2 * time.Millisecond},
			},
			StatusReads: 7,
		},
	}
}

func soakProblemsOf(record probe.VMValidationRecord, planned *config.VM, soakSec int, require bool) string {
	return strings.Join(SoakProblems(record, planned, soakSec, require), "\n")
}

func TestSoakProblemsAcceptsAnHonestSummary(t *testing.T) {
	vm := soakPlannedVM()
	if problems := soakProblemsOf(soakRecord(), &vm, 60, true); problems != "" {
		t.Fatalf("an honest summary is refused: %s", problems)
	}
	// Without a plan the summary is held only to itself.
	if problems := soakProblemsOf(soakRecord(), nil, 0, true); problems != "" {
		t.Fatalf("an honest summary is refused without a plan: %s", problems)
	}
}

// Each way a summary can contradict the plan or itself is a problem; the
// error says which.
func TestSoakProblemsRefusesAContradiction(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*probe.VMValidationRecord)
		require bool
		soakSec int
		want    string
	}{
		{"no summary for a passing VM of a tier with a soak", func(r *probe.VMValidationRecord) { r.Soak = nil }, true, 60, "passed without a record of its services being checked during its tier's 60 s soak"},
		{"a summary for a tier with no soak", func(r *probe.VMValidationRecord) {}, true, 0, "holds its tier for no soak"},
		{"a soak of another length", func(r *probe.VMValidationRecord) { r.Soak.ConfiguredSec = 30 }, true, 60, "records a soak of 30 s; the plan holds the tier for 60 s"},
		{"no interval", func(r *probe.VMValidationRecord) { r.Soak.IntervalSec = 0 }, true, 60, "both must be positive"},
		{"more failed checks than checks", func(r *probe.VMValidationRecord) { r.Soak.FailedSamples = 4 }, true, 60, "records 4 failed check(s) of 3"},
		{"a failed check under a pass", func(r *probe.VMValidationRecord) {
			r.Soak.FailedSamples = 1
			r.Soak.Probes[0].Passed, r.Soak.Probes[0].Failed, r.Soak.Probes[0].FirstError = 2, 1, "connection refused"
		}, true, 60, "recorded as a pass, and 1 of its 3 service check(s) failed"},
		{"no check at all", func(r *probe.VMValidationRecord) {
			r.Soak.Samples, r.Soak.FirstSampleAt, r.Soak.LastSampleAt = 0, "", ""
			r.Soak.Probes[0].Passed, r.Soak.Probes[1].Passed = 0, 0
		}, true, 60, "no service check ran during its soak"},
		{"the last check before the end of the period", func(r *probe.VMValidationRecord) { r.Soak.LastSampleAt = "2026-09-30T10:00:59Z" }, true, 60, "before the configured 60 s were over"},
		{"a start that is not a time", func(r *probe.VMValidationRecord) { r.Soak.StartedAt = "last tuesday" }, true, 60, "started_at \"last tuesday\" is not an RFC 3339 time"},
		{"checks that run backwards", func(r *probe.VMValidationRecord) {
			r.Soak.FirstSampleAt, r.Soak.LastSampleAt = "2026-09-30T10:01:00Z", "2026-09-30T10:00:30Z"
		}, true, 60, "do not run forward"},
		{"a check before the soak began", func(r *probe.VMValidationRecord) { r.Soak.FirstSampleAt = "2026-09-30T09:59:00Z" }, true, 60, "do not run forward"},
		{"a probe's counts that do not add up", func(r *probe.VMValidationRecord) { r.Soak.Probes[0].Passed = 2 }, true, 60, "records 2 passed, 0 skipped and 0 failed check(s), and the soak has 3"},
		{"a probe that is not the record's", func(r *probe.VMValidationRecord) { r.Soak.Probes[0].Description = "another" }, true, 60, "is not the record's probe 2"},
		{"a probe position past the record", func(r *probe.VMValidationRecord) { r.Soak.Probes[1].Probe = 9 }, true, 60, "names probe position 9"},
		{"probe entries out of order", func(r *probe.VMValidationRecord) { r.Soak.Probes[1].Probe = 2 }, true, 60, "not after the entry before it"},
		{"a hypervisor probe repeated", func(r *probe.VMValidationRecord) {
			r.Soak.Probes = append([]probe.SoakProbeEvidence{{Probe: 1, Type: "qmp", Description: "VM is running", Passed: 3}}, r.Soak.Probes...)
		}, true, 60, "is not a service probe"},
		{"a service probe left out", func(r *probe.VMValidationRecord) { r.Soak.Probes = r.Soak.Probes[:1] }, true, 60, "repeats 1 probe(s); the plan has 2 service probe(s) to repeat"},
		{"a skip the probe stage did not have", func(r *probe.VMValidationRecord) {
			r.Soak.Probes[1].Passed, r.Soak.Probes[1].Skipped = 2, 1
		}, true, 60, "was skipped in 1 check(s), and it was not skipped in the probe stage"},
		{"a failure with no error text", func(r *probe.VMValidationRecord) {
			r.Soak.FailedSamples = 1
			r.Soak.Probes[0].Passed, r.Soak.Probes[0].Failed = 2, 1
		}, false, 60, "a failure has its error, and only a failure does"},
		{"an error text that is not bounded", func(r *probe.VMValidationRecord) {
			r.Soak.FailedSamples = 1
			r.Soak.Probes[0].Passed, r.Soak.Probes[0].Failed, r.Soak.Probes[0].FirstError = 2, 1, strings.Repeat("x", MaxSoakErrorBytes+1)
		}, false, 60, "more than the 512 a summary keeps"},
		{"failed checks no probe failed", func(r *probe.VMValidationRecord) {
			r.Soak.FailedSamples = 1
			r.VerificationStatus, r.AllPassed = "failed", false
		}, false, 60, "its probes failed 0 time(s)"},
		{"a negative worst duration", func(r *probe.VMValidationRecord) { r.Soak.Probes[0].WorstDuration = -1 }, true, 60, "negative worst duration"},
		{"a pass whose state PVE never reported", func(r *probe.VMValidationRecord) {
			r.Soak.StatusReads, r.Soak.StatusReadFailures, r.Soak.FirstStatusError = 4, 4, "HTTP 401"
		}, true, 60, "PVE never reported its state during the soak (4 of 4 status read(s) failed)"},
		{"more failed status reads than reads", func(r *probe.VMValidationRecord) { r.Soak.StatusReadFailures, r.Soak.FirstStatusError = 9, "x" }, true, 60, "records 9 failed status read(s) of 7"},
		{"failed status reads and no error", func(r *probe.VMValidationRecord) { r.Soak.StatusReadFailures = 1 }, true, 60, "a failure has its error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := soakRecord()
			// Deep-copy the shared slices a mutation edits.
			record.Soak.Probes = append([]probe.SoakProbeEvidence(nil), record.Soak.Probes...)
			vm := soakPlannedVM()
			tc.mutate(&record)
			got := soakProblemsOf(record, &vm, tc.soakSec, tc.require)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("problems = %q, want one containing %q", got, tc.want)
			}
		})
	}
}

// A signed report carries any integer in soak.configured_sec. 9223372037 s,
// multiplied by time.Second, wraps to a negative Duration, and "the last check
// ran before the period was over" would then be false for any check, skipping
// the rule without a word. The period and the interval are bounded by what a
// plan can ask for (config.MaxDurationSec, 7 days) and an out-of-range value
// is a problem, with or without a plan.
func TestSoakProblemsRefusesAPeriodOrIntervalBeyondWhatAPlanAllows(t *testing.T) {
	const wraps = 9223372037 // *1e9 passes MaxInt64 and wraps negative
	const bounds = "neither may exceed 604800 s (7 days)"
	vm := soakPlannedVM()
	for _, tc := range []struct {
		name    string
		mutate  func(*probe.VMValidationRecord)
		planned *config.VM
		soakSec int
	}{
		{"a period that wraps, with no plan", func(r *probe.VMValidationRecord) { r.Soak.ConfiguredSec = wraps }, nil, 0},
		{"a period that wraps, with a plan", func(r *probe.VMValidationRecord) { r.Soak.ConfiguredSec = wraps }, &vm, 60},
		{"a period of the largest int", func(r *probe.VMValidationRecord) { r.Soak.ConfiguredSec = int(^uint(0) >> 1) }, nil, 0},
		{"a period one second over the limit", func(r *probe.VMValidationRecord) { r.Soak.ConfiguredSec = config.MaxDurationSec + 1 }, nil, 0},
		{"an interval that wraps", func(r *probe.VMValidationRecord) { r.Soak.IntervalSec = wraps }, nil, 0},
		{"an interval one second over the limit", func(r *probe.VMValidationRecord) { r.Soak.IntervalSec = config.MaxDurationSec + 1 }, &vm, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := soakRecord()
			tc.mutate(&record)
			if problems := soakProblemsOf(record, tc.planned, tc.soakSec, true); !strings.Contains(problems, bounds) {
				t.Fatalf("a period or interval out of range is not a problem: %q", problems)
			}
		})
	}
	// The limit itself is a duration a plan can ask for.
	record := soakRecord()
	record.Soak.ConfiguredSec, record.Soak.IntervalSec = config.MaxDurationSec, config.MaxDurationSec
	record.Soak.LastSampleAt = "2026-10-07T10:00:00Z"
	if problems := soakProblemsOf(record, nil, 0, true); problems != "" {
		t.Fatalf("a soak of the longest period is refused: %s", problems)
	}
	// The wrapped period does not hide a last check that came too early.
	record = soakRecord()
	record.Soak.ConfiguredSec = wraps
	if problems := soakProblemsOf(record, nil, 0, true); !strings.Contains(problems, "before the configured") {
		t.Fatalf("a last check too early for a period out of range is not reported: %q", problems)
	}
}

// A VM of a run that failed elsewhere may sit in a tier that failed before
// its soak began, and is not required to carry a summary.
func TestSoakProblemsDoesNotRequireASummaryOfAVMOfAFailedRun(t *testing.T) {
	vm := soakPlannedVM()
	record := soakRecord()
	record.Soak = nil
	if problems := soakProblemsOf(record, &vm, 60, false); problems != "" {
		t.Fatalf("a summary was required of a VM of a failed run: %s", problems)
	}
	if problems := soakProblemsOf(record, &vm, 60, true); problems == "" {
		t.Fatal("a VM of a passing report with no summary is accepted")
	}
}

// A skip is allowed for an optional guest-agent probe that the probe stage
// skipped too, and only then.
func TestSoakProblemsAllowsASkipTheProbeStageHad(t *testing.T) {
	vm := soakPlannedVM()
	vm.Probes[2].RequireQGA = false
	record := soakRecord()
	record.ProbeResults[2].Skipped = true
	record.Soak.Probes = []probe.SoakProbeEvidence{
		{Probe: 2, Type: "tcp", Description: "database", Passed: 3},
		{Probe: 3, Type: "qga", Description: "agent", Skipped: 3},
	}
	if problems := soakProblemsOf(record, &vm, 60, true); problems != "" {
		t.Fatalf("a skip the probe stage also had is refused: %s", problems)
	}
}

// The summary is signed: it round-trips through the report, is part of the
// canonical bytes, and a report that never had one is byte-for-byte what
// schema 1.6 wrote.
func TestSchema17SoakIsTheMinorThatAddsIt(t *testing.T) {
	if CurrentReportSchemaVersion != "1.7" {
		t.Fatalf("CurrentReportSchemaVersion = %q; the soak summary is schema 1.7", CurrentReportSchemaVersion)
	}
	if SoakSchemaMinor != 7 {
		t.Fatalf("SoakSchemaMinor = %d", SoakSchemaMinor)
	}
	_, key, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	record := soakRecord()
	report := BuildReport(&config.Plan{PlanID: "soak", Name: "Soak"}, "node.example", 0, true, []probe.VMValidationRecord{record}, "")
	signed := signedBytes(t, report, key)
	for _, field := range []string{`"soak"`, `"configured_sec"`, `"interval_sec"`, `"started_at"`, `"first_sample_at"`, `"last_sample_at"`, `"samples"`, `"failed_samples"`, `"worst_duration"`, `"status_reads"`} {
		if !bytes.Contains(signed, []byte(field)) {
			t.Errorf("the signed report does not carry %s", field)
		}
	}
	verified, valid, err := VerifyReportSignatureOnly(signed)
	if err != nil || !valid {
		t.Fatalf("report does not verify: valid=%v err=%v", valid, err)
	}
	got := verified.VMRecords[0].Soak
	if got == nil || got.Samples != 3 || got.StatusReads != 7 || got.Probes[0].WorstDuration != 4*time.Millisecond {
		t.Fatalf("the verified report lost the summary: %+v", got)
	}
	for _, tamper := range []struct{ from, to string }{
		{`"samples": 3`, `"samples": 9`},
		{`"failed_samples": 0`, `"failed_samples": 2`},
		{`"worst_duration": 4000000`, `"worst_duration": 1`},
		{`"last_sample_at": "2026-09-30T10:01:00Z"`, `"last_sample_at": "2026-09-30T10:09:00Z"`},
		{`"status_reads": 7`, `"status_reads": 8`},
	} {
		altered := bytes.Replace(signed, []byte(tamper.from), []byte(tamper.to), 1)
		if bytes.Equal(altered, signed) {
			t.Fatalf("the signed report does not contain %s", tamper.from)
		}
		if _, valid, _ := VerifyReportSignatureOnly(altered); valid {
			t.Errorf("a report with %s changed to %s still verifies", tamper.from, tamper.to)
		}
	}
	// A record with no soak writes no soak key at all.
	record.Soak = nil
	data, err := json.Marshal(BuildReport(&config.Plan{PlanID: "p", Name: "n"}, "node.example", 0, true, []probe.VMValidationRecord{record}, ""))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"soak"`)) || bytes.Contains(data, []byte(`"status_reads"`)) {
		t.Errorf("a record with no soak writes its keys: %s", data)
	}
}
