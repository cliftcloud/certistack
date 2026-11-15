// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

func plannedVM() *config.VM {
	return &config.VM{
		VMID: 9001,
		SourcePBS: config.SourcePBS{Drives: []config.SourceDrive{
			{Slot: "scsi0", Archive: "drive-scsi0"}, {Slot: "scsi1", Archive: "drive-scsi1"},
		}},
		Probes: []config.Probe{
			{Type: "tcp", TargetIP: "192.0.2.10", Port: 389, Description: "ldap"},
			{Type: "qga", Command: "systemctl is-active x", Description: "service"},
		},
	}
}

// The rules the controller and verify-report share: disks.
func TestDiskProblemsHoldRecordedDisksToTheNamedDrives(t *testing.T) {
	disk := func(slot, archive string) probe.SourceDiskEvidence {
		return probe.SourceDiskEvidence{Slot: slot, Archive: archive}
	}
	for name, tc := range map[string]struct {
		disks []probe.SourceDiskEvidence
		plan  *config.VM
		want  string // a fragment of the one problem, or "" for none
	}{
		"the named drives":            {[]probe.SourceDiskEvidence{disk("scsi0", "drive-scsi0"), disk("scsi1", "drive-scsi1")}, plannedVM(), ""},
		"with firmware state":         {[]probe.SourceDiskEvidence{disk("scsi0", "drive-scsi0"), disk("scsi1", "drive-scsi1"), disk("efidisk0", "x"), disk("tpmstate0", "y")}, plannedVM(), ""},
		"one missing":                 {[]probe.SourceDiskEvidence{disk("scsi0", "drive-scsi0")}, plannedVM(), `no integrity evidence for disk "scsi1"`},
		"another archive":             {[]probe.SourceDiskEvidence{disk("scsi0", "drive-other"), disk("scsi1", "drive-scsi1")}, plannedVM(), `from archive "drive-other"; the plan restores archive "drive-scsi0"`},
		"an unplanned disk":           {[]probe.SourceDiskEvidence{disk("scsi0", "drive-scsi0"), disk("scsi1", "drive-scsi1"), disk("scsi2", "z")}, plannedVM(), `"scsi2", which the plan does not restore`},
		"a slot twice":                {[]probe.SourceDiskEvidence{disk("scsi0", "drive-scsi0"), disk("scsi0", "drive-scsi0"), disk("scsi1", "drive-scsi1")}, plannedVM(), `"scsi0" more than once`},
		"no plan":                     {[]probe.SourceDiskEvidence{disk("scsi0", "a"), disk("scsi7", "b")}, nil, ""},
		"a plan that names no drives": {[]probe.SourceDiskEvidence{disk("scsi0", "a"), disk("scsi7", "b")}, &config.VM{VMID: 9001}, ""},
		"a slot twice, with no plan":  {[]probe.SourceDiskEvidence{disk("scsi0", "a"), disk("scsi0", "a")}, nil, "more than once"},
	} {
		problems := DiskProblems(probe.VMValidationRecord{VMID: 9001, SourceDisks: tc.disks}, tc.plan)
		switch {
		case tc.want == "" && len(problems) != 0:
			t.Errorf("%s: %v", name, problems)
		case tc.want != "" && (len(problems) != 1 || !strings.Contains(problems[0], tc.want)):
			t.Errorf("%s: %v, want %q", name, problems, tc.want)
		}
	}
}

// And probes: the plan's probes, in order, with their targets.
func TestProbeProblemsHoldResultsToThePlannedProbes(t *testing.T) {
	plan := plannedVM()
	good := func() probe.VMValidationRecord {
		return probe.VMValidationRecord{VMID: 9001, ProbeResults: []probe.Result{
			{Type: "tcp", Target: "192.0.2.10:389", Description: "ldap", Passed: true},
			{Type: "qga", Target: "systemctl is-active x", Description: "service", Passed: true},
		}}
	}
	if problems := ProbeProblems(good(), plan, -1); len(problems) != 0 {
		t.Fatalf("the plan's own probes: %v", problems)
	}
	for name, mutate := range map[string]func(*probe.VMValidationRecord){
		"another target":           func(r *probe.VMValidationRecord) { r.ProbeResults[0].Target = "203.0.113.99:389" },
		"another type":             func(r *probe.VMValidationRecord) { r.ProbeResults[0].Type = "http" },
		"a required probe skipped": func(r *probe.VMValidationRecord) { r.ProbeResults[0].Skipped = true },
		"a probe missing":          func(r *probe.VMValidationRecord) { r.ProbeResults = r.ProbeResults[:1] },
		"no results":               func(r *probe.VMValidationRecord) { r.ProbeResults = nil },
		"the guest agent's probe alone": func(r *probe.VMValidationRecord) {
			r.ProbeResults[0] = probe.Result{Type: "tcp", Target: "192.0.2.10:389", Description: "ldap", Passed: true, Skipped: true}
		},
	} {
		record := good()
		mutate(&record)
		if problems := ProbeProblems(record, plan, -1); len(problems) == 0 {
			t.Errorf("%s: no problem found", name)
		}
	}
	// An optional guest-agent probe may be skipped when a wire probe ran.
	record := good()
	record.ProbeResults[1].Skipped = true
	if problems := ProbeProblems(record, plan, -1); len(problems) != 0 {
		t.Errorf("a skipped optional guest-agent probe: %v", problems)
	}
	// The fault drill's one injected failure is allowed at its index only.
	record = good()
	record.ProbeResults[0].Passed = false
	if problems := ProbeProblems(record, plan, 0); len(problems) != 0 {
		t.Errorf("the injected failure: %v", problems)
	}
	if problems := ProbeProblems(record, plan, 1); len(problems) == 0 {
		t.Error("a failure at another index was allowed")
	}
}

// A report records the target the prober dialed, and an IPv6 host
// is bracketed there ("[fd00:99::10]:22"), as in every address a dialer reads.
// The verifier builds the same string from the plan; the two agree for IPv4
// and IPv6 alike (cmd/certistack runs each real prober to keep them in step).
func TestExpectedProbeTargetBracketsAnIPv6Host(t *testing.T) {
	for _, tc := range []struct {
		probe config.Probe
		want  string
	}{
		{config.Probe{Type: "tcp", TargetIP: "192.0.2.10", Port: 22}, "192.0.2.10:22"},
		{config.Probe{Type: "tcp", TargetIP: "fd00:99::10", Port: 22}, "[fd00:99::10]:22"},
		{config.Probe{Type: "ldap", TargetIP: "192.0.2.20"}, "192.0.2.20:389"},
		{config.Probe{Type: "ldap", TargetIP: "fd00:99::20"}, "[fd00:99::20]:389"},
		{config.Probe{Type: "ldap", TargetIP: "fd00:99::20", Port: 636}, "[fd00:99::20]:636"},
	} {
		got, carried := ExpectedProbeTarget(tc.probe)
		if !carried || got != tc.want {
			t.Errorf("ExpectedProbeTarget(%s %s:%d) = %q, %v; want %q", tc.probe.Type, tc.probe.TargetIP, tc.probe.Port, got, carried, tc.want)
		}
	}
}
