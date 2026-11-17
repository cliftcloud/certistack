// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package attest

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

func TestSnapshotGroupAcceptsOnlyCanonicalPaths(t *testing.T) {
	for _, tc := range []struct {
		path       string
		whole      bool
		wantID     int
		wantAccept bool
	}{
		{"vm/100/2026-09-27T03:12:59Z", true, 100, true},
		{"vm/100/2026-09-27T03:12:59Z", false, 100, true},
		{"vm/100/latest", false, 100, true},
		{"vm/100", false, 100, true},
		{"vm/100/latest", true, 0, false},
		{"vm/100", true, 0, false},
		{"vm/100/2026-09-27", true, 0, false},
		{"vm/100/2026-09-27T03:12:59Z/extra", true, 0, false},
		{"vm/0100/2026-09-27T03:12:59Z", true, 0, false},
		{"vm/+100/2026-09-27T03:12:59Z", true, 0, false},
		{"vm/0/2026-09-27T03:12:59Z", true, 0, false},
		{"vm/-1/2026-09-27T03:12:59Z", true, 0, false},
		{"ct/100/2026-09-27T03:12:59Z", true, 0, false},
		{"latest", false, 0, false},
		{"", false, 0, false},
	} {
		id, ok := snapshotGroup(tc.path, tc.whole)
		if ok != tc.wantAccept || id != tc.wantID {
			t.Errorf("snapshotGroup(%q, whole=%v) = %d, %v; want %d, %v", tc.path, tc.whole, id, ok, tc.wantID, tc.wantAccept)
		}
	}
}

func TestExpectedSourceVMID(t *testing.T) {
	for _, tc := range []struct {
		name string
		vm   config.VM
		want int
	}{
		{"an explicit source VM", config.VM{SourceVMID: 7, SourcePBS: config.SourcePBS{Snapshot: "vm/9/latest"}}, 7},
		{"a group selector", config.VM{SourcePBS: config.SourcePBS{Snapshot: "vm/9/latest"}}, 9},
		{"a pinned snapshot", config.VM{SourcePBS: config.SourcePBS{Snapshot: "vm/9/2026-09-27T03:12:59Z"}}, 9},
		{"latest without a source VM", config.VM{SourcePBS: config.SourcePBS{Snapshot: "latest"}}, 0},
		{"a group that is not canonical", config.VM{SourcePBS: config.SourcePBS{Snapshot: "vm/09/latest"}}, 0},
	} {
		if got := ExpectedSourceVMID(tc.vm); got != tc.want {
			t.Errorf("%s: ExpectedSourceVMID = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestSourceProblems(t *testing.T) {
	const snapshot = "vm/100/2026-09-27T03:12:59Z"
	record := func(mutate func(*probe.VMValidationRecord)) probe.VMValidationRecord {
		r := probe.VMValidationRecord{VMID: 9001, SourceVMID: 100, SourceSnapshot: snapshot,
			SourceDisks: []probe.SourceDiskEvidence{{Slot: "scsi0", IntegrityStatus: probe.DiskMapped}}}
		if mutate != nil {
			mutate(&r)
		}
		return r
	}
	latest := &config.VM{SourceVMID: 100, SourcePBS: config.SourcePBS{Snapshot: "latest"}}
	pinned := &config.VM{SourceVMID: 100, SourcePBS: config.SourcePBS{Snapshot: " " + snapshot + " "}}
	for _, tc := range []struct {
		name    string
		record  probe.VMValidationRecord
		planned *config.VM
		want    string // empty: none
	}{
		{"a record of the latest", record(nil), latest, ""},
		{"a record of the pinned snapshot", record(nil), pinned, ""},
		{"no plan", record(nil), nil, ""},
		{"a record with no source VM", record(func(r *probe.VMValidationRecord) { r.SourceVMID = 0 }), nil, ""},
		{"no snapshot", record(func(r *probe.VMValidationRecord) { r.SourceSnapshot = "" }), nil, "records no source snapshot"},
		{"a group, not a snapshot", record(func(r *probe.VMValidationRecord) { r.SourceSnapshot = "vm/100" }), nil, "which is not a PBS snapshot path"},
		{"a snapshot of another VM", record(func(r *probe.VMValidationRecord) { r.SourceSnapshot = "vm/101/2026-09-27T03:12:59Z" }), nil, "a backup of VM 101, and source VM 100"},
		{"another pinned snapshot", record(func(r *probe.VMValidationRecord) { r.SourceSnapshot = "vm/100/2026-09-28T03:12:59Z" }), pinned, "the plan pins " + `"` + snapshot + `"`},
		{"another group than the plan's latest", record(func(r *probe.VMValidationRecord) {
			r.SourceVMID, r.SourceSnapshot = 0, "vm/101/2026-09-27T03:12:59Z"
		}), latest, "a backup of VM 101; the plan restores source VM 100"},
		{"a disk status of nobody's", record(func(r *probe.VMValidationRecord) { r.SourceDisks[0].IntegrityStatus = "" }), nil, `disk "scsi0" records integrity_status ""`},
	} {
		got := strings.Join(SourceProblems(tc.record, tc.planned), "; ")
		switch {
		case tc.want == "" && got != "":
			t.Errorf("%s: problems %q, want none", tc.name, got)
		case tc.want != "" && !strings.Contains(got, tc.want):
			t.Errorf("%s: problems %q, want one containing %q", tc.name, got, tc.want)
		}
	}
}

func TestProbePolicyProblemsWithoutAPlan(t *testing.T) {
	record := probe.VMValidationRecord{VMID: 9001, ProbeResults: []probe.Result{
		{Type: "screendump", Description: "console", Passed: true},
		{Type: "qga", Description: "agent", Passed: true, Skipped: true, RequireQGA: true},
		{Type: "tcp", Description: "web", Passed: true, Attempts: -1, ImageSHA256: "XYZ"},
	}}
	got := strings.Join(ProbePolicyProblems(record, nil, nil), "\n")
	for _, want := range []string{
		`VM 9001 probe 1 (screendump "console") passed without recording the SHA-256 of the image it captured`,
		`VM 9001 probe 2 (qga "agent") is required but was skipped`,
		`VM 9001 probe 3 (tcp "web") records a negative timeout, retries or attempts count`,
		`VM 9001 probe 3 (tcp "web") records an image_sha256 that is not a SHA-256 digest`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("problems %q lack %q", got, want)
		}
	}
	if clean := ProbePolicyProblems(probe.VMValidationRecord{VMID: 1, ProbeResults: []probe.Result{{Type: "tcp", Passed: true, TimeoutSec: 5, Retries: 2, Attempts: 3}}}, nil, nil); len(clean) != 0 {
		t.Errorf("a result with only its own policy has problems: %q", clean)
	}
}
