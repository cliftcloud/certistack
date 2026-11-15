// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

// The plan lists what recovery of an interrupted run's journal does. For a host
// probe address whose addition was never recorded that is no longer "stop for an
// operator": recovery reads the host, and the plan says what it reads and when
// it removes. Any other allocation it cannot name still stops.
func TestPlanBeforeSaysWhatRecoveryDoesWithAHostAddressAllocation(t *testing.T) {
	stateDir := t.TempDir()
	write := func(r journal.Record) {
		t.Helper()
		if err := journal.Write(filepath.Join(stateDir, "active.json"), r); err != nil {
			t.Fatal(err)
		}
	}
	text := func(r journal.Record) string {
		steps, _ := planBefore(stateDir, "", time.Now())
		var lines []string
		for _, step := range steps {
			lines = append(lines, step.Action+" "+step.Kind+" "+step.Target+" | "+step.Detail)
		}
		return strings.Join(lines, "\n")
	}

	pending := journal.Record{RunID: "run-old", Phase: "running", AllocationPending: journal.HostAddressPending("10.100.0.1/24", "csVn01")}
	write(pending)
	got := text(pending)
	table := sysutil.IsolationTableName("csVn01", "10.100.0.1/24")
	for _, want := range []string{"recovery reads csVn01 and nft table inet " + table, "removes them only if that table is there", "leaves an address that has no such table"} {
		if !strings.Contains(got, want) {
			t.Errorf("steps:\n%s\nlack %q", got, want)
		}
	}
	if strings.Contains(got, "stop for an operator") {
		t.Errorf("steps:\n%s\nsay a host address stops a run: recovery settles it", got)
	}

	other := journal.Record{RunID: "run-old", Phase: "running", AllocationPending: "VM 9123 creation"}
	write(other)
	if got := text(other); !strings.Contains(got, "a run would stop for an operator to review it") {
		t.Errorf("steps:\n%s\nlack the stop for an allocation recovery cannot settle", got)
	}
}
