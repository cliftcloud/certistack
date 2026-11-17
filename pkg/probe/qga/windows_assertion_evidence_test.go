// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package qga

import (
	"context"
	"strings"
	"testing"
	"time"
)

// One sc.exe answer satisfies two plans that require different substrings
// ("RUNNING" and "ACCEPTS_SHUTDOWN"). The result of a pass names the substring
// the plan asserted, so the two results differ rather than signing the same
// evidence.
func TestWindowsServicePassRecordsTheAssertedOutput(t *testing.T) {
	probeFor := func(expected string) (passed bool, detail string) {
		socketPath, _ := windowsAgent(t, 0, scQueryOutput("4  RUNNING"))
		result := NewQGAProber(socketPath, "sc query MSSQL$SQLEXPRESS", expected, true, 2*time.Second, "SQL service").Probe(context.Background())
		return result.Passed, result.Detail
	}
	runningOK, runningDetail := probeFor("RUNNING")
	shutdownOK, shutdownDetail := probeFor("ACCEPTS_SHUTDOWN")
	if !runningOK || !shutdownOK {
		t.Fatalf("passed = %v and %v, want both plans satisfied by the one answer", runningOK, shutdownOK)
	}
	if runningDetail == shutdownDetail {
		t.Fatalf("two different assertions leave the same detail %q", runningDetail)
	}
	if !strings.Contains(runningDetail, `"RUNNING"`) || !strings.Contains(shutdownDetail, `"ACCEPTS_SHUTDOWN"`) {
		t.Fatalf("details %q and %q do not name the asserted output", runningDetail, shutdownDetail)
	}
	// The detail still names the service state, and a plan with no expected
	// output says none.
	if !strings.Contains(shutdownDetail, "MSSQL$SQLEXPRESS is RUNNING") {
		t.Fatalf("detail %q does not say the service is RUNNING", shutdownDetail)
	}
	socketPath, _ := windowsAgent(t, 0, scQueryOutput("4  RUNNING"))
	bare := NewQGAProber(socketPath, "sc query MSSQL$SQLEXPRESS", "", true, 2*time.Second, "SQL service").Probe(context.Background())
	if !bare.Passed || strings.Contains(bare.Detail, "expected") {
		t.Fatalf("a probe with no expected output records %q", bare.Detail)
	}
}

// The recorded substring is bounded like every other guest-visible or
// plan-supplied text in a result.
func TestWindowsServicePassBoundsTheAssertedOutput(t *testing.T) {
	long := strings.Repeat("X", 10*maxReportOutputBytes)
	socketPath, _ := windowsAgent(t, 0, scQueryOutput("4  RUNNING")+long)
	result := NewQGAProber(socketPath, "sc query MSSQL$SQLEXPRESS", long, true, 2*time.Second, "SQL service").Probe(context.Background())
	if !result.Passed || len(result.Detail) > 2*maxReportOutputBytes {
		t.Fatalf("passed=%v, detail of %d bytes, want a pass whose detail is bounded", result.Passed, len(result.Detail))
	}
}
