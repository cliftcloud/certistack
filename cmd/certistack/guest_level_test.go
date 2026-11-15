// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"testing"

	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// The run marks a VM verified only by a guest-level assertion
// (config.IsGuestLevelProbe, which the orchestrator and plan validation
// use), and the verdict on a signed report applies the same rule to the
// result types the probers record (probeIsGuestLevel). The two agree for
// every result type a report can hold.
func TestVerdictAndRunAgreeOnWhichProbesAreGuestLevel(t *testing.T) {
	for resultType, want := range map[string]bool{
		"tcp": true, "http": true, "dns": true, "ldap": true, "mssql": true, "smb": true, "qga": true,
		"qmp": false, "screendump": false,
		// Results the orchestrator itself records for a VM that did not
		// get as far as its probes, or whose probe stage failed.
		"recovery": false, "validation": false, "probe_stage": false, "": false,
	} {
		if got := attest.ProbeIsGuestLevel(resultType); got != want {
			t.Errorf("attest.ProbeIsGuestLevel(%q) = %v, want %v", resultType, got, want)
		}
		if got := config.IsGuestLevelProbe(resultType); got != want {
			t.Errorf("config.IsGuestLevelProbe(%q) = %v, want %v", resultType, got, want)
		}
	}
	// A plan's aliases name the same probes as their canonical types.
	for alias, canonical := range map[string]string{"tcp_handshake": "tcp", "http_get": "http", "qga_ping": "qga", "qmp_status": "qmp"} {
		if config.IsGuestLevelProbe(alias) != config.IsGuestLevelProbe(canonical) {
			t.Errorf("alias %q and %q disagree on being guest-level", alias, canonical)
		}
	}
}

// The record the run writes for a VM whose probes passed but asserted
// nothing in the guest (verification_status "unverified", its probe results
// and a failed probe_stage result) is never accepted, and the verdict names
// the status.
func TestReportAcceptanceRejectsAnUnverifiedVM(t *testing.T) {
	plan := mustLoadFixturePlan()
	report := passReport(plan)
	record := &report.VMRecords[0]
	record.AllPassed = false
	record.VerificationStatus = "unverified"
	record.ProbeResults = append(record.ProbeResults, probe.Result{
		Type:        "probe_stage",
		Target:      "vm/9001",
		Description: "At least one guest-level assertion ran and passed",
		Error:       "VM 9001 is unverified: only its qmp or screendump probes ran",
	})
	report.AllPassed = false
	report.FailureReason = "VM 9001 probes: VM 9001 is unverified"
	expectRejected(t, "an unverified VM", report, fixtureExpectations(plan, accept.OutcomePass), `VM 9001 verification_status is "unverified", not "verified"`)
	expectRejected(t, "an unverified VM (unbound)", report, accept.Expectations{}, `VM 9001 verification_status is "unverified", not "verified"`)
}
