// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	accept "github.com/cliftcloud/certistack/pkg/acceptance"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// privilegeWarning is the warning the shared preflight raises when the node
// token lacks the privileges the run works around.
const privilegeWarning = "the PVE token lacks VM.Config.CDROM, VM.Console and Sys.Audit; the run works around these"

// warnedHost is a host whose checks pass and raise two warnings: the token's
// privileges and the untested version pair, the second as the real preflight
// words it.
func warnedHost() preflight.Result {
	return preflight.Result{Ready: true, Checks: []preflight.CheckItem{
		{Name: "kvm", Status: "passed", Detail: "/dev/kvm is accessible"},
		{Name: "pve_privileges", Status: "warning", Detail: privilegeWarning},
		{Name: preflight.VersionCheckName, Status: "warning", Detail: "PVE 10.0.1 and PBS 3.4.0 are untested"},
	}}
}

// The warnings of a passing worker preflight reach an operator on the `run`
// path (that the token lacks a privilege the run works around, say): they go to
// the run's progress channel, once each; the untested version warning stays the
// runner's alone, so it is not said twice.
func TestNodeRunTellsTheOperatorWhatAPassingPreflightWarned(t *testing.T) {
	var events []progress.Event
	result, _, _ := nodeRunOnVersionHostWith(t, "10.0.1", clientPBS3, warnedHost(), &events)
	if strings.HasPrefix(result.Error, accept.PreflightFailurePrefix) {
		t.Fatalf("the worker refused on a passing preflight: %q", result.Error)
	}
	if got := countWarnings(events, "works around"); got != 1 {
		t.Errorf("the privilege warning was said %d times, want once; events %v", got, events)
	}
	if got := countWarnings(events, "pve_privileges: "+privilegeWarning); got != 1 {
		t.Errorf("the privilege warning does not name its check and carry its text; events %v", events)
	}
	// The fixture's run stops at the backup read, before the runner warns of
	// the untested pair (pkg/runner TestRunRecordsTheProxmoxVersionsInItsReport
	// covers its one warning); here the worker must not have said it for the runner.
	if got := countWarnings(events, "untested"); got != 0 {
		t.Errorf("the worker's preflight said the untested-version warning %d times; the runner says it, once: %v", got, events)
	}
	for _, event := range events {
		if strings.Contains(event.Message, "kvm") || strings.Contains(event.Message, preflight.VersionCheckName) {
			t.Errorf("an event that is neither a warning nor the worker's to say: %v", event)
		}
	}
}

// A failing preflight: the worker refuses with the failed check, and says no
// warning on the way.
func TestNodeRunRefusesWithTheFailedPreflightCheckAndNoWarning(t *testing.T) {
	failed := preflight.Result{Ready: false, Checks: []preflight.CheckItem{
		{Name: "pve_privileges", Status: "warning", Detail: privilegeWarning},
		{Name: "kvm", Status: "failed", Detail: "/dev/kvm is not accessible"},
	}}
	var events []progress.Event
	result, pveRequests, _ := nodeRunOnVersionHostWith(t, "10.0.1", clientPBS3, failed, &events)
	if result.Report == nil || !strings.Contains(result.Error, "kvm: /dev/kvm is not accessible") {
		t.Fatalf("the refusal lost its failed check: report %v, error %q", result.Report != nil, result.Error)
	}
	if strings.Contains(result.Error, "works around") {
		t.Errorf("the refusal carries a warning as if it were a failure: %q", result.Error)
	}
	for _, event := range events {
		if event.Stage == "Preflight" {
			t.Errorf("a refused preflight announced %v", event)
		}
	}
	if got := pveRequests(); len(got) != 0 {
		t.Errorf("a refused preflight touched PVE: %v", got)
	}
}

// announcePreflightWarnings, by itself: warnings only, in the order the checks
// ran, the version check left to the runner.
func TestAnnouncePreflightWarningsSaysOnlyWarningsInOrder(t *testing.T) {
	stop := captureProgressEvents(t)
	announcePreflightWarnings(preflight.Result{Ready: true, Checks: []preflight.CheckItem{
		{Name: "stale_loops", Status: "warning", Detail: "a loop device is attached to a deleted file"},
		{Name: "kvm", Status: "passed", Detail: "ok"},
		{Name: "docker", Status: "skipped", Detail: "not checked"},
		{Name: preflight.VersionCheckName, Status: "warning", Detail: "untested"},
		{Name: "pve_privileges", Status: "warning", Detail: "multi\nline"},
	}})
	events := stop()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2: %v", len(events), events)
	}
	if events[0].Message != "stale_loops: a loop device is attached to a deleted file" || events[1].Message != "pve_privileges: multi; line" {
		t.Errorf("events = %v", events)
	}
	for _, event := range events {
		if event.Level != "WARN" || event.Stage != "Preflight" {
			t.Errorf("event %v is not a Preflight WARN", event)
		}
	}
}

// The routes a node would not give are warned of once, by the run that goes on
// to check them again (pkg/runner requireSandboxSafe): the preflight's copy of
// the same words is left out, as the untested-version warning is.
func TestAnnouncePreflightWarningsLeavesTheSandboxNetworkToTheRunner(t *testing.T) {
	stop := captureProgressEvents(t)
	announcePreflightWarnings(preflight.Result{Ready: true, Checks: []preflight.CheckItem{
		{Name: preflight.SandboxNetworkCheckName, Status: "warning", Detail: "could not check the node's routes"},
		{Name: "stale_loops", Status: "warning", Detail: "a loop device is attached to a deleted file"},
	}})
	events := stop()
	if len(events) != 1 || events[0].Message != "stale_loops: a loop device is attached to a deleted file" {
		t.Fatalf("events = %v, want only the stale_loops warning", events)
	}
}
