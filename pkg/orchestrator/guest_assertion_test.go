// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
)

// A VM is verified only by a guest-level assertion that ran and passed (a wire
// probe, or a QGA probe that was not skipped). QMP says QEMU runs the VM, which
// the QMP check already required, and a screendump captures whatever the
// framebuffer shows, a black screen at a boot failure included: both are
// supporting evidence. A stage whose passes are only those leaves the VM
// unverified and fails, keeping the results and saying why.
func TestRunProbesLeavesAVMUnverifiedWithoutAGuestLevelAssertion(t *testing.T) {
	qmpProbe := config.Probe{Type: "qmp", Description: "VM is running", TimeoutSec: 2, Retries: 1}
	screenProbe := config.Probe{Type: "screendump", Description: "console screenshot", TimeoutSec: 2, Retries: 1}
	optionalQGA := config.Probe{Type: "qga", Command: "ping", Description: "agent answers", TimeoutSec: 1, Retries: 1}
	requiredQGA := optionalQGA
	requiredQGA.RequireQGA = true

	for name, tc := range map[string]struct {
		probes []config.Probe
		// agent is whether a guest agent answers on the VM's QGA socket.
		agent bool
		// wire adds a passing tcp probe to the probes.
		wire       bool
		unverified string // the reason the VM is unverified; "" when the stage passes
	}{
		"qmp only":                             {probes: []config.Probe{qmpProbe}, unverified: "only its qmp or screendump probes ran"},
		"screendump only, on a black screen":   {probes: []config.Probe{screenProbe}, unverified: "only its qmp or screendump probes ran"},
		"qmp and screendump":                   {probes: []config.Probe{qmpProbe, screenProbe}, unverified: "only its qmp or screendump probes ran"},
		"qmp and an optional qga, no agent":    {probes: []config.Probe{qmpProbe, optionalQGA}, unverified: "its guest-agent probes were skipped"},
		"qmp and a required qga answered":      {probes: []config.Probe{qmpProbe, requiredQGA}, agent: true},
		"qmp and an optional qga answered":     {probes: []config.Probe{qmpProbe, optionalQGA}, agent: true},
		"screendump and a wire probe":          {probes: []config.Probe{screenProbe}, wire: true},
		"qmp and a wire probe":                 {probes: []config.Probe{qmpProbe}, wire: true},
		"a wire probe alone (control)":         {wire: true},
		"a required qga answered (control)":    {probes: []config.Probe{requiredQGA}, agent: true},
		"an optional qga only, no agent (038)": {probes: []config.Probe{optionalQGA}, unverified: "all 1 probes were skipped"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := shortSocketDir(t)
			fakeQMP(t, dir, 9105, true, 0)
			if tc.agent {
				fakeQGA(t, dir, 9105, map[string]any{"guest-ping": map[string]any{"return": map[string]any{}}}, nil)
			}
			scratch := t.TempDir()
			if err := os.Chmod(scratch, 0o700); err != nil {
				t.Fatal(err)
			}
			o := &Orchestrator{opts: Options{QMPSocketDir: dir, QGASocketDir: dir, ScratchDir: scratch}}
			probes := append([]config.Probe(nil), tc.probes...)
			if tc.wire {
				probes = append(probes, config.Probe{Type: "tcp", TargetIP: "127.0.0.1", Port: acceptingPort(t), Description: "service port", TimeoutSec: 1})
			}
			results, passed, err := o.runProbes(context.Background(), config.VM{VMID: 9105, Probes: probes})

			record := &probe.VMValidationRecord{VMID: 9105, AllPassed: true, VerificationStatus: "booted", ProbeResults: results}
			if tc.unverified == "" {
				if !passed || err != nil {
					t.Fatalf("stage passed=%v err=%v results=%+v, want a pass", passed, err, results)
				}
				return
			}
			if passed || err == nil || !strings.Contains(err.Error(), "VM 9105 is unverified: ") || !strings.Contains(err.Error(), tc.unverified) {
				t.Fatalf("stage passed=%v err=%v, want it unverified: %s", passed, err, tc.unverified)
			}
			// The probes that ran keep their results, and one failed result
			// says why the VM is unverified.
			if len(results) != len(probes)+1 {
				t.Fatalf("results = %+v, want the %d probe results and a probe_stage result", results, len(probes))
			}
			last := results[len(results)-1]
			if last.Type != "probe_stage" || last.Passed || last.Skipped || last.Error != err.Error() {
				t.Fatalf("last result = %+v, want a failed probe_stage result carrying the reason", last)
			}
			for _, res := range results[:len(results)-1] {
				if !res.Passed {
					t.Fatalf("results = %+v, want the probes that ran to have passed (the VM is unverified, not failed)", results)
				}
			}
			markVMRecordProbeFailure(record, err)
			if record.VerificationStatus != "unverified" || record.AllPassed {
				t.Fatalf("record = %+v, want verification_status unverified and not a pass", record)
			}
		})
	}
}

// A probe that failed is a failed VM, not an unverified one, whether
// or not it sits beside a hypervisor probe that passed: "unverified" is only
// the absence of evidence.
func TestAVMWithAFailedProbeIsFailedNotUnverified(t *testing.T) {
	dir := shortSocketDir(t)
	fakeQMP(t, dir, 9106, true, 0)
	o := &Orchestrator{opts: Options{QMPSocketDir: dir}}
	results, passed, err := o.runProbes(context.Background(), config.VM{VMID: 9106, Probes: []config.Probe{
		{Type: "qmp", Description: "VM is running", TimeoutSec: 2, Retries: 1},
		{Type: "tcp", TargetIP: "127.0.0.1", Port: 1, Description: "closed port", TimeoutSec: 1, Retries: 1},
	}})
	if passed || err == nil || strings.Contains(err.Error(), "unverified") {
		t.Fatalf("stage passed=%v err=%v results=%+v, want a plain probe failure", passed, err, results)
	}
	record := &probe.VMValidationRecord{VMID: 9106, AllPassed: true, ProbeResults: results}
	markVMRecordProbeFailure(record, err)
	if record.VerificationStatus != "failed" || record.AllPassed {
		t.Fatalf("record = %+v, want verification_status failed", record)
	}
}

// `certistack plan` says which probes are supporting evidence and
// which can be skipped, so nobody reads a qmp or screendump line as a check
// of the guest.
func TestPlanProbeDetailSaysWhichProbesDoNotVerifyTheGuest(t *testing.T) {
	for _, tc := range []struct {
		probe config.Probe
		want  string
	}{
		{config.Probe{Type: "qmp", Description: "VM is running", TimeoutSec: 30}, "supporting evidence only: it does not verify the guest"},
		{config.Probe{Type: "screendump", Description: "console", TimeoutSec: 30}, "supporting evidence only: it does not verify the guest"},
		{config.Probe{Type: "qga", Command: "ping", TimeoutSec: 30}, "skipped, and not evidence, if the guest agent does not answer"},
		{config.Probe{Type: "qga", Command: "ping", RequireQGA: true, TimeoutSec: 30}, ""},
		{config.Probe{Type: "tcp", TargetIP: "10.100.0.10", Port: 22, TimeoutSec: 30}, ""},
	} {
		detail := probeDetail(tc.probe)
		if tc.want == "" && (strings.Contains(detail, "supporting evidence") || strings.Contains(detail, "skipped")) {
			t.Errorf("%s probe detail %q carries a caveat it should not", tc.probe.Type, detail)
		}
		if tc.want != "" && !strings.Contains(detail, tc.want) {
			t.Errorf("%s probe detail %q lacks %q", tc.probe.Type, detail, tc.want)
		}
	}
}

// The runtime rule and the plan rule share one definition of a guest-level
// probe (config.IsGuestLevelProbe), so a plan that validates never reaches a
// stage that leaves its VM unverified for want of a guest-level probe type.
func TestNoGuestAssertionAgreesWithPlanValidation(t *testing.T) {
	for _, probeType := range []string{"tcp", "http", "dns", "ldap", "mssql", "smb", "qga"} {
		if reason := noGuestAssertion([]probe.Result{{Type: probeType, Passed: true}}); reason != "" {
			t.Errorf("a passed %s result leaves the VM unverified: %s", probeType, reason)
		}
		if reason := noGuestAssertion([]probe.Result{{Type: probeType, Passed: true, Skipped: true}}); reason == "" {
			t.Errorf("a skipped %s result counts as a guest-level assertion", probeType)
		}
	}
	for _, probeType := range []string{"qmp", "screendump"} {
		if reason := noGuestAssertion([]probe.Result{{Type: probeType, Passed: true}}); reason == "" {
			t.Errorf("a passed %s result counts as a guest-level assertion", probeType)
		}
	}
}
