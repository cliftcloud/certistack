// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"reflect"
	"strings"
	"testing"
)

// preserveTargetPlan is the reported plan: two distinct VMIDs in one
// tier, both in the given recovery mode, each with a TCP probe on port 389,
// the first at 10.100.0.10 and the second at secondTarget.
func preserveTargetPlan(mode, secondTarget string) *Plan {
	p := validPlan()
	first := &p.Tiers[0].VMs[0]
	first.NetworkRecovery = NetworkRecovery{Mode: mode}
	first.Probes = []Probe{{
		Type: "tcp", TargetIP: "10.100.0.10", Port: 389, TimeoutSec: 5, Description: "first preserved VM service",
	}}
	second := *first
	second.VMID = 9002
	second.Name = "cs-test-dc02"
	second.SourcePBS = SourcePBS{StorageID: "pbs", Snapshot: "vm/101/2026-03-30T02:00:00Z", Drive: "drive-scsi0"}
	second.Probes = []Probe{{
		Type: "tcp", TargetIP: secondTarget, Port: 389, TimeoutSec: 5, Description: "second preserved VM service",
	}}
	p.Tiers[0].VMs = append(p.Tiers[0].VMs, second)
	return p
}

// The reported case: the controller and worker loaders accepted two
// preserve-mode VMIDs whose probes name one wire target, so one guest or one
// shared listener could satisfy both. Both loaders refuse it now, in preserve
// mode as in auto mode, naming the target and both owners; a distinct target
// loads.
func TestLoadersRefuseOnePreservedWireTargetOnTwoVMs(t *testing.T) {
	for _, mode := range []string{"preserve", "auto"} {
		controllerErr, workerErr := loadBothWays(t, preserveTargetPlan(mode, "10.100.0.10"))
		for who, err := range map[string]error{"controller": controllerErr, "worker": workerErr} {
			if err == nil {
				t.Errorf("mode %s: the %s loader accepted one wire target on two VMs", mode, who)
				continue
			}
			if !strings.Contains(err.Error(), "10.100.0.10") {
				t.Errorf("mode %s: the %s loader's error %q does not name the target", mode, who, err)
			}
		}
	}
	// Preserve mode names the owner and the rule.
	var found bool
	for _, err := range Validate(preserveTargetPlan("preserve", "10.100.0.10")) {
		if err.Field == "tiers[0].vms[1].probes[0].target_ip" &&
			strings.Contains(err.Message, "also VM 9001's address") && strings.Contains(err.Message, "exactly one VM") {
			found = true
		}
	}
	if !found {
		t.Errorf("no error names the owner of the target: %v", Validate(preserveTargetPlan("preserve", "10.100.0.10")))
	}
	if controllerErr, workerErr := loadBothWays(t, preserveTargetPlan("preserve", "10.100.0.11")); controllerErr != nil || workerErr != nil {
		t.Fatalf("distinct-target control refused: controller=%v worker=%v", controllerErr, workerErr)
	}
}

// What the shared rule reports, and what it leaves alone: a guest with several
// addresses, or several services on one, is one VM naming them.
func TestSharedWireTargets(t *testing.T) {
	probe := func(ip string, port int) Probe {
		return Probe{Type: "tcp", TargetIP: ip, Port: port, Description: "svc"}
	}
	plan := func(vms ...VM) *Plan { return &Plan{Tiers: []Tier{{VMs: vms}}} }
	cases := []struct {
		name string
		plan *Plan
		want []SharedWireTarget
	}{
		{"nil plan", nil, nil},
		{"distinct targets", plan(VM{VMID: 1, Probes: []Probe{probe("10.0.0.10", 80)}}, VM{VMID: 2, Probes: []Probe{probe("10.0.0.11", 80)}}), nil},
		{"one VM, several services and addresses", plan(VM{VMID: 1, Probes: []Probe{probe("10.0.0.10", 80), probe("10.0.0.10", 443), probe("10.0.0.20", 80)}}), nil},
		{"one address, two VMs", plan(VM{VMID: 2, Probes: []Probe{probe("10.0.0.10", 80)}}, VM{VMID: 1, Probes: []Probe{probe("10.0.0.10", 443)}}),
			[]SharedWireTarget{{Address: "10.0.0.10", VMIDs: []int{1, 2}}}},
		{"the IPv4-mapped spelling is the same address", plan(VM{VMID: 1, Probes: []Probe{probe("10.0.0.10", 80)}}, VM{VMID: 2, Probes: []Probe{probe("::ffff:10.0.0.10", 80)}}),
			[]SharedWireTarget{{Address: "10.0.0.10", VMIDs: []int{1, 2}}}},
		{"across tiers and three VMs", &Plan{Tiers: []Tier{
			{VMs: []VM{{VMID: 3, Probes: []Probe{probe("10.0.0.10", 80)}}}},
			{VMs: []VM{{VMID: 1, Probes: []Probe{probe("10.0.0.10", 80)}}, {VMID: 2, Probes: []Probe{probe("10.0.0.10", 25)}}}},
		}}, []SharedWireTarget{{Address: "10.0.0.10", VMIDs: []int{1, 2, 3}}}},
		{"QGA and hypervisor probes name no wire target", plan(
			VM{VMID: 1, Probes: []Probe{{Type: "qga", TargetIP: "10.0.0.10"}, {Type: "qmp", TargetIP: "10.0.0.10"}}},
			VM{VMID: 2, Probes: []Probe{probe("10.0.0.10", 80)}}), nil},
		{"a target that is no address is reported where it is checked", plan(VM{VMID: 1, Probes: []Probe{probe("db.example", 80)}}, VM{VMID: 2, Probes: []Probe{probe("db.example", 80)}}), nil},
	}
	for _, tc := range cases {
		if got := SharedWireTargets(tc.plan); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: SharedWireTargets = %+v, want %+v", tc.name, got, tc.want)
		}
	}
	shared := SharedWireTarget{Address: "10.0.0.10", VMIDs: []int{1, 2}}
	if !shared.Names(2) || shared.Names(3) {
		t.Error("Names does not tell the VMs that name the address")
	}
}
