// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package config

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// macPlan is the test plan: two VMIDs in one tier with distinct sandbox
// addresses, the first with MAC 02:AA:BB:CC:DD:EE and the second with
// secondMAC.
func macPlan(secondMAC string) *Plan {
	plan := validPlan()
	first := &plan.Tiers[0].VMs[0]
	first.MAC = "02:AA:BB:CC:DD:EE"
	first.NICModel = "virtio"
	first.NetworkRecovery = NetworkRecovery{Mode: "auto", SandboxIP: "10.100.0.10"}
	second := *first
	second.VMID = 9002
	second.Name = "cs-test-dc02"
	second.MAC = secondMAC
	second.SourcePBS = SourcePBS{StorageID: "pbs", Snapshot: "vm/101/2026-03-30T02:00:00Z", Drive: "drive-scsi0"}
	second.NetworkRecovery = NetworkRecovery{Mode: "auto", SandboxIP: "10.100.0.11"}
	second.Probes = []Probe{{
		Type: "tcp", TargetIP: "10.100.0.11", Port: 389, TimeoutSec: 30, Description: "second distinct guest address",
	}}
	plan.Tiers[0].VMs = append(plan.Tiers[0].VMs, second)
	return plan
}

// loadBothWays runs a plan through the controller loader and, as the
// controller would hand it over, through the worker loader. The worker's input
// is marshalled from the struct, not from the controller's result, so the
// worker loader is tested on its own even when the controller loader refuses.
func loadBothWays(t *testing.T, plan *Plan) (controllerErr, workerErr error) {
	t.Helper()
	encoded, err := yaml.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	_, controllerErr = LoadFromReader(bytes.NewReader(encoded))
	workerYAML, err := MarshalWorkerPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	_, workerErr = LoadFromReaderForWorker(bytes.NewReader(workerYAML))
	return controllerErr, workerErr
}

func macErrors(plan *Plan) []ValidationError {
	var out []ValidationError
	for _, err := range Validate(plan) {
		if strings.HasSuffix(err.Field, ".mac") || strings.HasSuffix(err.Field, ".attach_all_nics") {
			out = append(out, err)
		}
	}
	return out
}

// Two VMIDs with the same MAC and distinct sandbox addresses: both loaders
// refuse it, naming both owners and the address; the distinct-MAC control
// loads.
func TestLoadersRefuseOneMACOnTwoVMs(t *testing.T) {
	controllerErr, workerErr := loadBothWays(t, macPlan("02:AA:BB:CC:DD:EE"))
	for who, err := range map[string]error{"controller": controllerErr, "worker": workerErr} {
		if err == nil {
			t.Fatalf("the %s loader accepted one MAC on two VMs", who)
		}
		for _, want := range []string{"tiers[0].vms[1].mac", "VM 9002 net0", "VM 9001 net0", "02:AA:BB:CC:DD:EE", "unique"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the %s loader's error %q does not mention %q", who, err, want)
			}
		}
	}
	if controllerErr, workerErr := loadBothWays(t, macPlan("02:AA:BB:CC:DD:EF")); controllerErr != nil || workerErr != nil {
		t.Fatalf("distinct-MAC control refused: controller=%v worker=%v", controllerErr, workerErr)
	}
}

// The same address in another spelling is the same address.
func TestDuplicateMACInAnySpellingIsRefused(t *testing.T) {
	for _, spelling := range []string{"02:aa:bb:cc:dd:ee", "02-AA-BB-CC-DD-EE", "02-aa-bb-cc-dd-ee", "02aa.bbcc.ddee"} {
		errs := macErrors(macPlan(spelling))
		if len(errs) != 1 || errs[0].Field != "tiers[0].vms[1].mac" || !strings.Contains(errs[0].Message, "02:AA:BB:CC:DD:EE") {
			t.Errorf("second MAC %q: errors %v", spelling, errs)
		}
	}
}

// Earlier tiers stay up while later ones start, so the registry is the
// plan's, not the tier's, and preserve mode is no exception.
func TestDuplicateMACAcrossTiersAndInPreserveMode(t *testing.T) {
	plan := macPlan("02:AA:BB:CC:DD:EE")
	second := plan.Tiers[0].VMs[1]
	plan.Tiers[0].VMs = plan.Tiers[0].VMs[:1]
	plan.Tiers = append(plan.Tiers, Tier{Level: 2, Name: "Second tier", VMs: []VM{second}})
	if errs := macErrors(plan); len(errs) != 1 || errs[0].Field != "tiers[1].vms[0].mac" {
		t.Errorf("duplicate across tiers: %v", errs)
	}

	preserve := macPlan("02:AA:BB:CC:DD:EE")
	for i := range preserve.Tiers[0].VMs {
		preserve.Tiers[0].VMs[i].NetworkRecovery = NetworkRecovery{Mode: "preserve"}
	}
	if errs := macErrors(preserve); len(errs) != 1 || errs[0].Field != "tiers[0].vms[1].mac" {
		t.Errorf("duplicate in preserve mode: %v", errs)
	}
}

// After resolution: a MAC can come from a backup, and attach_all_nics
// can add the same one as net1. The loader cannot see those; the runner and
// the orchestrator ask CheckNICIdentities, which reports each collision with
// both owners and slots.
func TestCheckNICIdentitiesFindsResolvedCollisions(t *testing.T) {
	const mac = "BC:24:11:00:00:01"
	plan := validPlan()
	plan.Tiers[0].VMs[0].MAC = mac
	plan.Tiers[0].VMs[0].AdditionalNICs = []SourceNIC{{Slot: "net1", Model: "virtio", MAC: mac}}
	second := plan.Tiers[0].VMs[0]
	second.VMID, second.Name = 9002, "cs-test-dc02"
	second.AdditionalNICs = nil
	plan.Tiers[0].VMs = append(plan.Tiers[0].VMs, second)

	err := CheckNICIdentities(plan)
	if err == nil {
		t.Fatal("a MAC on net0 and net1 of one VM, and on net0 of another, was accepted")
	}
	for _, want := range []string{"VM 9001 net1 and VM 9001 net0", "VM 9002 net0 and VM 9001 net0", mac} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	plan.Tiers[0].VMs[0].AdditionalNICs[0].MAC = "BC:24:11:00:00:02"
	plan.Tiers[0].VMs[1].MAC = "BC:24:11:00:00:03"
	if err := CheckNICIdentities(plan); err != nil {
		t.Fatalf("distinct resolved MACs refused: %v", err)
	}
	plan.Tiers[0].VMs[0].AdditionalNICs[0].MAC = "01:00:5E:00:00:01"
	if err := CheckNICIdentities(plan); err == nil || !strings.Contains(err.Error(), "multicast") {
		t.Fatalf("an attached multicast NIC: %v", err)
	}
	// A VM whose MAC PVE will choose holds no address to collide with.
	empty := validPlan()
	empty.Tiers[0].VMs = append(empty.Tiers[0].VMs, empty.Tiers[0].VMs[0])
	empty.Tiers[0].VMs[1].VMID = 9002
	if err := CheckNICIdentities(empty); err != nil {
		t.Fatalf("two VMs without a MAC: %v", err)
	}
}

// Of the all-zero address, the broadcast address, an IPv4 and an IPv6
// multicast address on net0, and the locally administered unicast control,
// both loaders load only the control.
func TestLoadersRefuseAddressesNoInterfaceCanHold(t *testing.T) {
	for _, mac := range []string{"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01", "33:33:00:00:00:01"} {
		plan := validPlan()
		plan.Tiers[0].VMs[0].MAC = mac
		controllerErr, workerErr := loadBothWays(t, plan)
		for who, err := range map[string]error{"controller": controllerErr, "worker": workerErr} {
			if err == nil || !strings.Contains(err.Error(), "tiers[0].vms[0].mac") || !strings.Contains(err.Error(), "not a usable MAC address") {
				t.Errorf("the %s loader on %s: %v", who, mac, err)
			}
		}
	}
	for _, mac := range []string{"02:AA:BB:CC:DD:EE", "02:aa:bb:cc:dd:ee", "00:11:22:33:44:55"} {
		plan := validPlan()
		plan.Tiers[0].VMs[0].MAC = mac
		if controllerErr, workerErr := loadBothWays(t, plan); controllerErr != nil || workerErr != nil {
			t.Errorf("control %s refused: controller=%v worker=%v", mac, controllerErr, workerErr)
		}
	}
}

// A malformed value is still refused with a reason that says what is wrong.
func TestMalformedMACStillRefusedWithAReason(t *testing.T) {
	for _, mac := range []string{"not-a-mac", "02:AA:BB:CC:DD", "02:AA:BB:CC:DD:EE:FF", "02:AA:BB:CC:DD:EE,bridge=vmbr0"} {
		plan := validPlan()
		plan.Tiers[0].VMs[0].MAC = mac
		errs := macErrors(plan)
		if len(errs) != 1 || !strings.Contains(errs[0].Message, "six-octet") {
			t.Errorf("MAC %q: %v", mac, errs)
		}
	}
}

// A usable MAC leaves the loader in PVE's spelling, so the request, the report
// and the guest profile read one form whichever the plan used; one that is not
// usable stays as written, for the validation error to quote.
func TestLoadedPlanCarriesMACsInPVEsSpelling(t *testing.T) {
	for _, spelling := range []string{"02:aa:bb:cc:dd:ee", "02-AA-BB-CC-DD-EE", "02aa.bbcc.ddee"} {
		plan := validPlan()
		plan.Tiers[0].VMs[0].MAC = spelling
		encoded, err := yaml.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := LoadFromReader(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("%q: %v", spelling, err)
		}
		if got := loaded.Tiers[0].VMs[0].MAC; got != "02:AA:BB:CC:DD:EE" {
			t.Errorf("%q loaded as %q", spelling, got)
		}
		worker, err := MarshalWorkerPlan(loaded)
		if err != nil || !bytes.Contains(worker, []byte("02:AA:BB:CC:DD:EE")) {
			t.Errorf("%q: the worker plan carries %s (%v)", spelling, worker, err)
		}
	}
	plan := validPlan()
	plan.Tiers[0].VMs[0].MAC = "ff:ff:ff:ff:ff:ff"
	if errs := macErrors(plan); len(errs) != 1 || !strings.Contains(errs[0].Message, `"ff:ff:ff:ff:ff:ff"`) {
		t.Errorf("an unusable MAC is quoted as written: %v", errs)
	}
}
