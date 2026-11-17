// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"strings"
	"testing"
)

func macIdentityConfig(mac string, nics ...NIC) VMConfig {
	return VMConfig{
		VMID: 9900, Name: "mac-identity", Bridge: "csVn203", MAC: mac, NICModel: "virtio",
		DiskOverlays:   []DiskOverlay{{Slot: "scsi0", Path: "/tmp/mac-identity.qcow2"}},
		AdditionalNICs: nics,
	}
}

// The all-zero, broadcast, IPv4-multicast and IPv6-multicast addresses: a
// request is refused whichever NIC holds one, and the locally administered
// unicast control builds.
func TestCreateParamsRefuseAddressesNoInterfaceCanHold(t *testing.T) {
	for _, mac := range []string{"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "01:00:5E:00:00:01", "33:33:00:00:00:01"} {
		if _, err := macIdentityConfig(mac).CreateParams(); err == nil || !strings.Contains(err.Error(), "invalid net0 MAC address") {
			t.Errorf("net0 %s: %v", mac, err)
		}
		cfg := macIdentityConfig("02:AA:BB:CC:DD:EE", NIC{Slot: "net1", Model: "virtio", MAC: mac})
		if _, err := cfg.CreateParams(); err == nil || !strings.Contains(err.Error(), "invalid net1 MAC address") {
			t.Errorf("net1 %s: %v", mac, err)
		}
		// The public create call refuses it before anything reaches PVE.
		client := NewClient(Config{BaseURL: "http://localhost:1"})
		if _, err := client.CreateVM(context.Background(), "pve1", macIdentityConfig(mac)); err == nil {
			t.Errorf("CreateVM accepted net0 %s", mac)
		}
	}
	params, err := macIdentityConfig("02:AA:BB:CC:DD:EE", NIC{Slot: "net1", Model: "virtio", MAC: "02:AA:BB:CC:DD:EF"}).CreateParams()
	if err != nil {
		t.Fatalf("unicast control refused: %v", err)
	}
	if params["net0"] != "virtio=02:AA:BB:CC:DD:EE,bridge=csVn203,firewall=1" || params["net1"] != "virtio=02:AA:BB:CC:DD:EF,bridge=csVn203,firewall=1" {
		t.Errorf("control NIC strings: net0=%v net1=%v", params["net0"], params["net1"])
	}
}

// Three identical NIC strings on one bridge are refused: one VM's NICs may
// not share an address, in any spelling; a
// net0 that PVE will choose the address of holds none to share.
func TestCreateParamsRefuseOneAddressOnTwoNICsOfAVM(t *testing.T) {
	const mac = "02:AA:BB:CC:DD:EE"
	for _, spelling := range []string{mac, "02:aa:bb:cc:dd:ee", "02-AA-BB-CC-DD-EE", "02aa.bbcc.ddee"} {
		_, err := macIdentityConfig(mac, NIC{Slot: "net1", Model: "virtio", MAC: spelling}).CreateParams()
		if err == nil || !strings.Contains(err.Error(), "net1 and net0 both use MAC address "+mac) {
			t.Errorf("net1 %q beside net0: %v", spelling, err)
		}
	}
	_, err := macIdentityConfig(mac,
		NIC{Slot: "net1", Model: "virtio", MAC: "02:AA:BB:CC:DD:EF"},
		NIC{Slot: "net2", Model: "e1000", MAC: "02:aa:bb:cc:dd:ef"},
	).CreateParams()
	if err == nil || !strings.Contains(err.Error(), "net2 and net1 both use MAC address 02:AA:BB:CC:DD:EF") {
		t.Errorf("net2 beside net1: %v", err)
	}
	if _, err := macIdentityConfig("", NIC{Slot: "net1", Model: "virtio", MAC: mac}).CreateParams(); err != nil {
		t.Errorf("a net0 without an address collided: %v", err)
	}
	// The create call is the same check.
	client := NewClient(Config{BaseURL: "http://localhost:1"})
	if _, err := client.CreateVM(context.Background(), "pve1", macIdentityConfig(mac, NIC{Slot: "net1", Model: "virtio", MAC: mac})); err == nil {
		t.Error("CreateVM accepted net0 and net1 with one address")
	}
}

// PVE takes an address as colon-separated hex pairs. net0 is written the way
// the other NICs are, and the hardware the report records is what was sent.
func TestCreateParamsWriteAddressesInPVEsSpelling(t *testing.T) {
	for _, spelling := range []string{"02:aa:bb:cc:dd:ee", "02-AA-BB-CC-DD-EE", "02aa.bbcc.ddee"} {
		cfg := macIdentityConfig(spelling)
		params, err := cfg.CreateParams()
		if err != nil {
			t.Fatalf("%q: %v", spelling, err)
		}
		if want := "virtio=02:AA:BB:CC:DD:EE,bridge=csVn203,firewall=1"; params["net0"] != want {
			t.Errorf("%q: net0 = %v, want %q", spelling, params["net0"], want)
		}
		if got := cfg.EffectiveHardware().MAC; got != "02:AA:BB:CC:DD:EE" {
			t.Errorf("%q: recorded MAC %q", spelling, got)
		}
	}
	if got := macIdentityConfig("").EffectiveHardware().MAC; got != "" {
		t.Errorf("no MAC requested, recorded %q", got)
	}
}
