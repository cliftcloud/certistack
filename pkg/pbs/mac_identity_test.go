// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pbs

import (
	"fmt"
	"strings"
	"testing"
)

// unusableSourceMACs each pass net.ParseMAC as six octets, and Linux refuses
// all of them on an interface.
var unusableSourceMACs = []string{
	"00:00:00:00:00:00",
	"FF:FF:FF:FF:FF:FF",
	"01:00:5E:00:00:01",
	"33:33:00:00:00:01",
}

// Each value on net0 and on net1. The profile parser (full backup
// configuration) refuses a source whose net0 holds one, naming the reason; the
// layout parser, which never fails over net0, retains neither the MAC nor the
// model; and a net1 that holds one is kept as a bare slot, reported as omitted
// or refused if the plan attaches it, as for any other unusable NIC.
func TestSourceParsersRefuseAddressesNoInterfaceCanHold(t *testing.T) {
	for _, mac := range unusableSourceMACs {
		both := []byte(fmt.Sprintf("net0: virtio=%s,bridge=vmbr0\nnet1: e1000=%s,bridge=vmbr0\n", mac, mac))
		if _, err := ParseVMProfile(both); err == nil || !strings.Contains(err.Error(), "invalid source net0 MAC address") {
			t.Errorf("ParseVMProfile accepted net0 %s: %v", mac, err)
		}
		layout, err := ParseVMLayout(both)
		if err != nil {
			t.Fatalf("ParseVMLayout failed over net0 %s: %v", mac, err)
		}
		if layout.MAC != "" || layout.NICModel != "" {
			t.Errorf("ParseVMLayout retained net0 %s: MAC %q model %q", mac, layout.MAC, layout.NICModel)
		}
		if len(layout.NICs) != 1 || layout.NICs[0] != (SourceNIC{Slot: "net1"}) {
			t.Errorf("ParseVMLayout retained net1 %s: %+v", mac, layout.NICs)
		}

		secondary := []byte(fmt.Sprintf("net0: virtio=02:AA:BB:CC:DD:EE,bridge=vmbr0\nnet1: e1000=%s,bridge=vmbr0\n", mac))
		profile, err := ParseVMProfile(secondary)
		if err != nil {
			t.Fatalf("ParseVMProfile failed over net1 %s: %v", mac, err)
		}
		layout, err = ParseVMLayout(secondary)
		if err != nil {
			t.Fatalf("ParseVMLayout failed over net1 %s: %v", mac, err)
		}
		if len(profile.NICs) != 1 || profile.NICs[0] != (SourceNIC{Slot: "net1"}) || len(layout.NICs) != 1 || layout.NICs[0] != (SourceNIC{Slot: "net1"}) {
			t.Errorf("a net1 holding %s was retained: profile %+v layout %+v", mac, profile.NICs, layout.NICs)
		}
		if profile.MAC != "02:AA:BB:CC:DD:EE" || layout.MAC != "02:AA:BB:CC:DD:EE" {
			t.Errorf("net0 beside an unusable net1: profile %q layout %q", profile.MAC, layout.MAC)
		}
	}
}

// Ordinary unicast MACs still parse, in either case, as PVE writes them.
func TestSourceParsersKeepIndividualAddresses(t *testing.T) {
	for _, mac := range []string{"02:AA:BB:CC:DD:EE", "02:aa:bb:cc:dd:ee", "00:11:22:33:44:55"} {
		input := []byte(fmt.Sprintf("net0: virtio=%s,bridge=vmbr0\nnet1: e1000=%s,bridge=vmbr0\n", mac, mac))
		want := strings.ToUpper(mac)
		profile, profileErr := ParseVMProfile(input)
		layout, layoutErr := ParseVMLayout(input)
		if profileErr != nil || layoutErr != nil {
			t.Fatalf("%s: profile=%v layout=%v", mac, profileErr, layoutErr)
		}
		if profile.MAC != want || layout.MAC != want || len(profile.NICs) != 1 || profile.NICs[0].MAC != want || len(layout.NICs) != 1 || layout.NICs[0].MAC != want {
			t.Errorf("%s: profile %q %+v, layout %q %+v", mac, profile.MAC, profile.NICs, layout.MAC, layout.NICs)
		}
	}
}
