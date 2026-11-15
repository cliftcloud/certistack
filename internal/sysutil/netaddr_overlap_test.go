// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// A PVE node whose own management network lies inside the sandbox range, and whose
// default gateway is the probe address, is cut off from its controller while a run
// lasts (the PVE 8 test node: management 10.60.71.161/23, gateway 10.60.70.1,
// sandbox 10.60.70.0/23 with probe address 10.60.70.1). The probe address is
// refused there; a node whose own networks lie elsewhere is not affected.
func TestAddInterfaceAddressRefusesARangeTheNodeItselfUses(t *testing.T) {
	const laneRoutes = "default via 10.60.20.1 dev vmbr0.20 proto kernel onlink\n" +
		"10.60.10.0/24 dev vmbr0.10 proto kernel scope link src 10.60.10.36\n" +
		"10.60.20.0/24 dev vmbr0.20 proto kernel scope link src 10.60.20.36\n" +
		"169.254.0.0/16 dev idrac proto kernel scope link src 169.254.0.2\n" +
		"10.60.70.0/23 dev csVn70 proto kernel scope link src 10.60.70.1\n"
	const laneAddresses = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n" +
		"4: idrac    inet 169.254.0.2/16 brd 169.254.255.255 scope global idrac\\ \n" +
		"8: vmbr0.20    inet 10.60.20.36/24 scope global vmbr0.20\\ \n" +
		"9: vmbr0.10    inet 10.60.10.36/24 scope global vmbr0.10\\ \n" +
		"4: csVn70    inet 10.60.70.9/23 scope global csVn70\\ \n"
	const other = "3: vmbr1    inet 192.0.2.10/24 scope global vmbr1\\ \n"
	for _, tc := range []struct {
		name, addresses, routes, want string
	}{
		{"a node with its own networks elsewhere", laneAddresses, laneRoutes, ""},
		{"an address of the node inside the range",
			"3: vmbr0    inet 10.60.71.161/23 scope global vmbr0\\ \n", "10.60.70.0/23 dev vmbr0 proto kernel scope link src 10.60.71.161\n", "the node itself uses"},
		{"the default gateway inside the range", other,
			"default via 10.60.70.1 dev vmbr1 onlink\n192.0.2.0/24 dev vmbr1 scope link src 192.0.2.10\n", "gateway 10.60.70.1"},
		{"a route for a bigger network around the range", other, "10.60.0.0/16 via 192.0.2.1 dev vmbr1\n", "has a route for 10.60.0.0/16"},
		{"a route for an unrelated network", other, "198.51.100.0/24 via 192.0.2.1 dev vmbr1\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldRun, oldRunWithInput := runCommand, runCommandWithInput
			t.Cleanup(func() { runCommand, runCommandWithInput = oldRun, oldRunWithInput })
			runCommandWithInput = func(_ context.Context, _ time.Duration, _ io.Reader, _ string, _ ...string) (*Result, error) {
				return &Result{}, nil
			}
			runCommand = func(_ context.Context, _ time.Duration, binary string, args ...string) (*Result, error) {
				command := binary + " " + strings.Join(args, " ")
				switch {
				case binary == "sysctl":
					return &Result{Stdout: []byte("0\n")}, nil
				case command == "ip -4 -o address show":
					return &Result{Stdout: []byte(tc.addresses)}, nil
				case command == "ip -4 route show":
					return &Result{Stdout: []byte(tc.routes)}, nil
				}
				return &Result{}, nil
			}
			err := AddInterfaceAddress(context.Background(), "csVn70", "10.60.70.1/23")
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("error = %v, want the address added", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want a refusal containing %q", err, tc.want)
			}
		})
	}
}
