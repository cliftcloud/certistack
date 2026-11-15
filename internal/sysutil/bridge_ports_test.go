// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sysutil

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The ports of a bridge are what the kernel lists under its brif directory,
// whatever PVE's configuration says. A bridge that is not on this node, or an
// interface that is not a bridge, has no list of ports to show: that is an
// error, never an empty bridge.
func TestBridgePortsAreTheKernelsListAndAMissingBridgeIsNoList(t *testing.T) {
	sys, _, _ := fakeNodeRoots(t)
	for _, port := range []string{"tap9101i0", "fwpr105p0", "veth103i0"} {
		if err := os.MkdirAll(filepath.Join(sys, "csVnet1", "brif", port), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ports, err := BridgePorts("csVnet1")
	if want := []string{"fwpr105p0", "tap9101i0", "veth103i0"}; err != nil || !reflect.DeepEqual(ports, want) {
		t.Fatalf("BridgePorts = %v, %v; want %v", ports, err, want)
	}

	if err := os.MkdirAll(filepath.Join(sys, "csEmpty", "brif"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ports, err := BridgePorts("csEmpty"); err != nil || len(ports) != 0 {
		t.Fatalf("BridgePorts of a bridge with no port = %v, %v; want none", ports, err)
	}

	if err := os.MkdirAll(filepath.Join(sys, "eth0"), 0o755); err != nil {
		t.Fatal(err)
	}
	for iface, want := range map[string]string{
		"csGone":   "is not on this node",
		"eth0":     "is not a bridge",
		"../etc":   "invalid bridge name",
		"":         "invalid bridge name",
		"csVnet1/": "invalid bridge name",
	} {
		if ports, err := BridgePorts(iface); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("BridgePorts(%q) = %v, %v; want an error saying it %s", iface, ports, err, want)
		}
	}
}
