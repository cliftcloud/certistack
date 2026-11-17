// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// Every value init sends to the node is checked on the controller first.
func TestBuildNodeDiscoverCommand(t *testing.T) {
	command, err := buildNodeDiscoverCommand(initplan.Request{
		Node: "pve-node-02", Namespace: "certistack-test", VMIDs: []int{7011, 7214},
		FirstVMID: 17000, AvoidVMIDs: []int{17011}, AvoidSDNIDs: []string{"csLab70", "csVn70"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	want := "node-discover --node pve-node-02 --namespace certistack-test --vm 7011,7214 --first-vmid 17000 --avoid-vmid 17011 --avoid-sdn csLab70,csVn70"
	if got := strings.Join(command, " "); got != want {
		t.Fatalf("command = %s\nwant      %s", got, want)
	}
	// The scratch directory goes with them, right after --node.
	withScratch, err := buildNodeDiscoverCommand(initplan.Request{Node: "pve-node-02"}, "/var/lib/certistack/scratch")
	if err != nil || strings.Join(withScratch, " ") != "node-discover --node pve-node-02 --scratch /var/lib/certistack/scratch" {
		t.Fatalf("command with scratch = %v, %v", withScratch, err)
	}
	for _, bad := range []initplan.Request{
		{Node: "pve1; rm -rf /"},
		{Node: "pve1", Namespace: "ns/../x y"},
		{Node: "pve1", VMIDs: []int{0}},
		{Node: "pve1", AvoidSDNIDs: []string{"cs-zone"}},
		{Node: "pve1", FirstVMID: 50},
		{Node: "pve1", All: true, VMIDs: []int{100}},
	} {
		if _, err := buildNodeDiscoverCommand(bad, ""); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

// A worker a signal stopped reports "interrupted…"; the controller returns
// an interruption, not a failed validation, with the node's reason.
func TestNodeInterruptedError(t *testing.T) {
	for reason, want := range map[string]string{
		"interrupted: the node began shutting down (SIGTERM from systemd)": "the node began shutting down (SIGTERM from systemd)",
		"interrupted by SIGINT": "the node worker received SIGINT",
	} {
		err := &NodeInterruptedError{Reason: reason}
		if err.Error() != want || !errors.Is(err, context.Canceled) {
			t.Errorf("%q: %q, canceled %v", reason, err.Error(), errors.Is(err, context.Canceled))
		}
	}
}
