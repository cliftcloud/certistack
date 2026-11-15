// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// noForeignBridgePorts is a sandbox bridge on the node with no port but the
// run's own: the run tests do not model the node's kernel.
func noForeignBridgePorts(string) ([]string, error) { return nil, nil }

// bridgePortsOrchestrator is a pre-provisioned run on node pve1 whose PVE
// answers the guest list with guests (and each listed guest's configuration
// with pending[vmid]), and whose node bridge holds ports, or cannot be read
// (portsErr).
func bridgePortsOrchestrator(t *testing.T, mode, guests string, pending map[string]string, ports []string, portsErr error) *Orchestrator {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data json.RawMessage
		switch path := strings.TrimPrefix(r.URL.Path, "/api2/json/"); {
		case path == "cluster/resources":
			data = json.RawMessage(guests)
		case pending[path] != "":
			data = json.RawMessage(pending[path])
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	t.Cleanup(server.Close)
	plan := &config.Plan{Network: config.Network{Mode: mode, Lifecycle: "preprovisioned", ZoneID: "csSbExt", VNetID: "csVnExt", Tag: 4100}}
	o := New(plan, Options{NodeName: "pve1", StateDir: t.TempDir(), ScratchDir: t.TempDir()}, nil, pve.NewClient(pve.Config{BaseURL: server.URL}))
	o.bridgePortsFn = func(bridge string) ([]string, error) {
		if bridge != "csVnExt" {
			t.Errorf("ports of %q read, want the sandbox VNet's bridge", bridge)
		}
		return ports, portsErr
	}
	return o
}

// PVE lists only the guests the token may audit, and only what their
// configuration says. The node's bridge is what the kernel has attached: a
// port there that is not one of the run's own sandbox VMs (created by this
// run, journaled by it) is a guest that could answer a probe in a restored
// VM's place, even when the token's guest list shows nothing.
func TestTheSandboxBridgeOnTheNodeHoldsOnlyTheRunsOwnPorts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		ports   []string
		created bool  // VM 9101's creation was confirmed
		err     error // the read of the ports
		want    string
	}{
		{name: "an empty bridge", mode: "simple"},
		{name: "the run's VM, its firewall ports too", mode: "simple", created: true, ports: []string{"fwln9101i0", "fwpr9101p0", "fwpr9101p1", "tap9101i0", "tap9101i1"}},
		{name: "a VXLAN zone's tunnel port", mode: "vxlan", created: true, ports: []string{"tap9101i0", "vxlan_csVnExt"}},
		{name: "a VM the token cannot see", mode: "simple", created: true, ports: []string{"tap105i0", "tap9101i0"}, want: "tap105i0 (VM 105)"},
		{name: "another VM's firewall port", mode: "simple", ports: []string{"fwpr105p0"}, want: "fwpr105p0 (VM 105)"},
		{name: "a container", mode: "simple", ports: []string{"veth103i0"}, want: "veth103i0 (container 103)"},
		{name: "a journaled VM whose creation was never confirmed", mode: "simple", ports: []string{"tap9101i0"}, want: "tap9101i0 (VM 9101)"},
		{name: "a port of another kind", mode: "simple", ports: []string{"eno1"}, want: `"eno1"`},
		{name: "a tunnel port in a simple zone", mode: "simple", ports: []string{"vxlan_csVnExt"}, want: `"vxlan_csVnExt"`},
		{name: "another VNet's tunnel port", mode: "vxlan", ports: []string{"vxlan_other"}, want: `"vxlan_other"`},
		{name: "the bridge is not on the node", mode: "simple", err: errors.New("bridge csVnExt is not on this node"), want: "bridge csVnExt is not on this node"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := bridgePortsOrchestrator(t, tc.mode, `[]`, nil, tc.ports, tc.err)
			o.record.AddVM(9101, "pve1", 0, "")
			if tc.created {
				o.noteVMCreated(9101)
			}
			err := o.checkSandboxVNetHoldsOnlyTheRun(context.Background())
			if tc.want == "" {
				if err != nil {
					t.Fatalf("check = %v, want none", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "csVnExt") {
				t.Fatalf("check = %v, want a refusal naming %s", err, tc.want)
			}
		})
	}
}

// A guest on the VNet that carries CertiStack's tag is another run's sandbox
// VM, or one a crashed run left: the refusal says so, and what to do. Any
// other guest keeps the plain refusal.
func TestAnotherCertiStackSandboxVMOnTheVNetIsNamedAsOne(t *testing.T) {
	const guest = `[{"vmid":9200,"type":"qemu","node":"pve1","name":"app","status":"running"}]`
	for _, tc := range []struct {
		name, config string
		certistack   bool
	}{
		{name: "another run's sandbox VM", config: `[{"key":"net0","value":"virtio=BC:24:11:00:92:00,bridge=csVnExt"},{"key":"tags","value":"certistack;run-0"},{"key":"description","value":"owner=certistack\nrun_id=run-0"}]`, certistack: true},
		{name: "a guest tagged so by hand", config: `[{"key":"net0","value":"virtio=BC:24:11:00:92:00,bridge=csVnExt"},{"key":"tags","value":"certistack"}]`, certistack: true},
		{name: "a guest whose tag only contains the word", config: `[{"key":"net0","value":"virtio=BC:24:11:00:92:00,bridge=csVnExt"},{"key":"tags","value":"not-certistack"}]`},
		{name: "any other guest", config: `[{"key":"net0","value":"virtio=BC:24:11:00:92:00,bridge=csVnExt"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := bridgePortsOrchestrator(t, "simple", guest, map[string]string{"nodes/pve1/qemu/9200/pending": tc.config}, nil, nil)
			err := o.checkSandboxVNetHoldsOnlyTheRun(context.Background())
			if err == nil || !strings.Contains(err.Error(), "VM 9200 (app) on pve1, running, net0") {
				t.Fatalf("check = %v, want VM 9200 refused", err)
			}
			says := strings.Contains(err.Error(), "Two CertiStack runs must not share a pre-provisioned VNet at once") &&
				strings.Contains(err.Error(), "certistack-node recover") && strings.Contains(err.Error(), "Issue 26")
			if says != tc.certistack {
				t.Fatalf("check = %v; want the advice for CertiStack's VMs: %v", err, tc.certistack)
			}
			if tc.certistack && !strings.Contains(err.Error(), "tagged certistack") {
				t.Fatalf("check = %v; want VM 9200 shown as tagged certistack", err)
			}
			if !tc.certistack && !strings.Contains(err.Error(), "move those devices to another bridge, or use network.lifecycle: ephemeral") {
				t.Fatalf("check = %v; want the plain refusal kept", err)
			}
		})
	}
}
