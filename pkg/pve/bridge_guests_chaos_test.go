// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A guest's configuration read that carries no configuration is not an
// answer that the guest has no network device: reading it as one leaves a
// guest on the VNet out of the list, and the run would share the VNet with
// a guest that can answer a probe in a restored VM's place.
func TestGuestsOnBridgeRefusesAGuestReadThatCarriesNoConfiguration(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{name: "data null", body: `{"data":null}`},
		{name: "no data field", body: `{}`},
		{name: "data an empty string", body: `{"data":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/cluster/resources") {
					_, _ = w.Write([]byte(`{"data":[{"vmid":101,"type":"qemu","node":"pve1","name":"web-01","status":"running"}]}`))
					return
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			guests, err := NewClient(Config{BaseURL: server.URL}).GuestsOnBridge(context.Background(), "csVnSandbox", "", nil, "")
			if err == nil {
				t.Fatalf("GuestsOnBridge = %v, nil; want an error: guest 101's configuration was never read", guests)
			}
			if !strings.Contains(err.Error(), "guest 101") {
				t.Fatalf("err = %v; want it to name guest 101", err)
			}
		})
	}
}

// A configuration entry CertiStack cannot read is not one that names no
// bridge: a network device's specification that is not text, or an entry
// whose key is not text (it could be a network device), is an error.
func TestGuestsOnBridgeRefusesAConfigurationEntryItCannotRead(t *testing.T) {
	for _, tc := range []struct{ name, pending string }{
		{name: "a device value that is an object", pending: `[{"key":"net0","value":{"bridge":"csVnSandbox"}}]`},
		{name: "a device value that is a number", pending: `[{"key":"net0","value":7}]`},
		{name: "a pending device value that is a list", pending: `[{"key":"net0","value":"virtio=BC:24:11:00:00:01,bridge=vmbr0","pending":["bridge=csVnSandbox"]}]`},
		{name: "a key that is not text", pending: `[{"key":["net0"],"value":"virtio=BC:24:11:00:00:01,bridge=csVnSandbox"}]`},
		{name: "an entry with no key", pending: `[{"value":"virtio=BC:24:11:00:00:01,bridge=csVnSandbox"}]`},
		{name: "an entry that is not an object", pending: `[{"key":"memory","value":"2048"},"net0"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := &bridgeCluster{
				resources: `[{"vmid":101,"type":"qemu","node":"pve1","name":"web-01","status":"running"}]`,
				pending:   map[string]string{"pve1/qemu/101": tc.pending},
			}
			guests, err := cluster.client(t).GuestsOnBridge(context.Background(), "csVnSandbox", "", nil, "")
			if err == nil {
				t.Fatalf("GuestsOnBridge = %v, nil; want an error", guests)
			}
		})
	}

	// A value of another type under a key that names no device is not read
	// for a bridge, and is no reason to refuse.
	cluster := &bridgeCluster{
		resources: `[{"vmid":101,"type":"qemu","node":"pve1","name":"web-01","status":"running"}]`,
		pending:   map[string]string{"pve1/qemu/101": `[{"key":"memory","value":2048},{"key":"onboot","value":1,"pending":0},{"key":"net0","value":"virtio=BC:24:11:00:00:01,bridge=csVnSandbox","delete":1}]`},
	}
	guests, err := cluster.client(t).GuestsOnBridge(context.Background(), "csVnSandbox", "", nil, "")
	if err != nil || len(guests) != 1 || guests[0].Device != "net0" {
		t.Fatalf("GuestsOnBridge = %v, %v; want VM 101's net0", guests, err)
	}
}

// What PVE says of a guest reaches the refusal's message: a status with a
// line break or a terminal escape must not show as part of the message.
func TestBridgeGuestStatusCannotPassForPartOfTheMessage(t *testing.T) {
	g := BridgeGuest{VMID: 7, Type: "qemu", Name: "web", Node: "pve1", Status: "running\n\x1b[2KERROR fake", Device: "net0"}
	got := g.String()
	if strings.ContainsAny(got, "\n\x1b") {
		t.Fatalf("String() = %q", got)
	}
}

// A guest on the VNet that carries CertiStack's exact tag is a sandbox VM of
// another run, or one a crashed run left: the refusal shows it as tagged, so
// that the run can say what to do about it (a run's own VM, in own and with
// its markers, is not listed at all). A tag that only contains the word is not
// CertiStack's.
func TestAnotherRunsSandboxVMOnTheVNetIsShownTagged(t *testing.T) {
	cluster := &bridgeCluster{
		resources: `[{"vmid":9101,"type":"qemu","node":"pve1","name":"app","status":"stopped"}]`,
		pending: map[string]string{"pve1/qemu/9101": `[{"key":"net0","value":"virtio=BC:24:11:00:91:01,bridge=csVnSandbox"},` +
			`{"key":"tags","value":"certistack;run-0"},{"key":"description","value":"owner=certistack\nrun_id=run-0"}]`},
	}
	guests, err := cluster.client(t).GuestsOnBridge(context.Background(), "csVnSandbox", "", nil, "run-1")
	if err != nil || len(guests) != 1 {
		t.Fatalf("GuestsOnBridge = %v, %v", guests, err)
	}
	if got := guests[0].String(); got != "VM 9101 (app) on pve1, stopped, net0, tagged certistack" || !guests[0].CertiStack {
		t.Fatalf("String() = %q; want VM 9101 shown tagged certistack", got)
	}
	guests[0].CertiStack = false
	if got := guests[0].String(); got != "VM 9101 (app) on pve1, stopped, net0" {
		t.Fatalf("String() = %q for a guest without the tag", got)
	}
}
