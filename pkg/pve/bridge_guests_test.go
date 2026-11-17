// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// bridgeCluster is a PVE that answers the guest list and each guest's
// configuration with its pending changes.
type bridgeCluster struct {
	mu        sync.Mutex
	resources string
	pending   map[string]string // "node/kind/vmid" -> the data of its pending read
	failing   map[string]bool   // "node/kind/vmid" whose read fails
	afterFail string            // the guest list after a read failed
	reads     []string
	failed    bool
}

func (b *bridgeCluster) client(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/api2/json/")
		if path == "cluster/resources" {
			list := b.resources
			if b.failed && b.afterFail != "" {
				list = b.afterFail
			}
			_, _ = w.Write([]byte(`{"data":` + list + `}`))
			return
		}
		guest := strings.TrimSuffix(strings.TrimPrefix(path, "nodes/"), "/pending")
		b.reads = append(b.reads, guest)
		if b.failing[guest] {
			b.failed = true
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"data":null,"message":"guest config read failed"}`))
			return
		}
		data, ok := b.pending[guest]
		if !ok {
			t.Errorf("unexpected read of %s", path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"data":` + data + `}`))
	}))
	t.Cleanup(server.Close)
	return NewClient(Config{BaseURL: server.URL})
}

const runMarkers = `{"key":"tags","value":"certistack;run-1"},{"key":"description","value":"owner=certistack\nrun_id=run-1"}`

func TestGuestsOnBridgeListsEveryGuestAttachedToIt(t *testing.T) {
	cluster := &bridgeCluster{
		resources: `[
			{"vmid":101,"type":"qemu","node":"pve1","name":"web-01","status":"running"},
			{"vmid":102,"type":"qemu","node":"pve2","name":"db-01","status":"stopped"},
			{"vmid":103,"type":"lxc","node":"pve1","name":"dns","status":"running"},
			{"vmid":104,"type":"qemu","node":"pve1","name":"tmpl","status":"stopped","template":1},
			{"vmid":105,"type":"qemu","node":"pve1","name":"other","status":"running"},
			{"vmid":17016,"type":"qemu","node":"pve1","name":"sandbox","status":"running"},
			{"vmid":17017,"type":"qemu","node":"pve1","name":"copy","status":"running"}
		]`,
		pending: map[string]string{
			// On the bridge now.
			"pve1/qemu/101": `[{"key":"net0","value":"virtio=BC:24:11:00:00:01,bridge=vmbr0"},{"key":"net1","value":"virtio=BC:24:11:00:00:02,bridge=csVnSandbox,firewall=1"},{"key":"memory","value":2048}]`,
			// On it once a pending change is applied.
			"pve2/qemu/102": `[{"key":"net0","value":"virtio=BC:24:11:00:00:03,bridge=vmbr0","pending":"virtio=BC:24:11:00:00:03,bridge=csVnSandbox"}]`,
			// A container.
			"pve1/lxc/103": `[{"key":"net0","value":"name=eth0,bridge=csVnSandbox,ip=dhcp"}]`,
			// A bridge whose name only starts with the VNet's.
			"pve1/qemu/105": `[{"key":"net0","value":"virtio=BC:24:11:00:00:05,bridge=csVnSandbox0"}]`,
			// The run's own sandbox VM.
			"pve1/qemu/17016": `[{"key":"net0","value":"virtio=BC:24:11:00:00:06,bridge=csVnSandbox"},` + runMarkers + `]`,
			// A VM in the run's list that does not carry its markers.
			"pve1/qemu/17017": `[{"key":"net0","value":"virtio=BC:24:11:00:00:07,bridge=csVnSandbox"},{"key":"tags","value":"certistack"}]`,
		},
	}
	client := cluster.client(t)
	guests, err := client.GuestsOnBridge(context.Background(), "csVnSandbox", "", map[int]bool{17016: true, 17017: true}, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, g := range guests {
		got = append(got, g.String())
	}
	want := []string{
		"VM 101 (web-01) on pve1, running, net1",
		"VM 102 (db-01) on pve2, stopped, net0",
		"container 103 (dns) on pve1, running, net0",
		"VM 17017 (copy) on pve1, running, net0, tagged certistack",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("guests on csVnSandbox:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, read := range cluster.reads {
		if read == "pve1/qemu/104" {
			t.Errorf("a template's configuration was read")
		}
	}

	// One node only: the other node's guests are not read.
	cluster.reads = nil
	guests, err = client.GuestsOnBridge(context.Background(), "csVnSandbox", "pve1", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(guests) != 4 { // 101, 103, 17016 and 17017: with no run, none is the run's
		t.Fatalf("guests on pve1's csVnSandbox: %v", guests)
	}
	for _, read := range cluster.reads {
		if strings.HasPrefix(read, "pve2/") {
			t.Errorf("a guest of another node was read: %s", read)
		}
	}
}

// A list that cannot be read in full is an error, never a shorter list.
func TestGuestsOnBridgeRefusesAListItCannotReadInFull(t *testing.T) {
	for _, tc := range []struct {
		name, resources, want string
		failing               map[string]bool
		afterFail             string
	}{
		{name: "an entry without a VMID", resources: `[{"type":"qemu","node":"pve1"}]`, want: "names no VMID"},
		{name: "no data", resources: `null`, want: "carries no data field"},
		{name: "an unknown guest type", resources: `[{"vmid":101,"type":"openvz","node":"pve1"}]`, want: `type "openvz"`},
		{
			name:      "a guest whose configuration cannot be read",
			resources: `[{"vmid":101,"type":"qemu","node":"pve1","status":"running"}]`,
			failing:   map[string]bool{"pve1/qemu/101": true},
			want:      "read the network devices of guest 101 on pve1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cluster := &bridgeCluster{resources: tc.resources, failing: tc.failing, afterFail: tc.afterFail, pending: map[string]string{}}
			_, err := cluster.client(t).GuestsOnBridge(context.Background(), "csVnSandbox", "", nil, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}

	// A guest removed between the list and the read of its configuration is
	// on no bridge.
	cluster := &bridgeCluster{
		resources: `[{"vmid":101,"type":"qemu","node":"pve1","status":"running"},{"vmid":102,"type":"qemu","node":"pve1","status":"running"}]`,
		afterFail: `[{"vmid":102,"type":"qemu","node":"pve1","status":"running"}]`,
		failing:   map[string]bool{"pve1/qemu/101": true},
		pending:   map[string]string{"pve1/qemu/102": `[{"key":"net0","value":"virtio=BC:24:11:00:00:01,bridge=csVnSandbox"}]`},
	}
	guests, err := cluster.client(t).GuestsOnBridge(context.Background(), "csVnSandbox", "", nil, "")
	if err != nil || len(guests) != 1 || guests[0].VMID != 102 {
		t.Fatalf("guests = %v, %v; want VM 102 alone", guests, err)
	}
}

func TestBridgeGuestNameIsQuotedWhenItIsNotADNSName(t *testing.T) {
	g := BridgeGuest{VMID: 7, Type: "qemu", Name: "x\nERROR fake", Node: "pve1", Status: "running", Device: "net0"}
	if got := g.String(); strings.Contains(got, "\n") || !strings.Contains(got, `"x\nERROR fake"`) {
		t.Fatalf("String() = %q", got)
	}
}
