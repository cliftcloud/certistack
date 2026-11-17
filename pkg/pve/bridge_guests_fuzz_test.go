// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package pve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// FuzzGuestsOnBridgeNeverMissesAGuestOnTheBridge holds GuestsOnBridge to its
// promise for any answer PVE gives to a guest's configuration read: a guest
// whose network device names the bridge, now or pending, is in the list, or
// the call is an error. It is never left out, which would let a run share a
// pre-provisioned VNet with a guest that can answer its probes.
func FuzzGuestsOnBridgeNeverMissesAGuestOnTheBridge(f *testing.F) {
	for _, seed := range []string{
		`[{"key":"net0","value":"virtio=BC:24:11:00:00:01,bridge=csVnSandbox"}]`,
		`[{"key":"net0","value":"virtio=BC:24:11:00:00:01,bridge=vmbr0","pending":"virtio=BC:24:11:00:00:01,bridge=csVnSandbox"}]`,
		`[{"key":"net1","pending":"name=eth0,bridge=csVnSandbox,ip=dhcp"},{"key":"memory","value":2048}]`,
		`[{"key":"net0","value":"virtio=BC:24:11:00:00:01,bridge=csVnSandbox","delete":1}]`,
		`[]`, `null`, `{}`, `[null]`, `[{"key":"net0","value":7}]`,
	} {
		f.Add([]byte(seed))
	}
	var mu sync.Mutex
	var pending []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/cluster/resources") {
			_, _ = w.Write([]byte(`{"data":[{"vmid":101,"type":"qemu","node":"pve1","name":"web","status":"running"}]}`))
			return
		}
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write([]byte(`{"data":`))
		_, _ = w.Write(pending)
		_, _ = w.Write([]byte(`}`))
	}))
	f.Cleanup(server.Close)
	client := NewClient(Config{BaseURL: server.URL})
	client.retryDelays = []time.Duration{}
	device := regexp.MustCompile(`^net[0-9]+$`)

	f.Fuzz(func(t *testing.T, data []byte) {
		mu.Lock()
		pending = data
		mu.Unlock()
		guests, err := client.GuestsOnBridge(context.Background(), "csVnSandbox", "", nil, "")
		if err != nil {
			return
		}
		// What PVE's answer says, read on its own: does any device name the bridge?
		var answer struct {
			Data []map[string]any `json:"data"`
		}
		if json.Unmarshal(append(append([]byte(`{"data":`), data...), '}'), &answer) != nil {
			if len(guests) != 0 {
				t.Fatalf("an answer that is not JSON gave guests %v", guests)
			}
			return
		}
		onBridge := false
		for _, entry := range answer.Data {
			key, _ := entry["key"].(string)
			if !device.MatchString(key) {
				continue
			}
			for _, field := range []string{"value", "pending"} {
				if spec, ok := entry[field].(string); ok && deviceBridge(spec) == "csVnSandbox" {
					onBridge = true
				}
			}
		}
		if onBridge && len(guests) == 0 {
			t.Fatalf("PVE's answer %s puts guest 101 on the bridge, and GuestsOnBridge listed no guest and no error", data)
		}
	})
}
