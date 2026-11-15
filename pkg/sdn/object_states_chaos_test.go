// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/pkg/pve"
)

// PVE's pending view of the zones is what tells the run whether a zone is
// there to delete. An entry of it whose ID cannot be read could be the
// zone: reading the list without it took the run's zone for absent, and a zone
// absent needs no proof that it is the run's, so DestroyZone deleted a zone
// that nothing showed to be the run's. A list that cannot be read in full is
// an error, and nothing is deleted.
func TestAZoneListWithAnUnreadableEntryDeletesNothing(t *testing.T) {
	for name, entry := range map[string]string{
		"an entry with no zone ID":           `{"type":"simple","state":"changed"}`,
		"an entry whose zone ID is a number": `{"zone":7,"type":"simple"}`,
		"an entry that is null":              `null`,
	} {
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var deletes []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/sdn/zones":
					_, _ = w.Write([]byte(`{"data":[{"zone":"lab","type":"simple"},` + entry + `]}`))
				case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/sdn/vnets":
					_, _ = w.Write([]byte(`{"data":[]}`))
				case r.Method == http.MethodDelete:
					deletes = append(deletes, r.URL.Path)
					_, _ = w.Write([]byte(`{"data":null}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			m := holding(NewManager(pve.NewClient(pve.Config{BaseURL: server.URL})), "tok")
			m.SetOwnerMarker(runMarker)
			err := m.DestroyZone(context.Background(), "csSb01")
			mu.Lock()
			defer mu.Unlock()
			if len(deletes) != 0 {
				t.Fatalf("DestroyZone = %v and deleted %v; the zone was never shown absent or the run's", err, deletes)
			}
			if err == nil || !strings.Contains(err.Error(), "csSb01") {
				t.Fatalf("DestroyZone = %v, want an error naming the zone", err)
			}
		})
	}
}

// The same for the read DestroyVNet makes before it deletes a VNet, and the
// one DestroyZone makes without a marker: an entry of the list whose ID
// cannot be read could be the object, so the object is not shown absent, and
// nothing is deleted.
func TestAnSDNListWithAnUnreadableEntryIsNotAnAbsence(t *testing.T) {
	for _, tc := range []struct {
		name, list, marker string
		destroy            func(*Manager) error
	}{
		{name: "a VNet", list: "vnets", marker: runMarker, destroy: func(m *Manager) error { return m.DestroyVNet(context.Background(), "csVn01") }},
		{name: "a zone, no marker", list: "zones", destroy: func(m *Manager) error { return m.DestroyZone(context.Background(), "csSb01") }},
	} {
		for entryName, entry := range map[string]string{
			"no ID":        `{"type":"simple","alias":"` + runMarker + `"}`,
			"a numeric ID": `{"vnet":7,"zone":7}`,
			"a null entry": `null`,
		} {
			t.Run(tc.name+", "+entryName, func(t *testing.T) {
				var mu sync.Mutex
				var writes []string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					switch {
					case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/sdn/"+tc.list:
						_, _ = w.Write([]byte(`{"data":[` + entry + `]}`))
					case r.Method == http.MethodGet:
						_, _ = w.Write([]byte(`{"data":[]}`))
					default:
						writes = append(writes, r.Method+" "+r.URL.Path)
						_, _ = w.Write([]byte(`{"data":null}`))
					}
				}))
				defer server.Close()
				m := holding(NewManager(pve.NewClient(pve.Config{BaseURL: server.URL})), "tok")
				m.SetOwnerMarker(tc.marker)
				err := tc.destroy(m)
				mu.Lock()
				defer mu.Unlock()
				if len(writes) != 0 || err == nil {
					t.Fatalf("destroy = %v, writes %v; want an error and nothing changed", err, writes)
				}
			})
		}
	}
}
