// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// Review R2-01: the range is read by one parser (config.ParseSandboxRange). A
// spelling it refuses (here a prefix length with a leading zero) is never sent
// to PVE as the subnet to create and never matched against the subnet PVE holds.
func TestCreateSubnetNeverSendsANonCanonicalRange(t *testing.T) {
	for _, text := range []string{"10.0.0.0/08", "10.42.15.0/024", " 10.42.15.0/24", "10.42.15.5/24"} {
		var posted []string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			posted = append(posted, r.Method+" "+r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
		}))
		manager := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
		err := manager.CreateSubnet(context.Background(), config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: text})
		server.Close()
		if err == nil || !strings.Contains(err.Error(), "network.ip_range") {
			t.Errorf("CreateSubnet(%q) error = %v, want a refusal naming network.ip_range", text, err)
		}
		if len(posted) != 0 {
			t.Errorf("CreateSubnet(%q) sent %v to PVE", text, posted)
		}
	}
}

func TestPreprovisionedSandboxDoesNotMatchANonCanonicalRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data json.RawMessage
		switch r.URL.Path {
		case "/api2/json/cluster/sdn/zones":
			data = json.RawMessage(`[{"zone":"csSbExisting","type":"simple","ipam":"pve"}]`)
		case "/api2/json/cluster/sdn/zones/csSbExisting":
			data = json.RawMessage(`{"zone":"csSbExisting","type":"simple","ipam":"pve"}`)
		case "/api2/json/cluster/sdn/vnets":
			data = json.RawMessage(`[{"vnet":"csVnExisting","zone":"csSbExisting"}]`)
		case "/api2/json/cluster/sdn/vnets/csVnExisting":
			data = json.RawMessage(`{"vnet":"csVnExisting","zone":"csSbExisting"}`)
		case "/api2/json/cluster/sdn/vnets/csVnExisting/subnets":
			data = json.RawMessage(`[{"cidr":"10.0.0.0/8","vnet":"csVnExisting"}]`)
		default:
			data = json.RawMessage(`[]`)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	defer server.Close()
	manager := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
	network := config.Network{Mode: "simple", ZoneID: "csSbExisting", VNetID: "csVnExisting", IPRange: "10.0.0.0/8"}
	if err := manager.ValidatePreprovisionedSandbox(context.Background(), network); err != nil {
		t.Fatalf("the canonical range was refused: %v", err)
	}
	network.IPRange = "10.0.0.0/08"
	err := manager.ValidatePreprovisionedSandbox(context.Background(), network)
	if err == nil || !strings.Contains(err.Error(), "write it as 10.0.0.0/8") {
		t.Fatalf("a range spelled 10.0.0.0/08 gave %v, want a refusal naming 10.0.0.0/8", err)
	}
}
