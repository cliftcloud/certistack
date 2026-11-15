// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package sdn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

func TestEnsureSandboxAvailable(t *testing.T) {
	tests := []struct {
		name           string
		zoneStatus     int
		vnetStatus     int
		wantCollision  string
		wantCalls      int
		wantErrContain string
	}{
		{
			name:       "both identifiers absent",
			zoneStatus: http.StatusNotFound,
			vnetStatus: http.StatusNotFound,
			wantCalls:  2,
		},
		{
			name:          "existing VNet",
			zoneStatus:    http.StatusNotFound,
			vnetStatus:    http.StatusOK,
			wantCollision: "VNet",
			wantCalls:     2,
		},
		{
			name:           "zone authorization failure is fail closed",
			zoneStatus:     http.StatusForbidden,
			wantCalls:      1,
			wantErrContain: "check whether sandbox zone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				// PVE's zone and VNet lists: NotFound stands for an ID the
				// list lacks, OK for one it has.
				status, entry := tt.vnetStatus, `{"vnet":"csVnCheck","zone":"z"}`
				if r.URL.Path == "/api2/json/cluster/sdn/zones" {
					status, entry = tt.zoneStatus, `{"zone":"csSbCheck"}`
				} else if r.URL.Path != "/api2/json/cluster/sdn/vnets" {
					t.Errorf("availability read %s, not a list", r.URL.Path)
				}
				if status == http.StatusForbidden {
					http.Error(w, http.StatusText(status), status)
					return
				}
				// Each entry carries its list's identity field, as PVE's do.
				list := `[{"vnet":"other","zone":"z"}]`
				if r.URL.Path == "/api2/json/cluster/sdn/zones" {
					list = `[{"zone":"other"}]`
				}
				if status == http.StatusOK {
					list = "[" + entry + "]"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(list)})
			}))
			defer server.Close()

			mgr := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
			err := mgr.EnsureSandboxAvailable(context.Background(), config.Network{ZoneID: "csSbCheck", VNetID: "csVnCheck"})
			if calls != tt.wantCalls {
				t.Fatalf("availability checks = %d, want %d", calls, tt.wantCalls)
			}
			if tt.wantCollision == "" {
				if tt.wantErrContain == "" && err != nil {
					t.Fatalf("EnsureSandboxAvailable() error = %v", err)
				}
				if tt.wantErrContain != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrContain)) {
					t.Fatalf("EnsureSandboxAvailable() error = %v, want %q", err, tt.wantErrContain)
				}
				return
			}
			var collision *OwnershipCollisionError
			if !errors.As(err, &collision) || collision.Resource != tt.wantCollision {
				t.Fatalf("EnsureSandboxAvailable() error = %v, collision = %+v; want %s collision", err, collision, tt.wantCollision)
			}
		})
	}
}

func TestValidatePreprovisionedSandbox(t *testing.T) {
	tests := []struct {
		name           string
		zoneData       json.RawMessage
		vnetData       json.RawMessage
		subnetsData    json.RawMessage
		wantCalls      int
		wantErrContain string
	}{
		{
			name:        "isolated sandbox is accepted without mutation",
			zoneData:    json.RawMessage(`{"zone":"csSbExisting","type":"simple","ipam":"pve"}`),
			vnetData:    json.RawMessage(`{"vnet":"csVnExisting","zone":"csSbExisting"}`),
			subnetsData: json.RawMessage(`[{"cidr":"10.100.0.0/24","vnet":"csVnExisting"}]`),
			wantCalls:   3,
		},
		{
			// PVE 8.4 lists a simple zone created without an ipam option with no "ipam" member at
			// all: PVE's own IPAM is the default (as a real node answers: 'uses IPAM ""').
			name:        "a zone that lists no ipam uses PVE's own IPAM and is accepted",
			zoneData:    json.RawMessage(`{"zone":"csSbExisting","type":"simple"}`),
			vnetData:    json.RawMessage(`{"vnet":"csVnExisting","zone":"csSbExisting"}`),
			subnetsData: json.RawMessage(`[{"cidr":"10.100.0.0/24","vnet":"csVnExisting"}]`),
			wantCalls:   3,
		},
		{
			name:           "an external IPAM plugin is rejected",
			zoneData:       json.RawMessage(`{"zone":"csSbExisting","type":"simple","ipam":"netbox"}`),
			wantCalls:      1,
			wantErrContain: "uses IPAM \"netbox\"",
		},
		{
			name:           "gateway is rejected",
			zoneData:       json.RawMessage(`{"zone":"csSbExisting","type":"simple","ipam":"pve"}`),
			vnetData:       json.RawMessage(`{"vnet":"csVnExisting","zone":"csSbExisting"}`),
			subnetsData:    json.RawMessage(`[{"cidr":"10.100.0.0/24","vnet":"csVnExisting","gateway":"10.100.0.1"}]`),
			wantCalls:      3,
			wantErrContain: "has a gateway",
		},
		{
			name:           "a zone the list does not show is missing or unaudited",
			zoneData:       json.RawMessage(`{"zone":"otherZone","type":"simple","ipam":"pve"}`),
			wantCalls:      1,
			wantErrContain: "does not exist, or the token lacks SDN.Audit on /sdn/zones/csSbExisting",
		},
		{
			name:           "VNet from another zone is rejected",
			zoneData:       json.RawMessage(`{"zone":"csSbExisting","type":"simple","ipam":"pve"}`),
			vnetData:       json.RawMessage(`{"vnet":"csVnExisting","zone":"anotherZone"}`),
			wantCalls:      2,
			wantErrContain: "belongs to zone",
		},
		{
			name:           "a VNet the list does not show is missing or unaudited",
			zoneData:       json.RawMessage(`{"zone":"csSbExisting","type":"simple","ipam":"pve"}`),
			vnetData:       json.RawMessage(`{"vnet":"otherVNet","zone":"csSbExisting"}`),
			wantCalls:      2,
			wantErrContain: "VNet \"csVnExisting\" does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodGet {
					t.Fatalf("preprovisioned validation made mutating request %s %s", r.Method, r.URL.Path)
				}
				var data json.RawMessage
				switch r.URL.Path {
				case "/api2/json/cluster/sdn/zones":
					data = listOf(tt.zoneData)
				case "/api2/json/cluster/sdn/vnets":
					data = listOf(tt.vnetData)
				case "/api2/json/cluster/sdn/vnets/csVnExisting/subnets":
					data = tt.subnetsData
				default:
					t.Fatalf("unexpected preprovisioned validation request %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
			}))
			defer server.Close()

			mgr := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
			err := mgr.ValidatePreprovisionedSandbox(context.Background(), config.Network{
				Mode: "simple", ZoneID: "csSbExisting", VNetID: "csVnExisting", IPRange: "10.100.0.0/24",
			})
			if calls != tt.wantCalls {
				t.Fatalf("validation calls = %d, want %d", calls, tt.wantCalls)
			}
			if tt.wantErrContain == "" && err != nil {
				t.Fatalf("ValidatePreprovisionedSandbox() error = %v", err)
			}
			if tt.wantErrContain != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrContain)) {
				t.Fatalf("ValidatePreprovisionedSandbox() error = %v, want %q", err, tt.wantErrContain)
			}
		})
	}
}

// listOf is a PVE list holding entry, or an empty list for no entry.
func listOf(entry json.RawMessage) json.RawMessage {
	if len(entry) == 0 {
		return json.RawMessage(`[]`)
	}
	return json.RawMessage("[" + string(entry) + "]")
}

func TestValidatePreprovisionedSandboxRejectsWrongVXLANVNI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var data json.RawMessage
		switch r.URL.Path {
		case "/api2/json/cluster/sdn/zones":
			data = json.RawMessage(`[{"zone":"other","type":"simple","ipam":"pve"},{"zone":"csVxlan","type":"vxlan","ipam":"pve","peers":"10.0.0.1"}]`)
		case "/api2/json/cluster/sdn/vnets":
			data = json.RawMessage(`[{"vnet":"csVnVxlan","zone":"csVxlan","tag":7000}]`)
		case "/api2/json/cluster/sdn/vnets/csVnVxlan/subnets":
			data = json.RawMessage(`[{"cidr":"10.101.0.0/24","vnet":"csVnVxlan"}]`)
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	defer server.Close()

	err := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL})).ValidatePreprovisionedSandbox(context.Background(), config.Network{
		Mode: "vxlan", ZoneID: "csVxlan", VNetID: "csVnVxlan", Tag: 7001, Peers: "10.0.0.1", IPRange: "10.101.0.0/24",
	})
	if err == nil || !strings.Contains(err.Error(), "VXLAN VNI") {
		t.Fatalf("ValidatePreprovisionedSandbox() error = %v", err)
	}
}

func TestSDNManager_VXLANRequestBodies(t *testing.T) {
	var zoneBody map[string]any
	var vnetBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s for %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode %s request: %v", r.URL.Path, err)
		}
		switch r.URL.Path {
		case "/api2/json/cluster/sdn/zones":
			zoneBody = body
		case "/api2/json/cluster/sdn/vnets":
			vnetBody = body
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
	}))
	defer server.Close()

	netCfg := config.Network{
		Mode:   "vxlan",
		ZoneID: "csVxlanBody",
		VNetID: "csVnVxlanBody",
		Tag:    7001,
		Peers:  "10.0.0.2,10.0.0.1",
	}
	mgr := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
	if err := mgr.CreateZone(context.Background(), netCfg, ""); err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	if err := mgr.CreateVNet(context.Background(), netCfg); err != nil {
		t.Fatalf("CreateVNet: %v", err)
	}
	if got := zoneBody["peers"]; got != "10.0.0.1,10.0.0.2" {
		t.Fatalf("zone peers = %v, want canonical peer list", got)
	}
	if _, present := zoneBody["tag"]; present {
		t.Fatalf("zone body unexpectedly contains VNI tag: %v", zoneBody)
	}
	if got := vnetBody["tag"]; got != float64(7001) {
		t.Fatalf("VNet tag = %v, want 7001", got)
	}
	if _, present := vnetBody["peers"]; present {
		t.Fatalf("VNet body unexpectedly contains peers: %v", vnetBody)
	}
}

func TestEnsureSandboxAvailableRejectsUsedVXLANVNI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api2/json/cluster/sdn/zones":
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
		case "/api2/json/cluster/sdn/vnets":
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"vnet":"existing-vnet","tag":7001}]`)})
		default:
			t.Fatalf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()

	err := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL})).EnsureSandboxAvailable(context.Background(), config.Network{
		Mode: "vxlan", ZoneID: "csVxlanCheck", VNetID: "csVnVxlanCheck", Tag: 7001, Peers: "10.0.0.1",
	})
	if err == nil || !strings.Contains(err.Error(), "VNI 7001 is already used") {
		t.Fatalf("EnsureSandboxAvailable() error = %v, want VNI collision", err)
	}
}

func TestSDNManager_Lifecycle(t *testing.T) {
	var requestedPaths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.Method+" "+r.URL.Path)

		var data json.RawMessage
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/sdn":
			data = json.RawMessage(`"UPID:pve1:1:1:1:1:1:"`)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tasks/UPID:pve1:1:1:1:1:1:/status"):
			data = json.RawMessage(`{"status":"stopped","exitstatus":"OK"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/sdn/vnets":
			data = json.RawMessage(`[]`)
		default:
			data = json.RawMessage(`"OK"`)
		}
		resp := pve.APIResponse{Data: data}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := pve.NewClient(pve.Config{
		BaseURL: server.URL,
	})
	mgr := NewManager(client)
	mgr.SetOwnerMarker("certistack run-lifecycle")

	ctx := context.Background()
	netCfg := config.Network{
		Mode:    "simple",
		ZoneID:  "csSb01",
		VNetID:  "csVn01",
		IPRange: "10.100.0.0/24",
	}

	// 1. Create Zone
	if err := mgr.CreateZone(ctx, netCfg, ""); err != nil {
		t.Fatalf("CreateZone failed: %v", err)
	}

	// 2. Create VNet
	if err := mgr.CreateVNet(ctx, netCfg); err != nil {
		t.Fatalf("CreateVNet failed: %v", err)
	}
	if err := mgr.CreateSubnet(ctx, netCfg); err != nil {
		t.Fatalf("CreateSubnet failed: %v", err)
	}

	// 3. Reload
	if err := holding(mgr, "tok").Reload(ctx); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// 4. Destroy VNet
	if err := mgr.DestroyVNet(ctx, netCfg.VNetID); err != nil {
		t.Fatalf("DestroyVNet failed: %v", err)
	}

	// 5. Destroy Zone
	if err := mgr.DestroyZone(ctx, netCfg.ZoneID); err != nil {
		t.Fatalf("DestroyZone failed: %v", err)
	}

	expectedCalls := []string{
		"POST /api2/json/cluster/sdn/zones",
		"POST /api2/json/cluster/sdn/vnets",
		"POST /api2/json/cluster/sdn/vnets/csVn01/subnets",
		// The apply returns once PVE has it; the node's own reload is
		// the caller's to wait for.
		"PUT /api2/json/cluster/sdn",
		// The VNet is read before its deletion, to show it is the run's.
		"GET /api2/json/cluster/sdn/vnets",
		"GET /api2/json/cluster/sdn/vnets/csVn01/subnets",
		"DELETE /api2/json/cluster/sdn/vnets/csVn01",
		"DELETE /api2/json/cluster/sdn/zones/csSb01",
	}

	if len(requestedPaths) != len(expectedCalls) {
		t.Fatalf("expected %d calls, got %d: %v", len(expectedCalls), len(requestedPaths), requestedPaths)
	}

	for i, expected := range expectedCalls {
		if requestedPaths[i] != expected {
			t.Errorf("call %d: expected %s, got %s", i, expected, requestedPaths[i])
		}
	}
}

func TestReloadRejectsMissingOrMalformedTaskIdentifier(t *testing.T) {
	for _, taskID := range []string{"", "OK", "UPID::missing-node"} {
		t.Run(fmt.Sprintf("task=%q", taskID), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(fmt.Sprintf("%q", taskID))})
			}))
			defer server.Close()

			err := holding(NewManager(pve.NewClient(pve.Config{BaseURL: server.URL})), "tok").Reload(context.Background())
			if err == nil || !strings.Contains(err.Error(), "invalid task identifier") {
				t.Fatalf("Reload(%q) error = %v", taskID, err)
			}
		})
	}
}

func TestDestroyAbsentResourcesIsIdempotent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The VNet and zone lists (the ownership reads) are empty; the VNet's
		// subnet list answers 404 as the VNet does.
		if r.Method == http.MethodGet && (r.URL.Path == "/api2/json/cluster/sdn/vnets" || r.URL.Path == "/api2/json/cluster/sdn/zones") {
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
			return
		}
		if r.Method != http.MethodDelete && !strings.HasSuffix(r.URL.Path, "/subnets") {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	mgr := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
	mgr.SetOwnerMarker("certistack run-gone")
	if err := mgr.DestroyVNet(context.Background(), "csVnAlreadyGone"); err != nil {
		t.Fatalf("destroy already-absent VNet: %v", err)
	}
	if err := mgr.DestroyZone(context.Background(), "csZoneAlreadyGone"); err != nil {
		t.Fatalf("destroy already-absent zone: %v", err)
	}
}

func TestDestroyVNetSurfacesChildSubnetDeletionFailures(t *testing.T) {
	deleteAttempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api2/json/cluster/sdn/vnets":
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"vnet":"csVnFailure","alias":"certistack run-f"}]`)})
		case "DELETE /api2/json/cluster/sdn/vnets/csVnFailure":
			deleteAttempts++
			if deleteAttempts == 1 {
				http.Error(w, "subnet still exists", http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
		case "GET /api2/json/cluster/sdn/vnets/csVnFailure/subnets":
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"id":"10.100.0.0-24"}]`)})
		case "DELETE /api2/json/cluster/sdn/vnets/csVnFailure/subnets/10.100.0.0-24":
			http.Error(w, "subnet delete denied", http.StatusForbidden)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	mgr := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
	mgr.SetOwnerMarker("certistack run-f")
	err := mgr.DestroyVNet(context.Background(), "csVnFailure")
	if err == nil || !strings.Contains(err.Error(), "delete SDN subnet") || !strings.Contains(err.Error(), "subnet delete denied") {
		t.Fatalf("DestroyVNet error = %v, want surfaced child subnet deletion failure", err)
	}
}

func TestSDNManagerRejectsUnsafeIdentifiersBeforeAPICall(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{}`)})
	}))
	defer server.Close()

	mgr := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
	unsafe := "../cluster"
	operations := map[string]func() error{
		"availability": func() error {
			return mgr.EnsureSandboxAvailable(context.Background(), config.Network{ZoneID: unsafe, VNetID: "csVn01"})
		},
		"preprovisioned": func() error {
			return mgr.ValidatePreprovisionedSandbox(context.Background(), config.Network{ZoneID: unsafe, VNetID: "csVn01"})
		},
		"create-zone": func() error {
			return mgr.CreateZone(context.Background(), config.Network{Mode: "simple", ZoneID: unsafe}, "")
		},
		"create-vnet": func() error {
			return mgr.CreateVNet(context.Background(), config.Network{Mode: "simple", ZoneID: unsafe, VNetID: "csVn01"})
		},
		"destroy-zone": func() error { return mgr.DestroyZone(context.Background(), unsafe) },
		"destroy-vnet": func() error { return mgr.DestroyVNet(context.Background(), unsafe) },
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			if err := operation(); err == nil || !strings.Contains(err.Error(), "identifier") {
				t.Fatalf("%s accepted unsafe identifier: %v", name, err)
			}
		})
	}
	if requests != 0 {
		t.Fatalf("unsafe SDN identifiers made %d API request(s)", requests)
	}
}

func TestCreateVNet_RejectsGateway(t *testing.T) {
	mgr := NewManager(nil)
	err := mgr.CreateVNet(context.Background(), config.Network{
		Mode:    "simple",
		ZoneID:  "csZone",
		VNetID:  "csVnet",
		Gateway: "10.100.0.1",
	})
	if err == nil {
		t.Fatal("expected gateway configuration to be rejected")
	}
}

func TestCreateSubnet_FailsWhenSubnetRegistrationFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/cluster/sdn/vnets/csVnet/subnets" {
			http.Error(w, "IPAM unavailable", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
	}))
	defer server.Close()

	err := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL})).CreateSubnet(context.Background(), config.Network{
		Mode: "simple", ZoneID: "csZone", VNetID: "csVnet", IPRange: "10.100.0.0/24",
	})
	if err == nil || !strings.Contains(err.Error(), "register subnet") {
		t.Fatalf("subnet registration failure = %v, want fatal error", err)
	}
}

// PVE answers a missing zone or VNet with HTTP 500 "sdn zone '<id>' does
// not exist", not 404 (lab, init on 05aa019). Teardown of an object that is
// already gone succeeds; a 500 about anything else still fails.
func TestDestroyAcceptsPVEsMissingObjectAnswer(t *testing.T) {
	for _, tc := range []struct {
		message string
		wantErr bool
	}{
		{"sdn zone 'csSb01' does not exist", false},
		{"sdn vnet 'csVn01' does not exist", false},
		{"sdn zone 'otherZone' does not exist", true},
		{"cfs-lock 'file-sdn_cfg' error: got lock request timeout", true},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// The ownership reads see the run's VNet, its deletion pending,
			// in the run's zone; the deletions then meet tc.message.
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/sdn/vnets" && r.URL.Query().Get("pending") == "1":
				_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"vnet":"csVn01","zone":"csSb01","alias":"certistack run-a","state":"deleted"}]`)})
				return
			case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/sdn/vnets":
				_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
				return
			case r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/sdn/zones":
				_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"zone":"csSb01"}]`)})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": tc.message})
		}))
		mgr := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
		mgr.SetOwnerMarker("certistack run-a")
		zoneErr := mgr.DestroyZone(context.Background(), "csSb01")
		vnetErr := mgr.DestroyVNet(context.Background(), "csVn01")
		server.Close()
		switch {
		case strings.Contains(tc.message, "csSb01") && zoneErr != nil:
			t.Errorf("%q: DestroyZone = %v, want the zone already gone", tc.message, zoneErr)
		case strings.Contains(tc.message, "csVn01") && vnetErr != nil:
			t.Errorf("%q: DestroyVNet = %v, want the VNet already gone", tc.message, vnetErr)
		case tc.wantErr && (zoneErr == nil || vnetErr == nil):
			t.Errorf("%q: DestroyZone = %v, DestroyVNet = %v; want both to fail", tc.message, zoneErr, vnetErr)
		}
	}
}

func TestUsedIDs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := map[string]string{
			"/api2/json/cluster/sdn/zones": `[{"zone":"csLab70","type":"simple"},{"zone":"csZone1"}]`,
			"/api2/json/cluster/sdn/vnets": `[{"vnet":"csVn70","zone":"csLab70"}]`,
		}[r.URL.Path]
		if data == "" {
			t.Errorf("unexpected read %s", r.URL.Path)
			data = "[]"
		}
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(data)})
	}))
	defer server.Close()
	used, err := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL})).UsedIDs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(used) != 3 || !used["cslab70"] || !used["cszone1"] || !used["csvn70"] {
		t.Fatalf("used = %v", used)
	}
}

// Plan's view after recovery: an unfinished run's zone and VNet, which
// recovery deletes first, are no collision; anything else still is.
func TestEnsureSandboxAvailableAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data := map[string]string{
			"/api2/json/cluster/sdn/zones": `[{"zone":"csSb01"}]`,
			"/api2/json/cluster/sdn/vnets": `[{"vnet":"csVn01","zone":"csSb01"}]`,
		}[r.URL.Path]
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(data)})
	}))
	defer server.Close()
	mgr := NewManager(pve.NewClient(pve.Config{BaseURL: server.URL}))
	netCfg := config.Network{ZoneID: "csSb01", VNetID: "csVn01"}
	gone := func(id string) bool { return id == "csSb01" || id == "csVn01" }
	if err := mgr.EnsureSandboxAvailableAfter(context.Background(), netCfg, gone); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	onlyZone := func(id string) bool { return id == "csSb01" }
	var collision *OwnershipCollisionError
	if err := mgr.EnsureSandboxAvailableAfter(context.Background(), netCfg, onlyZone); !errors.As(err, &collision) || collision.ID != "csVn01" {
		t.Fatalf("VNet not recovered: %v", err)
	}
}
