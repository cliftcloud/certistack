// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/guestnet"
	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
	"github.com/cliftcloud/certistack/pkg/admission"
	"github.com/cliftcloud/certistack/pkg/cleanup"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/probe/qga"
	"github.com/cliftcloud/certistack/pkg/probe/screendump"
	"github.com/cliftcloud/certistack/pkg/pve"
)

type fakeHostAddressManager struct {
	added                []string
	removed              []string
	containmentRemoved   []string
	onAdd                func()
	onRemove             func()
	addErr               error
	removeContainmentErr error
	removeErr            error
	identifyErr          error
	// taken and takenErr are what HostAddressTaken reports.
	taken    string
	takenErr error
	// bridges records SettleBridge and DisableForwarding calls in order.
	bridges []string
}

func (f *fakeHostAddressManager) SettleBridge(_ context.Context, bridge string, present bool, _ time.Duration) error {
	f.bridges = append(f.bridges, fmt.Sprintf("settle %s present=%v", bridge, present))
	return nil
}

// Identify answers as a kernel that has installed the address: interface index
// 7 and table handle 11, unless identifyErr says the read failed.
func (f *fakeHostAddressManager) Identify(context.Context, string, string) (int, uint64, error) {
	if f.identifyErr != nil {
		return 0, 0, f.identifyErr
	}
	return 7, 11, nil
}

func (f *fakeHostAddressManager) DisableForwarding(_ context.Context, bridge string) error {
	f.bridges = append(f.bridges, "no-forwarding "+bridge)
	return nil
}

func (f *fakeHostAddressManager) DisableForwardingOf(_ context.Context, bridge string, families []string) error {
	f.bridges = append(f.bridges, "no-forwarding-of "+bridge+" "+strings.Join(families, ","))
	return nil
}

// InspectHostAddress answers as a healthy bridge (index 7, as Identify says):
// the address guard finds nothing to restore. It reads no field the run writes,
// since the guard calls it from its own goroutine. addrguard_test.go has the
// fake that breaks things.
func (f *fakeHostAddressManager) InspectHostAddress(context.Context, string, string) (sysutil.HostAddressState, error) {
	return sysutil.HostAddressState{BridgePresent: true, Ifindex: 7, AddressPresent: true, TablePresent: true, TableHandle: 11}, nil
}

// HostAddressTaken answers as a clean host unless taken or takenErr say otherwise.
func (f *fakeHostAddressManager) HostAddressTaken(context.Context, string, string) (string, error) {
	return f.taken, f.takenErr
}

func (f *fakeHostAddressManager) RestoreAddress(context.Context, string, string) error { return nil }

func (f *fakeHostAddressManager) RestoreContainment(context.Context, string, string) error {
	return nil
}

func TestNormalizeNetworkDiagnostic(t *testing.T) {
	if got := normalizeNetworkDiagnostic("\n  interface output\n"); got != "interface output" {
		t.Fatalf("normalized diagnostic = %q", got)
	}
	tooLarge := strings.Repeat("x", (16<<10)+1)
	if got := normalizeNetworkDiagnostic(tooLarge); !strings.HasSuffix(got, "\n[truncated]") || len(got) != (16<<10)+len("\n[truncated]") {
		t.Fatalf("large diagnostic was not capped: length=%d suffix=%q", len(got), got[len(got)-12:])
	}
}

func TestFormatGuestInterfaces(t *testing.T) {
	interfaces := []qga.NetworkInterface{{Name: "eth0", HardwareAddress: "aa:bb:cc:dd:ee:ff"}}
	interfaces[0].IPAddresses = append(interfaces[0].IPAddresses, struct {
		IPAddress string `json:"ip-address"`
		Prefix    int    `json:"prefix"`
	}{IPAddress: "10.70.0.15", Prefix: 24})
	if got := formatGuestInterfaces(interfaces); got != "[interfaces via QGA]\neth0 aa:bb:cc:dd:ee:ff 10.70.0.15/24" {
		t.Fatalf("formatted interfaces = %q", got)
	}
}

func TestRecoveryAddressDiagnosis(t *testing.T) {
	nic := func(mac string, addrs ...string) qga.NetworkInterface {
		iface := qga.NetworkInterface{Name: "enp6s18", HardwareAddress: mac}
		for _, a := range addrs {
			iface.IPAddresses = append(iface.IPAddresses, struct {
				IPAddress string `json:"ip-address"`
				Prefix    int    `json:"prefix"`
			}{IPAddress: a, Prefix: 24})
		}
		return iface
	}
	// Template 8104: the guest kept its own 10.60.70.239 instead of 10.60.70.46.
	got := recoveryAddressDiagnosis([]qga.NetworkInterface{nic("02:5a:3c:10:20:81", "10.60.70.239", "fe80::1")}, "02:5A:3C:10:20:81", "10.60.70.46")
	if !strings.Contains(got, "did not take effect") || !strings.Contains(got, "10.60.70.239/24") || !strings.Contains(got, "10.60.70.46") {
		t.Fatalf("diagnosis = %q", got)
	}
	if got := recoveryAddressDiagnosis([]qga.NetworkInterface{nic("02:5a:3c:10:20:81", "10.60.70.46")}, "02:5A:3C:10:20:81", "10.60.70.46"); got != "" {
		t.Fatalf("applied recovery address must not be diagnosed: %q", got)
	}
	if got := recoveryAddressDiagnosis([]qga.NetworkInterface{nic("aa:bb:cc:dd:ee:ff", "10.60.70.239")}, "02:5A:3C:10:20:81", "10.60.70.46"); got != "" {
		t.Fatalf("another NIC must not be diagnosed: %q", got)
	}
	if got := recoveryAddressDiagnosis([]qga.NetworkInterface{nic("02:5a:3c:10:20:81")}, "02:5A:3C:10:20:81", "10.60.70.46"); !strings.Contains(got, "no IPv4 address") {
		t.Fatalf("missing-address diagnosis = %q", got)
	}
}

func TestBootTimeoutDuration(t *testing.T) {
	if got := bootTimeoutDuration(0); got != defaultBootTimeout {
		t.Fatalf("unset boot timeout = %v, want %v", got, defaultBootTimeout)
	}
	if got := bootTimeoutDuration(300); got != 300*time.Second {
		t.Fatalf("configured boot timeout = %v, want 5m", got)
	}
}

func TestShouldReadNetworkDiagnosticOnlyForFailedVMWithoutLiveEvidence(t *testing.T) {
	orch := &Orchestrator{
		networkDiagnostics:         make(map[int]string),
		networkDiagnosticRequested: make(map[int]bool),
		networkDiagnosticPartial:   make(map[int]bool),
	}
	if orch.shouldReadNetworkDiagnostic(42) {
		t.Fatal("passing VM should not read an optional COW diagnostic during cleanup")
	}
	orch.networkDiagnosticRequested[42] = true
	if !orch.shouldReadNetworkDiagnostic(42) {
		t.Fatal("failed VM without live diagnostics should read the COW fallback")
	}
	orch.networkDiagnostics[42] = "live QGA diagnostic"
	if orch.shouldReadNetworkDiagnostic(42) {
		t.Fatal("live diagnostic must suppress the slower COW fallback")
	}
	// EL7's agent allows no guest-exec (7396): the live read has interfaces
	// only, so the overlay's boot-time listeners are still read.
	orch.networkDiagnosticPartial[42] = true
	if !orch.shouldReadNetworkDiagnostic(42) {
		t.Fatal("a live read without guest-exec must still read the COW fallback")
	}
}

func TestFirewallPorts(t *testing.T) {
	ports := firewallPorts([]config.Probe{{Type: "http", Port: 443}, {Type: "dns", Port: 53}, {Type: "tcp", Port: 443}})
	if len(ports) != 3 || ports[0] != (guestnet.FirewallPort{Protocol: "tcp", Port: 443}) {
		t.Fatalf("firewall ports = %#v", ports)
	}
	windows := firewallPorts([]config.Probe{{Type: "mssql", Port: 1433}, {Type: "smb", Port: 445}})
	if len(windows) != 2 || windows[0] != (guestnet.FirewallPort{Protocol: "tcp", Port: 1433}) || windows[1] != (guestnet.FirewallPort{Protocol: "tcp", Port: 445}) {
		t.Fatalf("protocol probe ports = %#v, want tcp/1433 and tcp/445", windows)
	}
	for _, probeType := range []string{"mssql", "smb", "ldap", "dns"} {
		if origin := probeOrigin(probeType); origin != "worker_host" {
			t.Errorf("probeOrigin(%s) = %s, want worker_host", probeType, origin)
		}
	}
}

func TestAnnotateReachableTargetRejection(t *testing.T) {
	result := probe.Result{Passed: false, Error: "dial tcp: connect: connection refused"}
	annotateReachableTargetRejection(&result, nil)
	if !strings.Contains(result.Detail, "actively rejected") || !strings.Contains(result.Detail, "recovery addressing is reachable") || strings.Contains(result.Detail, "attach_all_nics") {
		t.Fatalf("connection-refused diagnostic = %q", result.Detail)
	}

	// Nginx also listened on net1's address, which the sandbox VM
	// lacked, and exited, taking port 80 with it.
	multiNIC := probe.Result{Passed: false, Error: "dial tcp 10.60.71.205:80: connect: connection refused"}
	annotateReachableTargetRejection(&multiNIC, []string{"net1"})
	if !strings.Contains(multiNIC.Detail, "lacks its source NIC(s) net1") || !strings.Contains(multiNIC.Detail, "network_recovery.attach_all_nics") {
		t.Fatalf("omitted-NIC diagnostic = %q", multiNIC.Detail)
	}

	nonRefusal := probe.Result{Passed: false, Error: "context deadline exceeded"}
	annotateReachableTargetRejection(&nonRefusal, []string{"net1"})
	if nonRefusal.Detail != "" {
		t.Fatalf("timeout must not be mislabeled as a reachable target rejection: %q", nonRefusal.Detail)
	}
}

func TestVMRecordFailureAndInterruptionEvidence(t *testing.T) {
	failed := &probe.VMValidationRecord{VMID: 42, AllPassed: true}
	markVMRecordFailed(failed, errors.New("QMP connection to VM 9001 failed"))
	if failed.AllPassed || failed.VerificationStatus != "failed" || len(failed.ProbeResults) != 1 {
		t.Fatalf("failed record did not preserve explicit bootstrap evidence: %+v", failed)
	}
	if failed.ProbeResults[0].Type != "recovery" || failed.ProbeResults[0].Passed {
		t.Fatalf("failed record recovery evidence = %+v", failed.ProbeResults[0])
	}

	incomplete := &probe.VMValidationRecord{VMID: 43, AllPassed: true, VerificationStatus: "booted"}
	markVMRecordIncomplete(incomplete, context.Canceled)
	if incomplete.AllPassed || incomplete.VerificationStatus != "incomplete" || len(incomplete.ProbeResults) != 1 {
		t.Fatalf("interrupted record did not preserve incomplete verification evidence: %+v", incomplete)
	}
	if incomplete.ProbeResults[0].Type != "validation" || incomplete.ProbeResults[0].Passed || !strings.Contains(incomplete.ProbeResults[0].Error, "interrupted before probes") {
		t.Fatalf("interrupted record evidence = %+v", incomplete.ProbeResults[0])
	}
}

func TestRecoveryMemoryReservationCountsEveryResidentTier(t *testing.T) {
	plan := &config.Plan{Tiers: []config.Tier{
		{Level: 1, VMs: []config.VM{
			{HardwareOverrides: config.HardwareOverrides{MemoryMB: 4096}},
			{},
		}},
		{Level: 2, VMs: []config.VM{{HardwareOverrides: config.HardwareOverrides{MemoryMB: 4096}}}},
	}}
	memoryMB, count, tier, err := admission.RecoveryMemoryReservation(plan)
	if err != nil {
		t.Fatal(err)
	}
	// Tier 1 stays running while tier 2 boots:
	// (4096 + default 2048 + 2x256) + (4096 + 256) = 11008 MiB.
	if memoryMB != 11008 || count != 3 || tier != 2 {
		t.Fatalf("reservation = %d MiB / %d VM(s) / tier %d, want 11008 / 3 / 2", memoryMB, count, tier)
	}
}

func (m *fakeHostAddressManager) Add(_ context.Context, iface, cidr string) error {
	m.added = append(m.added, iface+"="+cidr)
	if m.onAdd != nil {
		m.onAdd()
	}
	return m.addErr
}

func (m *fakeHostAddressManager) RemoveContainment(_ context.Context, iface, cidr string) error {
	m.containmentRemoved = append(m.containmentRemoved, iface+"="+cidr)
	return m.removeContainmentErr
}

func (m *fakeHostAddressManager) Remove(_ context.Context, iface, cidr string) error {
	m.removed = append(m.removed, iface+"="+cidr)
	if m.onRemove != nil {
		m.onRemove()
	}
	return m.removeErr
}

func TestOrchestrator_AdmissionDenied(t *testing.T) {
	plan := &config.Plan{
		Version: "v1",
		PlanID:  "test-admission-denied",
		Name:    "Admission Test",
		AdmissionControl: config.AdmissionControl{
			MaxHostRAMPercent:     0.00001, // Force deny
			MaxHostIOWaitPercent:  100.0,
			DeferRetryIntervalSec: 1,
			MaxDeferRetries:       1,
		},
		Network: config.Network{
			Mode:    "simple",
			ZoneID:  "csSb01",
			VNetID:  "csVn01",
			IPRange: "10.100.0.0/24",
			ProbeIP: "10.100.0.1",
		},
	}

	pveClient := pve.NewClient(pve.Config{BaseURL: "http://localhost:1"})
	pbsClient := pbs.New(pbs.Config{})

	orch := New(plan, Options{ScratchDir: t.TempDir()}, pbsClient, pveClient)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res, err := orch.Run(ctx)
	if err == nil {
		t.Fatal("expected orchestrator to fail on admission, got nil")
	}
	if res.AllPassed {
		t.Errorf("expected res.AllPassed to be false, got true")
	}
	// Nothing was restored, so there is no recovery time; the phases keep where
	// the time went.
	if len(res.VMRecords) != 0 || res.RTO != 0 || res.PhaseTimings == nil || res.PhaseTimings.TotalRTOSec != 0 {
		t.Fatalf("a run refused before any restore records a recovery time: rto=%v timings=%+v", res.RTO, res.PhaseTimings)
	}
}

func TestOrchestrator_NetworkSetupAndTeardown(t *testing.T) {
	var requestedPaths []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodGet && (r.URL.Path == "/api2/json/cluster/sdn/zones" || r.URL.Path == "/api2/json/cluster/sdn/vnets") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
			return
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/sdn" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"UPID:pve1:1:1:1:1:1:"`)})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/pve1/tasks/UPID:pve1:1:1:1:1:1:/status" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{"status":"stopped","exitstatus":"OK"}`)})
			return
		}
		resp := pve.APIResponse{
			Data: json.RawMessage(`"OK"`),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	plan := &config.Plan{
		Version: "v1",
		PlanID:  "test-network-setup",
		Name:    "Network Setup Test",
		AdmissionControl: config.AdmissionControl{
			MaxHostRAMPercent:     100.0, // Pass
			MaxHostIOWaitPercent:  100.0,
			DeferRetryIntervalSec: 1,
			MaxDeferRetries:       1,
		},
		Network: config.Network{
			Mode:    "simple",
			ZoneID:  "csSb01",
			VNetID:  "csVn01",
			IPRange: "10.100.0.0/24",
			ProbeIP: "10.100.0.1",
		},
		Tiers: []config.Tier{}, // No VMs in this test
	}

	pveClient := pve.NewClient(pve.Config{BaseURL: server.URL})
	pbsClient := pbs.New(pbs.Config{})

	stateDir := t.TempDir()
	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbsClient, pveClient)
	hostAddresses := &fakeHostAddressManager{}
	orch.hostAddresses = hostAddresses
	ctx := context.Background()

	res, err := orch.Run(ctx)
	if err != nil {
		t.Fatalf("expected plan with empty tiers to succeed, got %v", err)
	}
	if !res.AllPassed {
		t.Errorf("expected AllPassed to be true, got false")
	}
	if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned || !res.TeardownEvidence.SDNClusterReloaded ||
		res.TeardownEvidence.SDNZoneRemoved != "csSb01" || res.TeardownEvidence.SDNVNetRemoved != "csVn01" {
		t.Fatalf("unexpected teardown evidence: %+v", res.TeardownEvidence)
	}

	// Verify SDN setup and cleanup occurred
	var hasCreateZone, hasCreateVNet, hasCreateSubnet, hasDeleteZone, hasDeleteVNet bool
	reloadCount := 0
	for _, p := range requestedPaths {
		if p == "POST /api2/json/cluster/sdn/zones" {
			hasCreateZone = true
		}
		if p == "POST /api2/json/cluster/sdn/vnets" {
			hasCreateVNet = true
		}
		if p == "POST /api2/json/cluster/sdn/vnets/csVn01/subnets" {
			hasCreateSubnet = true
		}
		if p == "DELETE /api2/json/cluster/sdn/zones/csSb01" {
			hasDeleteZone = true
		}
		if p == "DELETE /api2/json/cluster/sdn/vnets/csVn01" {
			hasDeleteVNet = true
		}
		if p == "PUT /api2/json/cluster/sdn" {
			reloadCount++
		}
	}

	if !hasCreateZone || !hasCreateVNet || !hasCreateSubnet {
		t.Errorf("expected SDN zone, VNet, and subnet creation calls, got: %v", requestedPaths)
	}
	if !hasDeleteZone || !hasDeleteVNet {
		t.Errorf("expected LIFO cleanup to delete SDN zone and vnet, got: %v", requestedPaths)
	}
	if reloadCount != 2 {
		t.Errorf("expected one SDN reload to apply setup and one after teardown, got %d: %v", reloadCount, requestedPaths)
	}
	if len(hostAddresses.added) != 1 || len(hostAddresses.removed) != 1 ||
		hostAddresses.added[0] != "csVn01=10.100.0.1/24" || hostAddresses.removed[0] != hostAddresses.added[0] {
		t.Errorf("unexpected host probe address lifecycle: added=%v removed=%v", hostAddresses.added, hostAddresses.removed)
	}
	record, err := journal.Load(stateDir + "/active.json")
	if err != nil {
		t.Fatalf("load completed run journal: %v", err)
	}
	if record.Phase != "cleaned" || len(record.CleanupErrors) != 0 {
		t.Fatalf("completed run journal = phase %q cleanup_errors=%v; want clean terminal state", record.Phase, record.CleanupErrors)
	}
}

// A journal write that fails after the host probe address and its nft
// containment table are added does not leave both allocated: teardown still
// removes them.
func TestOrchestrator_JournalFailureAfterHostAddressStillRemovesIt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && (r.URL.Path == "/api2/json/cluster/sdn/zones" || r.URL.Path == "/api2/json/cluster/sdn/vnets") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/sdn" {
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"UPID:pve1:1:1:1:1:1:"`)})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/pve1/tasks/UPID:pve1:1:1:1:1:1:/status" {
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{"status":"stopped","exitstatus":"OK"}`)})
			return
		}
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
	}))
	defer server.Close()

	plan := &config.Plan{
		Version: "v1",
		PlanID:  "test-journal-failure",
		Name:    "Journal Failure Test",
		AdmissionControl: config.AdmissionControl{
			MaxHostRAMPercent:     100.0,
			MaxHostIOWaitPercent:  100.0,
			DeferRetryIntervalSec: 1,
			MaxDeferRetries:       1,
		},
		Network: config.Network{
			Mode:    "simple",
			ZoneID:  "csSb01",
			VNetID:  "csVn01",
			IPRange: "10.100.0.0/24",
			ProbeIP: "10.100.0.1",
		},
	}

	stateDir := t.TempDir()
	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	journalPath := filepath.Join(stateDir, "active.json")
	hostAddresses := &fakeHostAddressManager{onAdd: func() {
		// Every journal write from here on fails: a directory now occupies
		// the journal path, so the atomic rename cannot replace it.
		if err := os.Remove(journalPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(journalPath, 0700); err != nil {
			t.Fatal(err)
		}
	}}
	orch.hostAddresses = hostAddresses

	res, err := orch.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "persist recovery journal") {
		t.Fatalf("Run error = %v, want the journal write failure", err)
	}
	if res.AllPassed {
		t.Fatal("run with a failed journal write passed")
	}
	if len(hostAddresses.added) != 1 || len(hostAddresses.removed) != 1 || hostAddresses.removed[0] != hostAddresses.added[0] {
		t.Fatalf("host probe address lifecycle after journal failure: added=%v removed=%v", hostAddresses.added, hostAddresses.removed)
	}
}

// The teardown's own journal write is part of its evidence: when it cannot be
// made, the run has cleaned the host but cannot say so durably, and the signed
// evidence must not claim all_cleaned. The journal is broken when the run asks PVE
// to confirm that its zone and VNet are gone, after the last removal, so that the
// only write left is the one that marks the run cleaned.
func TestOrchestrator_TeardownJournalFailureIsNotAllCleaned(t *testing.T) {
	stateDir := t.TempDir()
	journalPath := filepath.Join(stateDir, "active.json")
	broken, zoneDeleted, applied := false, false, false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/api2/json/cluster/sdn/zones" || r.URL.Path == "/api2/json/cluster/sdn/vnets"):
			if applied && !broken {
				broken = true
				if err := os.Remove(journalPath); err != nil {
					t.Error(err)
				}
				if err := os.Mkdir(journalPath, 0700); err != nil {
					t.Error(err)
				}
			}
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/sdn":
			applied = applied || zoneDeleted
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"UPID:pve1:1:1:1:1:1:"`)})
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/pve1/tasks/UPID:pve1:1:1:1:1:1:/status":
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{"status":"stopped","exitstatus":"OK"}`)})
		default:
			if r.Method == http.MethodDelete && strings.HasSuffix(r.URL.Path, "/zones/csSb01") {
				zoneDeleted = true
			}
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
		}
	}))
	t.Cleanup(server.Close)
	orch := New(networkOnlyPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	hostAddresses := &fakeHostAddressManager{}
	orch.hostAddresses = hostAddresses

	res, err := orch.Run(context.Background())
	if !broken {
		t.Fatalf("the run never verified the SDN teardown (err %v); the journal was not broken", err)
	}
	if res == nil || res.TeardownEvidence == nil {
		t.Fatalf("result = %+v, err = %v; want the teardown evidence", res, err)
	}
	evidence := res.TeardownEvidence
	if evidence.AllCleaned || evidence.OrphanSweepClean {
		t.Fatalf("evidence = %+v; a teardown that could not record its end must not claim all_cleaned", evidence)
	}
	if res.AllPassed || res.Error == nil {
		t.Fatalf("a run whose teardown could not be recorded passed: AllPassed=%v Error=%v", res.AllPassed, res.Error)
	}
	if !strings.Contains(strings.Join(evidence.CleanupErrors, "\n"), "journal") {
		t.Fatalf("cleanup errors = %v, want the journal failure named", evidence.CleanupErrors)
	}
}

func sdnSetupTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && (r.URL.Path == "/api2/json/cluster/sdn/zones" || r.URL.Path == "/api2/json/cluster/sdn/vnets") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/sdn" {
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"UPID:pve1:1:1:1:1:1:"`)})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/pve1/tasks/UPID:pve1:1:1:1:1:1:/status" {
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{"status":"stopped","exitstatus":"OK"}`)})
			return
		}
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
	}))
	t.Cleanup(server.Close)
	return server
}

func networkOnlyPlan() *config.Plan {
	return &config.Plan{
		Version: "v1",
		PlanID:  "test-host-address-rollback",
		Name:    "Host Address Rollback Test",
		AdmissionControl: config.AdmissionControl{
			MaxHostRAMPercent:     100.0,
			MaxHostIOWaitPercent:  100.0,
			DeferRetryIntervalSec: 1,
			MaxDeferRetries:       1,
		},
		Network: config.Network{
			Mode:    "simple",
			ZoneID:  "csSb01",
			VNetID:  "csVn01",
			IPRange: "10.100.0.0/24",
			ProbeIP: "10.100.0.1",
		},
	}
}

// A failed host address assignment whose rollback also failed may leave the
// nft containment table installed. What the rollback left must be journaled
// and removed, and the evidence must stay unclean (not all_cleaned, not a
// cleaned journal) until that removal succeeds.
func TestOrchestrator_FailedHostAddressRollbackIsOwnedUntilRemoved(t *testing.T) {
	runsInBoot(t, testHostBoot, nil) // the record names the boot of its identities
	addFailed := errors.New("add address 10.100.0.1/24 to interface csVn01: exit status 2")
	containmentLeft := errors.Join(addFailed, fmt.Errorf("%w: roll back containment on csVn01: exit status 1", sysutil.ErrContainmentLeft))
	addressLeft := errors.Join(addFailed, fmt.Errorf("%w: roll back 10.100.0.1/24 on csVn01: exit status 2", sysutil.ErrAddressLeft))
	for name, tc := range map[string]struct {
		addErr               error
		removeContainmentErr error
		wantContainment      int
		wantAddress          int
		wantClean            bool
		wantJournalEntry     *journal.TrackedHostAddress
	}{
		"nothing left": {addErr: addFailed, wantClean: true},
		// A record stays, with the kernel identities the run read when it
		// installed the address, while its removal has not succeeded; once it
		// has, the record is dropped, so a journal kept for another resource's
		// failure cannot later remove a replacement.
		"table left, removal fails":    {addErr: containmentLeft, removeContainmentErr: errors.New("nft: permission denied"), wantContainment: 1, wantJournalEntry: &journal.TrackedHostAddress{Interface: "csVn01", CIDR: "10.100.0.1/24", ContainmentOnly: true, IfIndex: 7, TableHandle: 11, BootID: testHostBoot}},
		"table left, removal succeeds": {addErr: containmentLeft, wantContainment: 1, wantClean: true},
		"address left":                 {addErr: addressLeft, wantAddress: 1, wantClean: true},
	} {
		server := sdnSetupTestServer(t)
		stateDir := t.TempDir()
		orch := New(networkOnlyPlan(), Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
		hostAddresses := &fakeHostAddressManager{addErr: tc.addErr, removeContainmentErr: tc.removeContainmentErr}
		orch.hostAddresses = hostAddresses

		res, err := orch.Run(context.Background())
		if err == nil || res.AllPassed {
			t.Fatalf("%s: run with a failed host address passed (err %v)", name, err)
		}
		if len(hostAddresses.containmentRemoved) != tc.wantContainment || len(hostAddresses.removed) != tc.wantAddress {
			t.Errorf("%s: containment removals %v, address removals %v; want %d and %d", name, hostAddresses.containmentRemoved, hostAddresses.removed, tc.wantContainment, tc.wantAddress)
		}
		if res.TeardownEvidence == nil || res.TeardownEvidence.AllCleaned != tc.wantClean {
			t.Errorf("%s: teardown evidence %+v, want all_cleaned=%v", name, res.TeardownEvidence, tc.wantClean)
		}
		record, loadErr := journal.Load(filepath.Join(stateDir, "active.json"))
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if (record.Phase == "cleaned") != tc.wantClean {
			t.Errorf("%s: journal phase %q, want cleaned=%v", name, record.Phase, tc.wantClean)
		}
		if record.AllocationPending != "" {
			t.Errorf("%s: allocation still pending: %q", name, record.AllocationPending)
		}
		if tc.wantJournalEntry == nil {
			if len(record.HostAddresses) != 0 {
				t.Errorf("%s: journal records host resources %+v, want none", name, record.HostAddresses)
			}
		} else if len(record.HostAddresses) != 1 || record.HostAddresses[0] != *tc.wantJournalEntry {
			t.Errorf("%s: journal host resources %+v, want %+v", name, record.HostAddresses, *tc.wantJournalEntry)
		}
	}
}

// A probe target that is one of the worker's own addresses is answered by
// the host even from a socket bound to the sandbox interface, so the run must
// stop before it creates anything.
func TestOrchestrator_RefusesWireProbeTargetOnWorkerHost(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
	}))
	defer server.Close()
	plan := networkOnlyPlan()
	plan.Tiers = []config.Tier{{Level: 1, VMs: []config.VM{{
		VMID: 9100, Name: "web",
		Probes: []config.Probe{{Type: "tcp", TargetIP: "127.0.0.1", Port: 443, TimeoutSec: 1, Description: "worker listener"}},
	}}}}
	hostAddresses := &fakeHostAddressManager{}
	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	orch.hostAddresses = hostAddresses

	res, err := orch.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "address of the worker host") || res.AllPassed {
		t.Fatalf("Run = passed %v, err %v; want a refusal of the worker-host target", res.AllPassed, err)
	}
	if requests != 0 || len(hostAddresses.added) != 0 {
		t.Fatalf("run created resources before refusing: %d PVE request(s), host addresses %v", requests, hostAddresses.added)
	}
}

func TestOrchestrator_SubnetSetupFailureStillTearsDownTrackedParents(t *testing.T) {
	var requestedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodGet && (r.URL.Path == "/api2/json/cluster/sdn/zones" || r.URL.Path == "/api2/json/cluster/sdn/vnets") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[]`)})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api2/json/cluster/sdn/vnets/csVnSubnetFailure/subnets" {
			http.Error(w, "IPAM unavailable", http.StatusInternalServerError)
			return
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/sdn" {
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"UPID:pve1:1:1:1:1:1:"`)})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/pve1/tasks/UPID:pve1:1:1:1:1:1:/status" {
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{"status":"stopped","exitstatus":"OK"}`)})
			return
		}
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`"OK"`)})
	}))
	defer server.Close()

	plan := &config.Plan{
		Version: "v1", PlanID: "test-subnet-setup-failure", Name: "Subnet Setup Failure Test",
		AdmissionControl: config.AdmissionControl{MaxHostRAMPercent: 100, MaxHostIOWaitPercent: 100, DeferRetryIntervalSec: 1, MaxDeferRetries: 1},
		Network:          config.Network{Mode: "simple", ZoneID: "csSbSubnetFailure", VNetID: "csVnSubnetFailure", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"},
	}
	stateDir := t.TempDir()
	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	hostAddresses := &fakeHostAddressManager{}
	orch.hostAddresses = hostAddresses

	res, err := orch.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "register subnet") {
		t.Fatalf("subnet setup error = %v, want failed subnet registration", err)
	}
	if res.AllPassed || res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned ||
		res.TeardownEvidence.SDNVNetRemoved != "csVnSubnetFailure" || res.TeardownEvidence.SDNZoneRemoved != "csSbSubnetFailure" || !res.TeardownEvidence.SDNClusterReloaded {
		t.Fatalf("subnet setup failure did not retain clean parent teardown evidence: %+v", res.TeardownEvidence)
	}
	if len(hostAddresses.added) != 0 || len(hostAddresses.removed) != 0 {
		t.Fatalf("host probe address was touched after subnet setup failure: added=%v removed=%v", hostAddresses.added, hostAddresses.removed)
	}
	paths := strings.Join(requestedPaths, "\n")
	for _, expected := range []string{
		"POST /api2/json/cluster/sdn/vnets/csVnSubnetFailure/subnets",
		"DELETE /api2/json/cluster/sdn/vnets/csVnSubnetFailure",
		"DELETE /api2/json/cluster/sdn/zones/csSbSubnetFailure",
		"PUT /api2/json/cluster/sdn",
	} {
		if !strings.Contains(paths, expected) {
			t.Errorf("expected cleanup request %q, got:\n%s", expected, paths)
		}
	}
	record, loadErr := journal.Load(stateDir + "/active.json")
	if loadErr != nil || record.Phase != "cleaned" || record.AllocationPending != "" {
		t.Fatalf("terminal journal after subnet setup failure = %+v, load error = %v", record, loadErr)
	}
}

func TestOrchestrator_UsesValidatedPreprovisionedSandboxWithoutSDNMutation(t *testing.T) {
	var requestedPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet {
			http.Error(w, "preprovisioned sandbox must not be mutated", http.StatusInternalServerError)
			return
		}
		var data json.RawMessage
		switch r.URL.Path {
		case "/api2/json/cluster/sdn/zones":
			data = json.RawMessage(`[{"zone":"csSbExternal","type":"simple","ipam":"pve"}]`)
		case "/api2/json/cluster/sdn/vnets":
			data = json.RawMessage(`[{"vnet":"csVnExternal","zone":"csSbExternal"}]`)
		case "/api2/json/cluster/sdn/vnets/csVnExternal/subnets":
			data = json.RawMessage(`[{"cidr":"10.100.0.0/24","vnet":"csVnExternal"}]`)
		case "/api2/json/cluster/resources": // no other guest on the sandbox VNet
			data = json.RawMessage(`[]`)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	defer server.Close()

	plan := &config.Plan{
		Version: "v1",
		PlanID:  "test-preprovisioned-sandbox",
		Name:    "Preprovisioned Sandbox Test",
		AdmissionControl: config.AdmissionControl{
			MaxHostRAMPercent: 100.0, MaxHostIOWaitPercent: 100.0, DeferRetryIntervalSec: 1, MaxDeferRetries: 1,
		},
		Network: config.Network{
			Mode: "simple", Lifecycle: "preprovisioned", ZoneID: "csSbExternal", VNetID: "csVnExternal",
			IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1",
		},
	}
	stateDir := t.TempDir()
	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	orch.bridgePortsFn = noForeignBridgePorts
	hostAddresses := &fakeHostAddressManager{}
	orch.hostAddresses = hostAddresses

	res, err := orch.Run(context.Background())
	if err != nil || !res.AllPassed {
		t.Fatalf("preprovisioned run = result %+v, error %v", res, err)
	}
	if got, want := strings.Join(requestedPaths, "\n"), "GET /api2/json/cluster/sdn/zones\nGET /api2/json/cluster/sdn/vnets\nGET /api2/json/cluster/sdn/vnets/csVnExternal/subnets\nGET /api2/json/cluster/resources"; got != want {
		t.Fatalf("preprovisioned sandbox requests:\n%s\nwant:\n%s", got, want)
	}
	if len(hostAddresses.added) != 1 || len(hostAddresses.removed) != 1 || hostAddresses.added[0] != hostAddresses.removed[0] {
		t.Fatalf("host probe address lifecycle = added=%v removed=%v", hostAddresses.added, hostAddresses.removed)
	}
	evidence := res.TeardownEvidence
	if evidence == nil || !evidence.AllCleaned || evidence.SDNClusterReloaded || evidence.SDNProvisioning != "preprovisioned" ||
		evidence.SDNZoneValidated != "csSbExternal" || evidence.SDNVNetValidated != "csVnExternal" ||
		evidence.SDNZoneRemoved != "" || evidence.SDNVNetRemoved != "" {
		t.Fatalf("unexpected preprovisioned teardown evidence: %+v", evidence)
	}
	record, loadErr := journal.Load(stateDir + "/active.json")
	if loadErr != nil {
		t.Fatalf("load preprovisioned run journal: %v", loadErr)
	}
	if record.Phase != "cleaned" || len(record.SDNZones) != 0 || len(record.SDNVNets) != 0 {
		t.Fatalf("preprovisioned sandbox was recorded as CertiStack-owned: %+v", record)
	}
}

func TestOrchestrator_RefusesPreexistingSandboxWithoutClaimingCleanup(t *testing.T) {
	var requestedPaths []string
	mutatingRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.Method+" "+r.URL.Path)
		if r.Method != http.MethodGet {
			mutatingRequests++
			http.Error(w, "sandbox mutation must not occur after ownership collision", http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/api2/json/cluster/sdn/zones" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"zone":"otherZone"},{"zone":"csSbOccupied"}]`)})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	plan := &config.Plan{
		Version: "v1",
		PlanID:  "test-preexisting-sandbox",
		Name:    "Preexisting Sandbox Guard Test",
		AdmissionControl: config.AdmissionControl{
			MaxHostRAMPercent:     100.0,
			MaxHostIOWaitPercent:  100.0,
			DeferRetryIntervalSec: 1,
			MaxDeferRetries:       1,
		},
		Network: config.Network{
			Mode:    "simple",
			ZoneID:  "csSbOccupied",
			VNetID:  "csVnOccupied",
			IPRange: "10.100.0.0/24",
			ProbeIP: "10.100.0.1",
		},
	}
	stateDir := t.TempDir()
	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: stateDir}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))

	res, err := orch.Run(context.Background())
	if err == nil {
		t.Fatal("expected preexisting sandbox ownership check to fail")
	}
	if !strings.Contains(err.Error(), "sandbox ownership check") || !strings.Contains(err.Error(), "does not own or reuse") {
		t.Fatalf("unexpected ownership collision error: %v", err)
	}
	if mutatingRequests != 0 {
		t.Fatalf("ownership collision made %d mutating API request(s): %v", mutatingRequests, requestedPaths)
	}
	if len(requestedPaths) != 1 || requestedPaths[0] != "GET /api2/json/cluster/sdn/zones" {
		t.Fatalf("unexpected ownership check API calls: %v", requestedPaths)
	}
	if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned || res.TeardownEvidence.SDNClusterReloaded ||
		res.TeardownEvidence.SDNZoneRemoved != "" || res.TeardownEvidence.SDNVNetRemoved != "" {
		t.Fatalf("preexisting sandbox must not be represented as owned cleanup evidence: %+v", res.TeardownEvidence)
	}
	record, loadErr := journal.Load(stateDir + "/active.json")
	if loadErr != nil {
		t.Fatalf("load ownership-collision journal: %v", loadErr)
	}
	if record.Phase != "cleaned" || len(record.SDNZones) != 0 || len(record.SDNVNets) != 0 {
		t.Fatalf("ownership-collision journal tracked an unowned resource: %+v", record)
	}
}

func TestRunProbes_HTTPUsesWireProbeWithoutQGA(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	orch := &Orchestrator{}
	results, passed, err := orch.runProbes(context.Background(), config.VM{
		VMID: 9904,
		Probes: []config.Probe{{
			Type:           "http",
			TargetIP:       host,
			Port:           port,
			Path:           "/healthz",
			TLS:            false,
			ExpectedStatus: http.StatusOK,
			TimeoutSec:     2,
			Description:    "host wire health check",
		}},
	})
	if err != nil || !passed {
		t.Fatalf("runProbes = passed=%v, err=%v, results=%+v", passed, err, results)
	}
	if len(results) != 1 || !results[0].Passed {
		t.Fatalf("probe results = %+v, want one passed HTTP result", results)
	}
}

func TestDestroyOwnedVMTreatsDefiniteAbsenceAsClean(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/resources" {
			// A 404 is an absence only when the cluster's list has no such guest.
			_, _ = w.Write([]byte(`{"data":[{"vmid":9001}]}`))
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/node1/qemu/9900/config" {
			t.Errorf("unexpected cleanup request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"data":null,"errors":{"vmid":"does not exist"}}`))
	}))
	defer server.Close()

	orch := &Orchestrator{
		opts:      Options{NodeName: "node1"},
		pveClient: pve.NewClient(pve.Config{BaseURL: server.URL}),
	}
	if err := orch.destroyOwnedVM(9900, "run-test"); err != nil {
		t.Fatalf("already-absent CertiStack VM cleanup failed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("already-absent VM cleanup made %d requests, want the ownership lookup and the cluster list that backs its 404", calls)
	}
}

func TestDestroyOwnedVMRefusesQMFallbackWhenOwnershipChanges(t *testing.T) {
	configCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/nodes/node1/qemu/9901/status/stop" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errors":{"status":"temporary failure"}}`))
			return
		}
		if r.URL.Path != "/api2/json/nodes/node1/qemu/9901/config" {
			t.Errorf("unexpected cleanup request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		configCalls++
		w.Header().Set("Content-Type", "application/json")
		if configCalls == 1 {
			_, _ = w.Write([]byte(`{"data":{"tags":"certistack,run-test","description":"owner=certistack; run_id=run-test"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"tags":"other","description":"owner=other; run_id=other"}}`))
	}))
	defer server.Close()

	var fallbackCalls int
	orch := &Orchestrator{
		opts:      Options{NodeName: "node1"},
		pveClient: pve.NewClient(pve.Config{BaseURL: server.URL}),
		runQMFallbackFn: func(context.Context, []string) ([]byte, error) {
			fallbackCalls++
			return nil, nil
		},
	}
	if err := orch.destroyOwnedVM(9901, "run-test"); err == nil || !strings.Contains(err.Error(), "ownership changed") {
		t.Fatalf("ownership change did not block qm fallback: %v", err)
	}
	if fallbackCalls != 0 {
		t.Fatalf("qm fallback ran %d times after ownership changed", fallbackCalls)
	}
}

func TestDestroyOwnedVMQMFallbackRechecksOwnershipAndOmitsPurge(t *testing.T) {
	configCalls := 0
	destroyed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api2/json/nodes/node1/qemu/9902/config":
			configCalls++
			_, _ = w.Write([]byte(`{"data":{"tags":"certistack,run-test","description":"owner=certistack; run_id=run-test"}}`))
		case "/api2/json/nodes/node1/qemu/9902/status/stop", "/api2/json/nodes/node1/qemu/9902":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"errors":{"vmid":"temporary failure"}}`))
		case "/api2/json/cluster/resources":
			if destroyed {
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":[{"vmid":9902}]}`))
		case "/api2/json/nodes/node1/qemu/9902/status/current":
			if destroyed { // qm destroy removed it; success is PVE's answer, not the exit code
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"data":null}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"status":"stopped"}}`))
		default:
			t.Errorf("unexpected cleanup request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var fallbackArgs [][]string
	orch := &Orchestrator{
		opts:      Options{NodeName: "node1"},
		pveClient: pve.NewClient(pve.Config{BaseURL: server.URL}),
		runQMFallbackFn: func(_ context.Context, args []string) ([]byte, error) {
			fallbackArgs = append(fallbackArgs, append([]string(nil), args...))
			destroyed = destroyed || args[0] == "destroy"
			return nil, nil
		},
	}
	if err := orch.destroyOwnedVM(9902, "run-test"); err != nil {
		t.Fatalf("owned qm fallback cleanup failed: %v", err)
	}
	if configCalls != 4 {
		t.Fatalf("ownership checks = %d, want initial, one before the API destroy and one before each fallback", configCalls)
	}
	if len(fallbackArgs) != 2 {
		t.Fatalf("qm fallback calls = %v, want stop and destroy", fallbackArgs)
	}
	if strings.Join(fallbackArgs[0], " ") != "stop 9902 --skiplock 1" {
		t.Fatalf("stop fallback args = %v", fallbackArgs[0])
	}
	if strings.Join(fallbackArgs[1], " ") != "destroy 9902" {
		t.Fatalf("destroy fallback args = %v, want no --purge", fallbackArgs[1])
	}
}

func TestTrackOwnedVMRegistersCleanupBeforeCreate(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/api2/json/cluster/resources" {
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/node1/qemu/9900/config" {
			t.Errorf("unexpected cleanup request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"data":null,"errors":{"vmid":"does not exist"}}`))
	}))
	defer server.Close()

	orch := &Orchestrator{
		opts:      Options{NodeName: "node1", StateDir: t.TempDir()},
		runID:     "run-test",
		cleanup:   cleanup.New(),
		pveClient: pve.NewClient(pve.Config{BaseURL: server.URL}),
	}
	if err := orch.trackOwnedVM(9900); err != nil {
		t.Fatal(err)
	}
	if len(orch.record.VMs) != 1 || orch.record.VMs[0].VMID != 9900 {
		t.Fatalf("pre-create VM journal = %+v; want exact VM identity", orch.record.VMs)
	}
	if failures := orch.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("pre-create cleanup failures = %+v", failures)
	}
	if calls != 2 {
		t.Fatalf("pre-create cleanup made %d API calls, want the ownership lookup and the cluster list that backs its 404", calls)
	}
}

func TestTrackDeltaOverlayCleansPartialArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.qcow2")
	if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	orch := &Orchestrator{opts: Options{StateDir: t.TempDir()}, cleanup: cleanup.New()}
	if err := orch.trackDeltaOverlay(9900, path); err != nil {
		t.Fatal(err)
	}
	if len(orch.record.DeltaFiles) != 1 || orch.record.DeltaFiles[0] != path {
		t.Fatalf("pre-create overlay journal = %+v; want exact overlay path", orch.record.DeltaFiles)
	}
	if failures := orch.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("partial-overlay cleanup failures = %+v", failures)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial overlay remains after cleanup: %v", err)
	}
}

func TestVerifyTrackedVMsAbsentChecksOnlyJournaledIdentities(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`{"vmid":9900,"status":"running"}`)})
	}))
	defer server.Close()

	orch := &Orchestrator{pveClient: pve.NewClient(pve.Config{BaseURL: server.URL})}
	if err := orch.verifyTrackedVMsAbsent(); err != nil {
		t.Fatal("an empty resource journal should be clean")
	}
	if calls != 0 {
		t.Fatalf("untracked planned VMs were queried %d time(s)", calls)
	}
	orch.record.AddVM(9900, "node1", 0, "")
	if err := orch.verifyTrackedVMsAbsent(); err == nil || !strings.Contains(err.Error(), "remains") {
		t.Fatalf("a present tracked VM must fail teardown verification, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("tracked VM checks = %d, want 1", calls)
	}
}

func TestVerifyTrackedOverlaysRemovedReportsEveryIndeterminateResource(t *testing.T) {
	remaining := filepath.Join(t.TempDir(), "remaining.qcow2")
	if err := os.WriteFile(remaining, []byte("not removed"), 0600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "already-removed.qcow2")
	orch := &Orchestrator{}
	orch.record.DeltaFiles = []string{remaining, missing, ""}

	allRemoved, removed, verifyErrs := orch.verifyTrackedOverlaysRemoved()
	if allRemoved {
		t.Fatal("remaining or malformed overlays must make cleanup unverified")
	}
	if len(removed) != 1 || removed[0] != filepath.Base(missing) {
		t.Fatalf("removed overlays = %v, want only %q", removed, filepath.Base(missing))
	}
	if len(verifyErrs) != 2 || !strings.Contains(verifyErrs[0].Error(), "remains") || !strings.Contains(verifyErrs[1].Error(), "empty") {
		t.Fatalf("overlay verification errors = %v, want explicit remaining and malformed errors", verifyErrs)
	}
}

func TestVerifyTrackedLoopsUnmappedTreatsMissingJournaledDeviceAsClean(t *testing.T) {
	orch := &Orchestrator{}
	orch.record.AddLoop("/dev/loop999999", "expected-backing")

	allUnmapped, unmapped, verifyErrs := orch.verifyTrackedLoopsUnmapped()
	if !allUnmapped || len(verifyErrs) != 0 {
		t.Fatalf("missing loop device = allUnmapped=%v errs=%v, want clean", allUnmapped, verifyErrs)
	}
	if len(unmapped) != 1 || unmapped[0] != "/dev/loop999999" {
		t.Fatalf("unmapped loops = %v", unmapped)
	}
}

func TestRunProbes_CollectsEveryProbeFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	parsedURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	orch := &Orchestrator{}
	results, passed, err := orch.runProbes(context.Background(), config.VM{
		VMID: 9904,
		Probes: []config.Probe{
			{
				Type: "http", TargetIP: host, Port: port, Path: "/", ExpectedStatus: http.StatusNoContent,
				TimeoutSec: 1, Description: "healthy endpoint",
			},
			{
				Type: "tcp", TargetIP: host, Port: 1, TimeoutSec: 1, Description: "closed TCP port",
			},
			{
				Type: "unsupported", TimeoutSec: 1, Description: "unsupported test probe",
			},
		},
	})
	if passed || err == nil {
		t.Fatalf("runProbes = passed=%v, err=%v; want aggregated failure", passed, err)
	}
	if len(results) != 3 || !results[0].Passed || results[1].Passed || results[2].Passed {
		t.Fatalf("runProbes results = %+v; want pass/fail/fail", results)
	}
	if !strings.Contains(err.Error(), "closed TCP port") || !strings.Contains(err.Error(), "unknown probe type") {
		t.Fatalf("aggregate error = %v; want both failures", err)
	}
}

func TestRunProberWithRetryHonorsConfiguredAdditionalAttempts(t *testing.T) {
	attempts := 0
	prober := probe.ProberFunc(func(context.Context) probe.Result {
		attempts++
		return probe.Result{Passed: attempts == 3, Error: "not ready"}
	})

	result, gotAttempts := runProberWithRetry(context.Background(), prober, 3*time.Second, 2)
	if !result.Passed || attempts != 3 || gotAttempts != 3 {
		t.Fatalf("explicit retry result = %+v, attempts=%d/%d; want success on third attempt", result, gotAttempts, attempts)
	}
}

func TestRunProberWithRetryReportsLastCompletedAttemptAtTimeout(t *testing.T) {
	prober := probe.ProberFunc(func(ctx context.Context) probe.Result {
		deadline, _ := ctx.Deadline()
		if time.Until(deadline) < 150*time.Millisecond {
			<-ctx.Done()
			return probe.Result{Error: "timed out waiting for guest process to exit: " + ctx.Err().Error()}
		}
		return probe.Result{Error: "exit code 3; output: inactive"}
	})

	result, attempts := runProberWithRetry(context.Background(), prober, 700*time.Millisecond, 0)
	if result.Passed || attempts < 2 {
		t.Fatalf("result = %+v after %d attempts; want a failure after polling", result, attempts)
	}
	if !strings.Contains(result.Error, "inactive") || !strings.Contains(result.Error, "last completed attempt") {
		t.Fatalf("error = %q; want the last completed attempt's answer, not the deadline", result.Error)
	}
}

func TestRunProberWithRetryStopsImmediatelyOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts := 0
	prober := probe.ProberFunc(func(context.Context) probe.Result {
		attempts++
		return probe.Result{Error: "not ready"}
	})

	_, gotAttempts := runProberWithRetry(ctx, prober, 3*time.Second, 10)
	if attempts != 0 || gotAttempts != 0 {
		t.Fatalf("canceled retry loop made %d/%d attempts, want none", gotAttempts, attempts)
	}
}

func TestNetworkRecoveryEnabled_DefaultsToAutoWithExplicitPreserveOptOut(t *testing.T) {
	plan := &config.Plan{
		Network: config.Network{IPRange: "10.70.0.0/24", ProbeIP: "10.70.0.1"},
		Tiers: []config.Tier{{VMs: []config.VM{{
			VMID:   9904,
			Probes: []config.Probe{{Type: "tcp", TargetIP: "10.70.0.15"}},
		}}}},
	}
	orch := &Orchestrator{plan: plan}
	enabled, err := orch.networkRecoveryEnabled()
	if err != nil || !enabled {
		t.Fatalf("default recovery mode = enabled=%v, err=%v; want auto", enabled, err)
	}
	plan.Tiers[0].VMs[0].NetworkRecovery.Mode = "preserve"
	enabled, err = orch.networkRecoveryEnabled()
	if err != nil || enabled {
		t.Fatalf("preserve recovery mode = enabled=%v, err=%v; want disabled", enabled, err)
	}
}

func TestTrackFailureArtifactRemovesOnlyRegisteredPNG(t *testing.T) {
	dir := t.TempDir()
	pngPath := dir + "/certistack-failure.png"
	if err := os.WriteFile(pngPath, []byte("forensic image"), 0600); err != nil {
		t.Fatal(err)
	}
	unrelatedPath := dir + "/keep.png"
	if err := os.WriteFile(unrelatedPath, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}

	orch := &Orchestrator{cleanup: cleanup.New()}
	orch.trackFailureArtifact(&screendump.Artifact{PNGPath: pngPath})
	if err := orch.cleanup.Unwind(); err != nil {
		t.Fatalf("unwind: %v", err)
	}
	if _, err := os.Stat(pngPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("registered screenshot still exists: %v", err)
	}
	if _, err := os.Stat(unrelatedPath); err != nil {
		t.Fatalf("unrelated file was removed: %v", err)
	}
}

// A VM ID that is already in use on the node is refused before the run creates
// anything. The sandbox is pre-provisioned and answers only reads, the probe
// target is not an address of the worker, and the guest's disk is left alone,
// so every earlier stage of the run succeeds and the refusal is the guard's:
// the test fails if the guard is removed (the run would go on to map the
// backup and create the VM) and does not pass for an unrelated setup fault.
func TestOrchestrator_PreexistingVMGuard(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("a run is admitted on the host's RAM and I/O wait, which only a Linux host reports (/proc); the guard is reached only after admission")
	}
	var mu sync.Mutex
	var reads, writes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api2/json/")
		mu.Lock()
		if r.Method == http.MethodGet {
			reads = append(reads, path)
		} else {
			writes = append(writes, r.Method+" "+path)
		}
		mu.Unlock()
		reply := func(data string) { _ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(data)}) }
		switch {
		case r.Method != http.MethodGet:
			http.Error(w, "the guard must refuse before anything is created", http.StatusInternalServerError)
		case path == "cluster/sdn/zones":
			reply(`[{"zone":"csSbExternal","type":"simple","ipam":"pve"}]`)
		case path == "cluster/sdn/vnets":
			reply(`[{"vnet":"csVnExternal","zone":"csSbExternal"}]`)
		case path == "cluster/sdn/vnets/csVnExternal/subnets":
			reply(`[{"cidr":"10.100.0.0/24","vnet":"csVnExternal"}]`)
		case path == "cluster/resources":
			reply(`[]`)
		case path == "nodes/localhost/capabilities/qemu/machines":
			reply(`[]`)
		case path == "nodes/localhost/qemu/9001/status/current":
			// VM 9001 already exists on the node.
			reply(`{"vmid": 9001, "status": "running"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	plan := &config.Plan{
		Version: "v1",
		PlanID:  "test-preexisting-guard",
		Name:    "Preexisting VM Guard Test",
		AdmissionControl: config.AdmissionControl{
			MaxHostRAMPercent:     100.0,
			MaxHostIOWaitPercent:  100.0,
			DeferRetryIntervalSec: 1,
			MaxDeferRetries:       1,
		},
		Network: config.Network{
			Mode:      "simple",
			Lifecycle: "preprovisioned",
			ZoneID:    "csSbExternal",
			VNetID:    "csVnExternal",
			IPRange:   "10.100.0.0/24",
			ProbeIP:   "10.100.0.1",
		},
		Tiers: []config.Tier{
			{
				Level: 1,
				Name:  "Core",
				VMs: []config.VM{
					{
						VMID: 9001,
						Name: "existing-vm",
						// The guest's disk is left as it is: no network recovery step
						// (libguestfs) stands between the run and the guard.
						NetworkRecovery: config.NetworkRecovery{Mode: "preserve"},
						SourcePBS: config.SourcePBS{
							StorageID: "pbs-test",
							Snapshot:  "vm/9001/2026-01-01T00:00:00Z",
							Drive:     "drive-scsi0.img.fidx",
						},
						Probes: []config.Probe{
							{
								Type:        "tcp",
								Port:        80,
								TargetIP:    "10.100.0.50", // not an address of this host
								TimeoutSec:  1,
								Description: "test probe",
							},
						},
					},
				},
			},
		},
	}

	pveClient := pve.NewClient(pve.Config{BaseURL: server.URL})
	pbsClient := pbs.New(pbs.Config{})

	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir(), NodeName: "localhost"}, pbsClient, pveClient)
	orch.bridgePortsFn = noForeignBridgePorts
	host := &fakeHostAddressManager{}
	orch.hostAddresses = host
	res, err := orch.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "preexisting VM guard triggered: VM 9001 already exists on node localhost (status: running)") {
		t.Fatalf("run error = %v, want the preexisting VM guard of the node", err)
	}
	if res.AllPassed {
		t.Errorf("expected AllPassed to be false")
	}
	mu.Lock()
	defer mu.Unlock()
	// The stages before the guard were reached: the pre-provisioned sandbox
	// was read, the probe address was put on the VNet, and the guard looked
	// the VM ID up in the cluster and on the node.
	for _, want := range []string{"cluster/sdn/zones", "cluster/sdn/vnets", "cluster/resources", "nodes/localhost/qemu/9001/status/current"} {
		found := false
		for _, read := range reads {
			found = found || read == want
		}
		if !found {
			t.Errorf("the run never read %s before the guard: %v", want, reads)
		}
	}
	if len(host.added) != 1 || host.added[0] != "csVnExternal=10.100.0.1/24" {
		t.Errorf("the probe address was not put on the sandbox VNet before the guard: %v", host.added)
	}
	// Nothing was created: the guard refused before any write to PVE.
	if len(writes) != 0 {
		t.Errorf("expected no write to PVE when the preexisting VM guard triggers, got %v", writes)
	}
}

func TestOrchestrator_PreexistingVMGuardChecksClusterWideVMID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api2/json/cluster/resources" {
			_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(`[{"type":"qemu","vmid":9003,"node":"other-node"}]`)})
			return
		}
		t.Errorf("node-local lookup should not run after cluster collision: %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	}))
	defer server.Close()

	orch := &Orchestrator{
		opts:      Options{NodeName: "localhost"},
		pveClient: pve.NewClient(pve.Config{BaseURL: server.URL}),
	}
	record, err := orch.bootAndVerifyVM(context.Background(), config.VM{VMID: 9003, SourceVMID: 7003}, 0, nil)
	if err == nil || !strings.Contains(err.Error(), "already exists in the PVE cluster") {
		t.Fatalf("cluster-wide VMID collision error = %v, record = %+v", err, record)
	}
	if record == nil || record.SourceVMID != 7003 {
		t.Fatalf("refused VM record must still name its source VM: %+v", record)
	}
}

// A VM whose QEMU monitor cannot be reached is a failed run, not a passed
// boot. The run is driven through bootAndVerifyVM to the QMP wait: the backup
// is mapped, the overlay made and scanned, PVE creates and starts the VM, and
// only then does the QMP socket directory (which holds no socket) refuse. The
// test fails if the QMP check is removed (the run would go on to the probes)
// and does not pass for an unrelated fault earlier in the setup.
func TestOrchestrator_QMPCheck_FailClosed(t *testing.T) {
	f := newLoopFixture(t, "exit 0")
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.log), "qemu-img"), []byte("#!/bin/sh\n"+okQemuImg), 0o755); err != nil {
		t.Fatal(err)
	}
	const upid = "UPID:localhost:00001234:12345678:00000001:qcreate:9002:root@pam:"
	var mu sync.Mutex
	var created, started bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api2/json/")
		reply := func(data string) { _ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(data)}) }
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && path == "cluster/resources":
			reply(`[]`)
		case r.Method == http.MethodGet && path == "nodes/localhost/qemu/9002/status/current":
			if !started {
				// The VM does not exist yet.
				http.Error(w, `{"errors": "Configuration file does not exist"}`, http.StatusNotFound)
				return
			}
			reply(`{"vmid":9002,"status":"running","qmpstatus":"running"}`)
		case r.Method == http.MethodGet && path == "nodes/localhost/capabilities/qemu/machines":
			reply(`[]`)
		case r.Method == http.MethodPost && path == "nodes/localhost/qemu":
			created = true
			reply(`"` + upid + `"`)
		case r.Method == http.MethodGet && path == "nodes/localhost/tasks/"+upid+"/status":
			reply(`{"status": "stopped", "exitstatus": "OK"}`)
		case r.Method == http.MethodGet && path == "nodes/localhost/qemu/9002/config":
			reply(`{}`)
		case r.Method == http.MethodPost && path == "nodes/localhost/qemu/9002/status/start":
			started = true
			reply(`"` + upid + `"`)
		default:
			t.Errorf("unexpected PVE request %s %s", r.Method, path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	plan := &config.Plan{
		Version: "v1",
		PlanID:  "test-qmp-fail-closed",
		Name:    "QMP Fail Closed Test",
		Network: config.Network{
			Mode:    "simple",
			ZoneID:  "csSb01",
			VNetID:  "csVn01",
			IPRange: "10.100.0.0/24",
			ProbeIP: "10.100.0.1",
		},
	}
	// Point QMP to a directory with no socket in it.
	qmpDir := t.TempDir()
	orch := New(plan, Options{
		NodeName:     "localhost",
		ScratchDir:   t.TempDir(),
		StateDir:     t.TempDir(),
		QMPSocketDir: qmpDir,
		SkipQMP:      false,
	}, pbs.New(pbs.Config{Repository: "u@pbs!tok@pbs.example:store"}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	if err := os.Chmod(orch.opts.ScratchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	orch.deviceBytesFn = func(string) (int64, error) { return 36 << 20, nil }
	orch.freeBytesFn = func(string) (int64, error) { return 500 << 30, nil }
	orch.sharedDisksFn = func(context.Context, string, string) ([]string, error) { return nil, nil }
	orch.verifyImageFn = func(_ context.Context, _, _ string, _ pbs.DiskSize, _ func(int64)) (*pbs.VerifySummary, string, error) {
		return &pbs.VerifySummary{Detail: "verified", BytesRead: 36 << 20}, strings.Repeat("ab", 32), nil
	}
	vm := mapTestVM()
	vm.VMID = 9002
	vm.Name = "qmp-fail-vm"
	vm.NetworkRecovery = config.NetworkRecovery{Mode: "preserve"} // the guest's disk is left as it is
	vm.CopyBeforeBoot = config.CopyBeforeBootNever
	vm.SourceImageBytes = map[string]int64{"scsi0": 36 << 20}
	vm.SourceDiskBytes = map[string]int64{"scsi0": 33 << 20}

	record, err := orch.bootAndVerifyVM(context.Background(), vm, 60, nil)
	wantSocket := filepath.Join(qmpDir, "9002.qmp")
	if err == nil || !strings.Contains(err.Error(), "QMP connection to VM 9002 failed") || !strings.Contains(err.Error(), wantSocket) {
		t.Fatalf("bootAndVerifyVM = %v, want the QMP connection failure naming %s", err, wantSocket)
	}
	if record == nil || record.AllPassed {
		t.Errorf("a VM whose monitor could not be reached must not be recorded as passed: %+v", record)
	}
	mu.Lock()
	defer mu.Unlock()
	// The earlier stages were reached: PVE created the VM and started it, and
	// the backup's disk was scanned, before the monitor was asked.
	if !created || !started {
		t.Errorf("the run stopped before the QMP wait: created %v, started %v", created, started)
	}
	if record != nil && (len(record.SourceDisks) != 1 || record.SourceDisks[0].IntegrityStatus != "verified") {
		t.Errorf("the backup's disk was not verified before the VM started: %+v", record.SourceDisks)
	}
}
