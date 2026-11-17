//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

// Linux-only: Run starts with the host's admission check, which reads the
// node's /proc counters, and a Windows host has none ("host total RAM must be
// positive"). The VM asks for 128 MiB so the check admits on any host that has
// them.

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// soakRunPlan is a one-tier plan on a preprovisioned sandbox whose single VM is
// probed through the guest agent, and the PVE that serves it: the sandbox's
// SDN objects and the VM's status, which says running.
func soakRunPlan(t *testing.T, soakSec int) (*config.Plan, *pve.Client) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "preprovisioned sandbox must not be mutated", http.StatusInternalServerError)
			return
		}
		var data json.RawMessage
		switch {
		case r.URL.Path == "/api2/json/cluster/sdn/zones":
			data = json.RawMessage(`[{"zone":"csSbExternal","type":"simple","ipam":"pve"}]`)
		case r.URL.Path == "/api2/json/cluster/sdn/vnets":
			data = json.RawMessage(`[{"vnet":"csVnExternal","zone":"csSbExternal"}]`)
		case r.URL.Path == "/api2/json/cluster/sdn/vnets/csVnExternal/subnets":
			data = json.RawMessage(`[{"cidr":"10.100.0.0/24","vnet":"csVnExternal"}]`)
		case r.URL.Path == "/api2/json/cluster/resources": // no other guest on the sandbox VNet
			data = json.RawMessage(`[]`)
		case strings.HasSuffix(r.URL.Path, "/status/current"):
			data = json.RawMessage(`{"status":"running","qmpstatus":"running"}`)
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	t.Cleanup(server.Close)
	plan := &config.Plan{
		Version: "v1",
		PlanID:  "soak-run",
		Name:    "Soak run",
		AdmissionControl: config.AdmissionControl{
			MaxHostRAMPercent: 100.0, MaxHostIOWaitPercent: 100.0, DeferRetryIntervalSec: 1, MaxDeferRetries: 1,
		},
		Network: config.Network{
			Mode: "simple", Lifecycle: "preprovisioned", ZoneID: "csSbExternal", VNetID: "csVnExternal",
			IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1",
		},
		Tiers: []config.Tier{{Level: 1, Name: "core", SoakTimeSec: soakSec, VMs: []config.VM{{
			VMID: 9101, Name: "app", HardwareOverrides: config.HardwareOverrides{MemoryMB: 128},
			Probes: []config.Probe{{Type: "qga", Command: "ping", RequireQGA: true, TimeoutSec: 1, Description: "the agent answers"}},
		}}}},
	}
	return plan, pve.NewClient(pve.Config{BaseURL: server.URL})
}

// guestAgent serves guest-ping on VM 9101's agent socket, answering the first
// `answers` pings (negative: every ping) and refusing the rest.
func guestAgent(t *testing.T, dir string, answers int64) {
	t.Helper()
	var pings atomic.Int64
	serveUnixSocket(t, filepath.Join(dir, "9101.qga"), func(conn net.Conn) {
		reader, encoder := bufio.NewReader(conn), json.NewEncoder(conn)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var request struct {
				Execute   string         `json:"execute"`
				Arguments map[string]any `json:"arguments"`
			}
			if json.Unmarshal(line, &request) != nil {
				return
			}
			reply := map[string]any{"error": map[string]any{"class": "GenericError", "desc": "the agent is not answering"}}
			switch {
			case request.Execute == "guest-sync":
				reply = map[string]any{"return": request.Arguments["id"]}
			case request.Execute == "guest-ping" && (answers < 0 || pings.Add(1) <= answers):
				reply = map[string]any{"return": map[string]any{}}
			}
			if encoder.Encode(reply) != nil {
				return
			}
		}
	})
}

func soakRunOrchestrator(t *testing.T, plan *config.Plan, client *pve.Client, qgaDir string) *Orchestrator {
	t.Helper()
	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir(), QGASocketDir: qgaDir, NodeName: "pve1"}, pbs.New(pbs.Config{}), client)
	orch.bridgePortsFn = noForeignBridgePorts
	orch.hostAddresses = &fakeHostAddressManager{}
	// The restore is not what these tests are about: the VM comes up passing.
	orch.bootVMFn = func(_ context.Context, vm config.VM, _ int, _ *attest.PhaseTimings) (*probe.VMValidationRecord, error) {
		return &probe.VMValidationRecord{VMID: vm.VMID, Name: vm.Name, AllPassed: true}, nil
	}
	return orch
}

// Through a whole run: the tier's probes pass once, the guest agent
// stops answering, and the run does not end with a pass. The VM's record is
// failed, carries the summary of the checks that found it, and the run's error
// says which check failed.
func TestRunFailsATierWhoseServiceStoppedAnsweringDuringItsSoak(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	plan, client := soakRunPlan(t, 1)
	dir := shortSocketDir(t)
	guestAgent(t, dir, 1)
	orch := soakRunOrchestrator(t, plan, client, dir)

	res, err := orch.Run(context.Background())
	if err == nil || res == nil || res.AllPassed {
		t.Fatalf("a run whose guest agent stopped answering after the probe stage passed: res.AllPassed=%v err=%v", res != nil && res.AllPassed, err)
	}
	if !strings.Contains(err.Error(), "during the soak") || !strings.Contains(err.Error(), "service check 1 of the soak failed") {
		t.Errorf("the run's error does not name the failed check: %v", err)
	}
	if len(res.VMRecords) != 1 {
		t.Fatalf("records = %+v", res.VMRecords)
	}
	record := res.VMRecords[0]
	if record.VerificationStatus != "failed" || record.AllPassed {
		t.Errorf("the VM is recorded as %q (all_passed %v), want failed", record.VerificationStatus, record.AllPassed)
	}
	if record.Soak == nil || record.Soak.Samples != 1 || record.Soak.FailedSamples != 1 || record.Soak.Probes[0].Failed != 1 {
		t.Errorf("the record's soak summary = %+v", record.Soak)
	}
	// The failed VM's stage results are the passing ones, and the summary
	// is what tells the failure apart: the rules accept its arithmetic.
	if problems := attest.SoakProblems(record, &plan.Tiers[0].VMs[0], 1, false); len(problems) != 0 {
		t.Errorf("the failed run's own summary does not add up: %v", problems)
	}
}

// The control: the same run, its agent answering throughout, passes, and the
// record carries the summary of an honest soak that the report rules accept.
func TestRunPassesATierWhoseServiceKeepsAnsweringThroughItsSoak(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	plan, client := soakRunPlan(t, 1)
	dir := shortSocketDir(t)
	guestAgent(t, dir, -1)
	orch := soakRunOrchestrator(t, plan, client, dir)

	res, err := orch.Run(context.Background())
	if err != nil || res == nil || !res.AllPassed {
		t.Fatalf("run: res=%+v err=%v", res, err)
	}
	record := res.VMRecords[0]
	if record.VerificationStatus != "verified" || record.Soak == nil || record.Soak.Samples < 2 || record.Soak.FailedSamples != 0 {
		t.Fatalf("record = %+v, soak = %+v", record, record.Soak)
	}
	if problems := attest.SoakProblems(record, &plan.Tiers[0].VMs[0], 1, true); len(problems) != 0 {
		t.Errorf("the report rules refuse an honest run's summary: %v", problems)
	}
	if res.PhaseTimings == nil || res.PhaseTimings.SoakTimeSec < 1 {
		t.Errorf("the soak was not timed: %+v", res.PhaseTimings)
	}
}

// A tier with no soak records none: nothing is held, nothing is claimed.
func TestRunRecordsNoSoakForATierWithoutOne(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	plan, client := soakRunPlan(t, 0)
	dir := shortSocketDir(t)
	guestAgent(t, dir, -1)
	res, err := soakRunOrchestrator(t, plan, client, dir).Run(context.Background())
	if err != nil || !res.AllPassed || res.VMRecords[0].Soak != nil {
		t.Fatalf("run: err=%v res=%+v", err, res)
	}
}

// Through a whole run: PVE refuses every status read, the soak does not
// take that for a running VM, and the run fails with the reason.
func TestRunFailsATierWhoseVMStateWasNeverReadDuringItsSoak(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	plan, _ := soakRunPlan(t, 1)
	// The sandbox is preprovisioned and read from PVE too: answer that, and
	// refuse only the status.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			http.Error(w, `{"message":"audit status endpoint unavailable"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	t.Cleanup(server.Close)
	dir := shortSocketDir(t)
	guestAgent(t, dir, -1)
	orch := soakRunOrchestrator(t, plan, pve.NewClient(pve.Config{BaseURL: server.URL}), dir)

	res, err := orch.Run(context.Background())
	if err == nil || res == nil || res.AllPassed {
		t.Fatalf("a run whose VM state was never readable passed: err=%v res=%+v", err, res)
	}
	if !strings.Contains(err.Error(), "liveness is unknown") {
		t.Errorf("the run's error does not say the liveness was unknown: %v", err)
	}
}
