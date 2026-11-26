//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

// Linux-only for the reason soak_run_linux_test.go gives: Run's admission check
// reads the node's /proc counters.

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// guardedRun is a run whose host is a reloadHost, whose guard looks every
// millisecond and whose log is returned. A test sets bootVMFn to change the
// node's network while the run is up.
func guardedRun(t *testing.T, plan *config.Plan, client *pve.Client, host *reloadHost) (*Orchestrator, *lockedBuffer) {
	t.Helper()
	dir := shortSocketDir(t)
	guestAgent(t, dir, -1)
	orch := New(plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir(), QGASocketDir: dir, NodeName: "pve1"}, pbs.New(pbs.Config{}), client)
	orch.bridgePortsFn = noForeignBridgePorts
	orch.hostAddresses = host
	orch.addrGuardEvery = time.Millisecond
	logs := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return orch, logs
}

func passingRecord(vm config.VM) *probe.VMValidationRecord {
	return &probe.VMValidationRecord{VMID: vm.VMID, Name: vm.Name, AllPassed: true}
}

// The whole sequence of calls after the address was added: every look and
// repair of the guard comes before the removal of the address, and none after.
func assertGuardEndedBeforeRemoval(t *testing.T, host *reloadHost) {
	t.Helper()
	events := host.log()
	removed := -1
	for i, event := range events {
		if strings.HasPrefix(event, "remove-address") {
			removed = i
		}
	}
	if removed < 0 {
		t.Fatalf("the address was never removed: %v", events)
	}
	for _, event := range events[removed+1:] {
		if strings.HasPrefix(event, "inspect") || strings.HasPrefix(event, "restore") || strings.HasPrefix(event, "disable-forwarding") || strings.HasPrefix(event, "add") {
			t.Fatalf("%q ran after the address was removed (guard not stopped before the teardown removed it): %v", event, events)
		}
	}
}

// A pre-provisioned sandbox: a reload removes the address and turns forwarding
// on while the VM is up; the guard puts both back, says so once each, and is
// gone before the teardown removes the address.
func TestRunPutsTheProbeAddressBackAfterANetworkReload(t *testing.T) {
	plan, client := soakRunPlan(t, 0)
	host := newReloadHost()
	orch, logs := guardedRun(t, plan, client, host)
	orch.bootVMFn = func(ctx context.Context, vm config.VM, _ int, _ *attest.PhaseTimings) (*probe.VMValidationRecord, error) {
		host.reload() // ifreload -a on the node
		deadline := time.Now().Add(10 * time.Second)
		for host.count("restore-address") == 0 || host.count("disable-forwarding") == 0 {
			if time.Now().After(deadline) || ctx.Err() != nil {
				return nil, errors.New("the guard did not put the address back")
			}
			time.Sleep(time.Millisecond)
		}
		return passingRecord(vm), nil
	}

	res, err := orch.Run(context.Background())
	if err != nil || res == nil || !res.AllPassed {
		t.Fatalf("the run did not pass: %v (%+v)", err, res)
	}
	if got := host.count("restore-address csVnExternal 10.100.0.1/24"); got != 1 {
		t.Errorf("the address was put back %d times for one reload: %v", got, host.log())
	}
	if host.count("restore-table") != 0 {
		t.Errorf("a table that was there was installed again: %v", host.log())
	}
	if n := len(logs.lines("WARN", "probe address 10.100.0.1/24 was removed from csVnExternal")); n != 1 {
		t.Errorf("%d warnings about the address:\n%s", n, logs.String())
	}
	if n := len(logs.lines("WARN", "forwarding was turned back on for csVnExternal")); n != 1 {
		t.Errorf("%d warnings about forwarding:\n%s", n, logs.String())
	}
	assertGuardEndedBeforeRemoval(t, host)
	if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned {
		t.Errorf("teardown evidence = %+v", res.TeardownEvidence)
	}
	if host.fakeHostAddressManager.removed == nil || len(host.fakeHostAddressManager.removed) != 1 {
		t.Errorf("the address was removed %v times", host.fakeHostAddressManager.removed)
	}
}

// An ephemeral sandbox: the same, with the SDN created and applied by the run.
func TestRunPutsTheProbeAddressBackOnAnEphemeralSandbox(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var data json.RawMessage
		switch {
		case r.Method == http.MethodGet && (r.URL.Path == "/api2/json/cluster/sdn/zones" || r.URL.Path == "/api2/json/cluster/sdn/vnets"):
			data = json.RawMessage(`[]`)
		case r.Method == http.MethodPut && r.URL.Path == "/api2/json/cluster/sdn":
			data = json.RawMessage(`"UPID:pve1:1:1:1:1:1:"`)
		case r.Method == http.MethodGet && r.URL.Path == "/api2/json/nodes/pve1/tasks/UPID:pve1:1:1:1:1:1:/status":
			data = json.RawMessage(`{"status":"stopped","exitstatus":"OK"}`)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/status/current"):
			data = json.RawMessage(`{"status":"running","qmpstatus":"running"}`)
		default:
			data = json.RawMessage(`"OK"`)
		}
		_ = json.NewEncoder(w).Encode(pve.APIResponse{Data: data})
	}))
	defer server.Close()
	plan, _ := soakRunPlan(t, 0)
	plan.Network = config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}
	client := pve.NewClient(pve.Config{BaseURL: server.URL})
	host := newReloadHost()
	orch, logs := guardedRun(t, plan, client, host)
	orch.bootVMFn = func(ctx context.Context, vm config.VM, _ int, _ *attest.PhaseTimings) (*probe.VMValidationRecord, error) {
		host.reload()
		deadline := time.Now().Add(10 * time.Second)
		for host.count("restore-address") == 0 {
			if time.Now().After(deadline) || ctx.Err() != nil {
				return nil, errors.New("the guard did not put the address back")
			}
			time.Sleep(time.Millisecond)
		}
		return passingRecord(vm), nil
	}

	res, err := orch.Run(context.Background())
	if err != nil || res == nil || !res.AllPassed {
		t.Fatalf("the run did not pass: %v (%+v)", err, res)
	}
	events := host.log()
	// The run's own turning forwarding off, once, at setup; the guard's once more,
	// for the one switch the reload turned on.
	if host.count("disable-forwarding csVn01") != 1 || host.count("disable-forwarding-of csVn01 IPv4") != 1 {
		t.Errorf("forwarding was turned off %d times: %v", host.count("disable-forwarding"), events)
	}
	if host.count("restore-address csVn01 10.100.0.1/24") != 1 || len(logs.lines("WARN", "probe address 10.100.0.1/24 was removed from csVn01")) != 1 {
		t.Errorf("events %v\n%s", events, logs.String())
	}
	// The address is added once, by the run; the repair never adds it through Add.
	if host.count("add") != 1 {
		t.Errorf("Add ran %d times: %v", host.count("add"), events)
	}
	assertGuardEndedBeforeRemoval(t, host)
	if res.TeardownEvidence == nil || !res.TeardownEvidence.AllCleaned {
		t.Errorf("teardown evidence = %+v", res.TeardownEvidence)
	}
}

// Fail closed: the containment table is removed and cannot be installed again.
// The run's context ends, the run reports why, and teardown still removes the
// address.
func TestRunStopsWhenTheContainmentCannotBeRestored(t *testing.T) {
	plan, client := soakRunPlan(t, 0)
	host := newReloadHost()
	orch, logs := guardedRun(t, plan, client, host)
	stopped := make(chan struct{})
	orch.bootVMFn = func(ctx context.Context, vm config.VM, _ int, _ *attest.PhaseTimings) (*probe.VMValidationRecord, error) {
		host.set(func(h *reloadHost) { h.table, h.tableErr = false, errors.New("nft: Operation not permitted") })
		select {
		case <-ctx.Done():
			close(stopped)
			return &probe.VMValidationRecord{VMID: vm.VMID, Name: vm.Name}, ctx.Err()
		case <-time.After(30 * time.Second):
			return nil, errors.New("the run was not stopped")
		}
	}

	res, err := orch.Run(context.Background())
	select {
	case <-stopped:
	default:
		t.Fatal("the run's context was not canceled")
	}
	if err == nil || res == nil || res.AllPassed {
		t.Fatalf("a run that lost its containment passed: %v", err)
	}
	for _, want := range []string{"isolation could not be restored", "Operation not permitted"} {
		if !strings.Contains(err.Error(), want) || res.Error == nil || !strings.Contains(res.Error.Error(), want) {
			t.Errorf("the run's error lacks %q: err=%v res.Error=%v", want, err, res.Error)
		}
	}
	if len(logs.lines("ERROR", "isolation could not be restored")) != 1 {
		t.Errorf("log:\n%s", logs.String())
	}
	assertGuardEndedBeforeRemoval(t, host)
	if len(host.fakeHostAddressManager.removed) != 1 {
		t.Errorf("teardown did not remove the address: %v", host.log())
	}
}

// A zone removed during the run takes its bridge: one message, no spinning, and
// the run is not stopped by the guard.
func TestRunSurvivesTheBridgeGoing(t *testing.T) {
	plan, client := soakRunPlan(t, 0)
	host := newReloadHost()
	orch, logs := guardedRun(t, plan, client, host)
	looks := 0
	orch.bootVMFn = func(ctx context.Context, vm config.VM, _ int, _ *attest.PhaseTimings) (*probe.VMValidationRecord, error) {
		host.set(func(h *reloadHost) { h.bridge = false })
		for len(logs.lines("WARN", "is gone")) == 0 && ctx.Err() == nil {
			time.Sleep(time.Millisecond)
		}
		looks = host.count("inspect")
		time.Sleep(30 * time.Millisecond) // many intervals
		return passingRecord(vm), nil
	}
	if _, err := orch.Run(context.Background()); err != nil {
		t.Fatalf("a bridge that went stopped the run: %v", err)
	}
	if host.count("inspect") != looks || host.count("restore") != 0 {
		t.Errorf("the guard kept looking: %v", host.log())
	}
	if len(logs.lines("WARN", "csVnExternal is gone")) != 1 {
		t.Errorf("log:\n%s", logs.String())
	}
}

// A wire probe looks at the probe address before its attempts, and a probe of
// any other kind does not. The guard's goroutine never ticks here (an hour), so
// the only looks are the probes'.
func TestWireProbesLookAtTheAddressBeforeTheyStart(t *testing.T) {
	plan, client := soakRunPlan(t, 0)
	vm := &plan.Tiers[0].VMs[0]
	host := newReloadHost()
	orch, _ := guardedRun(t, plan, client, host)
	orch.addrGuard = newAddrGuard(host, "csVnExternal", "10.100.0.1/24", time.Hour, nil)
	host.reload()

	// The guest-agent probe is not a wire probe.
	if _, _, err := orch.runProbeSet(context.Background(), *vm, true); err != nil {
		t.Fatalf("guest-agent probe: %v", err)
	}
	if got := host.log(); len(got) != 0 {
		t.Fatalf("a guest-agent probe looked at the probe address: %v", got)
	}

	// The wire probe fails here (no sandbox interface on the test host), after
	// the address was put back.
	wire := *vm
	wire.Probes = []config.Probe{{Type: "tcp", TargetIP: "10.100.0.10", Port: 80, TimeoutSec: 1, Description: "web"}}
	results, ok, _ := orch.runProbeSet(context.Background(), wire, true)
	if ok || len(results) != 1 {
		t.Fatalf("results = %+v", results)
	}
	if host.count("inspect") < 1 || host.count("restore-address csVnExternal 10.100.0.1/24") != 1 || host.count("restore-address") != 1 {
		t.Fatalf("the probe did not look at the address before it started: %v", host.log())
	}
	if first := host.log()[0]; !strings.HasPrefix(first, "inspect") {
		t.Errorf("the first event was %q, want the look before the first attempt", first)
	}
}
