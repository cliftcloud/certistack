//go:build linux

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package recovery

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/sysutil"
)

func TestRecover_CleanRun(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, "active.json")

	// Pre-create a completed record
	record := journal.Record{
		RunID:     "run-clean",
		Phase:     "cleaned",
		UpdatedAt: time.Now().UTC(),
	}
	if err := journal.Write(path, record); err != nil {
		t.Fatalf("journal.Write failed: %v", err)
	}

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("Recover failed on cleaned run: %v", err)
	}
}

func TestRecoverLocked_CleanRun(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, "active.json")
	record := journal.Record{RunID: "run-clean-locked", Phase: "cleaned", UpdatedAt: time.Now().UTC()}
	if err := journal.Write(path, record); err != nil {
		t.Fatalf("journal.Write failed: %v", err)
	}

	// The caller normally owns journal.Lock here. A cleaned record makes this
	// unit test independent of host mutations while verifying the locked path.
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("RecoverLocked failed on cleaned run: %v", err)
	}
}

func TestRecoverLockedRejectsMalformedJournal(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, "active.json")
	if err := os.WriteFile(path, []byte(`{"run_id":`), 0600); err != nil {
		t.Fatal(err)
	}

	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "failed to load journal") {
		t.Fatalf("RecoverLocked malformed journal error = %v, want fail-closed load error", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("malformed journal must be retained for operator recovery: %v", err)
	}
}

func TestWithheldClientOutputDetailDoesNotExposePBSClientContent(t *testing.T) {
	secretOutput := []byte("repository=backup@pbs!automation password=must-not-log")
	detail := withheldClientOutputDetail(secretOutput)
	if strings.Contains(detail, "automation") || strings.Contains(detail, "must-not-log") || strings.Contains(detail, string(secretOutput)) {
		t.Fatalf("withheld client output detail exposed content: %q", detail)
	}
	if want := fmt.Sprintf("withheld (%d bytes)", len(secretOutput)); detail != want {
		t.Fatalf("withheld client output detail = %q, want %q", detail, want)
	}
}

// PVE answers every request with HTTP 500 "does not exist", so
// neither the zone and VNet lists nor the lock can be had. Recovery cannot
// tell what is left, so it deletes and applies nothing, and keeps the
// journal unclean (it once counted the 500s as absence and applied
// unlocked).
func TestRecover_UnreadableSDNStateFailsClosed(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data":    nil,
			"message": "recorded SDN object does not exist",
		})
	}))
	defer server.Close()
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "test-secret")
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")

	stateDir := t.TempDir()
	record := journal.Record{RunID: "recover-absent-sdn", Phase: "cleanup_failed", UpdatedAt: time.Now().UTC()}
	record.AddSDNVNet("csVn77")
	record.AddSDNZone("csZone77")
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}

	if err := RecoverLocked(stateDir); err == nil {
		t.Fatal("Recover succeeded although PVE's SDN state could not be read")
	}
	// The zone list cannot be read, so recovery takes the lock to be sure,
	// and PVE refuses that too (HTTP 500, a definite answer that is not a
	// grant, not a pending refusal and not a lock held by another client).
	if got, want := strings.Join(calls, "\n"), "GET /api2/json/cluster/sdn/zones\nPOST /api2/json/cluster/sdn/lock"; got != want {
		t.Fatalf("unexpected requests:\n%s\nwant:\n%s", got, want)
	}
	loaded, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Phase == "cleaned" || len(loaded.SDNZones) != 1 || len(loaded.SDNVNets) != 1 {
		t.Fatalf("recovered journal = %+v; want it unclean, with the zone and VNet kept", loaded)
	}
}

// node-run reconciles the journal before preflight, so recovery is the first
// PVE request a worker can make and must honour the insecure-TLS opt-in too.
func TestRecover_InsecureTLSWithoutLabOptInSendsNoRequest(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": ""})
	}))
	defer server.Close()
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "test-secret")
	t.Setenv("PVE_TLS_INSECURE", "true")
	t.Setenv("CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB", "")
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")

	stateDir := t.TempDir()
	record := journal.Record{RunID: "recover-insecure", Phase: "cleanup_failed", UpdatedAt: time.Now().UTC()}
	record.AddSDNVNet("csVn78")
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}

	if err := RecoverLocked(stateDir); err == nil || !strings.Contains(err.Error(), "PVE_TLS_INSECURE is forbidden") {
		t.Fatalf("Recover error = %v, want the insecure-TLS refusal", err)
	}
	if requests != 0 {
		t.Fatalf("recovery sent %d PVE request(s) with verification disabled and no lab opt-in", requests)
	}
	loaded, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Phase == "cleaned" {
		t.Fatal("refused recovery marked the journal cleaned")
	}
}

func TestRecover_AlreadyAbsentLoopIsClean(t *testing.T) {
	stateDir := t.TempDir()
	record := journal.Record{RunID: "recover-missing-loop", Phase: "running", UpdatedAt: time.Now().UTC()}
	record.AddLoop("/dev/loop999999", "recorded-backing")
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("Recover failed for an already-absent loop: %v", err)
	}
	loaded, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Phase != "cleaned" {
		t.Fatalf("recovered journal phase = %q, want cleaned", loaded.Phase)
	}
}

func TestRecover_RemovesOnlyJournaledPVEResources(t *testing.T) {
	var calls []string
	destroyed, stopped := false, false
	// PVE's lists follow the deletions, as its own do: recovery confirms
	// them there and does not trust a delete's reply.
	zoneGone, vnetGone, subnetGone := false, false, false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		var data any = ""
		switch r.Method + " " + r.URL.Path {
		case "GET /api2/json/nodes/node1/qemu/9100/status/current":
			if destroyed { // as PVE 9 answers for a VM that does not exist
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]any{"data": nil, "message": "Configuration file 'nodes/node1/qemu-server/9100.conf' does not exist"})
				return
			}
			status := "running"
			if stopped { // recovery asks the VM itself after its stop task
				status = "stopped"
			}
			data = map[string]any{"vmid": 9100, "status": status}
		case "GET /api2/json/nodes/node1/qemu/9100/config":
			data = map[string]any{"tags": "certistack,recover-pve", "description": "owner=certistack; run_id=recover-pve"}
		case "POST /api2/json/nodes/node1/qemu/9100/status/stop":
			data = "UPID:node1:stop:task"
		case "GET /api2/json/nodes/node1/tasks/UPID:node1:stop:task/status":
			stopped = true
			data = map[string]any{"status": "stopped", "exitstatus": "OK"}
		case "DELETE /api2/json/nodes/node1/qemu/9100":
			data = "UPID:node1:destroy:task"
		case "GET /api2/json/nodes/node1/tasks/UPID:node1:destroy:task/status":
			destroyed = true
			data = map[string]any{"status": "stopped", "exitstatus": "OK"}
		case "DELETE /api2/json/cluster/sdn/vnets/csVn77", "DELETE /api2/json/cluster/sdn/zones/csZone77":
			if r.URL.Query().Get("lock-token") != "tok-9" {
				t.Errorf("%s %s without the SDN lock token", r.Method, r.URL.Path)
			}
			if strings.Contains(r.URL.Path, "/zones/") {
				zoneGone = true
			} else {
				vnetGone = true
			}
			data = ""
		case "GET /api2/json/cluster/sdn/zones":
			data = []map[string]any{}
			if !zoneGone {
				data = []map[string]any{{"zone": "csZone77"}}
			}
		case "GET /api2/json/cluster/sdn/vnets":
			data = []map[string]any{}
			if !vnetGone {
				data = []map[string]any{{"vnet": "csVn77", "zone": "csZone77", "alias": "certistack recover-pve"}}
			}
		case "GET /api2/json/cluster/sdn/vnets/csVn77/subnets":
			data = []map[string]any{}
			if !subnetGone {
				data = []map[string]any{{"subnet": "csZone77-10.89.0.0-24"}}
			}
		case "DELETE /api2/json/cluster/sdn/vnets/csVn77/subnets/csZone77-10.89.0.0-24":
			if r.URL.Query().Get("lock-token") != "tok-9" {
				t.Errorf("%s %s without the SDN lock token", r.Method, r.URL.Path)
			}
			subnetGone = true
			data = ""
		case "POST /api2/json/cluster/sdn/lock":
			data = "tok-9"
		case "GET /api2/json/nodes":
			data = []map[string]any{{"node": "node1"}}
		case "PUT /api2/json/cluster/sdn":
			data = "UPID:node1:reload:sdn-task"
		case "GET /api2/json/nodes/node1/tasks/UPID:node1:reload:sdn-task/status":
			data = map[string]any{"status": "stopped", "exitstatus": "OK"}
		default:
			t.Fatalf("unexpected PVE recovery request: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer server.Close()

	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "test-secret")
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")

	stateDir := t.TempDir()
	record := journal.Record{RunID: "recover-pve", Phase: "running", UpdatedAt: time.Now().UTC(), SDNOwner: "certistack recover-pve"}
	record.AddVM(9100, "node1", 0, "")
	record.AddSDNVNet("csVn77")
	record.AddSDNZone("csZone77")
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	for _, expected := range []string{
		"POST /api2/json/nodes/node1/qemu/9100/status/stop",
		"DELETE /api2/json/nodes/node1/qemu/9100",
		"DELETE /api2/json/cluster/sdn/vnets/csVn77",
		"DELETE /api2/json/cluster/sdn/vnets/csVn77/subnets/csZone77-10.89.0.0-24",
		"DELETE /api2/json/cluster/sdn/zones/csZone77",
		"POST /api2/json/cluster/sdn/lock",
		"PUT /api2/json/cluster/sdn",
	} {
		if !strings.Contains(strings.Join(calls, "\n"), expected) {
			t.Fatalf("expected recovery request %q; calls:\n%s", expected, strings.Join(calls, "\n"))
		}
	}
	loaded, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Phase != "cleaned" {
		t.Fatalf("recovered journal phase = %q, want cleaned", loaded.Phase)
	}
	// The node keeps what recovery did, whoever started it.
	logPath := filepath.Join(stateDir, "logs", "recover-pve.log")
	kept, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("recovery kept no log: %v", err)
	}
	for _, want := range []string{
		"INFO Recovering what run recover-pve left",
		"INFO Destroyed sandbox VM 9100 on node1.",
		"INFO Deleted sandbox VNet csVn77.",
		"INFO Recovered run recover-pve: its journal is clean.",
	} {
		if !strings.Contains(string(kept), want) {
			t.Errorf("recovery log lacks %q:\n%s", want, kept)
		}
	}
	if info, err := os.Stat(logPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("recovery log mode = %v, %v; want 0600", info, err)
	}
}

func TestRecoveryLogNamesTheRunAndRefusesOddNames(t *testing.T) {
	stateDir := t.TempDir()
	for _, runID := range []string{"run-3f2504e0-4f89-41d3-9a0c-0305e82c3301", "../../etc/passwd"} {
		stop := keepLog(stateDir, runID)
		say("INFO", "line for %s", runID)
		stop()
	}
	say("INFO", "not recorded")
	if _, err := os.Stat(filepath.Join(stateDir, "logs", "3f2504e0-4f89-41d3-9a0c-0305e82c3301.log")); err != nil {
		t.Fatalf("a worker run's log is not named after its workspace: %v", err)
	}
	odd, err := os.ReadFile(filepath.Join(stateDir, "logs", "unnamed-run.log"))
	if err != nil || !strings.Contains(string(odd), "line for ../../etc/passwd") || strings.Contains(string(odd), "not recorded") {
		t.Fatalf("an odd run ID's log = %q, %v", odd, err)
	}
	entries, _ := os.ReadDir(filepath.Join(stateDir, "logs"))
	if len(entries) != 2 {
		t.Fatalf("logs = %v, want two", entries)
	}
}

func TestRecover_PreservesFailedPVEResourceJournalForRetry(t *testing.T) {
	// Deliberately provide no PVE credentials. Recovery must retain this exact
	// identity for a later controller worker instead of marking it cleaned.
	t.Setenv("PVE_URL", "")
	t.Setenv("PVE_TOKEN_ID", "")
	t.Setenv("PVE_TOKEN_SECRET", "")

	stateDir := t.TempDir()
	record := journal.Record{RunID: "recover-retry", Phase: "running", UpdatedAt: time.Now().UTC()}
	record.AddVM(9101, "node1", 0, "")
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err == nil {
		t.Fatal("Recover unexpectedly succeeded without PVE credentials")
	}
	loaded, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Phase == "cleaned" || len(loaded.VMs) != 1 || loaded.VMs[0].VMID != 9101 {
		t.Fatalf("failed recovery lost retry state: %#v", loaded)
	}
}

func TestRecover_PreservesUnconfirmedAllocationForOperatorReview(t *testing.T) {
	stateDir := t.TempDir()
	record := journal.Record{
		RunID:             "recover-unconfirmed-allocation",
		Phase:             "running",
		UpdatedAt:         time.Now().UTC(),
		AllocationPending: "SDN zone csSbPending",
	}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}

	err := RecoverLocked(stateDir)
	if err == nil || !strings.Contains(err.Error(), "cannot safely reconcile unconfirmed allocation") {
		t.Fatalf("Recover error = %v; want unconfirmed allocation refusal", err)
	}
	loaded, loadErr := journal.Load(filepath.Join(stateDir, "active.json"))
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if loaded.Phase == "cleaned" || loaded.AllocationPending != record.AllocationPending {
		t.Fatalf("unconfirmed allocation was discarded: %+v", loaded)
	}
}

func TestInspect_Record(t *testing.T) {
	stateDir := t.TempDir()
	path := filepath.Join(stateDir, "active.json")

	record := journal.Record{
		RunID:      "run-test-inspect",
		Phase:      "probing",
		LoopDevice: "/dev/loop1",
		UpdatedAt:  time.Now().UTC(),
	}
	record.AddLoop("/dev/loop1", "vm/100/drive-scsi0.img")
	record.AddVM(9100, "node1", 1234, "5678")

	if err := journal.Write(path, record); err != nil {
		t.Fatalf("journal.Write failed: %v", err)
	}

	inspected, err := Inspect(stateDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if inspected.RunID != "run-test-inspect" {
		t.Errorf("expected RunID 'run-test-inspect', got '%s'", inspected.RunID)
	}
	if len(inspected.Loops) != 1 {
		t.Errorf("expected 1 loop in inspected record, got %d", len(inspected.Loops))
	}
}

func TestRecover_DoesNotDeleteScratchDirectory(t *testing.T) {
	stateDir := t.TempDir()
	scratchDir := t.TempDir()
	unrelated := filepath.Join(scratchDir, "unrelated-host-file")
	if err := os.WriteFile(unrelated, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(scratchDir, "certistack-delta-vm101.qcow2")
	if err := os.WriteFile(overlay, []byte("overlay"), 0600); err != nil {
		t.Fatal(err)
	}

	record := journal.Record{
		RunID:     "run-recovery-scratch",
		Phase:     "running",
		Scratch:   scratchDir,
		UpdatedAt: time.Now().UTC(),
	}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}

	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("recovery removed unrelated scratch content: %v", err)
	}
	if _, err := os.Stat(overlay); err != nil {
		t.Fatalf("recovery removed an unregistered overlay: %v", err)
	}
}

func TestRecover_RemovesOnlyJournalRegisteredOverlay(t *testing.T) {
	stateDir := t.TempDir()
	scratchDir := t.TempDir()
	overlay := filepath.Join(scratchDir, "certistack-delta-vm101.qcow2")
	if err := os.WriteFile(overlay, []byte("overlay"), 0600); err != nil {
		t.Fatal(err)
	}
	record := journal.Record{RunID: "run-owned-overlay", Phase: "running", Scratch: scratchDir, UpdatedAt: time.Now().UTC()}
	record.AddDeltaFile(overlay)
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("Recover failed: %v", err)
	}
	if _, err := os.Stat(overlay); !os.IsNotExist(err) {
		t.Fatalf("expected registered overlay to be removed, got: %v", err)
	}
}

// A journal whose only resource is a map begun but never recorded, and whose
// map does not exist on this host, recovers clean.
func TestRecoverLockedWithAnUnresolvedMapIntentAndNoMap(t *testing.T) {
	stateDir := t.TempDir()
	// A host with no processes and no maps, not this one: what runs on it (other
	// test runs share its /proc) is not the test's business.
	hostWithProcs(t, t.TempDir(), noSignal(t))
	path := filepath.Join(stateDir, "active.json")
	record := journal.Record{RunID: "run-map-intent", Phase: "running", UpdatedAt: time.Now().UTC()}
	record.AddMapIntent("vm/7214/2026-09-27T03:12:59Z", "drive-scsi1.img", scsi1Tail, time.Now())
	if err := journal.Write(path, record); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("RecoverLocked: %v", err)
	}
	after, err := journal.Load(path)
	if err != nil || after.Phase != "cleaned" {
		t.Fatalf("journal after recovery: %+v, %v", after, err)
	}
}

// hostWithProcs points recovery's view of the host at a fake process tree
// under root, signalling through signal, and at fake maps. It restores the
// real host when the test ends.
func hostWithProcs(t *testing.T, root string, signal func(journal.Process, syscall.Signal) error) fakeMaps {
	t.Helper()
	oldReaper, oldFinder := hostMapReaper, hostLeakFinder
	t.Cleanup(func() { hostMapReaper, hostLeakFinder = oldReaper, oldFinder })
	hostMapReaper = testReaper(root, signal)
	maps := newFakeMaps(t)
	hostLeakFinder = leakFinder{sysBlock: maps.sysBlock, runDir: maps.runDir, mountInfo: maps.mountInfo}
	oldSysBlock := sysutil.SysBlockDir
	t.Cleanup(func() { sysutil.SysBlockDir = oldSysBlock })
	sysutil.SysBlockDir = maps.sysBlock
	return maps
}

// An unresolved map's process that survives SIGINT and SIGKILL
// (both refused here) leaves recovery incomplete: the journal keeps the
// intent and the process it identified, and the next recovery tries again
// instead of skipping a cleaned journal. Once the process is gone,
// recovery completes.
func TestRecoverLockedKeepsTheJournalWhileAMapProcessSurvives(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 201, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	signals := 0
	hostWithProcs(t, root, func(journal.Process, syscall.Signal) error { signals++; return syscall.EPERM })
	path := filepath.Join(stateDir, "active.json")
	if err := journal.Write(path, journal.Record{RunID: "map-still-live", Phase: "mapping", MapIntents: []journal.MapIntent{intent}}); err != nil {
		t.Fatal(err)
	}

	err := RecoverLocked(stateDir)
	record, loadErr := journal.Load(path)
	if err == nil || loadErr != nil || record.Phase != "cleanup_failed" || len(record.CleanupErrors) != 1 || !strings.Contains(record.CleanupErrors[0], "PBS map process 201") {
		t.Fatalf("recovery = %v; journal %+v, %v; want it incomplete, naming process 201", err, record, loadErr)
	}
	if open := record.UnresolvedMapIntents(); len(open) != 1 || len(open[0].Processes) != 1 || open[0].Processes[0].PID != 201 {
		t.Fatalf("unresolved intents = %+v, want the intent with process 201", open)
	}
	if err := RecoverLocked(stateDir); err == nil || signals != 4 {
		t.Fatalf("second recovery = %v after %d signals; want it to try again", err, signals)
	}
	if err := os.RemoveAll(filepath.Join(root, "201")); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery once the process is gone: %v", err)
	}
	if record, err := journal.Load(path); err != nil || record.Phase != "cleaned" {
		t.Fatalf("journal = %+v, %v; want cleaned", record, err)
	}
}

// The journaled process is what a retry stops, even when that retry
// can no longer tell the process by its environment; and while it runs, the
// journal is not cleaned by a recovery that finds no candidate.
func TestRecoverLockedRetriesAJournaledMapProcess(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	fakeMapProc(t, root, 201, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	self, err := statIdentity(root, 201)
	if err != nil {
		t.Fatal(err)
	}
	intent.AddProcess(self)
	// A neighbor journaled long ago that is not this map: gone, PID reused.
	intent.AddProcess(journal.Process{PID: 202, StartTicks: "5"})
	fakeProc(t, root, 202, []string{"/usr/sbin/cron"}, reaperBoot.Add(time.Hour))
	if err := os.Remove(filepath.Join(root, "201", "environ")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "201", "environ"), 0o755); err != nil {
		t.Fatal(err)
	}
	var signaled []int
	hostWithProcs(t, root, func(p journal.Process, _ syscall.Signal) error {
		signaled = append(signaled, p.PID)
		return nil // ignores every signal
	})
	path := filepath.Join(stateDir, "active.json")
	if err := journal.Write(path, journal.Record{RunID: "retry", Phase: "cleanup_failed", MapIntents: []journal.MapIntent{intent}}); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err == nil || !strings.Contains(err.Error(), "PBS map process 201") {
		t.Fatalf("recovery = %v, want the journaled process reported", err)
	}
	if fmt.Sprint(signaled) != "[201 201]" {
		t.Fatalf("signalled %v, want SIGINT and SIGKILL to 201 only", signaled)
	}
	if record, err := journal.Load(path); err != nil || record.Phase != "cleanup_failed" {
		t.Fatalf("journal = %+v, %v; want it kept unclean", record, err)
	}
}

// Another operation maps the same snapshot and archive while the
// run's map is left behind: from another repository, and a restore whose
// target is named "map". Recovery stops the run's own map, leaves both
// alone, and is complete.
func TestRecoverLockedLeavesAnotherOperationsMapAlone(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	intent := ownIntent(at)
	started := at.Add(time.Second)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), started, ownRepo, "team-a", ownToken)
	fakeMapProc(t, root, 101, mapArgv(otherRepo), started, otherRepo, "team-a", "")
	fakeMapProc(t, root, 102, []string{"/usr/bin/proxmox-backup-client", "restore", "--repository", otherRepo, mapSnapshot, mapArchive, "map"}, started, otherRepo, "team-a", "")
	var signaled []int
	hostWithProcs(t, root, func(p journal.Process, _ syscall.Signal) error {
		signaled = append(signaled, p.PID)
		return os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID)))
	})
	path := filepath.Join(stateDir, "active.json")
	if err := journal.Write(path, journal.Record{RunID: "two-maps", Phase: "mapping", MapIntents: []journal.MapIntent{intent}}); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery = %v, want it complete", err)
	}
	if fmt.Sprint(signaled) != "[100]" || !present(root, 101) || !present(root, 102) {
		t.Fatalf("signalled %v; 101 present %v, 102 present %v; want only the run's own 100 stopped", signaled, present(root, 101), present(root, 102))
	}
}

// A journal from an earlier version has no token, no owner and no
// processes. Recovery loads it, stops no process it cannot prove the run's,
// keeps the journal unclean with what it found, and completes once the
// operator has stopped the process.
func TestRecoverLockedOfAnRc1JournalStopsNoMapProcess(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", "")
	hostWithProcs(t, root, noSignal(t))
	// Exactly what an earlier version wrote.
	earlierJournal := `{"run_id":"run-earlier-1","phase":"mapping","updated_at":"2026-09-27T10:00:00Z","scratch":"","map_intents":[{"snapshot":"` + mapSnapshot + `","archive":"` + mapArchive + `","name_suffix":"x","at":"` + at.Format(time.RFC3339) + `"}]}`
	path := filepath.Join(stateDir, "active.json")
	if err := os.WriteFile(path, []byte(earlierJournal), 0o600); err != nil {
		t.Fatal(err)
	}
	err := RecoverLocked(stateDir)
	record, loadErr := journal.Load(path)
	if err == nil || loadErr != nil || record.Phase != "cleanup_failed" || !strings.Contains(err.Error(), "process 100") || len(record.UnresolvedMapIntents()) != 1 {
		t.Fatalf("recovery = %v; journal %+v, %v; want it incomplete, naming process 100", err, record, loadErr)
	}
	if !present(root, 100) {
		t.Fatal("the process was touched")
	}
	if err := os.RemoveAll(filepath.Join(root, "100")); err != nil { // the operator stops it
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery once the process is gone: %v", err)
	}
	if record, err := journal.Load(path); err != nil || record.Phase != "cleaned" {
		t.Fatalf("journal = %+v, %v; want cleaned", record, err)
	}
}

// The identity a retry needs is on disk before the process is
// signalled: a recovery killed in the middle of its stop (the journal is
// what survives) still names it.
func TestRecoverLockedJournalsAMapProcessBeforeSignallingIt(t *testing.T) {
	root, stateDir := t.TempDir(), t.TempDir()
	at := reaperBoot.Add(10 * time.Hour)
	fakeMapProc(t, root, 100, mapArgv(ownRepo), at.Add(time.Second), ownRepo, "team-a", ownToken)
	self, err := statIdentity(root, 100)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "active.json")
	journaled := false
	hostWithProcs(t, root, func(p journal.Process, _ syscall.Signal) error {
		record, err := journal.Load(path)
		if err != nil {
			t.Errorf("journal at the time of the signal: %v", err)
			return nil
		}
		if open := record.UnresolvedMapIntents(); len(open) == 1 && len(open[0].Processes) == 1 && open[0].Processes[0] == p && p == self {
			journaled = true
		}
		return os.RemoveAll(filepath.Join(root, fmt.Sprint(p.PID)))
	})
	if err := journal.Write(path, journal.Record{RunID: "journal-first", Phase: "mapping", MapIntents: []journal.MapIntent{ownIntent(at)}}); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if !journaled {
		t.Fatal("the process was signalled before the journal named it")
	}
}

// A run that died holding PVE's SDN lock left every SDN change in the
// cluster refused. Recovery releases it with the token the run journaled.
func TestRecoverReleasesTheSDNLockADeadRunHeld(t *testing.T) {
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": nil})
	}))
	defer server.Close()
	t.Setenv("PVE_URL", server.URL)
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "test-secret")
	t.Setenv("PVE_TLS_INSECURE", "")
	t.Setenv("CERTISTACK_PVE_CA_SOURCE", "")

	stateDir := t.TempDir()
	record := journal.Record{RunID: "recover-sdn-lock", Phase: "running", UpdatedAt: time.Now().UTC(), SDNLockToken: "dead-tok"}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), record); err != nil {
		t.Fatal(err)
	}
	if err := RecoverLocked(stateDir); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if got := strings.Join(calls, "\n"); got != "DELETE /api2/json/cluster/sdn/lock?lock-token=dead-tok" {
		t.Fatalf("requests:\n%s\nwant the lock released with the journaled token", got)
	}
	loaded, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil || loaded.Phase != "cleaned" || loaded.SDNLockToken != "" {
		t.Fatalf("journal = %+v, %v; want cleaned with no lock", loaded, err)
	}
}
