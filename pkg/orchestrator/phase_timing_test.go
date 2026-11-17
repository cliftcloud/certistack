// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// A phase's duration was added to the report's phase timings only
// after the phase succeeded, so the report of a run that failed in it showed
// zero for the work that failed or stalled and left the time unexplained. The
// tests below fail each phase they can reach after a delay, and check that the
// report keeps the delay.

// phaseSum is the time the report names: every phase.
func phaseSum(t *attest.PhaseTimings) float64 {
	return t.AdmissionCheckSec + t.SDNProvisioningSec + t.PBSMappingSec + t.OverlayCreationSec +
		t.COWGuestNetworkRecoverySec + t.VMRegistrationSec + t.VMStartSec + t.QMPRunningWaitSec +
		t.IntegrityVerificationSec + t.StartupGracePeriodSec + t.ProbesExecutionSec + t.SoakTimeSec + t.TeardownSec
}

// Two failed runs keep the durations of their phases: an admission that kept
// retrying until it gave up, and an SDN setup that failed after 250 milliseconds.
func TestFailedAdmissionAndSDNKeepTheirDurations(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("admission reads the node's /proc counters")
	}
	plan := networkOnlyPlan()
	plan.PlanID = "failed-admission-timing"
	plan.AdmissionControl.MaxHostRAMPercent = 0.00001
	plan.AdmissionControl.MaxDeferRetries = 1
	o := New(plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: "http://127.0.0.1:1"}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := o.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "admission control guardrail triggered") {
		t.Fatalf("admission error = %v, want the guardrail failure", err)
	}
	timings := result.PhaseTimings
	// Two checks and the one-second retry interval between them.
	if timings.AdmissionCheckSec < 1.0 {
		t.Errorf("a failed admission that waited a second to retry recorded %.3fs of admission (total %.3fs)", timings.AdmissionCheckSec, timings.TotalRTOSec)
	}
	if gap := timings.TotalRTOSec - phaseSum(timings); gap > timings.AdmissionCheckSec {
		t.Errorf("%.3fs of the failed run's %.3fs is in no phase, more than the %.3fs of admission", gap, timings.TotalRTOSec, timings.AdmissionCheckSec)
	}

	const delay = 250 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		http.Error(w, `{"data":null,"message":"synthetic SDN refusal"}`, http.StatusBadRequest)
	}))
	defer server.Close()
	sdnPlan := networkOnlyPlan()
	sdnPlan.PlanID = "failed-sdn-timing"
	sdn := New(sdnPlan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: server.URL}))
	sdn.hostAddresses = &fakeHostAddressManager{}
	result, err = sdn.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "SDN sandbox setup failed") {
		t.Fatalf("SDN error = %v, want the setup failure", err)
	}
	timings = result.PhaseTimings
	if timings.AdmissionCheckSec <= 0 {
		t.Errorf("the admission that succeeded recorded %.3fs", timings.AdmissionCheckSec)
	}
	if timings.SDNProvisioningSec < delay.Seconds()*0.9 {
		t.Errorf("an SDN setup that failed after %v recorded %.3fs of SDN (total %.3fs)", delay, timings.SDNProvisioningSec, timings.TotalRTOSec)
	}
	if gap := timings.TotalRTOSec - phaseSum(timings); gap > timings.SDNProvisioningSec {
		t.Errorf("%.3fs of the failed run's %.3fs is in no phase, more than the %.3fs of SDN", gap, timings.TotalRTOSec, timings.SDNProvisioningSec)
	}
}

// An admission the operator cancels while it waits to retry keeps the time it
// waited, too.
func TestACancelledAdmissionKeepsTheTimeItWaited(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("admission reads the node's /proc counters")
	}
	plan := networkOnlyPlan()
	plan.PlanID = "cancelled-admission-timing"
	plan.AdmissionControl.MaxHostRAMPercent = 0.00001
	plan.AdmissionControl.MaxDeferRetries = 5
	plan.AdmissionControl.DeferRetryIntervalSec = 30
	o := New(plan, Options{ScratchDir: t.TempDir(), StateDir: t.TempDir()}, pbs.New(pbs.Config{}), pve.NewClient(pve.Config{BaseURL: "http://127.0.0.1:1"}))
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	result, err := o.Run(ctx)
	if err == nil {
		t.Fatal("a cancelled admission succeeded")
	}
	if timings := result.PhaseTimings; timings.AdmissionCheckSec < 1.0 {
		t.Errorf("an admission cancelled after 1.5s recorded %.3fs", timings.AdmissionCheckSec)
	}
}

// phaseHarness maps the test VM as a run does (see scanOrchestrator) against a
// PVE that answers what a restore asks until it reaches the phase under test.
type phaseHarness struct {
	o       *Orchestrator
	vm      config.VM
	timings *attest.PhaseTimings
}

// newPhaseHarness: createDelay and startDelay make VM creation and the start
// request take that long and then fail; a zero createDelay lets the creation
// succeed. qemuImg is the body of the fake qemu-img that makes the overlay.
func newPhaseHarness(t *testing.T, qemuImg string, scanDelay, createDelay, startDelay time.Duration, scanFails bool) *phaseHarness {
	t.Helper()
	f := newLoopFixture(t, "exit 0")
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.log), "qemu-img"), []byte("#!/bin/sh\n"+qemuImg), 0o755); err != nil {
		t.Fatal(err)
	}
	const upid = "UPID:localhost:1:1:1:1:1:"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api2/json/")
		reply := func(data string) { _ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(data)}) }
		switch {
		case r.Method == http.MethodGet && path == "cluster/resources":
			reply(`[]`)
		case r.Method == http.MethodGet && path == "nodes/localhost/qemu/9001/status/current":
			http.Error(w, `{"errors": "Configuration file does not exist"}`, http.StatusNotFound)
		case r.Method == http.MethodGet && path == "nodes/localhost/capabilities/qemu/machines":
			reply(`[]`)
		case r.Method == http.MethodPost && path == "nodes/localhost/qemu":
			time.Sleep(createDelay)
			if createDelay > 0 {
				http.Error(w, `{"data":null,"message":"synthetic create refusal"}`, http.StatusInternalServerError)
				return
			}
			reply(`"` + upid + `"`)
		case r.Method == http.MethodGet && path == "nodes/localhost/tasks/"+upid+"/status":
			reply(`{"status":"stopped","exitstatus":"OK"}`)
		case r.Method == http.MethodGet && path == "nodes/localhost/qemu/9001/config":
			reply(`{}`)
		case r.Method == http.MethodPost && path == "nodes/localhost/qemu/9001/status/start":
			time.Sleep(startDelay)
			http.Error(w, `{"data":null,"message":"synthetic start refusal"}`, http.StatusInternalServerError)
		default:
			t.Errorf("unexpected PVE request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	o, _ := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	o.pveClient = pve.NewClient(pve.Config{BaseURL: server.URL})
	if err := os.Chmod(o.opts.ScratchDir, 0o700); err != nil { // the overlay's directory must be private
		t.Fatal(err)
	}
	o.deviceBytesFn = func(string) (int64, error) { return 36 << 20, nil }
	o.freeBytesFn = func(string) (int64, error) { return 500 << 30, nil }
	o.sharedDisksFn = func(context.Context, string, string) ([]string, error) { return nil, nil }
	o.verifyImageFn = func(_ context.Context, _, _ string, _ pbs.DiskSize, _ func(int64)) (*pbs.VerifySummary, string, error) {
		time.Sleep(scanDelay)
		if scanFails {
			return nil, "", errScanStops
		}
		return &pbs.VerifySummary{Detail: "verified", BytesRead: 36 << 20}, strings.Repeat("ab", 32), nil
	}
	o.plan.Network = config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}
	vm := mapTestVM()
	vm.NetworkRecovery = config.NetworkRecovery{Mode: "preserve"}
	vm.CopyBeforeBoot = config.CopyBeforeBootNever
	vm.SourceImageBytes = map[string]int64{"scsi0": 36 << 20}
	vm.SourceDiskBytes = map[string]int64{"scsi0": 33 << 20}
	return &phaseHarness{o: o, vm: vm, timings: &attest.PhaseTimings{}}
}

func (h *phaseHarness) run(t *testing.T) error {
	t.Helper()
	_, err := h.o.bootAndVerifyVM(context.Background(), h.vm, 60, h.timings)
	return err
}

const okQemuImg = "for last; do :; done\n: > \"$last\"\n"

// The phases of a restore that a delayed failure can reach without a hypervisor:
// each keeps the time it took.
func TestAFailedRestorePhaseKeepsItsDuration(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fake commands are shell scripts")
	}
	const delay = 300 * time.Millisecond
	seconds := delay.Seconds() * 0.8
	t.Run("overlay creation", func(t *testing.T) {
		h := newPhaseHarness(t, "/bin/sleep 0.3\nexit 1\n", 0, 0, 0, false)
		if err := h.run(t); err == nil || !strings.Contains(err.Error(), "delta overlay") {
			t.Fatalf("restore = %v, want the overlay refused", err)
		}
		if h.timings.OverlayCreationSec < seconds {
			t.Errorf("an overlay that failed after %v recorded %.3fs", delay, h.timings.OverlayCreationSec)
		}
	})
	t.Run("integrity verification", func(t *testing.T) {
		h := newPhaseHarness(t, okQemuImg, delay, 0, 0, true)
		if err := h.run(t); err == nil {
			t.Fatal("a failed scan succeeded")
		}
		if h.timings.IntegrityVerificationSec < seconds {
			t.Errorf("a scan that failed after %v recorded %.3fs", delay, h.timings.IntegrityVerificationSec)
		}
	})
	t.Run("VM registration", func(t *testing.T) {
		h := newPhaseHarness(t, okQemuImg, 0, delay, 0, false)
		if err := h.run(t); err == nil || !strings.Contains(err.Error(), "CreateVM") {
			t.Fatalf("restore = %v, want the VM creation refused", err)
		}
		if h.timings.VMRegistrationSec < seconds {
			t.Errorf("a registration that failed after %v recorded %.3fs", delay, h.timings.VMRegistrationSec)
		}
	})
	t.Run("VM start", func(t *testing.T) {
		h := newPhaseHarness(t, okQemuImg, 0, 0, delay, false)
		if err := h.run(t); err == nil || !strings.Contains(err.Error(), "StartVM") {
			t.Fatalf("restore = %v, want the VM start refused", err)
		}
		if h.timings.VMStartSec < seconds {
			t.Errorf("a start that failed after %v recorded %.3fs", delay, h.timings.VMStartSec)
		}
		if h.timings.VMRegistrationSec <= 0 {
			t.Errorf("the registration that succeeded recorded %.3fs", h.timings.VMRegistrationSec)
		}
	})
}

// The phases a unit test cannot drive to a delayed failure (the Stage 1 wait for
// the hypervisor, and the tier's startup grace period and soak, which need a
// running VM) are held by their shape: a phase timer is stopped, or its stop
// deferred, before any return that follows its start, and a tier wait adds its
// time before its error is looked at.
func TestEveryPhaseIsTimedWhicheverWayItEnds(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "orchestrator.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	started := 0
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// timers maps a timer variable to whether it has been stopped (or its
		// stop deferred) yet, as the statements are walked in source order.
		timers := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false // a return inside a closure is not the function's
			case *ast.AssignStmt:
				if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
					if call, ok := n.Rhs[0].(*ast.CallExpr); ok {
						if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "startPhase" {
							timers[n.Lhs[0].(*ast.Ident).Name] = false
							started++
						}
					}
				}
			case *ast.CallExpr:
				if selector, ok := n.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "stop" {
					if receiver, ok := selector.X.(*ast.Ident); ok {
						if _, known := timers[receiver.Name]; known {
							timers[receiver.Name] = true
						}
					}
				}
			case *ast.ReturnStmt:
				for name, stopped := range timers {
					if !stopped {
						t.Errorf("%s: the return at %s comes before the phase timer %s is stopped, so a failure here leaves the phase out of the report", fn.Name.Name, fset.Position(n.Pos()), name)
					}
				}
			}
			return true
		})
	}
	if started < 6 {
		t.Errorf("found %d phase timers in orchestrator.go, want at least 6 (admission, SDN, overlay, registration, start, Stage 1)", started)
	}

	// A tier wait (the startup grace and the soak) starts its clock in a
	// statement of the tier loop's block, and its time is added by a later
	// statement of the same block that comes before the first one that returns
	// on an error: the wait's error is looked at only after its time is counted.
	for _, tierWait := range []struct{ clock, field string }{{"tSoak", "StartupGracePeriodSec"}, {"tSoakEnd", "SoakTimeSec"}} {
		found := false
		ast.Inspect(file, func(n ast.Node) bool {
			block, ok := n.(*ast.BlockStmt)
			if !ok {
				return true
			}
			clock := -1
			for i, stmt := range block.List {
				if assign, ok := stmt.(*ast.AssignStmt); ok && len(assign.Lhs) == 1 {
					if name, ok := assign.Lhs[0].(*ast.Ident); ok && name.Name == tierWait.clock {
						clock = i
					}
				}
			}
			if clock < 0 {
				return true
			}
			counted, checked := -1, -1
			for i := clock + 1; i < len(block.List); i++ {
				text := sourceOf(fset, block.List[i:i+1])
				if _, isIf := block.List[i].(*ast.IfStmt); isIf && checked < 0 && strings.Contains(text[:min(len(text), 40)], "err != nil") {
					checked = i
				}
				if counted < 0 && strings.HasPrefix(strings.TrimSpace(text), "timings."+tierWait.field) {
					counted = i
				}
			}
			if counted > clock && checked > counted {
				found = true
			}
			return true
		})
		if !found {
			t.Errorf("the tier wait timed by %s does not add its time to %s before its error is checked", tierWait.clock, tierWait.field)
		}
	}
}

// sourceOf is the source text of statements, from the file on disk.
func sourceOf(fset *token.FileSet, stmts []ast.Stmt) string {
	if len(stmts) == 0 {
		return ""
	}
	start, end := fset.Position(stmts[0].Pos()), fset.Position(stmts[len(stmts)-1].End())
	data, err := os.ReadFile(start.Filename)
	if err != nil || end.Offset > len(data) {
		return ""
	}
	return string(data[start.Offset:end.Offset])
}

// A phase is stopped where it ends and also deferred to cover its early
// returns: the first stop counts, and a later one must not count it again.
func TestAPhaseTimerCountsOnce(t *testing.T) {
	var seconds float64
	timer := startPhase(&seconds)
	time.Sleep(50 * time.Millisecond)
	timer.stop()
	first := seconds
	if first < 0.04 {
		t.Fatalf("a phase of 50ms recorded %.3fs", first)
	}
	time.Sleep(50 * time.Millisecond)
	timer.stop()
	if seconds != first {
		t.Errorf("a second stop changed the phase from %.3fs to %.3fs", first, seconds)
	}
	var none *phaseTimer
	none.stop() // a timer that was never started stops nothing
}
