// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// What PVE answers a VM status read with, for the soak and watcher tests.
const (
	pveRunning int32 = iota
	pveStopped
	pveUnauthorized
	pveForbidden
	pveMalformed
	pveNoState
	pveErrored
	pveGone
	pveHangs
)

// statusPVE is a PVE that answers VM status reads as a test sets it to, per VM
// or for all: running, stopped, or one of the ways it can fail to say.
type statusPVE struct {
	reads  atomic.Int64
	mode   atomic.Int32
	mu     sync.Mutex
	vmMode map[int]int32
	client *pve.Client
}

func newStatusPVE(t *testing.T) *statusPVE {
	t.Helper()
	f := &statusPVE{vmMode: map[int]int32{}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if !strings.HasSuffix(r.URL.Path, "/status/current") || len(parts) < 3 {
			http.NotFound(w, r)
			return
		}
		vmid, _ := strconv.Atoi(parts[len(parts)-3])
		f.reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch f.modeOf(vmid) {
		case pveRunning:
			_, _ = w.Write([]byte(`{"data":{"status":"running","qmpstatus":"running"}}`))
		case pveStopped:
			_, _ = w.Write([]byte(`{"data":{"status":"stopped","qmpstatus":"shutdown"}}`))
		case pveUnauthorized:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"audit status endpoint unavailable"}`))
		case pveForbidden:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"Permission check failed (/vms/` + strconv.Itoa(vmid) + `, VM.Audit)"}`))
		case pveMalformed:
			_, _ = w.Write([]byte(`{"data": {"status": "runn`))
		case pveNoState:
			_, _ = w.Write([]byte(`{"data":null}`))
		case pveErrored:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"pveproxy worker exited"}`))
		case pveHangs:
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		case pveGone:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, `{"message":"Configuration file 'nodes/pve1/qemu-server/%d.conf' does not exist"}`, vmid)
		}
	}))
	t.Cleanup(server.Close)
	f.client = pve.NewClient(pve.Config{BaseURL: server.URL})
	return f
}

func (f *statusPVE) modeOf(vmid int) int32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if mode, ok := f.vmMode[vmid]; ok {
		return mode
	}
	return f.mode.Load()
}

func (f *statusPVE) setVM(vmid int, mode int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vmMode[vmid] = mode
}

// soakFast makes the soak's cadence and the halt polls short.
func soakFast(t *testing.T, interval time.Duration) {
	t.Helper()
	fastHaltPolls(t)
	oldInterval, oldLimit := soakSampleInterval, statusUnknownLimit
	soakSampleInterval = interval
	t.Cleanup(func() { soakSampleInterval, statusUnknownLimit = oldInterval, oldLimit })
}

func soakOrchestrator(t *testing.T, f *statusPVE) *Orchestrator {
	t.Helper()
	return New(&config.Plan{}, Options{NodeName: "pve1", StateDir: t.TempDir()}, nil, f.client)
}

// soakHostPort splits a test server's address.
func soakHostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

// toggledService is an HTTP service on loopback that a test turns on and off:
// off, it answers 503.
type toggledService struct {
	up   atomic.Bool
	hits atomic.Int64
	// lastHit is when the service was last reached, in Unix nanoseconds.
	lastHit atomic.Int64
	host    string
	port    int
}

func newToggledService(t *testing.T) *toggledService {
	t.Helper()
	service := &toggledService{}
	service.up.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		service.hits.Add(1)
		service.lastHit.Store(time.Now().UnixNano())
		if !service.up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	service.host, service.port = soakHostPort(t, server.URL)
	return service
}

// reachedTimes blocks until the service has been reached n times (or ten
// seconds have passed): a test that wants its outage after the soak's first
// passing checks waits for them instead of for a time that a loaded machine can
// overrun.
func (s *toggledService) reachedTimes(n int64) {
	for deadline := time.Now().Add(10 * time.Second); s.hits.Load() < n && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *toggledService) probe(timeoutSec int) config.Probe {
	return config.Probe{Type: "http", TargetIP: s.host, Port: s.port, Path: "/", ExpectedStatus: http.StatusOK, TimeoutSec: timeoutSec, Description: "web service"}
}

// soakRun is what runProbes records for vm and then what the soak makes of it:
// the stage passes first, as it must for the VM to reach the soak at all.
func soakRun(t *testing.T, o *Orchestrator, vm config.VM, soakSec int) (map[int]error, map[int]*probe.SoakEvidence, []probe.Result, error) {
	t.Helper()
	stage, passed, err := o.runProbes(context.Background(), vm)
	if err != nil || !passed {
		t.Fatalf("the probe stage did not pass: passed=%v err=%v results=%+v", passed, err, stage)
	}
	failed, evidence, soakErr := o.soakTier(context.Background(), config.Tier{Level: 1, Name: "soak", SoakTimeSec: soakSec}, []tierVMRun{{config: vm, recordIndex: 0, results: stage}})
	return failed, evidence, stage, soakErr
}

// passRecord is the record a report would carry for a VM that passed, to hand
// the report rules.
func passRecord(vm config.VM, stage []probe.Result, soak *probe.SoakEvidence) probe.VMValidationRecord {
	return probe.VMValidationRecord{VMID: vm.VMID, Name: vm.Name, ProbeResults: stage, VerificationStatus: "verified", AllPassed: true, Soak: soak}
}

// A loopback service answers the real probe once and then closes. The soak
// does not pass the VM on PVE status reads alone: the service checks come
// back after the first sample, find the service gone, and fail the VM with
// the check's evidence.
func TestSoakCatchesAServiceThatAnsweredOnceAndClosed(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port := soakHostPort(t, "tcp://"+listener.Addr().String())
	closed := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		_ = listener.Close()
		close(closed)
	}()
	f := newStatusPVE(t)
	o := soakOrchestrator(t, f)
	vm := config.VM{VMID: 9198, Name: "audit-soak-vm", Probes: []config.Probe{{Type: "tcp", TargetIP: host, Port: port, TimeoutSec: 1, Description: "audit service listener"}}}

	stage, passed, probeErr := o.runProbes(context.Background(), vm)
	if probeErr != nil || !passed {
		t.Fatalf("the first probe: passed=%v err=%v", passed, probeErr)
	}
	<-closed

	start := time.Now()
	failed, evidence, soakErr := o.soakTier(context.Background(), config.Tier{Level: 1, SoakTimeSec: 1}, []tierVMRun{{config: vm, results: stage}})
	if soakErr != nil {
		t.Fatal(soakErr)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("the soak took %s", time.Since(start))
	}
	failure := failed[vm.VMID]
	if failure == nil || !strings.Contains(failure.Error(), "service check 1 of the soak failed") || !strings.Contains(failure.Error(), "audit service listener") {
		t.Fatalf("the VM whose service was gone passed the soak: failure = %v", failure)
	}
	summary := evidence[vm.VMID]
	if summary == nil || summary.Samples != 1 || summary.FailedSamples != 1 || len(summary.Probes) != 1 || summary.Probes[0].Failed != 1 || summary.Probes[0].FirstError == "" {
		t.Fatalf("the soak summary does not say the check failed: %+v", summary)
	}
	if f.reads.Load() == 0 {
		t.Error("the soak did not read the VM's state from PVE at all")
	}
	// A report cannot present that VM as a pass.
	record := passRecord(vm, stage, summary)
	if problems := attest.SoakProblems(record, &vm, 1, true); len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), "failed") {
		t.Errorf("the report rules accept a pass built on a failed service check: %v", problems)
	}
}

// A service that keeps answering is checked at the cadence and at the end of
// the period, and the VM's summary says so; the hypervisor-only probes are not
// repeated.
func TestSoakRepeatsTheServiceProbesAndSummarisesTheChecks(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	f := newStatusPVE(t)
	o := soakOrchestrator(t, f)
	service := newToggledService(t)
	vm := config.VM{VMID: 9001, Name: "web", Probes: []config.Probe{
		{Type: "qmp", TimeoutSec: 1, Description: "VM is running"},
		service.probe(2),
	}}
	// The probe stage passed for both probes; the qmp probe would fail here
	// (there is no QEMU), so a soak that repeated it would fail the VM.
	stage := []probe.Result{
		{Type: "qmp", Description: "VM is running", Passed: true},
		{Type: "http", Target: fmt.Sprintf("http://%s:%d/", service.host, service.port), Description: "web service", Passed: true},
	}
	soakStart := time.Now()
	failed, evidence, err := o.soakTier(context.Background(), config.Tier{Level: 1, SoakTimeSec: 1}, []tierVMRun{{config: vm, results: stage}})
	if err != nil || len(failed) != 0 {
		t.Fatalf("soak: failed=%v err=%v", failed, err)
	}
	summary := evidence[vm.VMID]
	if summary == nil {
		t.Fatal("no soak summary")
	}
	// The soak ends with a check made when the period is over, not before it.
	if lastCheck := time.Unix(0, service.lastHit.Load()); lastCheck.Sub(soakStart) < time.Second {
		t.Errorf("the last service check was %s into a 1 s soak; the soak must end with one made when the period is over", lastCheck.Sub(soakStart))
	}
	if summary.Samples < 3 || summary.FailedSamples != 0 || summary.ConfiguredSec != 1 || summary.IntervalSec != 1 {
		// IntervalSec rounds the 100 ms test cadence up to a whole second.
		t.Errorf("summary = %+v, want at least 3 checks at the 100 ms cadence, none failed", summary)
	}
	if len(summary.Probes) != 1 || summary.Probes[0].Probe != 2 || summary.Probes[0].Type != "http" || summary.Probes[0].Passed != summary.Samples || summary.Probes[0].WorstDuration <= 0 {
		t.Errorf("probe entries = %+v, want only the http probe (position 2), passed in every check", summary.Probes)
	}
	if service.hits.Load() < int64(summary.Samples) {
		t.Errorf("the service was reached %d times for %d checks", service.hits.Load(), summary.Samples)
	}
	started, first, last := parseStamp(t, summary.StartedAt), parseStamp(t, summary.FirstSampleAt), parseStamp(t, summary.LastSampleAt)
	if last.Sub(started) < time.Second || first.Before(started) || last.Before(first) {
		t.Errorf("times started=%s first=%s last=%s: the last check must be at or after the end of the 1 s period", summary.StartedAt, summary.FirstSampleAt, summary.LastSampleAt)
	}
	if summary.StatusReads < 1 || summary.StatusReadFailures != 0 {
		t.Errorf("status reads = %d, failures %d", summary.StatusReads, summary.StatusReadFailures)
	}
	// The VM is a pass by the report rules, with the summary the soak made.
	record := passRecord(vm, stage, summary)
	if problems := attest.SoakProblems(record, &vm, 1, true); len(problems) != 0 {
		t.Errorf("the report rules refuse an honest soak: %v", problems)
	}
	if encoded, _ := json.Marshal(summary); len(encoded) > 2048 {
		t.Errorf("the summary is %d bytes; it must stay small however long the soak", len(encoded))
	}
}

func parseStamp(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("%q is not an RFC 3339 time: %v", value, err)
	}
	return parsed
}

// A service that fails a check mid-soak and recovers before the end
// still fails the VM, and the soak stops checking it: one failed check fails
// the run.
func TestSoakFailsAVMWhoseServiceWentDownMidSoakAndCameBack(t *testing.T) {
	soakFast(t, 150*time.Millisecond)
	f := newStatusPVE(t)
	o := soakOrchestrator(t, f)
	service := newToggledService(t)
	vm := config.VM{VMID: 9001, Name: "web", Probes: []config.Probe{service.probe(1)}}
	go func() {
		service.reachedTimes(3) // the probe stage and two passing checks
		service.up.Store(false)
		time.Sleep(1500 * time.Millisecond)
		service.up.Store(true)
	}()
	start := time.Now()
	failed, evidence, _, err := soakRun(t, o, vm, 6)
	if err != nil {
		t.Fatal(err)
	}
	if failed[vm.VMID] == nil {
		t.Fatal("a service that was down for longer than its probe's budget passed the soak")
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Errorf("the soak ran %s for a VM that had already failed; it stops checking it", elapsed)
	}
	summary := evidence[vm.VMID]
	if summary.FailedSamples != 1 || summary.Samples < 2 || summary.Probes[0].Passed < 1 || summary.Probes[0].Failed != 1 {
		t.Errorf("summary = %+v, want earlier checks passed and exactly one failed", summary)
	}
}

// The policy has a boundary and it is documented: a check is the probe under
// the plan's own policy, so an outage that ends inside the probe's timeout
// (its readiness polling) is not a failed check.
func TestSoakAbsorbsAnOutageThatEndsInsideTheProbesOwnBudget(t *testing.T) {
	soakFast(t, 150*time.Millisecond)
	f := newStatusPVE(t)
	o := soakOrchestrator(t, f)
	service := newToggledService(t)
	vm := config.VM{VMID: 9001, Name: "web", Probes: []config.Probe{service.probe(3)}}
	go func() {
		service.reachedTimes(3)
		service.up.Store(false)
		time.Sleep(500 * time.Millisecond)
		service.up.Store(true)
	}()
	failed, evidence, _, err := soakRun(t, o, vm, 2)
	if err != nil || len(failed) != 0 {
		t.Fatalf("an outage shorter than the probe's budget failed the soak: failed=%v err=%v", failed, err)
	}
	if summary := evidence[vm.VMID]; summary.FailedSamples != 0 || summary.Samples < 2 {
		t.Errorf("summary = %+v", summary)
	}
}

// A VM that halts during the soak is still found, and fails alone: its peer
// goes on being checked to the end of the period.
func TestSoakDropsAHaltedVMAndKeepsCheckingItsPeer(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	f := newStatusPVE(t)
	o := soakOrchestrator(t, f)
	service := newToggledService(t)
	a := config.VM{VMID: 9001, Name: "a", Probes: []config.Probe{service.probe(1)}}
	b := config.VM{VMID: 9002, Name: "b", Probes: []config.Probe{service.probe(1)}}
	stage := func(vm config.VM) []probe.Result {
		return []probe.Result{{Type: "http", Target: fmt.Sprintf("http://%s:%d/", service.host, service.port), Description: "web service", Passed: true}}
	}
	go func() {
		time.Sleep(350 * time.Millisecond)
		f.setVM(9001, pveStopped)
	}()
	failed, evidence, err := o.soakTier(context.Background(), config.Tier{Level: 1, SoakTimeSec: 1}, []tierVMRun{
		{config: a, recordIndex: 0, results: stage(a)}, {config: b, recordIndex: 1, results: stage(b)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := failed[9001]; got == nil || !strings.Contains(got.Error(), "VM 9001 is no longer running") {
		t.Errorf("VM 9001 (halted): %v", got)
	}
	if got, bad := failed[9002]; bad {
		t.Fatalf("VM 9002 (running, its service up) failed the soak: %v", got)
	}
	if evidence[9001].FailedSamples != 0 {
		t.Errorf("a halt is not a failed service check: %+v", evidence[9001])
	}
	summary := evidence[9002]
	if summary.Samples < 2 || summary.FailedSamples != 0 || parseStamp(t, summary.LastSampleAt).Sub(parseStamp(t, summary.StartedAt)) < time.Second {
		t.Errorf("the peer was not checked to the end of the period: %+v", summary)
	}
}

// An interruption ends the soak with the run's error, and the check it
// interrupted is neither recorded nor a failed service.
func TestSoakInterruptedMidCheckIsNotAServiceFailure(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	f := newStatusPVE(t)
	o := soakOrchestrator(t, f)
	service := newToggledService(t)
	vm := config.VM{VMID: 9001, Probes: []config.Probe{service.probe(30)}}
	stage, passed, err := o.runProbes(context.Background(), vm)
	if err != nil || !passed {
		t.Fatal(err)
	}
	service.up.Store(false)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(400 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	failed, evidence, soakErr := o.soakTier(ctx, config.Tier{Level: 1, SoakTimeSec: 60}, []tierVMRun{{config: vm, results: stage}})
	if soakErr == nil || ctx.Err() == nil {
		t.Fatalf("soak error = %v, want the interruption", soakErr)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("the interrupted soak took %s to end", time.Since(start))
	}
	if len(failed) != 0 || evidence[vm.VMID].FailedSamples != 0 || evidence[vm.VMID].Probes[0].Failed != 0 {
		t.Errorf("the interrupted check was counted: failed=%v summary=%+v", failed, evidence[vm.VMID])
	}
}

// PVE refuses every status read (HTTP 401) while the VM is stopped. The wait
// does not complete as if nothing halted: it fails the VM as one whose state
// is unknown, and the same VM, once readable, is found stopped.
func TestWaitDoesNotTakeAnUnreadableVMForARunningOne(t *testing.T) {
	fastHaltPolls(t)
	f := newStatusPVE(t)
	f.mode.Store(pveUnauthorized)
	o := soakOrchestrator(t, f)
	start := time.Now()
	halted, err := o.waitWatchingVMs(context.Background(), 4*time.Second, []int{9199})
	if err != nil {
		t.Fatal(err)
	}
	failure := halted[9199]
	var unobservable *vmUnobservableError
	if failure == nil || !asUnobservable(failure, &unobservable) {
		t.Fatalf("a VM whose status PVE refused for the whole wait passed it: halted = %v", halted)
	}
	if !strings.Contains(failure.Error(), "VM.Audit") || !strings.Contains(failure.Error(), "HTTP 401") {
		t.Errorf("the failure does not say what PVE answered or what the token needs: %v", failure)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("a refusal (401) took %s to be called in a 4 s wait; it cannot get better by waiting", elapsed)
	}
	// The same VM, once PVE says, is found stopped by the same helper.
	f.mode.Store(pveStopped)
	var haltedErr *vmHaltedError
	if err := o.vmHalted(context.Background(), 9199); !asHalted(err, &haltedErr) {
		t.Fatalf("vmHalted of a readable stopped VM = %v", err)
	}
}

func asUnobservable(err error, target **vmUnobservableError) bool {
	if u, ok := err.(*vmUnobservableError); ok {
		*target = u
		return true
	}
	return false
}

func asHalted(err error, target **vmHaltedError) bool {
	if h, ok := err.(*vmHaltedError); ok {
		*target = h
		return true
	}
	return false
}

// A status PVE cannot give is not a running VM, whichever way it fails: an
// error, a refusal, a malformed answer, an answer with no state. A short outage
// is waited through; one that lasts the limit, or covers the whole wait, fails
// the VM.
func TestWaitFailsAVMWhoseStatusStaysUnreadable(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      int32
		immediate bool
	}{
		{"HTTP 401", pveUnauthorized, true},
		{"HTTP 403", pveForbidden, true},
		{"a server error", pveErrored, false},
		{"a malformed answer", pveMalformed, false},
		{"an answer with no state", pveNoState, false},
	} {
		t.Run(tc.name+" for longer than the limit", func(t *testing.T) {
			fastHaltPolls(t)
			f := newStatusPVE(t)
			f.mode.Store(tc.mode)
			o := soakOrchestrator(t, f)
			// The limit is far off for a refusal, which must not wait for it.
			old, limit := statusUnknownLimit, 300*time.Millisecond
			if tc.immediate {
				limit = time.Hour
			}
			statusUnknownLimit = limit
			t.Cleanup(func() { statusUnknownLimit = old })
			start := time.Now()
			halted, observed, err := o.watchVMs(context.Background(), 5*time.Second, []int{9001}, nil)
			if err != nil {
				t.Fatal(err)
			}
			var unobservable *vmUnobservableError
			if failure := halted[9001]; failure == nil || !asUnobservable(failure, &unobservable) {
				t.Fatalf("halted = %v, want the VM's liveness reported unknown", halted)
			}
			if elapsed := time.Since(start); (tc.immediate && elapsed > 3*time.Second) || (!tc.immediate && elapsed < limit) || elapsed > 4500*time.Millisecond {
				t.Errorf("failed after %s (immediate=%v, limit %s, wait 5 s)", elapsed, tc.immediate, limit)
			}
			if obs := observed[9001]; obs.reads == 0 || obs.failed != obs.reads || obs.ok() || obs.firstErr == "" {
				t.Errorf("observation = %+v, want every read failed and the error kept", obs)
			}
		})
		t.Run(tc.name+" for a wait shorter than the limit", func(t *testing.T) {
			// Not one successful read in the whole wait: the wait is over and
			// nothing showed the VM running.
			fastHaltPolls(t)
			f := newStatusPVE(t)
			f.mode.Store(tc.mode)
			o := soakOrchestrator(t, f)
			old := statusUnknownLimit
			statusUnknownLimit = time.Hour
			t.Cleanup(func() { statusUnknownLimit = old })
			halted, _, err := o.watchVMs(context.Background(), 200*time.Millisecond, []int{9001}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if failure := halted[9001]; failure == nil {
				t.Fatalf("a %s wait with %d status reads, none of them readable, passed", tc.name, f.reads.Load())
			}
		})
	}
}

// A VM that PVE reports gone is a stop, with PVE's own words, not a state
// that may come back.
func TestWaitReportsAVMPVEHasNoConfigurationFor(t *testing.T) {
	fastHaltPolls(t)
	f := newStatusPVE(t)
	f.mode.Store(pveGone)
	o := soakOrchestrator(t, f)
	halted, err := o.waitWatchingVMs(context.Background(), time.Second, []int{9001})
	var haltedErr *vmHaltedError
	if err != nil || !asHalted(halted[9001], &haltedErr) || !strings.Contains(halted[9001].Error(), "no longer exists") {
		t.Fatalf("halted = %v, err = %v", halted, err)
	}
}

// Intermittent failures are waited through: the VM runs, some reads fail, and
// the wait passes with the failures counted.
func TestWaitToleratesAnIntermittentOutageAndCountsIt(t *testing.T) {
	fastHaltPolls(t)
	f := newStatusPVE(t)
	o := soakOrchestrator(t, f)
	old := statusUnknownLimit
	statusUnknownLimit = 1500 * time.Millisecond // a stall of the machine is not an outage
	t.Cleanup(func() { statusUnknownLimit = old })
	go func() {
		for i := 0; i < 4; i++ {
			f.mode.Store(pveErrored)
			time.Sleep(100 * time.Millisecond)
			f.mode.Store(pveRunning)
			time.Sleep(100 * time.Millisecond)
		}
	}()
	halted, observed, err := o.watchVMs(context.Background(), time.Second, []int{9001}, nil)
	if err != nil || len(halted) != 0 {
		t.Fatalf("an intermittent outage failed the wait: halted=%v err=%v", halted, err)
	}
	if obs := observed[9001]; obs.failed == 0 || !obs.ok() || obs.failed >= obs.reads {
		t.Errorf("observation = %+v, want some reads failed and some succeeded", obs)
	}
}

// A stop during an outage is found as soon as PVE can say.
func TestHaltDuringAnOutageIsStillFound(t *testing.T) {
	fastHaltPolls(t)
	f := newStatusPVE(t)
	f.mode.Store(pveErrored)
	o := soakOrchestrator(t, f)
	old := statusUnknownLimit
	statusUnknownLimit = time.Hour
	t.Cleanup(func() { statusUnknownLimit = old })
	go func() {
		time.Sleep(300 * time.Millisecond)
		f.mode.Store(pveStopped)
	}()
	halted, err := o.waitWatchingVMs(context.Background(), 5*time.Second, []int{9001})
	var haltedErr *vmHaltedError
	if err != nil || !asHalted(halted[9001], &haltedErr) || !strings.Contains(halted[9001].Error(), "no longer running") {
		t.Fatalf("halted = %v, err = %v", halted, err)
	}
}

// Cancellation while PVE cannot be read ends the wait with the run's error and
// does not call the VM unobservable.
func TestWaitCanceledWhileStatusIsUnavailableIsTheRunsInterruption(t *testing.T) {
	fastHaltPolls(t)
	f := newStatusPVE(t)
	f.mode.Store(pveErrored)
	o := soakOrchestrator(t, f)
	old := statusUnknownLimit
	statusUnknownLimit = time.Hour
	t.Cleanup(func() { statusUnknownLimit = old })
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	halted, err := o.waitWatchingVMs(ctx, time.Minute, []int{9001})
	if err == nil || ctx.Err() == nil || len(halted) != 0 {
		t.Fatalf("halted = %v, err = %v; want the interruption alone", halted, err)
	}
}

// Probes of a VM whose state PVE will not report end with the reason, not at
// their own timeouts.
func TestProbesEndWhenPVEWillNotReportTheVM(t *testing.T) {
	fastHaltPolls(t)
	f := newStatusPVE(t)
	f.mode.Store(pveForbidden)
	o := soakOrchestrator(t, f)
	vm := config.VM{VMID: 9001, Probes: []config.Probe{{Type: "tcp", TargetIP: "127.0.0.1", Port: 1, TimeoutSec: 60, Description: "ssh"}}}
	start := time.Now()
	results, passed, err := o.runProbes(context.Background(), vm)
	if passed || err == nil || time.Since(start) > 30*time.Second {
		t.Fatalf("passed=%v err=%v after %s", passed, err, time.Since(start))
	}
	if len(results) != 1 || !strings.Contains(results[0].Error, "liveness is unknown") {
		t.Fatalf("results = %+v", results)
	}
}

// The waits still only read the VM's status: a grace wait has no service to
// check, and the same point stands for it.
func TestWaitWatchingVMsOnlyReadsVMStatus(t *testing.T) {
	fastHaltPolls(t)
	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/status/current") {
			_, _ = w.Write([]byte(`{"data":{"status":"running","qmpstatus":"running"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	o := New(&config.Plan{}, Options{NodeName: "pve1", StateDir: t.TempDir()}, nil, pve.NewClient(pve.Config{BaseURL: server.URL}))

	halted, err := o.waitWatchingVMs(context.Background(), 300*time.Millisecond, []int{9001, 9002})
	if err != nil || len(halted) != 0 {
		t.Fatalf("a wait of running VMs: halted %v, err %v", halted, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) < 4 {
		t.Fatalf("the wait asked PVE about the VMs %d times in 300 ms; it watches them continuously", len(paths))
	}
	for _, path := range paths {
		if !strings.HasSuffix(path, "/status/current") {
			t.Errorf("the wait made the request %q; it only reads each VM's status", path)
		}
	}
}

// The plan preview describes the soak as it runs: the VMs are watched and the
// service probes run again.
func TestPlanDescribesTheSoakAsServiceChecks(t *testing.T) {
	plan := planTestPlan()
	plan.Tiers[0].SoakTimeSec = 90
	p, err := planOrchestrator(t, plan, planPVE(t, "")).Plan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range p.Steps {
		if step.Kind == "wait" && step.Target == "90 s" {
			for _, want := range []string{"service probes run again every 30 s", "when the soak ends", "one failed check fails the tier"} {
				if !strings.Contains(step.Detail, want) {
					t.Errorf("the soak step says %q, want it to say %q", step.Detail, want)
				}
			}
			return
		}
	}
	t.Fatalf("no soak step in the plan: %+v", p.Steps)
}

// An optional guest-agent probe that was skipped in the probe stage (the agent
// was not there) stays a skip in the soak; one that answered in the probe stage
// and is silent later is a failed check: the agent that was there is gone.
func TestSoakTreatsAGuestAgentThatWentSilentAsFailedOnlyIfItAnsweredBefore(t *testing.T) {
	soakFast(t, 100*time.Millisecond)
	f := newStatusPVE(t)
	o := soakOrchestrator(t, f)
	o.opts.QGASocketDir = shortSocketDir(t) // no agent socket: the probe is skipped
	service := newToggledService(t)
	vm := config.VM{VMID: 9001, Name: "web", Probes: []config.Probe{
		service.probe(1),
		{Type: "qga", Command: "ping", RequireQGA: false, TimeoutSec: 1, Description: "agent"},
	}}
	httpStage := probe.Result{Type: "http", Target: fmt.Sprintf("http://%s:%d/", service.host, service.port), Description: "web service", Passed: true}

	skippedBefore := []probe.Result{httpStage, {Type: "qga", Target: "ping", Description: "agent", Passed: true, Skipped: true}}
	failed, evidence, err := o.soakTier(context.Background(), config.Tier{Level: 1, SoakTimeSec: 1}, []tierVMRun{{config: vm, results: skippedBefore}})
	if err != nil || len(failed) != 0 {
		t.Fatalf("an agent that was never there failed the soak: failed=%v err=%v", failed, err)
	}
	summary := evidence[vm.VMID]
	if summary.Probes[1].Skipped != summary.Samples || summary.Probes[1].Passed != 0 || summary.Probes[1].Failed != 0 {
		t.Errorf("the agent probe's entry = %+v for %d checks, want every one skipped", summary.Probes[1], summary.Samples)
	}
	record := passRecord(vm, skippedBefore, summary)
	if problems := attest.SoakProblems(record, &vm, 1, true); len(problems) != 0 {
		t.Errorf("the report rules refuse the honest summary of a skipped optional probe: %v", problems)
	}

	answeredBefore := []probe.Result{httpStage, {Type: "qga", Target: "ping", Description: "agent", Passed: true}}
	failed, evidence, err = o.soakTier(context.Background(), config.Tier{Level: 1, SoakTimeSec: 1}, []tierVMRun{{config: vm, results: answeredBefore}})
	if err != nil {
		t.Fatal(err)
	}
	if failure := failed[vm.VMID]; failure == nil || !strings.Contains(failure.Error(), "answered in the probe stage and did not answer in this check") {
		t.Fatalf("an agent that answered and then went silent passed the soak: failure = %v", failure)
	}
	if summary := evidence[vm.VMID]; summary.FailedSamples != 1 || summary.Probes[1].Failed != 1 || summary.Probes[0].Passed != 1 {
		t.Errorf("summary = %+v", summary)
	}
}

// A status read that the run's own cancellation ends is neither a stop nor an
// unreadable VM, even when the VM has been unreadable for longer than the
// limit: the wait ends with the run's error, so an interrupted run is not
// reported as one whose VM could not be watched.
func TestWaitCanceledMidReadIsTheRunsInterruptionNotAnUnreadableVM(t *testing.T) {
	fastHaltPolls(t)
	f := newStatusPVE(t)
	f.mode.Store(pveHangs)
	o := soakOrchestrator(t, f)
	old := statusUnknownLimit
	statusUnknownLimit = time.Millisecond
	t.Cleanup(func() { statusUnknownLimit = old })
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	halted, _, err := o.watchVMs(ctx, time.Minute, []int{9001}, nil)
	if err == nil || ctx.Err() == nil || len(halted) != 0 {
		t.Fatalf("halted = %v, err = %v; want the interruption alone, not a VM called unreadable", halted, err)
	}
}
