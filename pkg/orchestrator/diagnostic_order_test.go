// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cliftcloud/certistack/internal/guestnet"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// livePVE is the one sandbox VM of a test as PVE keeps it, with the behavior
// that matters to the diagnostic read: a stop leaves the VM stopped, and
// destroying a stopped VM frees the volumes it owns. The disposable overlays are
// attached to the sandbox VM as volumes of a directory storage, so PVE's
// destroy removes the files (a real run read the overlay after the destroy and
// found "No such file or directory"). A fake that leaves the files in place
// passes whatever the order is.
type livePVE struct {
	t      *testing.T
	vmid   int
	runID  string
	mu     sync.Mutex
	state  string   // "running", "stopped" or "destroyed"
	volume []string // the files PVE frees when it destroys the VM
	events []string // "stop", "destroy" and, from the read, "read(<state>)"
	// statusDenied makes PVE refuse to say what state the VM is in while it
	// exists, so a stop cannot be confirmed.
	statusDenied bool
}

func (p *livePVE) log(event string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, event)
}

func (p *livePVE) snapshot() (state string, events []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state, append([]string(nil), p.events...)
}

// destroy is what qm destroy and the API's DELETE do: a running VM is refused,
// a stopped one is removed with the volumes it owns.
func (p *livePVE) destroy() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, "destroy")
	if p.state == "running" {
		return fmt.Errorf("VM %d is running - destroy failed", p.vmid)
	}
	for _, file := range p.volume {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			p.t.Errorf("fake PVE could not free volume %s: %v", file, err)
		}
	}
	p.state = "destroyed"
	return nil
}

func (p *livePVE) client() *pve.Client {
	p.t.Helper()
	task := func(kind string) string {
		return fmt.Sprintf("UPID:localhost:0000A1B2:00C3D4E5:66A1B2C3:%s:%d:root@pam:", kind, p.vmid)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		answer := func(data any) { _ = json.NewEncoder(w).Encode(map[string]any{"data": data}) }
		base := fmt.Sprintf("/api2/json/nodes/localhost/qemu/%d", p.vmid)
		state, _ := p.snapshot()
		switch r.Method + " " + r.URL.Path {
		case "GET /api2/json/cluster/resources":
			if state == "destroyed" {
				answer([]map[string]any{})
			} else {
				answer([]map[string]any{{"vmid": p.vmid}})
			}
		case "GET " + base + "/config":
			if state == "destroyed" {
				http.Error(w, `{"errors":"Configuration file does not exist"}`, http.StatusNotFound)
				return
			}
			answer(map[string]any{"tags": "certistack," + p.runID, "description": "owner=certistack; run_id=" + p.runID})
		case "GET " + base + "/status/current":
			switch {
			case state == "destroyed":
				http.Error(w, `{"errors":"Configuration file does not exist"}`, http.StatusNotFound)
			case p.statusDenied:
				http.Error(w, `{"errors":"permission denied"}`, http.StatusForbidden)
			default:
				answer(map[string]any{"status": state})
			}
		case "POST " + base + "/status/stop":
			p.log("stop")
			p.mu.Lock()
			if p.state == "running" {
				p.state = "stopped"
			}
			p.mu.Unlock()
			answer(task("qmstop"))
		case "DELETE " + base:
			if err := p.destroy(); err != nil {
				http.Error(w, fmt.Sprintf(`{"errors":%q}`, err.Error()), http.StatusInternalServerError)
				return
			}
			answer(task("qmdestroy"))
		default:
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/localhost/tasks/") {
				answer(map[string]any{"status": "stopped", "exitstatus": "OK", "node": "localhost"})
				return
			}
			p.t.Errorf("unexpected PVE request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	p.t.Cleanup(server.Close)
	return pve.NewClient(pve.Config{BaseURL: server.URL})
}

// diagnosticRun is a restore that got as far as starting the VM, which PVE
// refused, with guest-network recovery and capture_diagnostics on. The VM is
// then taken for a running guest whose probe failed: PVE keeps it as livePVE
// describes, and the guestfish calls are replaced by fakes that record what
// they saw.
type diagnosticRun struct {
	*evidenceRun
	pve   *livePVE
	reads *[]diagnosticRead
}

// diagnosticRead is what the fake overlay read saw when it was called.
type diagnosticRead struct {
	vmState      string // the VM's state in PVE at that moment
	overlayThere bool   // the first overlay still existed
	overlays     []string
}

// readFailure is guestfish's answer for an overlay that is not there, as a real
// run saw it.
func readFailure(path string) error {
	return fmt.Errorf("command failed with exit code 1: guestfish: access: %s: No such file or directory", path)
}

func diagnosticOrderRun(t *testing.T, diagnostic string) *diagnosticRun {
	t.Helper()
	run := newEvidenceRun(t, evidenceSpec{createOK: true, startStatus: 500})
	run.vm.NetworkRecovery = config.NetworkRecovery{Mode: "auto", CaptureDiagnostics: true}
	run.vm.Probes = []config.Probe{{Type: "tcp", Description: "web", TargetIP: "10.70.0.5", Port: 80}}
	run.o.plan.Network.IPRange, run.o.plan.Network.ProbeIP = "10.70.0.0/24", "10.70.0.1"
	run.o.applyGuestNetworkFn = func(_ context.Context, cfg guestnet.Config) (guestnet.Result, error) {
		return guestnet.Result{Strategy: "networkmanager", Address: cfg.Address, Files: []string{"/etc/NetworkManager/system-connections/90-certistack-recovery.nmconnection"}}, nil
	}
	if _, err := run.o.bootAndVerifyVM(context.Background(), run.vm, 60, nil); err == nil || !strings.Contains(err.Error(), "PVE StartVM error") {
		t.Fatalf("bootAndVerifyVM = %v, want the start refused", err)
	}
	if len(run.o.record.DeltaFiles) == 0 {
		t.Fatal("the restore made no overlay")
	}
	// A probe failed on a guest that is still running.
	run.o.networkDiagnosticRequested[run.vm.VMID] = true
	d := &diagnosticRun{evidenceRun: run}
	d.pve = &livePVE{t: t, vmid: run.vm.VMID, runID: run.o.runID, state: "running", volume: append([]string(nil), run.o.record.DeltaFiles...)}
	run.o.pveClient = d.pve.client()
	run.o.runQMFallbackFn = func(_ context.Context, args []string) ([]byte, error) {
		if args[0] == "destroy" {
			_ = d.pve.destroy()
		}
		return nil, nil
	}
	var reads []diagnosticRead
	d.reads = &reads
	run.o.readNetworkDiagnosticFn = func(_ context.Context, overlays []string) (string, error) {
		_, statErr := os.Stat(overlays[0])
		state, _ := d.pve.snapshot()
		d.pve.log("read(" + state + ")")
		reads = append(reads, diagnosticRead{vmState: state, overlayThere: statErr == nil, overlays: overlays})
		for _, overlay := range overlays {
			if _, err := os.Stat(overlay); err != nil {
				return "", readFailure(overlay)
			}
		}
		return diagnostic, nil
	}
	return d
}

func (d *diagnosticRun) vmid() int { return d.vm.VMID }

func (d *diagnosticRun) overlaysLeft() []string {
	var left []string
	for _, file := range d.o.record.DeltaFiles {
		if _, err := os.Stat(file); err == nil {
			left = append(left, file)
		}
	}
	return left
}

// A probe fails on a guest without a guest agent, so the boot-time diagnostic
// is read from its overlay. PVE's destroy frees the overlay, which is a volume
// of the sandbox VM, so a read after it would find no file, lose the
// diagnostic and fail the teardown of a run that cleaned everything. The read
// comes between the stop, which leaves QEMU no longer writing, and the destroy.
func TestTheOverlayDiagnosticIsReadOnceTheVMIsStoppedAndBeforePVEDestroysIt(t *testing.T) {
	d := diagnosticOrderRun(t, "[interfaces]\nens18 10.70.0.5/24")

	failures := d.o.cleanup.Unwind()
	if len(failures) != 0 {
		t.Fatalf("teardown failures: %v", failures)
	}
	state, events := d.pve.snapshot()
	if want := []string{"stop", "read(stopped)", "destroy"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("events = %v, want %v: the overlay is read after QEMU stopped and before PVE frees it", events, want)
	}
	if state != "destroyed" {
		t.Fatalf("the VM is %s after teardown", state)
	}
	read := (*d.reads)[0]
	if !read.overlayThere {
		t.Fatal("the overlay was gone when the diagnostic was read")
	}
	if got := d.o.networkDiagnostics[d.vmid()]; got != "[interfaces]\nens18 10.70.0.5/24" {
		t.Fatalf("diagnostic = %q", got)
	}
	if left := d.overlaysLeft(); len(left) != 0 {
		t.Fatalf("overlays left after teardown: %v", left)
	}
}

// The overlay is read once per VM, and a live diagnostic without listeners is
// completed with what the guest recorded at boot.
func TestTheOverlayDiagnosticIsReadOnlyOncePerVM(t *testing.T) {
	d := diagnosticOrderRun(t, "[listeners]\ntcp LISTEN :80")
	d.o.networkDiagnostics[d.vmid()] = "[interfaces via QGA]"
	d.o.networkDiagnosticPartial[d.vmid()] = true
	if failures := d.o.cleanup.Unwind(); len(failures) != 0 {
		t.Fatalf("teardown failures: %v", failures)
	}
	if len(*d.reads) != 1 {
		t.Fatalf("the overlay was read %d times, want once", len(*d.reads))
	}
	if got := d.o.networkDiagnostics[d.vmid()]; !strings.Contains(got, "[interfaces via QGA]\n[boot-time diagnostic from the COW overlay]\n[listeners]") {
		t.Fatalf("diagnostic = %q, want the live interfaces completed with the boot-time listeners", got)
	}
}

// If the VM cannot be confirmed stopped, QEMU may still be writing to the
// overlay: it is not read, and the report says why. Teardown carries on and
// destroys the VM; the missing diagnostic is not a cleanup failure.
func TestTheOverlayDiagnosticIsNotReadFromAVMThatMayStillRun(t *testing.T) {
	t.Run("PVE does not say whether the VM stopped", func(t *testing.T) {
		d := diagnosticOrderRun(t, "must not be read")
		d.pve.statusDenied = true
		failures := d.o.cleanup.Unwind()
		if len(*d.reads) != 0 {
			t.Fatalf("the overlay of a VM that may still run was read: %+v", *d.reads)
		}
		for _, failure := range failures {
			if strings.HasPrefix(failure.Step, "capture guest network diagnostic") {
				t.Fatalf("the missing diagnostic is a teardown failure: %v", failures)
			}
		}
		if got := d.o.networkDiagnostics[d.vmid()]; !strings.Contains(got, "not confirmed stopped") {
			t.Fatalf("the report's diagnostic = %q, want it to say the overlay was not read and why", got)
		}
	})
	t.Run("PVE stops answering", func(t *testing.T) {
		d := diagnosticOrderRun(t, "must not be read")
		// The teardown cannot verify who owns the VM.
		unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"errors":"unavailable"}`, http.StatusInternalServerError)
		}))
		defer unavailable.Close()
		d.o.pveClient = pve.NewClient(pve.Config{BaseURL: unavailable.URL})

		failures := d.o.cleanup.Unwind()
		if len(*d.reads) != 0 {
			t.Fatalf("the overlay of a VM that may still run was read: %+v", *d.reads)
		}
		destroyFailed, captureFailed := false, false
		for _, failure := range failures {
			destroyFailed = destroyFailed || strings.HasPrefix(failure.Step, "destroy VM")
			captureFailed = captureFailed || strings.HasPrefix(failure.Step, "capture guest network diagnostic")
		}
		if !destroyFailed || captureFailed {
			t.Fatalf("teardown failures = %v, want the destroy's and not a second one from the capture", failures)
		}
		if got := d.o.networkDiagnostics[d.vmid()]; !strings.Contains(got, "not confirmed stopped") {
			t.Fatalf("the report's diagnostic = %q, want it to say the overlay was not read and why", got)
		}
	})
}

// An overlay that is gone before the read, for any reason, is a fact about the
// evidence and goes into the diagnostic. It is not a cleanup error: nothing is
// left behind, and a run that cleaned everything is not "cleanup_failed".
func TestAnOverlayThatIsAlreadyGoneIsANoteNotACleanupError(t *testing.T) {
	d := diagnosticOrderRun(t, "must not be read")
	for _, file := range d.o.record.DeltaFiles {
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
	}
	failures := d.o.cleanup.Unwind()
	if len(failures) != 0 {
		t.Fatalf("teardown failures: %v", failures)
	}
	if len(*d.reads) != 0 {
		t.Fatalf("an overlay that is not there was read: %+v", *d.reads)
	}
	if got := d.o.networkDiagnostics[d.vmid()]; !strings.Contains(got, "already removed") {
		t.Fatalf("diagnostic = %q, want a note that the overlay was already removed", got)
	}
	if state, events := d.pve.snapshot(); state != "destroyed" || !reflect.DeepEqual(events, []string{"stop", "destroy"}) {
		t.Fatalf("state = %s, events = %v; the VM must still be stopped and destroyed", state, events)
	}

	t.Run("beside a live diagnostic without listeners", func(t *testing.T) {
		d := diagnosticOrderRun(t, "must not be read")
		d.o.networkDiagnostics[d.vmid()] = "[interfaces via QGA]"
		d.o.networkDiagnosticPartial[d.vmid()] = true
		for _, file := range d.o.record.DeltaFiles {
			_ = os.Remove(file)
		}
		if failures := d.o.cleanup.Unwind(); len(failures) != 0 {
			t.Fatalf("teardown failures: %v", failures)
		}
		got := d.o.networkDiagnostics[d.vmid()]
		if !strings.HasPrefix(got, "[interfaces via QGA]") || !strings.Contains(got, "already removed") {
			t.Fatalf("diagnostic = %q, want the live interfaces kept and the note added", got)
		}
	})
}

// A read that fails for a reason of its own (guestfish could not start, the
// guest's filesystem is damaged) loses the diagnostic and says so in it, but
// the destroy still follows and the teardown is not marked failed by it.
func TestAFailedOverlayReadIsReportedInTheDiagnosticAndDoesNotStopTheDestroy(t *testing.T) {
	d := diagnosticOrderRun(t, "")
	d.o.readNetworkDiagnosticFn = func(context.Context, []string) (string, error) {
		d.pve.log("read")
		return "", fmt.Errorf("command failed with exit code 1: guestfish: libguestfs: error: launch: the appliance did not start")
	}
	failures := d.o.cleanup.Unwind()
	if len(failures) != 0 {
		t.Fatalf("teardown failures: %v", failures)
	}
	if got := d.o.networkDiagnostics[d.vmid()]; !strings.Contains(got, "could not be read from the COW overlay") || !strings.Contains(got, "the appliance did not start") {
		t.Fatalf("diagnostic = %q, want the read failure named", got)
	}
	if state, events := d.pve.snapshot(); state != "destroyed" || !reflect.DeepEqual(events, []string{"stop", "read", "destroy"}) {
		t.Fatalf("state = %s, events = %v", state, events)
	}
}

// The read runs inside the VM's teardown, ahead of the destroy: whatever it
// does, the destroy still happens.
func TestAPanickingOverlayReadDoesNotKeepTheVMFromBeingDestroyed(t *testing.T) {
	d := diagnosticOrderRun(t, "")
	d.o.readNetworkDiagnosticFn = func(context.Context, []string) (string, error) {
		d.pve.log("read")
		panic("guestfish wrapper bug")
	}
	failures := d.o.cleanup.Unwind()
	if len(failures) != 0 {
		t.Fatalf("teardown failures: %v", failures)
	}
	if state, events := d.pve.snapshot(); state != "destroyed" || !reflect.DeepEqual(events, []string{"stop", "read", "destroy"}) {
		t.Fatalf("state = %s, events = %v; the VM must be destroyed after a read that panicked", state, events)
	}
}

// A VM that PVE no longer has runs nothing, so a overlay that is still there
// (the VM was never created, or something other than PVE kept the file) is
// still read.
func TestTheOverlayDiagnosticIsReadWhenTheVMIsAlreadyGone(t *testing.T) {
	d := diagnosticOrderRun(t, "[listeners]\ntcp LISTEN :80")
	d.pve.state = "destroyed"
	failures := d.o.cleanup.Unwind()
	if len(failures) != 0 {
		t.Fatalf("teardown failures: %v", failures)
	}
	if _, events := d.pve.snapshot(); !reflect.DeepEqual(events, []string{"read(destroyed)"}) {
		t.Fatalf("events = %v, want one read and no stop or destroy of a VM PVE does not have", events)
	}
	if got := d.o.networkDiagnostics[d.vmid()]; got != "[listeners]\ntcp LISTEN :80" {
		t.Fatalf("diagnostic = %q", got)
	}
}

// A live diagnostic stays the evidence, and a passing run reads nothing.
func TestTheOverlayDiagnosticIsReadOnlyWhenItIsNeeded(t *testing.T) {
	t.Run("a complete live diagnostic", func(t *testing.T) {
		d := diagnosticOrderRun(t, "must not be read")
		d.o.networkDiagnostics[d.vmid()] = "live"
		d.o.cleanup.Unwind()
		if len(*d.reads) != 0 || d.o.networkDiagnostics[d.vmid()] != "live" {
			t.Fatalf("reads = %+v, diagnostic = %q; the live diagnostic must stand", *d.reads, d.o.networkDiagnostics[d.vmid()])
		}
	})
	t.Run("a live diagnostic without listeners is completed from the overlay", func(t *testing.T) {
		d := diagnosticOrderRun(t, "[listeners]\ntcp LISTEN :80")
		d.o.networkDiagnostics[d.vmid()] = "[interfaces via QGA]"
		d.o.networkDiagnosticPartial[d.vmid()] = true
		d.o.cleanup.Unwind()
		if len(*d.reads) != 1 || (*d.reads)[0].vmState != "stopped" || !strings.Contains(d.o.networkDiagnostics[d.vmid()], "[boot-time diagnostic from the COW overlay]\n[listeners]") {
			t.Fatalf("reads = %+v, diagnostic = %q", *d.reads, d.o.networkDiagnostics[d.vmid()])
		}
	})
	t.Run("no probe failed", func(t *testing.T) {
		d := diagnosticOrderRun(t, "must not be read")
		d.o.networkDiagnosticRequested[d.vmid()] = false
		d.o.cleanup.Unwind()
		if len(*d.reads) != 0 {
			t.Fatalf("a run without a failed probe read the overlay: %+v", *d.reads)
		}
		if _, events := d.pve.snapshot(); !reflect.DeepEqual(events, []string{"stop", "destroy"}) {
			t.Fatalf("events = %v", events)
		}
	})
}
