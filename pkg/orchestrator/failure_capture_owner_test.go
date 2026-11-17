// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// A restore that was refused because its VMID was occupied created no VM, so no
// console is its own: the failure screenshot must not dial the occupant's QMP
// socket and put that guest's screen into the signed report as the backup's.
func TestNoFailureScreenshotOfAConsoleTheRunDidNotCreate(t *testing.T) {
	dir, err := os.MkdirTemp("", "cs-qmp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	var dialed atomic.Bool
	serveUnixSocket(t, filepath.Join(dir, "9100.qmp"), func(conn net.Conn) {
		dialed.Store(true)
	})

	// The occupant's socket exists; the run has no VM at that ID.
	o := &Orchestrator{opts: Options{QMPSocketDir: dir, ScratchDir: privateScratch(t)}, runID: "run-a"}
	if artifact := o.captureFailureArtifact(context.Background(), 9100); artifact != nil {
		t.Fatalf("a screenshot was taken of a VM the run did not create: %+v", artifact)
	}
	if dialed.Load() {
		t.Fatal("the occupant's QMP socket was opened")
	}

	// A VM of the journal, but PVE cannot say it is the run's (no PVE client here):
	// ownership that cannot be checked is not ownership.
	o.record.VMs = append(o.record.VMs, journal.TrackedVM{VMID: 9100, Node: "pve1"})
	if artifact := o.captureFailureArtifact(context.Background(), 9100); artifact != nil || dialed.Load() {
		t.Fatalf("a screenshot was taken although the VM's ownership could not be checked (artifact %v, dialed %v)", artifact, dialed.Load())
	}
}

// The console warning says "whatever runs under that ID is not photographed as
// the restored VM's" only when PVE shows a VM at that ID. When PVE shows none
// (the run stopped at admission, or its restore was refused), it says the run
// stopped before it created the VM. An ID PVE cannot answer for keeps the
// cautious text.
func TestTheConsoleWarningSaysTheVMWasNeverCreatedWhenNoVMHoldsTheID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(w http.ResponseWriter)
		want   string
		unlike string
	}{
		{"no VM holds the ID", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"data":null,"message":"Configuration file 'nodes/pve1/qemu-server/9100.conf' does not exist"}`))
		}, "No console image for VM 9100: the run stopped before it created the VM.", "whatever runs under that ID"},
		{"another VM holds the ID", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"data":{"name":"someone-elses","tags":"prod"}}`))
		}, "No console image was taken for VM 9100: this run did not create a VM with that ID, so whatever runs under that ID is not photographed as the restored VM's.", "stopped before it created"},
		{"PVE cannot say", func(w http.ResponseWriter) {
			http.Error(w, `{"data":null,"message":"permission denied"}`, http.StatusForbidden)
		}, "No console image was taken for VM 9100: this run did not create a VM with that ID", "stopped before it created"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api2/json/nodes/pve1/qemu/9100/config" {
					t.Errorf("unexpected PVE request %s %s", r.Method, r.URL.Path)
				}
				tc.answer(w)
			}))
			t.Cleanup(server.Close)
			o := &Orchestrator{
				opts:      Options{NodeName: "pve1", ScratchDir: privateScratch(t)},
				runID:     "run-a",
				pveClient: pve.NewClient(pve.Config{BaseURL: server.URL}),
			}
			stop := captureProgress(t)
			if artifact := o.captureFailureArtifact(context.Background(), 9100); artifact != nil {
				t.Fatalf("a screenshot was taken of a VM the run did not create: %+v", artifact)
			}
			var warnings []string
			for _, event := range stop() {
				if event.Level == "WARN" {
					warnings = append(warnings, event.Message)
				}
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], tc.want) || strings.Contains(warnings[0], tc.unlike) {
				t.Errorf("warnings = %q, want one containing %q and not %q", warnings, tc.want, tc.unlike)
			}
		})
	}
}
