//go:build linux

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
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/internal/process"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/pbs"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// A started VM's QEMU process is journaled by PID and start time, which name
// it only within one boot of the node: the journal also names the boot, so
// that recovery after a reboot does not take a later boot's process for it.
// This drives bootAndVerifyVM itself through the VM's start, to the QMP wait
// that the missing socket refuses, and reads the journal the run left.
func TestTheJournaledQEMUProcessNamesTheBootItRunsIn(t *testing.T) {
	f := newLoopFixture(t, "exit 0")
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.log), "qemu-img"), []byte("#!/bin/sh\n"+okQemuImg), 0o755); err != nil {
		t.Fatal(err)
	}
	qemu := exec.Command("/bin/sleep", "30")
	if err := qemu.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = qemu.Process.Kill(); _ = qemu.Wait() })

	const upid = "UPID:localhost:1:1:1:1:1:"
	var started atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api2/json/")
		reply := func(data string) { _ = json.NewEncoder(w).Encode(pve.APIResponse{Data: json.RawMessage(data)}) }
		switch {
		case r.Method == http.MethodGet && path == "cluster/resources":
			reply(`[]`)
		case r.Method == http.MethodGet && path == "nodes/localhost/qemu/9001/status/current":
			if !started.Load() {
				http.Error(w, `{"errors": "Configuration file does not exist"}`, http.StatusNotFound)
				return
			}
			reply(fmt.Sprintf(`{"vmid":9001,"status":"running","qmpstatus":"running","pid":%d}`, qemu.Process.Pid))
		case r.Method == http.MethodGet && path == "nodes/localhost/capabilities/qemu/machines":
			reply(`[]`)
		case r.Method == http.MethodPost && path == "nodes/localhost/qemu":
			reply(`"` + upid + `"`)
		case r.Method == http.MethodGet && path == "nodes/localhost/tasks/"+upid+"/status":
			reply(`{"status":"stopped","exitstatus":"OK"}`)
		case r.Method == http.MethodGet && path == "nodes/localhost/qemu/9001/config":
			reply(`{}`)
		case r.Method == http.MethodPost && path == "nodes/localhost/qemu/9001/status/start":
			started.Store(true)
			reply(`"` + upid + `"`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	o, stateDir := mapTestOrchestrator(t, pbs.Config{Repository: "u@pbs!tok@pbs.example:store"})
	o.pveClient = pve.NewClient(pve.Config{BaseURL: server.URL})
	o.opts.QMPSocketDir = t.TempDir() // no socket in it: the QMP wait fails at once
	if err := os.Chmod(o.opts.ScratchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	o.deviceBytesFn = func(string) (int64, error) { return 36 << 20, nil }
	o.freeBytesFn = func(string) (int64, error) { return 500 << 30, nil }
	o.sharedDisksFn = func(context.Context, string, string) ([]string, error) { return nil, nil }
	o.verifyImageFn = func(_ context.Context, _, _ string, _ pbs.DiskSize, _ func(int64)) (*pbs.VerifySummary, string, error) {
		return &pbs.VerifySummary{Detail: "verified", BytesRead: 36 << 20}, strings.Repeat("ab", 32), nil
	}
	o.plan.Network = config.Network{Mode: "simple", ZoneID: "csSb01", VNetID: "csVn01", IPRange: "10.100.0.0/24", ProbeIP: "10.100.0.1"}
	vm := mapTestVM()
	vm.NetworkRecovery = config.NetworkRecovery{Mode: "preserve"}
	vm.CopyBeforeBoot = config.CopyBeforeBootNever
	vm.SourceImageBytes = map[string]int64{"scsi0": 36 << 20}
	vm.SourceDiskBytes = map[string]int64{"scsi0": 33 << 20}

	if _, err := o.bootAndVerifyVM(context.Background(), vm, 60, nil); err == nil || !strings.Contains(err.Error(), "QMP connection to VM") {
		t.Fatalf("bootAndVerifyVM = %v, want the run to reach the QMP wait after the VM started", err)
	}
	record, err := journal.Load(filepath.Join(stateDir, "active.json"))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := process.ProcessIdentity(qemu.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := process.CurrentBootID()
	if err != nil || boot == "" {
		t.Fatalf("this boot's identity = %q, %v", boot, err)
	}
	want := journal.Process{PID: qemu.Process.Pid, StartTicks: identity.StartTicks, BootID: boot}
	if len(record.VMs) != 1 || record.VMs[0].Process != want {
		t.Fatalf("journaled VMs %+v, want the process %+v", record.VMs, want)
	}
}
