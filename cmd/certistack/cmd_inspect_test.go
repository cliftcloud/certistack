// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/journal"
)

// fakeQMPSocket serves QMP sessions that report a running VM, echoing any
// request id, and returns the socket path.
func fakeQMPSocket(t *testing.T) string {
	t.Helper()
	// Unix socket paths are limited to about 100 bytes; keep this one short.
	dir, err := os.MkdirTemp("", "qmp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "q.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				fmt.Fprintln(conn, `{"QMP": {"version": {"qemu": {"micro": 0, "minor": 2, "major": 9}, "package": ""}, "capabilities": []}}`)
				decoder := json.NewDecoder(conn)
				encoder := json.NewEncoder(conn)
				for {
					var request map[string]any
					if decoder.Decode(&request) != nil {
						return
					}
					response := map[string]any{"return": map[string]any{}}
					if request["execute"] == "query-status" {
						response["return"] = map[string]any{"status": "running", "running": true, "singlestep": false}
					}
					if id, ok := request["id"]; ok {
						response["id"] = id
					}
					if encoder.Encode(response) != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return path
}

func runInspect(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := inspectCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// An explicit --state-dir is honoured when a VMID is also given: the
// journal there is shown, and a journal that cannot be read fails the
// command, instead of being silently ignored.
func TestInspectHonoursStateDirWithVMID(t *testing.T) {
	qmpSocket := fakeQMPSocket(t)
	missingQGA := filepath.Join(t.TempDir(), "missing.qga")
	stateDir := t.TempDir()
	if err := journal.Write(filepath.Join(stateDir, "active.json"), journal.Record{RunID: "run-inspect", Phase: "provisioning"}); err != nil {
		t.Fatal(err)
	}

	out, err := runInspect(t, "123", "--state-dir", stateDir, "--qmp", qmpSocket, "--qga", missingQGA)
	if err != nil {
		t.Fatalf("inspect with a readable journal and a running VM failed: %v\n%s", err, out)
	}
	for _, want := range []string{"run-inspect", "Inspecting VM 123", "Status: running"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	missingState := filepath.Join(t.TempDir(), "missing-state")
	out, err = runInspect(t, "123", "--state-dir", missingState, "--qmp", qmpSocket, "--qga", missingQGA)
	if err == nil || !strings.Contains(err.Error(), "state journal") {
		t.Fatalf("inspect ignored an unreadable --state-dir given with a VMID: err=%v\n%s", err, out)
	}
	if !strings.Contains(out, "Status: running") {
		t.Errorf("the VM was not inspected after the journal failed:\n%s", out)
	}

	// Positive control: without a VMID, --state-dir alone selects the journal.
	if _, err := runInspect(t, "--state-dir", missingState); err == nil {
		t.Fatal("inspect of a missing journal succeeded")
	}
	out, err = runInspect(t, "--state-dir", stateDir)
	if err != nil || !strings.Contains(out, "run-inspect") {
		t.Fatalf("journal inspection: err=%v\n%s", err, out)
	}
}

// A VMID must be one whole Proxmox VE VMID; a suffix, sign, space,
// leading zero, out-of-range value or extra argument is refused before
// anything is inspected.
func TestInspectRejectsMalformedVMID(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	for _, args := range [][]string{
		{"123garbage"},
		{"--", "-123"},
		{"+123"},
		{" 123"},
		{"123 "},
		{"0123"},
		{"99"},
		{"1000000000"},
		{"99999999999999999999"},
		{""},
		{"123", "456"},
	} {
		out, err := runInspect(t, append([]string{"--qmp", missing, "--qga", missing}, args...)...)
		if err == nil {
			t.Errorf("inspect %q succeeded:\n%s", args, out)
			continue
		}
		if strings.Contains(out, "Inspecting VM") {
			t.Errorf("inspect %q inspected a VM before refusing it:\n%s", args, out)
		}
	}
}

// Inspect fails when it could learn nothing about the VM, and
// succeeds when QMP answers even without a guest agent.
func TestInspectFailsWhenNothingAnswers(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	out, err := runInspect(t, "123", "--qmp", missing+".qmp", "--qga", missing+".qga")
	if err == nil || !strings.Contains(err.Error(), "could not inspect VM 123") {
		t.Fatalf("inspect with neither socket answering = %v, want a failure:\n%s", err, out)
	}
	if exitCodeForError(err) == 0 {
		t.Fatal("total inspection failure maps to exit status 0")
	}

	out, err = runInspect(t, "123", "--qmp", fakeQMPSocket(t), "--qga", missing+".qga")
	if err != nil {
		t.Fatalf("inspect with QMP answering and no guest agent failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "UNAVAILABLE") {
		t.Errorf("missing guest agent not reported:\n%s", out)
	}
}
