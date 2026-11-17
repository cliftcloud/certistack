// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
)

// The dispatcher builds a guest-agent probe from the plan's command
// under either spelling of the type, and the agent runs a command outside
// its fast paths as "/bin/sh -c" in the guest. A command the allowlist
// refuses never reaches the agent, for qga_ping as for qga, and fails the
// probe at once instead of polling to its timeout.
func TestRunProbesNeverSendsADisallowedCommandToTheGuest(t *testing.T) {
	for _, probeType := range []string{"qga", "qga_ping"} {
		t.Run(probeType, func(t *testing.T) {
			dir := shortSocketDir(t)
			var guestCommands atomic.Int32
			serveUnixSocket(t, filepath.Join(dir, "9001.qga"), func(conn net.Conn) {
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
					if request.Execute == "guest-sync" {
						_ = encoder.Encode(map[string]any{"return": request.Arguments["id"]})
						continue
					}
					guestCommands.Add(1)
					_ = encoder.Encode(map[string]any{"return": map[string]any{"pid": 1, "exited": true, "exitcode": 0}})
				}
			})
			o := &Orchestrator{opts: Options{QGASocketDir: dir}}
			start := time.Now()
			results, passed, err := o.runProbes(context.Background(), config.VM{VMID: 9001, Probes: []config.Probe{{
				Type: probeType, Command: "printf audit-qga-alias-marker", ExpectedOutput: "audit-qga-alias-marker",
				RequireQGA: true, TimeoutSec: 30, Description: "audit alias validation boundary",
			}}})
			if passed || err == nil || len(results) != 1 || results[0].Passed {
				t.Fatalf("passed=%v err=%v results=%+v, want the probe refused", passed, err, results)
			}
			if !strings.Contains(results[0].Error, "arbitrary guest shell commands are not permitted") {
				t.Errorf("error = %q, want the allowlist named", results[0].Error)
			}
			if n := guestCommands.Load(); n != 0 {
				t.Errorf("the guest agent was sent %d commands, want none", n)
			}
			if elapsed := time.Since(start); elapsed > 5*time.Second {
				t.Errorf("a refused command held the probe for %v, want it to fail at once, not at its 30 s timeout", elapsed)
			}
		})
	}
}

// The control: the same probe with a command on the allowlist runs.
func TestRunProbesStillSendsAnAllowedCommandToTheGuest(t *testing.T) {
	for _, probeType := range []string{"qga", "qga_ping"} {
		dir := shortSocketDir(t)
		fakeQGA(t, dir, 9001, map[string]any{"guest-ping": map[string]any{"return": map[string]any{}}}, nil)
		o := &Orchestrator{opts: Options{QGASocketDir: dir}}
		results, passed, err := o.runProbes(context.Background(), config.VM{VMID: 9001, Probes: []config.Probe{{
			Type: probeType, Command: "ping", RequireQGA: true, TimeoutSec: 5, Description: "the agent answers",
		}}})
		if !passed || err != nil || len(results) != 1 || !results[0].Passed {
			t.Errorf("%s ping: passed=%v err=%v results=%+v", probeType, passed, err, results)
		}
	}
}
