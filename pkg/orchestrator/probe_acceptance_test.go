// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package orchestrator

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/probe/qga"
)

// shortSocketDir is a private directory for a VM's QGA or QMP socket. Not
// t.TempDir(): its path embeds the test name and can pass the ~108-byte unix
// socket limit.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cs-sock")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveUnixSocket listens on path and hands every connection to serve.
func serveUnixSocket(t *testing.T, path string, serve func(net.Conn)) {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen %s: %v", path, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				serve(conn)
			}()
		}
	}()
}

// fakeQGA answers guest-sync with its id and every other command from
// replies, keyed by command name, after that command's delay if any.
func fakeQGA(t *testing.T, dir string, vmid int, replies map[string]any, delays map[string]time.Duration) {
	t.Helper()
	serveUnixSocket(t, filepath.Join(dir, fmt.Sprintf("%d.qga", vmid)), func(conn net.Conn) {
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
			if err := json.Unmarshal(line, &request); err != nil {
				return
			}
			reply, ok := replies[request.Execute]
			switch {
			case request.Execute == "guest-sync":
				reply = map[string]any{"return": request.Arguments["id"]}
			case !ok:
				reply = map[string]any{"error": map[string]any{"class": "CommandNotFound", "desc": "unexpected command"}}
			}
			time.Sleep(delays[request.Execute])
			if err := encoder.Encode(reply); err != nil {
				return
			}
		}
	})
}

// The live network diagnostic does not take a guest command killed
// by a signal for a complete capture.
func TestCaptureLiveNetworkDiagnosticRejectsSignaledCommand(t *testing.T) {
	dir := shortSocketDir(t)
	fakeQGA(t, dir, 9101, map[string]any{
		"guest-network-get-interfaces": map[string]any{"return": []any{}},
		"guest-exec":                   map[string]any{"return": map[string]any{"pid": 77}},
		"guest-exec-status":            map[string]any{"return": map[string]any{"exited": true, "signal": 9}},
	}, nil)
	o := &Orchestrator{opts: Options{QGASocketDir: dir}}
	diagnostic, _, complete, err := o.captureLiveNetworkDiagnostic(context.Background(), 9101, "", "")
	if err != nil || complete {
		t.Fatalf("diagnostic complete=%v err=%v, want an incomplete capture", complete, err)
	}
	if !strings.Contains(diagnostic, "[guest diagnostic command was terminated by signal 9: ]") {
		t.Fatalf("diagnostic = %q, want the signal named", diagnostic)
	}
}

// The actual QGA prober under the retry wrapper: a ping answered
// after the probe's budget is a failure, reached when the budget runs out.
func TestRunProberWithRetryRejectsALateQGAPing(t *testing.T) {
	dir := shortSocketDir(t)
	fakeQGA(t, dir, 9102, map[string]any{"guest-ping": map[string]any{"return": map[string]any{}}},
		map[string]time.Duration{"guest-ping": 300 * time.Millisecond})
	prober := qga.NewQGAProber(filepath.Join(dir, "9102.qga"), "ping", "", true, time.Second, "late ping")
	start := time.Now()
	result, attempts := runProberWithRetry(context.Background(), prober, 50*time.Millisecond, 1)
	if result.Passed || attempts != 1 {
		t.Fatalf("late ping = %+v after %d attempts, want one failed attempt", result, attempts)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("late ping held the probe for %v, want it to stop at its 50ms budget", elapsed)
	}
}

// Whatever a prober does with its context, the wrapper does not
// accept a pass it returns after the budget ran out or the run was
// interrupted. A skip at the end of the budget stays a skip; after an
// interruption it is a failure too.
func TestRunProberWithRetryRejectsResultsAfterTheBudgetOrAnInterruption(t *testing.T) {
	slow := func(result probe.Result) probe.Prober {
		return probe.ProberFunc(func(context.Context) probe.Result {
			time.Sleep(150 * time.Millisecond) // ignores its context
			return result
		})
	}
	passed := probe.Result{Passed: true, Detail: "status=running running=true"}
	skipped := probe.Result{Passed: true, Skipped: true, Detail: "QGA skipped (channel unavailable)"}

	result, _ := runProberWithRetry(context.Background(), slow(passed), 50*time.Millisecond, 0)
	if result.Passed || !strings.Contains(result.Error, "after its 50ms budget ran out") {
		t.Fatalf("pass after the budget = %+v, want a failure", result)
	}

	interrupted := func() context.Context {
		ctx, cancel := context.WithCancelCause(context.Background())
		time.AfterFunc(30*time.Millisecond, func() { cancel(errors.New("received interrupt")) })
		return ctx
	}
	result, _ = runProberWithRetry(interrupted(), slow(passed), time.Second, 0)
	if result.Passed || !strings.Contains(result.Error, "after the run was interrupted (received interrupt)") {
		t.Fatalf("pass after an interruption = %+v, want a failure", result)
	}

	result, _ = runProberWithRetry(context.Background(), slow(skipped), 50*time.Millisecond, 0)
	if !result.Passed || !result.Skipped {
		t.Fatalf("skip at the end of the budget = %+v, want it kept as a skip", result)
	}
	result, _ = runProberWithRetry(interrupted(), slow(skipped), time.Second, 0)
	if result.Passed || result.Skipped {
		t.Fatalf("skip after an interruption = %+v, want a failure", result)
	}

	result, _ = runProberWithRetry(context.Background(), slow(passed), time.Second, 0)
	if !result.Passed {
		t.Fatalf("pass within the budget = %+v, want a pass", result)
	}
}

// fakeQMP plays QEMU on a VM's QMP socket: it negotiates, then answers each
// query-status with running (or paused) after delay. entered is closed when
// the first query arrives.
func fakeQMP(t *testing.T, dir string, vmid int, running bool, delay time.Duration) <-chan struct{} {
	t.Helper()
	entered := make(chan struct{})
	var once sync.Once
	serveUnixSocket(t, filepath.Join(dir, fmt.Sprintf("%d.qmp", vmid)), func(conn net.Conn) {
		reader, encoder := bufio.NewReader(conn), json.NewEncoder(conn)
		if err := encoder.Encode(map[string]any{"QMP": map[string]any{}}); err != nil {
			return
		}
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var command map[string]any
			if err := json.Unmarshal(line, &command); err != nil {
				return
			}
			var value any = map[string]any{}
			if command["execute"] == "screendump" {
				// A black 2x2 framebuffer: what a guest at a boot failure shows.
				arguments, _ := command["arguments"].(map[string]any)
				filename, _ := arguments["filename"].(string)
				if err := os.WriteFile(filename, []byte("P6\n2 2\n255\n"+strings.Repeat("\x00", 12)), 0o600); err != nil {
					return
				}
			}
			if command["execute"] == "query-status" {
				once.Do(func() { close(entered) })
				time.Sleep(delay)
				status := "paused"
				if running {
					status = "running"
				}
				value = map[string]any{"running": running, "status": status}
			}
			if err := encoder.Encode(map[string]any{"return": value, "id": command["id"]}); err != nil {
				return
			}
		}
	})
	return entered
}

// acceptingPort is a TCP port on the loopback that accepts and closes every
// connection: a wire probe on it passes, standing for a guest service.
func acceptingPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// The actual QMP probe in the actual probe stage. A running status
// that arrives after the parent's deadline, after a cancellation, or after
// the probe's own timeout_sec fails the probe and the stage; on-time
// running passes, and paused fails. A wire probe follows the QMP probe so
// that an on-time running status can pass the stage: QMP alone never can.
func TestRunProbesRejectsALateQMPRunningStatus(t *testing.T) {
	for name, tc := range map[string]struct {
		timeoutSec int
		deadline   time.Duration
		cancel     bool
		running    bool
		delay      time.Duration
		pass       bool
	}{
		"after the parent deadline": {2, 70 * time.Millisecond, false, true, 300 * time.Millisecond, false},
		"after cancellation":        {2, 0, true, true, 300 * time.Millisecond, false},
		"after timeout_sec":         {1, 0, false, true, 1300 * time.Millisecond, false},
		"on time (control)":         {2, 0, false, true, 0, true},
		"paused on time (control)":  {1, 0, false, false, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			dir := shortSocketDir(t)
			entered := fakeQMP(t, dir, 9103, tc.running, tc.delay)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.deadline > 0 {
				ctx, cancel = context.WithTimeout(context.Background(), tc.deadline)
				defer cancel()
			}
			if tc.cancel {
				go func() {
					<-entered
					cancel()
				}()
			}
			o := &Orchestrator{opts: Options{QMPSocketDir: dir}}
			vm := config.VM{VMID: 9103, Probes: []config.Probe{
				{Type: "qmp_status", Description: "running state", TimeoutSec: tc.timeoutSec, Retries: 1},
				{Type: "tcp", TargetIP: "127.0.0.1", Port: acceptingPort(t), Description: "service port", TimeoutSec: 1},
			}}
			results, passed, err := o.runProbes(ctx, vm)
			if len(results) < 1 || passed != tc.pass || results[0].Passed != tc.pass || (err == nil) != tc.pass {
				t.Fatalf("stage = %+v passed=%v err=%v, want passed=%v", results, passed, err, tc.pass)
			}
			if !tc.pass && tc.delay > 0 && results[0].Duration >= tc.delay {
				t.Fatalf("probe waited %v for a reply due after %v, want it to stop at its deadline", results[0].Duration, tc.delay)
			}
		})
	}
}

// A probe stage in which every probe was skipped checked nothing
// and fails, keeping the skipped results and saying why; one probe that
// ran and passed is enough, and a required probe on an absent agent fails.
func TestRunProbesFailsAStageWhereEveryProbeWasSkipped(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	optional := config.Probe{Type: "qga", Command: "systemctl is-active postgresql", ExpectedOutput: "active", TimeoutSec: 1, Retries: 1, Description: "PostgreSQL unit"}
	required := optional
	required.RequireQGA = true
	wire := config.Probe{Type: "tcp", TargetIP: "127.0.0.1", Port: port, TimeoutSec: 1, Description: "PostgreSQL port"}

	for name, tc := range map[string]struct {
		probes     []config.Probe
		pass       bool
		allSkipped bool
	}{
		"only optional qga":                {[]config.Probe{optional}, false, true},
		"two optional qga":                 {[]config.Probe{optional, optional}, false, true},
		"optional qga and a passing probe": {[]config.Probe{optional, wire}, true, false},
		"required qga (control)":           {[]config.Probe{required}, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			// No QGA socket in this directory: the guest agent is absent.
			o := &Orchestrator{opts: Options{QGASocketDir: shortSocketDir(t)}}
			results, passed, err := o.runProbes(context.Background(), config.VM{VMID: 9104, Probes: tc.probes})
			if passed != tc.pass || (err == nil) != tc.pass {
				t.Fatalf("stage passed=%v err=%v results=%+v, want passed=%v", passed, err, results, tc.pass)
			}
			for i, p := range tc.probes {
				if p.Type == "qga" && !p.RequireQGA && !results[i].Skipped {
					t.Fatalf("optional probe result = %+v, want it kept as a skip", results[i])
				}
			}
			if !tc.allSkipped {
				return
			}
			last := results[len(results)-1]
			if len(results) != len(tc.probes)+1 || last.Type != "probe_stage" || last.Passed || !strings.Contains(last.Error, "skipped because the guest agent did not answer, so nothing was checked") {
				t.Fatalf("results = %+v, want the skips kept and a failed probe_stage result saying why", results)
			}
			if !strings.Contains(err.Error(), "nothing was checked") {
				t.Fatalf("stage error = %v", err)
			}
		})
	}
}
