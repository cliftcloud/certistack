// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	"github.com/cliftcloud/certistack/pkg/progress"
)

// nodeRunOnVersionHost runs the real node-run command and runner against the
// host versionHost made, with the host checks passing, on the plan the
// controller would send for examples/three-tier-app.yaml.
func nodeRunOnVersionHost(t *testing.T, pveVersion, clientOutput string) (nodeapi.RunResult, func() []string, func() []string) {
	t.Helper()
	return nodeRunOnVersionHostWith(t, pveVersion, clientOutput, preflight.Result{Ready: true, Checks: []preflight.CheckItem{{Name: "kvm", Status: "passed", Detail: "/dev/kvm is accessible"}}}, nil)
}

// nodeRunOnVersionHostWith is nodeRunOnVersionHost with the result the shared
// preflight gives the worker, and, when events is not nil, the progress events
// the worker emitted on its standard error (the channel the operator reads).
func nodeRunOnVersionHostWith(t *testing.T, pveVersion, clientOutput string, hostChecks preflight.Result, events *[]progress.Event) (nodeapi.RunResult, func() []string, func() []string) {
	t.Helper()
	pveRequests, clientCalls := versionHost(t, pveVersion, clientOutput)
	var stopProgress func() []progress.Event
	environment := "PVE_URL=" + os.Getenv("PVE_URL") + "\nPVE_TOKEN_ID=certistack@pve!doctor\nPVE_TOKEN_SECRET=secret\n" +
		"PBS_REPOSITORY=" + os.Getenv("PBS_REPOSITORY") + "\nPBS_PASSWORD=pbs-secret\n"
	if events != nil {
		// The controller turns the event channel on in the worker's
		// environment file, and the worker takes its environment from there.
		stopProgress = captureProgressEvents(t)
		environment += progress.EnvironmentEvents + "=1\n"
	}

	previousLock, previousPreflight := acquireHostLock, runPreflight
	t.Cleanup(func() { acquireHostLock, runPreflight = previousLock, previousPreflight })
	root := t.TempDir()
	acquireHostLock = func() (*os.File, error) {
		return os.OpenFile(filepath.Join(root, "host.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	}
	runPreflight = func(context.Context, *config.Plan, preflight.Options) preflight.Result {
		return hostChecks
	}
	controllersPlan, err := config.LoadFromFile(filepath.Join("..", "..", "examples", "three-tier-app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sent, err := config.MarshalWorkerPlan(controllersPlan)
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(root, "plan.yaml")
	if err := os.WriteFile(planPath, sent, 0o600); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(root, "runtime.env")
	if err := os.WriteFile(envFile, []byte(environment), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := nodeRunCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--plan", planPath, "--node", "pve-01", "--env-file", envFile,
		"--state-dir", filepath.Join(root, "state"), "--scratch", filepath.Join(root, "scratch"),
		"--output", filepath.Join(root, "reports"), "--run-id", "run-versions",
	})
	err = cmd.ExecuteContext(context.Background())
	if stopProgress != nil {
		*events = stopProgress()
	}
	if err != nil {
		t.Fatalf("node-run: %v\n%s", err, stdout.String())
	}
	var result nodeapi.RunResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("the worker's result is not JSON: %v\n%s", err, stdout.String())
	}
	return result, pveRequests, clientCalls
}

// captureProgressEvents turns the progress channel on and sends what the test's
// process writes to standard error to the returned function's result, which
// also stops the capture.
func captureProgressEvents(t *testing.T) func() []progress.Event {
	t.Helper()
	t.Setenv(progress.EnvironmentEvents, "1")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = writer
	text := make(chan string, 1)
	go func() {
		data, _ := io.ReadAll(reader)
		text <- string(data)
	}()
	stopped := false
	var captured []progress.Event
	stop := func() []progress.Event {
		if stopped {
			return captured
		}
		stopped = true
		os.Stderr = previous
		_ = writer.Close()
		for _, line := range strings.Split(<-text, "\n") {
			if event, ok := progress.DecodeLine(line); ok {
				captured = append(captured, event)
			}
		}
		return captured
	}
	t.Cleanup(func() { stop() })
	return stop
}

// countWarnings counts the WARN events whose message contains text.
func countWarnings(events []progress.Event, text string) int {
	count := 0
	for _, event := range events {
		if event.Level == "WARN" && strings.Contains(event.Message, text) {
			count++
		}
	}
	return count
}

// run's worker refuses an unsupported pair before it creates anything: the
// refusal is the signed failure reason, it names the versions as doctor does,
// the report records them and that they are unsupported, and nothing but the
// two version reads touched PVE or PBS.
func TestNodeRunRefusesAnUnsupportedPairBeforeItCreatesAnything(t *testing.T) {
	for _, tc := range []struct {
		name, pve, client string
		want              []string
		versions          [3]string
	}{
		{"PVE 7", "7.4-20", clientPBS4, []string{"PVE 7.4-20", "PBS 4.2.7", "proxmox-backup-client 4.2.5", "unsupported", "older than PVE 8"}, [3]string{"7.4-20", "4.2.7", "4.2.5"}},
		{"PBS 2", "9.1.1", "client version: 2.4.1\nserver version: 2.4.7\n", []string{"PVE 9.1.1", "PBS 2.4.7", "unsupported", "older than PBS 3"}, [3]string{"9.1.1", "2.4.7", "2.4.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, pveRequests, clientCalls := nodeRunOnVersionHost(t, tc.pve, tc.client)
			if result.Report == nil {
				t.Fatalf("the worker returned no evidence of its refusal: %q", result.Error)
			}
			for _, want := range tc.want {
				if !strings.Contains(result.Error, want) {
					t.Errorf("the worker's refusal %q lacks %q", result.Error, want)
				}
			}
			if result.Report.AllPassed || result.Report.FailureReason != result.Error || len(result.Report.VMRecords) != 0 {
				t.Errorf("refusal report = passed %v, reason %q, %d VM records", result.Report.AllPassed, result.Report.FailureReason, len(result.Report.VMRecords))
			}
			if got := [3]string{result.Report.PVEVersion, result.Report.PBSVersion, result.Report.PBSClientVersion}; got != tc.versions || result.Report.VersionSupport != "unsupported" {
				t.Errorf("the refusal's report records versions %v (%q), want %v (unsupported)", got, result.Report.VersionSupport, tc.versions)
			}
			if got := pveRequests(); len(got) != 1 || got[0] != "GET /api2/json/version" {
				t.Errorf("PVE was asked %v; a refused run asks for its version and nothing else", got)
			}
			for _, call := range clientCalls() {
				if call != "version" {
					t.Errorf("proxmox-backup-client was asked to %q before the refusal", call)
				}
			}
		})
	}
}

// The same worker, on an untested pair, goes on past the version gate: it is
// not refused for its versions, and what it reads next is the backup.
func TestNodeRunDoesNotRefuseAnUntestedPair(t *testing.T) {
	result, _, clientCalls := nodeRunOnVersionHost(t, "10.0.1", clientPBS3)
	if strings.Contains(result.Error, "unsupported") || strings.Contains(result.Error, "release evidence") {
		t.Fatalf("an untested pair was refused: %q", result.Error)
	}
	sawBackup := false
	for _, call := range clientCalls() {
		if call == "snapshot" {
			sawBackup = true
		}
	}
	if !sawBackup {
		t.Errorf("the worker never went on to read a backup (client calls %v); result error %q", clientCalls(), result.Error)
	}
}
