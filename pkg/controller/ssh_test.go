// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/nodeapi"
	progresspkg "github.com/cliftcloud/certistack/pkg/progress"
	"github.com/google/uuid"
)

// workerRunIDExpr finds the run a command is for in its workspace path.
var workerRunIDExpr = regexp.MustCompile(`/workers/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)

type recordedCommand struct {
	name string
	args []string
}

type fakeCommandRunner struct {
	calls                 []recordedCommand
	nodePlanOutput        string
	nodeResult            nodeapi.RunResult
	nodeStderr            string
	nodeRunError          error
	nodeRunHook           func()
	workerStopResult      string
	workerRecoveryError   error
	workspaceRemoveErrors []error
	workspaceRemoveCalls  int
	recoveryMarkerState   string
	workspaceState        string
	journalPhase          string
	// journalState is the node journal's presence ("present" by default);
	// journalReads, when set, are the successive journals the node returns
	// as "<run_id> <phase>", the last one repeating; without them the
	// journal is this run's own, in journalPhase; recoverErrors are the
	// successive results of the worker's recover command. Once it has
	// succeeded, this run's own journal reads cleaned. transitions are the
	// run IDs the node holds a transition record for, and runID is the run
	// the controller started, known from its commands.
	journalState   string
	journalReads   []string
	transitions    []string
	recoverErrors  []error
	recoverCalls   int
	recovered      bool
	runID          string
	cleanupStarted chan struct{}
	cleanupWait    <-chan struct{}
	// nodeMachine is the node's `uname -m`; empty answers with the
	// controller's own architecture.
	nodeMachine string
	// nodeClockOffset is how far the node's clock is from the controller's
	// (positive: ahead); nodeClockAnswer, when set, is what `date` answers
	// instead of the time; nodeClockError is its failure.
	nodeClockOffset time.Duration
	nodeClockAnswer string
	nodeClockError  error
	// recoverStderr is what the worker's recover command streams.
	recoverStderr string
	// hook, when set, answers any command it handles first.
	hook func(name, joined string) (output []byte, err error, handled bool)
}

func (f *fakeCommandRunner) Run(ctx context.Context, name string, args []string) ([]byte, error) {
	copyArgs := append([]string(nil), args...)
	f.calls = append(f.calls, recordedCommand{name: name, args: copyArgs})
	if f.hook != nil {
		if output, err, handled := f.hook(name, strings.Join(args, " ")); handled {
			return output, err
		}
	}
	if name == "ssh" && strings.Contains(strings.Join(args, " "), "'/usr/bin/rm' '-rf' '/var/lib/certistack/workers/") {
		f.workspaceRemoveCalls++
		if index := f.workspaceRemoveCalls - 1; index < len(f.workspaceRemoveErrors) && f.workspaceRemoveErrors[index] != nil {
			return nil, f.workspaceRemoveErrors[index]
		}
	}
	joined := strings.Join(args, " ")
	if match := workerRunIDExpr.FindStringSubmatch(joined); match != nil {
		f.runID = "run-" + match[1]
	}
	if name == "ssh" && strings.Contains(joined, "'node-plan'") {
		return []byte(f.nodePlanOutput), nil
	}
	if name == "ssh" && strings.Contains(joined, "'/usr/bin/uname' '-m'") {
		machine := f.nodeMachine
		if machine == "" {
			machine = unameMachines[runtime.GOARCH][0]
		}
		return []byte(machine + "\n"), nil
	}
	if name == "ssh" && strings.Contains(joined, "'/usr/bin/date' '-u' '+%s'") {
		switch {
		case f.nodeClockError != nil:
			return nil, f.nodeClockError
		case f.nodeClockAnswer != "":
			return []byte(f.nodeClockAnswer + "\n"), nil
		}
		return []byte(strconv.FormatInt(time.Now().Add(f.nodeClockOffset).Unix(), 10) + "\n"), nil
	}
	if f.cleanupStarted != nil && strings.Contains(joined, `if [ ! -r "$pid_file" ]`) && strings.Contains(joined, "kill -TERM") {
		close(f.cleanupStarted)
		f.cleanupStarted = nil
		select {
		case <-f.cleanupWait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	pathProbe := name == "ssh" && strings.Contains(joined, "'/bin/sh' '-c' 'if [ -e")
	if pathProbe && strings.Contains(joined, "/runs/run-") {
		for _, id := range f.transitions {
			if strings.Contains(joined, "/runs/"+id+".json") {
				return []byte("present\n"), nil
			}
		}
		return []byte("absent\n"), nil
	}
	if name == "ssh" && strings.Contains(joined, "'/usr/bin/cat'") && strings.Contains(joined, "/runs/run-") {
		for _, id := range f.transitions {
			if strings.Contains(joined, "/runs/"+id+".json") {
				return []byte(`{"run_id":"` + id + `","phase":"cleaned","superseded_by":"run-later"}`), nil
			}
		}
		return nil, errors.New("cat: no such file")
	}
	if pathProbe && strings.Contains(joined, "active.json") {
		state := f.journalState
		if state == "" {
			state = "present"
		}
		return []byte(state + "\n"), nil
	}
	if pathProbe && strings.Contains(joined, "recovered.ok") {
		state := f.recoveryMarkerState
		if state == "" {
			state = "absent"
		}
		return []byte(state + "\n"), nil
	}
	if pathProbe {
		state := f.workspaceState
		if state == "" {
			state = "present"
		}
		return []byte(state + "\n"), nil
	}
	if name == "ssh" && strings.Contains(joined, "active.json") && strings.Contains(joined, "'/usr/bin/cat'") && len(f.journalReads) > 0 {
		runID, phase, _ := strings.Cut(f.journalReads[0], " ")
		if len(f.journalReads) > 1 {
			f.journalReads = f.journalReads[1:]
		}
		if f.recovered && runID == f.runID {
			phase = "cleaned"
		}
		return []byte(`{"run_id":"` + runID + `","phase":"` + phase + `"}`), nil
	}
	if name == "ssh" && strings.Contains(joined, "active.json") && strings.Contains(joined, "'/usr/bin/cat'") {
		phase := f.journalPhase
		if phase == "" {
			phase = "cleanup_failed"
		}
		if f.recovered {
			phase = "cleaned"
		}
		return []byte(`{"run_id":"` + f.runID + `","phase":"` + phase + `"}`), nil
	}
	if name == "ssh" && strings.Contains(joined, "worker.pid") && strings.Contains(joined, "$pinned_proc_dir/exe") && strings.Contains(joined, "kill -TERM") {
		if f.workerStopResult == "" {
			return []byte("stopped\n"), nil
		}
		return []byte(f.workerStopResult + "\n"), nil
	}
	if name == "ssh" && strings.Contains(joined, "'recover'") {
		f.recoverCalls++
		if index := f.recoverCalls - 1; index < len(f.recoverErrors) {
			if f.recoverErrors[index] == nil {
				f.recovered = true
			}
			return nil, f.recoverErrors[index]
		}
		if f.workerRecoveryError == nil {
			f.recovered = true
		}
		return nil, f.workerRecoveryError
	}
	if name == "ssh" && strings.Contains(joined, "node-run") {
		if f.nodeRunHook != nil {
			f.nodeRunHook()
		}
		if f.nodeRunError != nil {
			return nil, f.nodeRunError
		}
		// The worker names the run it was started for in its report.
		result := f.nodeResult
		if result.Report != nil && result.Report.RunID == "" {
			named := *result.Report
			named.RunID = f.runID
			result.Report = &named
		}
		return json.Marshal(result)
	}
	return nil, nil
}

func (f *fakeCommandRunner) RunWithStderr(ctx context.Context, name string, args []string, progress io.Writer) ([]byte, error) {
	if name == "ssh" && strings.Contains(strings.Join(args, " "), "node-run") && f.nodeStderr != "" {
		_, _ = io.WriteString(progress, f.nodeStderr)
	}
	if name == "ssh" && strings.Contains(strings.Join(args, " "), "'recover'") && f.recoverStderr != "" {
		_, _ = io.WriteString(progress, f.recoverStderr)
	}
	return f.Run(ctx, name, args)
}

func TestExecutorRunKeepsSecretsOutOfCommandsAndReportsOnController(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-super-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-super-secret")

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	t.Setenv("CERTISTACK_ALLOW_TEST_MODE", "1")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml")
	absPlan, err := filepath.Abs(plan)
	if err != nil {
		t.Fatal(err)
	}
	report := workerReportFor(t, RunOptions{PlanPath: absPlan, NodeName: "pve-01", SkipIntegrity: true})
	signer := testSigner(t)
	fake := &fakeCommandRunner{
		nodeResult: nodeapi.RunResult{Report: report},
		nodeStderr: progresspkg.EventPrefix + `{"level":"INFO","stage":"Storage","message":"Mounted PBS backup disk read-only."}` + "\n",
	}
	executor := &Executor{runner: fake}
	output := t.TempDir()
	var progress bytes.Buffer

	result, err := executor.Run(context.Background(), RunOptions{
		PlanPath:      absPlan,
		NodeName:      "pve-01",
		ScratchDir:    "/var/lib/certistack/scratch",
		StateDir:      "/var/lib/certistack",
		OutputDir:     output,
		Signer:        signer,
		SkipIntegrity: true,
		Build:         BuildInfo{Version: "controller-test", Commit: "abc123", BuildDate: "2026-09-17T00:00:00Z"},
		Writer:        &progress,
		SSH: SSHConfig{
			Host:           "pve.example",
			User:           "root",
			Port:           22,
			KnownHostsFile: knownHosts,
		},
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result == nil || result.ReportPath == "" {
		t.Fatal("controller did not return a locally saved report path")
	}
	if _, err := os.Stat(result.ReportPath); err != nil {
		t.Fatalf("controller report was not saved locally: %v", err)
	}
	if result.Report.Signature == "" {
		t.Fatal("controller did not sign the returned node evidence")
	}
	if result.Report.ValidationMode != attest.ValidationModeTestSkipIntegrity {
		t.Fatalf("controller validation mode = %q, want %q", result.Report.ValidationMode, attest.ValidationModeTestSkipIntegrity)
	}
	reportJSON, err := json.Marshal(result.Report)
	if err != nil {
		t.Fatal(err)
	}
	if _, valid, err := attest.VerifyReportSignatureOnly(reportJSON); err != nil || !valid {
		t.Fatalf("controller report signature does not cover its final metadata: valid=%v err=%v", valid, err)
	}
	// Edition boundary: the Community controller writes signed JSON only.
	// HTML/PDF binders are rendered by the Enterprise daemon on demand.
	for _, artifact := range []string{".html", ".pdf"} {
		if _, err := os.Stat(strings.TrimSuffix(result.ReportPath, ".json") + artifact); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Community controller must not write %s binders next to the JSON evidence (stat err=%v)", artifact, err)
		}
	}

	if len(fake.calls) == 0 {
		t.Fatal("controller did not issue any SSH/SCP commands")
	}
	joined := make([]string, 0, len(fake.calls))
	for _, call := range fake.calls {
		joined = append(joined, call.name+" "+strings.Join(call.args, " "))
	}
	allCommands := strings.Join(joined, "\n")
	for _, secret := range []string{"pve-super-secret", "pbs-super-secret"} {
		if strings.Contains(allCommands, secret) {
			t.Fatalf("controller leaked secret %q in an SSH/SCP command", secret)
		}
	}
	if !strings.Contains(allCommands, "'node-run'") {
		t.Fatalf("controller never invoked the protected node worker: %s", allCommands)
	}
	if !strings.Contains(allCommands, "'--skip-integrity'") {
		t.Fatalf("controller did not forward the explicit test-only integrity skip flag: %s", allCommands)
	}
	if !strings.Contains(allCommands, "'/usr/bin/rm' '-rf' '/var/lib/certistack/workers/") {
		t.Fatalf("controller did not schedule exact temporary workspace removal: %s", allCommands)
	}
	if !strings.Contains(allCommands, inRemoteScript("for dir in '/var/lib/certistack' '/var/lib/certistack/workers' '/var/lib/certistack/workers/")) || strings.Contains(allCommands, "'/usr/bin/install' '-d'") {
		t.Fatalf("controller did not create the state directory and its workers child private alongside the workspace, without changing existing ones: %s", allCommands)
	}
	if !strings.Contains(progress.String(), "INFO Preparing validation") || !strings.Contains(progress.String(), "[Storage] Mounted PBS backup disk read-only.") {
		t.Fatalf("controller did not stream safe progress updates: %s", progress.String())
	}
}

func TestPersistReportRejectsHostileWorkerIdentity(t *testing.T) {
	output := t.TempDir()
	validReportID := uuid.NewString()

	if _, err := prepareReport(&attest.Report{PlanID: "other-plan", ReportID: validReportID}, "expected-plan", "", RunOptions{OutputDir: output}); err == nil {
		t.Fatal("prepareReport accepted a worker report for a different plan")
	}

	if _, err := prepareReport(&attest.Report{PlanID: "../../outside", ReportID: validReportID}, "../../outside", "", RunOptions{OutputDir: output}); err == nil {
		t.Fatal("prepareReport accepted a report path outside the output directory")
	}

	if _, err := prepareReport(&attest.Report{PlanID: "expected-plan", ReportID: "../public_html/index"}, "expected-plan", "", RunOptions{OutputDir: output}); err == nil {
		t.Fatal("prepareReport accepted a non-UUID worker report ID")
	}
}

func TestBuildNodeRunCommandUsesCanonicalPOSIXPaths(t *testing.T) {
	workspace := "/var/lib/certistack/workers/01234567-89ab-cdef-0123-456789abcdef"
	command := buildNodeRunCommand(workspace, RunOptions{
		NodeName:      "pve-01",
		ScratchDir:    "/var/lib/certistack/scratch",
		StateDir:      "/var/lib/certistack",
		SkipIntegrity: true,
	})
	if len(command) == 0 || command[0] != path.Join(workspace, "certistack-node") {
		t.Fatalf("worker executable = %q, want %q", command[0], path.Join(workspace, "certistack-node"))
	}
	if strings.Contains(strings.Join(command, " "), `\`) {
		t.Fatalf("worker command contains a platform-specific backslash: %v", command)
	}
	for _, required := range []string{"node-run", "--plan", path.Join(workspace, "plan.yaml"), "--env-file", path.Join(workspace, "runtime.env"), "--skip-integrity"} {
		found := false
		for _, argument := range command {
			if argument == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("worker command %v does not contain %q", command, required)
		}
	}
	// Every argument once: a flag or value that appears twice is a command
	// built by appending the same thing in two places.
	seen := map[string]int{}
	for _, argument := range command {
		seen[argument]++
	}
	for argument, count := range seen {
		if count > 1 {
			t.Errorf("worker command repeats %q %d times: %v", argument, count, command)
		}
	}
}

func TestWriteWorkerPlanRedactsControllerSigningKey(t *testing.T) {
	planPath := filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml")
	plan, err := config.LoadFromFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "plan.yaml")
	if err := writeWorkerPlan(destination, plan); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sign_key_path") || strings.Contains(string(data), plan.Compliance.SignKeyPath) {
		t.Fatalf("staged worker plan contains controller signing configuration: %s", data)
	}
	if _, err := config.LoadFromFileForWorker(destination); err != nil {
		t.Fatalf("staged worker plan was rejected: %v", err)
	}
	if plan.Compliance.SignKeyPath == "" {
		t.Fatal("controller plan was modified while staging worker copy")
	}
}

func TestControllerRuntimeEnvPointsTheWorkerAtItsCopyOfThePBSKey(t *testing.T) {
	for name, value := range map[string]string{
		"PVE_URL":                 "https://pve.example:8006",
		"PVE_TOKEN_ID":            "certistack@pve!automation",
		"PVE_TOKEN_SECRET":        "pve-secret",
		"PBS_REPOSITORY":          "backup@pbs.example:store",
		"PBS_PASSWORD":            "pbs-secret",
		"CERTISTACK_PBS_KEYFILE":  "/home/operator/keys/pbs.enc",
		"PBS_ENCRYPTION_PASSWORD": "key-passphrase",
	} {
		t.Setenv(name, value)
	}
	values, err := controllerRuntimeEnv("/var/lib/certistack/workers/run")
	if err != nil {
		t.Fatal(err)
	}
	// The worker gets the path of the staged copy, never the controller's.
	if values["CERTISTACK_PBS_KEYFILE"] != "/var/lib/certistack/workers/run/"+pbsKeyfileName || values["PBS_ENCRYPTION_PASSWORD"] != "key-passphrase" {
		t.Fatalf("runtime environment: %+v", values)
	}
	envPath := filepath.Join(t.TempDir(), "runtime.env")
	if err := writeEnvFile(envPath, values); err != nil {
		t.Fatal(err)
	}
	envData, _ := os.ReadFile(envPath)
	for _, want := range []string{"CERTISTACK_PBS_KEYFILE=/var/lib/certistack/workers/run/" + pbsKeyfileName, "PBS_ENCRYPTION_PASSWORD=key-passphrase"} {
		if !strings.Contains(string(envData), want) {
			t.Errorf("runtime.env lacks %q", want)
		}
	}

	if err := checkKeyfileSource(filepath.Join(t.TempDir(), "missing.enc")); err == nil {
		t.Error("a missing key file was accepted")
	}
	if err := checkKeyfileSource(t.TempDir()); err == nil {
		t.Error("a directory was accepted as a key file")
	}
}

func TestControllerRuntimeEnvForwardsExplicitTestModeOptIn(t *testing.T) {
	for name, value := range map[string]string{
		"PVE_URL":          "https://pve.example:8006",
		"PVE_TOKEN_ID":     "certistack@pve!automation",
		"PVE_TOKEN_SECRET": "pve-secret",
		"PBS_REPOSITORY":   "backup@pbs.example:store",
		"PBS_PASSWORD":     "pbs-secret",
	} {
		t.Setenv(name, value)
	}
	t.Setenv("CERTISTACK_ALLOW_TEST_MODE", "1")

	values, err := controllerRuntimeEnv("/var/lib/certistack/workers/test")
	if err != nil {
		t.Fatal(err)
	}
	if values["CERTISTACK_ALLOW_TEST_MODE"] != "1" {
		t.Fatalf("runtime environment omitted explicit test-mode opt-in: %+v", values)
	}

	envPath := filepath.Join(t.TempDir(), "runtime.env")
	if err := writeEnvFile(envPath, values); err != nil {
		t.Fatal(err)
	}
	envData, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(envData), "CERTISTACK_ALLOW_TEST_MODE=1\n") {
		t.Fatalf("runtime environment file omitted test-mode opt-in: %s", envData)
	}
}

func TestProgressReporterHeartbeatNamesTheActivePhase(t *testing.T) {
	var output bytes.Buffer
	reporter := newProgressReporter(&output)
	reporter.lastStage = "Sandbox"
	reporter.lastMessage = "Inspecting guest networking and preparing a COW-only recovery profile for VM 9900."
	reporter.lastActivity = time.Now().Add(-31 * time.Second)
	reporter.lastHeartbeat = time.Now().Add(-31 * time.Second)

	reporter.mu.Lock()
	message := reporter.heartbeatMessageLocked()
	reporter.mu.Unlock()
	if !strings.Contains(message, "Still working: [Sandbox] Inspecting guest networking") {
		t.Fatalf("heartbeat did not name active phase: %s", message)
	}
}

func TestProgressReporterWriteDiscardsUnboundedUnterminatedInput(t *testing.T) {
	var output bytes.Buffer
	reporter := newProgressReporter(&output)

	// A hostile or malfunctioning node worker streams stderr without ever
	// writing a newline. Without a bound, progressReporter.pending would grow
	// for the entire life of the run.
	chunk := bytes.Repeat([]byte("a"), 4096)
	for i := 0; i < 1024; i++ { // 4 MiB total, well past maxPendingProgressBytes
		if _, err := reporter.Write(chunk); err != nil {
			t.Fatalf("Write returned error: %v", err)
		}
	}

	reporter.mu.Lock()
	pendingLen := len(reporter.pending)
	reporter.mu.Unlock()
	if pendingLen > maxPendingProgressBytes {
		t.Fatalf("progressReporter.pending grew to %d bytes, want capped near %d", pendingLen, maxPendingProgressBytes)
	}

	// The garbage stream eventually terminates with a newline of its own (as
	// it must, for a well-formed line to be distinguishable at all afterward);
	// whatever is left in pending at that point is flushed as one rejected
	// line. A legitimate, newline-terminated event written after that must
	// still be rendered normally: discarding unterminated overflow must not
	// wedge the reporter for the rest of the run.
	if _, err := reporter.Write([]byte("\n")); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	line := progresspkg.EventPrefix + `{"level":"INFO","message":"still working"}` + "\n"
	if _, err := reporter.Write([]byte(line)); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	// The writer is fed from a goroutine of the reporter's: closing it is
	// what makes the buffer this test reads complete.
	if err := reporter.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !strings.Contains(output.String(), "still working") {
		t.Fatalf("reporter did not render a well-formed event after discarding overflow: %s", output.String())
	}
}

func TestSupervisedWorkerCommandRefusesUntrackedStart(t *testing.T) {
	workspace := "/var/lib/certistack/workers/" + uuid.NewString()
	unit, err := workerUnitName("/var/lib/certistack/workers", workspace)
	if err != nil {
		t.Fatal(err)
	}
	command := (&Executor{}).supervisedWorkerCommand(SSHConfig{}, unit, "/var/lib/certistack/workers", workspace, path.Join(workspace, "worker.pid"), path.Join(workspace, "controller.lease"), "/var/lib/certistack", path.Join(workspace, "runtime.env"), path.Join(workspace, "worker-result.json"), path.Join(workspace, "worker-progress.log"), []string{
		path.Join(workspace, "certistack-node"), "node-run",
	})
	// What the node's shell runs, once systemd has read the command line.
	joined := strings.Join(append(command[:len(command)-1:len(command)-1], launchedScript(t, command)), " ")
	for _, required := range []string{"/usr/bin/systemd-run", unit, "worker.pid", "controller.lease", "worker-result.json", "worker-progress.log", "trap 'terminate_worker' INT TERM", "controller lease expired", "recover --state-dir", "if [ \"$lease_expired\" -eq 1 ]; then", "/usr/bin/rm -rf --"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("supervised worker command is missing %q: %s", required, joined)
		}
	}
	// The lease watch's own script, quoted into the supervisor's, removes the
	// workspace too; these orderings concern the supervisor's own steps.
	if i := strings.Index(joined, "wait \"$worker_pid\""); i >= 0 {
		joined := joined[i:]
		if markerAt, removalAt := strings.Index(joined, "/usr/bin/touch \"$recovery_marker\""), strings.Index(joined, "/usr/bin/rm -rf --"); markerAt < 0 || markerAt > removalAt {
			t.Fatalf("supervisor must write recovered.ok before removing its workspace: %s", joined)
		}
		// The lease-expiry branch opens the result before the workspace goes
		// and writes it to a controller that may be gone only afterwards, so
		// that write cannot change what happens to the workspace.
		if openAt, cleanupAt, writeAt := strings.Index(joined, "command exec 9< \"$result_file\""), strings.Index(joined, "/usr/bin/rm -rf --"), strings.Index(joined, "/usr/bin/cat <&9"); openAt < 0 || cleanupAt < openAt || writeAt < cleanupAt {
			t.Fatalf("supervisor must open the worker result, remove its workspace, then write the result: %d %d %d in %s", openAt, cleanupAt, writeAt, joined)
		}
		if cleanupAt, leaseRecoveryAt := strings.Index(joined, "/usr/bin/rm -rf --"), strings.Index(joined, "if [ \"$lease_expired\" -eq 1 ]; then"); cleanupAt < leaseRecoveryAt {
			t.Fatalf("supervisor must reserve workspace removal for lease-expiry recovery, not normal worker completion: %s", joined)
		}
	} else {
		t.Fatalf("supervisor never waits for its worker: %s", joined)
	}
	shPath, err := exec.LookPath("/bin/sh")
	if err != nil {
		shPath, err = exec.LookPath("sh")
	}
	if runtime.GOOS == "windows" {
		// The script runs on the PVE node. Git for Windows' sh reads its command
		// line with the MSYS rules, not the ones Go quotes an argument by, so a
		// syntax check here would test the quoting, not the script: it runs on
		// Linux.
	} else if err == nil {
		if output, err := exec.Command(shPath, "-n", "-c", launchedScript(t, command)).CombinedOutput(); err != nil {
			t.Fatalf("supervised worker shell script is invalid: %v: %s", err, output)
		}
	} else {
		t.Fatalf("locate sh: %v", err)
	}
}

func TestSupervisedWorkerCommandRefusesUnsafeWorkspace(t *testing.T) {
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := "/tmp/" + uuid.NewString()
	command := (&Executor{}).supervisedWorkerCommand(SSHConfig{}, "certistack-worker-test", workspaceRoot, workspace, path.Join(workspace, "worker.pid"), path.Join(workspace, "controller.lease"), "/var/lib/certistack", path.Join(workspace, "runtime.env"), path.Join(workspace, "worker-result.json"), path.Join(workspace, "worker-progress.log"), []string{
		path.Join(workspace, "certistack-node"), "node-run",
	})
	if command != nil {
		t.Fatalf("supervised worker command accepted workspace outside its exact root: %v", command)
	}
}

func TestReconcileCompletedWorkerAcceptsSupervisorRecovery(t *testing.T) {
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := workspaceRoot + "/" + uuid.NewString()
	fake := &fakeCommandRunner{workspaceState: "absent", journalPhase: "cleaned", runID: workerRunID(workspace)}
	err := (&Executor{runner: fake}).reconcileCompletedWorker(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace, "/var/lib/certistack", journalCheck{runID: workerRunID(workspace)})
	if err != nil {
		t.Fatalf("reconcileCompletedWorker() = %v, want supervisor recovery accepted", err)
	}
	if strings.Contains(recordedCommands(fake.calls), "'recover'") {
		t.Fatalf("controller attempted to rerun a deleted worker after verified supervisor recovery: %s", recordedCommands(fake.calls))
	}
}

func TestWorkerLeaseRejectsPathsOutsideExactWorkspace(t *testing.T) {
	executor := &Executor{runner: &fakeCommandRunner{}}
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := workspaceRoot + "/" + uuid.NewString()
	if err := executor.createWorkerLease(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace, "/tmp/controller.lease"); err == nil {
		t.Fatal("worker lease accepted a path outside its exact workspace")
	}
	if err := executor.renewWorkerLease(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace, "/tmp/controller.lease"); err == nil {
		t.Fatal("worker lease renewal accepted a path outside its exact workspace")
	}
}

func TestWorkerUnitRejectsPathsOutsideExactWorkspace(t *testing.T) {
	if _, err := workerUnitName("/var/lib/certistack/workers", "/tmp/"+uuid.NewString()); err == nil {
		t.Fatal("worker unit accepted a workspace outside its exact root")
	}
}

func TestExecutorRunReconcilesNodeResourcesAfterInterruptedWorkerSession(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "test-token")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "test-password")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0600); err != nil {
		t.Fatal(err)
	}
	planPath, err := filepath.Abs(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := &fakeCommandRunner{
		nodeRunHook:  cancel,
		nodeRunError: errors.New("ssh session ended"),
	}
	var progress bytes.Buffer
	_, err = (&Executor{runner: fake}).Run(ctx, RunOptions{
		PlanPath: planPath, NodeName: "pve-01", ScratchDir: "/var/lib/certistack/scratch",
		StateDir: "/var/lib/certistack", OutputDir: t.TempDir(), Writer: &progress,
		Signer: testSigner(t),
		SSH:    SSHConfig{Host: "pve.example", User: "root", KnownHostsFile: knownHosts},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted worker error = %v, want context cancellation", err)
	}
	joined := make([]string, 0, len(fake.calls))
	for _, call := range fake.calls {
		joined = append(joined, strings.Join(call.args, " "))
	}
	commands := strings.Join(joined, "\n")
	if !strings.Contains(commands, "worker.pid") || !strings.Contains(commands, "kill -TERM") {
		t.Fatalf("interruption did not target the recorded worker PID: %s", commands)
	}
	if !strings.Contains(commands, "'recover'") || !strings.Contains(commands, "'--env-file'") {
		t.Fatalf("interruption did not run authenticated journal recovery: %s", commands)
	}
	if !strings.Contains(progress.String(), "resources were reconciled before exit") {
		t.Fatalf("interruption result did not confirm cleanup: %s", progress.String())
	}
}

func TestExecutorRunAllowsExplicitCleanupAbandonment(t *testing.T) {
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "test-token")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "test-password")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0600); err != nil {
		t.Fatal(err)
	}
	planPath, err := filepath.Abs(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	cleanupCtx, cancelCleanup := context.WithCancel(context.Background())
	defer cancelCleanup()
	cleanupStarted := make(chan struct{})
	fake := &fakeCommandRunner{
		nodeRunHook:    cancelRun,
		nodeRunError:   errors.New("ssh session ended"),
		cleanupStarted: cleanupStarted,
		cleanupWait:    make(chan struct{}),
	}
	executor := &Executor{runner: fake}
	resultCh := make(chan error, 1)
	go func() {
		_, runErr := executor.Run(runCtx, RunOptions{
			PlanPath: planPath, NodeName: "pve-01", ScratchDir: "/var/lib/certistack/scratch",
			StateDir: "/var/lib/certistack", OutputDir: t.TempDir(), CleanupContext: cleanupCtx,
			Writer: io.Discard, Signer: testSigner(t),
			SSH: SSHConfig{Host: "pve.example", User: "root", KnownHostsFile: knownHosts},
		})
		resultCh <- runErr
	}()

	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("controller did not enter interruption cleanup")
	}
	cancelCleanup()

	select {
	case runErr := <-resultCh:
		if runErr == nil || !errors.Is(runErr, context.Canceled) {
			t.Fatalf("cleanup abandonment error = %v, want context cancellation", runErr)
		}
	case <-time.After(time.Second):
		t.Fatal("controller did not stop reconciliation after cleanup cancellation")
	}
}

func TestExecutorRunReconcilesCompletedWorkerTeardownBeforeRemovingWorkspace(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = "service probe failed"
	report.VMRecords[0].AllPassed = false
	report.VMRecords[0].VerificationStatus = "failed"
	report.VMRecords[0].ProbeResults[0].Passed = false
	report.TeardownEvidence = &attest.TeardownEvidence{
		AllCleaned:    false,
		CleanupErrors: []string{"destroy sandbox VM: transient PVE timeout"},
	}
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report, Error: "service probe failed"}}

	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "DR validation failed") {
		t.Fatalf("completed-worker result error = %v, want validation failure after cleanup", err)
	}
	if result == nil || result.Report == nil || result.Report.TeardownEvidence == nil {
		t.Fatalf("completed-worker result omitted evidence: %#v", result)
	}
	// The mode the worker reported is the mode requested, and is
	// signed as the worker reported it.
	if result.Report.ValidationMode != attest.ValidationModeFullIntegrity {
		t.Fatalf("report validation mode = %q, want %q", result.Report.ValidationMode, attest.ValidationModeFullIntegrity)
	}
	evidence := result.Report.TeardownEvidence
	if !evidence.AllCleaned || !evidence.OrphanSweepClean || !evidence.JournalRecoveryVerified || len(evidence.CleanupErrors) != 0 {
		t.Fatalf("completed-worker recovery evidence = %#v", evidence)
	}
	if len(evidence.InitialCleanupErrors) != 1 || evidence.InitialCleanupErrors[0] != "destroy sandbox VM: transient PVE timeout" {
		t.Fatalf("completed-worker initial cleanup evidence = %#v", evidence.InitialCleanupErrors)
	}
	if fake.workspaceRemoveCalls != 1 {
		t.Fatalf("workspace removal calls = %d, want 1 after journal reconciliation", fake.workspaceRemoveCalls)
	}
	commands := recordedCommands(fake.calls)
	if !strings.Contains(commands, "'recover'") {
		t.Fatalf("completed worker with failed teardown did not run journal recovery: %s", commands)
	}
}

func TestExecutorRunSucceedsWhenControllerRecoversAnOtherwisePassingWorker(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.TeardownEvidence = &attest.TeardownEvidence{
		AllCleaned:    false,
		CleanupErrors: []string{"destroy sandbox VM: transient PVE timeout"},
	}
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleanup_failed"}

	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("controller-recovered passing worker error = %v", err)
	}
	if result == nil || result.Report == nil || result.Report.TeardownEvidence == nil {
		t.Fatalf("controller-recovered passing worker result = %#v", result)
	}
	evidence := result.Report.TeardownEvidence
	if !result.Report.AllPassed || !evidence.AllCleaned || !evidence.OrphanSweepClean || !evidence.JournalRecoveryVerified || len(evidence.CleanupErrors) != 0 {
		t.Fatalf("controller-recovered passing worker evidence = %#v", result.Report)
	}
	if fake.workspaceRemoveCalls != 1 || !strings.Contains(recordedCommands(fake.calls), "'recover'") {
		t.Fatalf("controller did not reconcile and remove its workspace: calls=%d commands=%s", fake.workspaceRemoveCalls, recordedCommands(fake.calls))
	}
}

func TestExecutorRunFailsAWorkerReportThatDoesNotPassEvenWithoutAnError(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = "recovery time objective exceeded: completed in 90.0s, target was 60.0s"
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: report}, journalPhase: "cleaned"}

	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "recovery time objective exceeded") {
		t.Fatalf("worker report with all_passed=false and no error returned %v, want a validation failure", err)
	}
	if result == nil || result.Report == nil || result.Report.AllPassed {
		t.Fatalf("failed worker report was not preserved as failed evidence: %#v", result)
	}
}

func TestExecutorRunVerifiesWorkerClaimedCleanupEvenWhenAlreadyReportedClean(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{nodeResult: nodeapi.RunResult{Report: workerReportFor(t, opts)}, journalPhase: "cleanup_failed"}

	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("controller run with already-clean worker evidence error = %v", err)
	}
	if !strings.Contains(recordedCommands(fake.calls), "active.json") {
		t.Fatal("controller must independently verify the worker's durable journal even when the worker already reported all_cleaned: true")
	}
	if result == nil || result.Report == nil || result.Report.TeardownEvidence == nil || !result.Report.TeardownEvidence.JournalRecoveryVerified {
		t.Fatalf("controller did not record independent verification of an already-clean worker: %#v", result)
	}
}

func TestExecutorRunDowngradesWorkerClaimedCleanupWhenIndependentVerificationFails(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	// A compromised or downgraded worker asserts a clean teardown even
	// though the controller cannot confirm it.
	fake := &fakeCommandRunner{
		nodeResult:          nodeapi.RunResult{Report: workerReportFor(t, opts)},
		journalPhase:        "cleanup_failed",
		workerRecoveryError: errors.New("PVE recovery API unavailable"),
	}

	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "unverified temporary resource cleanup") {
		t.Fatalf("unsupported worker cleanup claim error = %v, want unverified cleanup", err)
	}
	if result == nil || result.Report == nil || result.Report.TeardownEvidence == nil {
		t.Fatalf("expected signed evidence alongside the unverified-cleanup error: %#v", result)
	}
	evidence := result.Report.TeardownEvidence
	if evidence.AllCleaned || evidence.OrphanSweepClean || evidence.JournalRecoveryVerified {
		t.Fatalf("signed report must not carry the worker's unsupported all_cleaned claim: %#v", evidence)
	}
	if result.Report.AllPassed || !strings.Contains(result.Report.FailureReason, unverifiedCleanupReason) {
		t.Fatalf("all_passed %v, failure_reason %q: a run whose cleanup is unverified did not pass", result.Report.AllPassed, result.Report.FailureReason)
	}
	if fake.workspaceRemoveCalls != 0 {
		t.Fatalf("workspace removal calls = %d, want 0 while cleanup is unverified", fake.workspaceRemoveCalls)
	}
	if result.ReportPath == "" {
		t.Fatal("controller did not save a report despite the downgraded evidence")
	}
	saved, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("read saved report: %v", err)
	}
	var savedReport attest.Report
	if err := json.Unmarshal(saved, &savedReport); err != nil {
		t.Fatalf("decode saved report: %v", err)
	}
	if savedReport.TeardownEvidence == nil || savedReport.TeardownEvidence.AllCleaned {
		t.Fatalf("report persisted to disk still carries the worker's unsupported all_cleaned claim: %#v", savedReport.TeardownEvidence)
	}
}

func TestExecutorRunRetainsWorkspaceWhenCompletedWorkerRecoveryFails(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	report := workerReportFor(t, opts)
	report.AllPassed = false
	report.FailureReason = "service probe failed"
	report.VMRecords[0].AllPassed = false
	report.VMRecords[0].VerificationStatus = "failed"
	report.VMRecords[0].ProbeResults[0].Passed = false
	report.TeardownEvidence = &attest.TeardownEvidence{AllCleaned: false}
	fake := &fakeCommandRunner{
		nodeResult:          nodeapi.RunResult{Report: report},
		journalPhase:        "cleanup_failed",
		workerRecoveryError: errors.New("PVE recovery API unavailable"),
	}

	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "unverified temporary resource cleanup") {
		t.Fatalf("recovery failure error = %v, want unverified cleanup", err)
	}
	if result == nil || result.Report == nil || result.Report.TeardownEvidence == nil || result.Report.TeardownEvidence.AllCleaned {
		t.Fatalf("failed recovery must preserve incomplete teardown evidence: %#v", result)
	}
	if fake.workspaceRemoveCalls != 0 {
		t.Fatalf("workspace removal calls = %d, want 0 while recovery is unverified", fake.workspaceRemoveCalls)
	}
	if !strings.Contains(recordedCommands(fake.calls), "'recover'") {
		t.Fatal("completed worker did not attempt durable journal recovery")
	}
}

func TestExecutorRunFailsWhenTemporaryWorkspaceRemovalCannotBeVerified(t *testing.T) {
	opts := completedWorkerTeardownOptions(t)
	fake := &fakeCommandRunner{
		nodeResult:   nodeapi.RunResult{Report: workerReportFor(t, opts)},
		journalPhase: "cleaned",
		workspaceRemoveErrors: []error{
			errors.New("first removal failed"),
			errors.New("second removal failed"),
			errors.New("third removal failed"),
		},
	}

	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if result == nil || result.Report == nil || !result.Report.AllPassed {
		t.Fatalf("expected signed validation evidence despite controller cleanup failure: %#v", result)
	}
	if err == nil || !strings.Contains(err.Error(), "temporary controller material cleanup was not verified") || !errors.Is(err, ErrControllerMaterialCleanupUnverified) {
		t.Fatalf("workspace cleanup error = %v, want unverified controller material", err)
	}
	if fake.workspaceRemoveCalls != 3 {
		t.Fatalf("workspace removal calls = %d, want 3 retries", fake.workspaceRemoveCalls)
	}
}

func completedWorkerTeardownOptions(t *testing.T) RunOptions {
	t.Helper()
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "test-token")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "test-password")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0600); err != nil {
		t.Fatal(err)
	}
	planPath, err := filepath.Abs(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	signer := testSigner(t)
	return RunOptions{
		PlanPath: planPath, NodeName: "pve-01", ScratchDir: "/var/lib/certistack/scratch",
		StateDir: "/var/lib/certistack", OutputDir: t.TempDir(), Signer: signer,
		SSH: SSHConfig{Host: "pve.example", User: "root", KnownHostsFile: knownHosts},
	}
}

// inRemoteScript is how text inside a shell script appears in a recorded
// SSH command, where the script is one single-quoted argument.
func inRemoteScript(text string) string {
	quoted := shellQuote(text)
	return quoted[1 : len(quoted)-1]
}

// A state directory of /tmp passed the controller's checks, and GNU
// install -d then made the node's /tmp mode 0700 before the worker refused
// it. The node's shared temporary directories are refused before the
// controller contacts the node.
func TestExecutorRefusesSharedTemporaryStateOrScratchBeforeContactingNode(t *testing.T) {
	for _, shared := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		for what, mutate := range map[string]func(*RunOptions){
			"state":   func(o *RunOptions) { o.StateDir = shared },
			"scratch": func(o *RunOptions) { o.ScratchDir = shared },
		} {
			opts := preflightTestOptions(t)
			mutate(&opts)
			fake := &fakeCommandRunner{}
			_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), shared+" is a shared temporary directory and cannot be the node's "+what+" directory") {
				t.Fatalf("%s %s: err = %v", what, shared, err)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("%s %s: the controller contacted the node: %s", what, shared, recordedCommands(fake.calls))
			}
		}
	}
	plan := &config.Plan{}
	plan.Storage.ScratchDir = "/tmp"
	if err := resolveScratchDir(&RunOptions{}, plan); err == nil {
		t.Fatal("a plan's storage.scratch_dir of /tmp was accepted")
	}
}

func recordedCommands(calls []recordedCommand) string {
	commands := make([]string, 0, len(calls))
	for _, call := range calls {
		commands = append(commands, strings.Join(call.args, " "))
	}
	return strings.Join(commands, "\n")
}

// A gone worker (SIGKILLed, say) is not signalled, and its journal is
// recovered at once, so its sandbox VM, maps and probe address do not stay
// live until the node's next run.
func TestReconcileInterruptedWorkerRecoversAfterTheWorkerIsGone(t *testing.T) {
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := workspaceRoot + "/" + uuid.NewString()
	fake := &fakeCommandRunner{workerStopResult: "gone"}
	_, err := (&Executor{runner: fake}).reconcileInterruptedWorker(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace, "/var/lib/certistack", nodeContact{name: "pve-01"})
	if err != nil || fake.recoverCalls != 1 {
		t.Fatalf("gone worker: err = %v, recover ran %d times; want the journal recovered once", err, fake.recoverCalls)
	}
}

func TestValidateOptionsRejectsRemoteCommandInjection(t *testing.T) {
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("host key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	opts := &RunOptions{
		PlanPath:   "/plans/plan.yaml",
		NodeName:   "pve-01;id",
		ScratchDir: "/var/lib/certistack/scratch",
		StateDir:   "/var/lib/certistack",
		OutputDir:  "/var/lib/certistack/reports",
		SSH: SSHConfig{
			Host:           "pve.example",
			User:           "root",
			KnownHostsFile: knownHosts,
		},
	}
	if err := validateOptions(opts); err == nil || !strings.Contains(err.Error(), "invalid PVE node") {
		t.Fatalf("expected invalid node rejection, got %v", err)
	}
}

func TestShellQuotePreservesSingleQuotes(t *testing.T) {
	if got, want := shellQuote("a'b"), "'a'\"'\"'b'"; got != want {
		t.Fatalf("shell quote = %q, want %q", got, want)
	}
}

func TestRemoveWorkspaceRetriesExactWorkspaceAndVerifiesAbsence(t *testing.T) {
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := workspaceRoot + "/" + uuid.NewString()
	fake := &fakeCommandRunner{workspaceRemoveErrors: []error{errors.New("transient SSH transport interruption")}}
	executor := &Executor{runner: fake}

	if err := executor.removeWorkspace(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace); err != nil {
		t.Fatalf("removeWorkspace should retry a transient failure: %v", err)
	}
	if fake.workspaceRemoveCalls != 2 {
		t.Fatalf("workspace removal attempts = %d, want 2", fake.workspaceRemoveCalls)
	}
	joined := make([]string, 0, len(fake.calls))
	for _, call := range fake.calls {
		joined = append(joined, strings.Join(call.args, " "))
	}
	commands := strings.Join(joined, "\n")
	if !strings.Contains(commands, "'/usr/bin/test' '!' '-e' '"+workspace+"'") {
		t.Fatalf("workspace removal did not verify exact-path absence: %s", commands)
	}
}

func TestRemoveRetainedKeyDeletesOnlyTheKey(t *testing.T) {
	workspaceRoot := "/var/lib/certistack/workers"
	workspace := workspaceRoot + "/" + uuid.NewString()
	fake := &fakeCommandRunner{}
	executor := &Executor{runner: fake}
	if err := executor.removeRetainedKey(context.Background(), SSHConfig{Host: "pve.example", User: "root"}, workspaceRoot, workspace); err != nil {
		t.Fatal(err)
	}
	var commands []string
	for _, call := range fake.calls {
		commands = append(commands, strings.Join(call.args, " "))
	}
	joined := strings.Join(commands, "\n")
	key := workspace + "/" + pbsKeyfileName
	if !strings.Contains(joined, "'/usr/bin/rm' '-f' '"+key+"'") || !strings.Contains(joined, "'/usr/bin/test' '!' '-e' '"+key+"'") {
		t.Fatalf("commands did not remove and verify exactly the key:\n%s", joined)
	}
	if strings.Contains(joined, "'-rf'") {
		t.Fatalf("removing the key touched the retained workspace:\n%s", joined)
	}
	if err := executor.removeRetainedKey(context.Background(), SSHConfig{Host: "pve.example"}, workspaceRoot, "/etc"); err == nil {
		t.Fatal("a path outside the workspace root was accepted")
	}
}

func TestResolveScratchDirPrecedence(t *testing.T) {
	plan := &config.Plan{}
	plan.Storage.ScratchDir = "/srv/certistack/plan-scratch"

	opts := RunOptions{}
	if err := resolveScratchDir(&opts, plan); err != nil || opts.ScratchDir != "/srv/certistack/plan-scratch" {
		t.Fatalf("plan scratch_dir was ignored: %q, %v", opts.ScratchDir, err)
	}
	opts = RunOptions{ScratchDir: "/var/tmp/flag-scratch"}
	if err := resolveScratchDir(&opts, plan); err != nil || opts.ScratchDir != "/var/tmp/flag-scratch" {
		t.Fatalf("explicit --scratch did not win over the plan: %q, %v", opts.ScratchDir, err)
	}
	opts = RunOptions{}
	if err := resolveScratchDir(&opts, &config.Plan{}); err != nil || opts.ScratchDir != defaultRemoteScratchDir {
		t.Fatalf("default scratch = %q, %v", opts.ScratchDir, err)
	}
	opts = RunOptions{}
	plan.Storage.ScratchDir = "relative/scratch"
	if err := resolveScratchDir(&opts, plan); err == nil {
		t.Fatal("relative plan scratch_dir was accepted")
	}
}

func TestBuildNodeRunCommandPassesOverlayStorageOnlyWhenSet(t *testing.T) {
	opts := RunOptions{NodeName: "pve1", ScratchDir: "/var/lib/certistack/scratch", StateDir: "/var/lib/certistack"}
	if got := strings.Join(buildNodeRunCommand("/w", opts), " "); strings.Contains(got, "--overlay-storage") {
		t.Fatalf("unset overlay storage leaked into the worker command: %s", got)
	}
	opts.OverlayStorage = "certistack-scratch"
	if got := strings.Join(buildNodeRunCommand("/w", opts), " "); !strings.Contains(got, "--overlay-storage certistack-scratch") {
		t.Fatalf("worker command %q lacks the overlay storage", got)
	}
}

// testSigner is a throwaway signer, as the Enterprise Edition hands the
// controller its own: it signs what the controller asks it to and counts its calls.
func testSigner(t *testing.T) *attesttest.Signer {
	t.Helper()
	_, privateKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return attesttest.NewSigner(privateKey)
}

func preflightTestOptions(t *testing.T) RunOptions {
	t.Helper()
	t.Setenv("PVE_URL", "https://pve.example:8006")
	t.Setenv("PVE_TOKEN_ID", "certistack@pve!automation")
	t.Setenv("PVE_TOKEN_SECRET", "pve-secret")
	t.Setenv("PBS_REPOSITORY", "backup@pbs!read@pbs.example:8007:datastore")
	t.Setenv("PBS_PASSWORD", "pbs-secret")
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0600); err != nil {
		t.Fatal(err)
	}
	planPath, err := filepath.Abs(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return RunOptions{
		PlanPath: planPath, NodeName: "pve-01", ScratchDir: "/var/lib/certistack/scratch",
		StateDir: "/var/lib/certistack", OutputDir: t.TempDir(), Signer: testSigner(t),
		Writer: io.Discard,
		SSH:    SSHConfig{Host: "pve.example", User: "root", KnownHostsFile: knownHosts},
	}
}

// An unwritable report directory stops the run before the controller contacts
// the node at all, not after the remote run, when the worker's evidence would
// be removed with its workspace. (The controller reads no signing key; a
// signer that fails is covered by TestRunFailsClosedWhenTheSignerFails.)
func TestExecutorRunChecksStorageBeforeContactingNode(t *testing.T) {
	notADirectory := filepath.Join(t.TempDir(), "reports-file")
	if err := os.WriteFile(notADirectory, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*RunOptions){
		"unwritable output path": func(o *RunOptions) { o.OutputDir = notADirectory },
	} {
		opts := preflightTestOptions(t)
		mutate(&opts)
		fake := &fakeCommandRunner{}
		if _, err := (&Executor{runner: fake}).Run(context.Background(), opts); err == nil {
			t.Fatalf("%s: Run succeeded", name)
		}
		if len(fake.calls) != 0 {
			t.Fatalf("%s: controller contacted the node before failing: %#v", name, fake.calls)
		}
	}
}

// The controller uploads its own executable as the worker, so an arm64
// controller must refuse an x86_64 PVE node rather than upload an arm64 binary.
func TestExecutorRunRefusesNodeOfAnotherArchitecture(t *testing.T) {
	opts := preflightTestOptions(t)
	fake := &fakeCommandRunner{nodeMachine: "s390x"}
	_, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), `architecture "s390x"`) {
		t.Fatalf("Run error = %v, want an architecture refusal", err)
	}
	for _, call := range fake.calls {
		if call.name == "scp" || strings.Contains(strings.Join(call.args, " "), "node-run") {
			t.Fatalf("controller staged or ran a worker on a node it cannot execute on: %#v", fake.calls)
		}
	}
}

// A report directory that fails after the run (for example a full disk) must
// not lose the evidence: the signed report is returned and printed.
func TestExecutorRunKeepsReportRecoverableWhenSaveFails(t *testing.T) {
	opts := preflightTestOptions(t)
	var progress bytes.Buffer
	opts.Writer = &progress
	report := workerReportFor(t, opts)
	planDir := filepath.Join(opts.OutputDir, report.PlanID)
	fake := &fakeCommandRunner{
		nodeResult:   nodeapi.RunResult{Report: report},
		journalPhase: "cleaned",
		nodeRunHook: func() {
			// The directory passed the pre-run check; now it cannot be used.
			if err := os.RemoveAll(planDir); err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(planDir, nil, 0600); err != nil {
				t.Error(err)
			}
		},
	}
	result, err := (&Executor{runner: fake}).Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "save controller report") {
		t.Fatalf("Run error = %v, want the save failure", err)
	}
	if result == nil || result.Report == nil || result.Report.Signature == "" || result.ReportPath != "" {
		t.Fatalf("Run result = %+v, want the signed, unsaved report", result)
	}
	text := progress.String()
	begin := strings.Index(text, "-----BEGIN CERTISTACK REPORT-----\n")
	end := strings.Index(text, "\n-----END CERTISTACK REPORT-----")
	if begin < 0 || end < begin {
		t.Fatalf("progress did not carry the unsaved report between markers:\n%s", text)
	}
	printed := text[begin+len("-----BEGIN CERTISTACK REPORT-----\n") : end]
	if _, valid, err := attest.VerifyReportSignatureOnly([]byte(printed)); err != nil || !valid {
		t.Fatalf("printed report does not verify: valid=%v err=%v", valid, err)
	}
	// The report was signed once, before it was saved; the failed save does not
	// ask the Signer again, and does not change what it signed.
	if calls := opts.Signer.(*attesttest.Signer).Calls(); calls != 1 {
		t.Fatalf("the Signer was called %d times, want once", calls)
	}
}

// CERTISTACK_SSH_HOST is a host name or an address of letters, digits, '.', '-'
// and ':', starting with a letter or a digit. Square brackets are not in the set
// anywhere, so "a[b" is refused, as is an IPv6 address written in brackets (its
// first character is not a letter or a digit); an IPv6 address is written
// without them. Every connection and `certistack check` apply the one rule.
func TestSSHHostAcceptsOnlyLettersDigitsDotsHyphensAndColons(t *testing.T) {
	for host, want := range map[string]bool{
		"pve1.example.com": true,
		"pve-node-01":      true,
		"10.0.0.5":         true,
		"fe80::1":          true,
		"2001:db8::1":      true,
		"a":                true,
		"a[b":              false,
		"a]b":              false,
		"a[b]":             false,
		"[::1]":            false,
		"[fd00::36]":       false,
		"]a":               false,
		"":                 false,
		"-oProxyCommand=x": false,
		".example":         false,
		":1":               false,
		"pve_1":            false,
		"user@pve1":        false,
		"pve1:22 ":         false,
	} {
		if got := ValidSSHHost(host); got != want {
			t.Errorf("ValidSSHHost(%q) = %v, want %v", host, got, want)
		}
		cfg := SSHConfig{Host: host, User: "root", KnownHostsFile: "/etc/certistack/known_hosts"}
		err := validateSSHConfig(cfg)
		if refused := err != nil && strings.Contains(err.Error(), "invalid SSH host"); refused == want {
			t.Errorf("validateSSHConfig with host %q: err %v, want the host %s", host, err, map[bool]string{true: "accepted", false: "refused"}[want])
		}
	}
}
