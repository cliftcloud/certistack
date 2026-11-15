// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/probe"
	"github.com/cliftcloud/certistack/pkg/telemetry"
)

// telemetryRig points the CLI's telemetry hooks at a temporary state file, a
// map for an environment (so a CI variable of the machine running the tests
// cannot leak in) and fake terminals.
type telemetryRig struct {
	t         *testing.T
	env       map[string]string
	statePath string
	terminals telemetryTerminals
	stderr    *bytes.Buffer
	timeout   time.Duration // the manager's allowance for one send
}

func newTelemetryRig(t *testing.T) *telemetryRig {
	t.Helper()
	rig := &telemetryRig{t: t, env: map[string]string{}, timeout: 2 * time.Second, statePath: filepath.Join(t.TempDir(), "cfg", "certistack", "telemetry.json"), stderr: &bytes.Buffer{}}
	rig.terminals = telemetryTerminals{Stdin: strings.NewReader(""), Stderr: rig.stderr}
	oldManager, oldTerminals, oldBudget := newTelemetryManager, processTelemetryTerminals, telemetryExitBudget
	newTelemetryManager = func() *telemetry.Manager {
		return &telemetry.Manager{Version: "9.9.9-test", StatePath: rig.statePath, Getenv: func(k string) string { return rig.env[k] }, Timeout: rig.timeout}
	}
	processTelemetryTerminals = func() telemetryTerminals { return rig.terminals }
	t.Cleanup(func() {
		newTelemetryManager, processTelemetryTerminals, telemetryExitBudget = oldManager, oldTerminals, oldBudget
		// Running a command names it for the signal handler; leave that as found.
		activeCommand.Store("")
		remoteWorkerStaged.Store(false)
	})
	for _, name := range []string{"PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "PBS_REPOSITORY", "PBS_PASSWORD", "CERTISTACK_SSH_HOST", "CERTISTACK_NODE", "CERTISTACK_SIGN_KEY"} {
		t.Setenv(name, "")
	}
	return rig
}

// interactive makes both streams terminals and gives the question its input.
func (r *telemetryRig) interactive(input string) {
	r.terminals = telemetryTerminals{Stdin: strings.NewReader(input), Stderr: r.stderr, StdinTerminal: true, StderrTerminal: true}
}

func (r *telemetryRig) execute(args ...string) (string, error) {
	r.t.Helper()
	root := newRootCmd(nil)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(io.Discard)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func (r *telemetryRig) state() telemetry.State {
	r.t.Helper()
	st, status := telemetry.ReadState(r.statePath)
	if status != telemetry.StateOK {
		r.t.Fatalf("state is %v", status)
	}
	return st
}

func (r *telemetryRig) hasState() bool {
	_, err := os.Stat(r.statePath)
	return err == nil
}

type countingServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []string
	dumps  []string
}

func newCountingServer(t *testing.T, handler http.HandlerFunc) *countingServer {
	t.Helper()
	c := &countingServer{}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		c.mu.Lock()
		c.bodies = append(c.bodies, string(body))
		c.dumps = append(c.dumps, r.Method+" "+r.URL.String()+" "+r.UserAgent()+" "+r.Header.Get("Content-Type")+"\n"+string(body))
		c.mu.Unlock()
		if handler != nil {
			handler(w, r)
		}
	}))
	t.Cleanup(c.Server.Close)
	return c
}

func (c *countingServer) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

// A report as a finished run hands it to the command: names, addresses and
// paths of the operator's estate all over it.
func finishedRun(passed bool) *controller.Result {
	return &controller.Result{
		ReportPath: "/srv/secret-reports/payroll-dr.json",
		Report: &attest.Report{
			Timestamp:        "2026-10-01T22:15:00Z",
			NodeFQDN:         "pve-secret-node.corp.example.net",
			PlanName:         "payroll-dr-plan",
			PlanID:           "plan-payroll",
			AllPassed:        passed,
			TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true},
			VMRecords:        []probe.VMValidationRecord{{VMID: 9001, Name: "payroll-db-vm"}, {VMID: 9002, Name: "ad-controller-02"}},
		},
	}
}

func stubRun(t *testing.T, result *controller.Result, err error) {
	t.Helper()
	old := runController
	runController = func(context.Context, controller.RunOptions) (*controller.Result, error) { return result, err }
	t.Cleanup(func() { runController = old })
}

func TestTelemetryCommandLifecycle(t *testing.T) {
	rig := newTelemetryRig(t)

	out, err := rig.execute("telemetry", "status")
	if err != nil || !strings.Contains(out, "telemetry: off") || !strings.Contains(out, "not been asked") || !strings.Contains(out, rig.statePath) || !strings.Contains(out, "(missing)") {
		t.Fatalf("status of a fresh install: %v\n%s", err, out)
	}
	if out, err = rig.execute("telemetry", "show"); err != nil || !strings.Contains(out, "nothing is sent: disabled") || strings.Contains(out, "install_id") {
		t.Fatalf("show while off: %v\n%s", err, out)
	}
	if rig.hasState() {
		t.Fatal("status and show created the state file")
	}

	if out, err = rig.execute("telemetry", "enable", "--business"); err != nil || !strings.Contains(out, "Telemetry is on") || !strings.Contains(out, "Business or commercial use: yes") {
		t.Fatalf("enable --business: %v\n%s", err, out)
	}
	st := rig.state()
	if !st.Answered || !st.Enabled || !st.BusinessUse || st.InstallID == "" {
		t.Fatalf("state after enable --business: %+v", st)
	}
	shown, err := rig.execute("telemetry", "show")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(shown))
	dec.DisallowUnknownFields()
	var payload telemetry.Payload
	if err := dec.Decode(&payload); err != nil {
		t.Fatalf("show is not exactly the payload: %v\n%s", err, shown)
	}
	if payload.InstallID != st.InstallID || payload.Version != "9.9.9-test" || !payload.BusinessUse || payload.ClusterCount != 0 {
		t.Fatalf("show = %+v", payload)
	}
	if out, err = rig.execute("telemetry", "status"); err != nil || !strings.Contains(out, "telemetry: on") || !strings.Contains(out, "install id: "+st.InstallID) || !strings.Contains(out, telemetry.DefaultURL) {
		t.Fatalf("status while on: %v\n%s", err, out)
	}
	// Nothing in show or status carries what must stay local.
	for _, text := range []string{shown, out} {
		if strings.Contains(text, st.Salt) {
			t.Errorf("the salt is printed:\n%s", text)
		}
	}

	// enable without --business answers no, and keeps the install id.
	if _, err = rig.execute("telemetry", "enable"); err != nil {
		t.Fatal(err)
	}
	if again := rig.state(); again.InstallID != st.InstallID || again.BusinessUse {
		t.Fatalf("state after a plain enable: %+v", again)
	}

	out, err = rig.execute("telemetry", "disable")
	if err != nil || !strings.Contains(out, "Telemetry is off") || !strings.Contains(out, st.InstallID) {
		t.Fatalf("disable: %v\n%s", err, out)
	}
	if off := rig.state(); !off.Answered || off.Enabled || off.InstallID != "" {
		t.Fatalf("state after disable: %+v", off)
	}
	if out, _ = rig.execute("telemetry", "show"); !strings.Contains(out, "nothing is sent: disabled") || !strings.Contains(out, "chose not to share") {
		t.Fatalf("show after disable:\n%s", out)
	}

	if _, err = rig.execute("telemetry", "enable"); err != nil {
		t.Fatal(err)
	}
	fresh := rig.state()
	out, err = rig.execute("telemetry", "reset")
	if err != nil || !strings.Contains(out, "deleted") || !strings.Contains(out, fresh.InstallID) {
		t.Fatalf("reset: %v\n%s", err, out)
	}
	if rig.hasState() {
		t.Fatal("reset left the state file")
	}
	if _, err = rig.execute("telemetry", "reset"); err != nil {
		t.Fatalf("reset with nothing to delete: %v", err)
	}
}

// The seams tests replace are the only difference from production: the real
// manager reads the process environment and the user's configuration
// directory, and carries this build's version.
func TestProductionWiringUsesTheProcessEnvironmentAndTheVersion(t *testing.T) {
	m := productionTelemetryManager()
	if m.Version != version || m.StatePath != "" || m.Getenv != nil || m.Now != nil || m.Timeout != 0 {
		t.Fatalf("production manager = %+v", m)
	}
	terminals := realTelemetryTerminals()
	if terminals.Stdin != io.Reader(os.Stdin) || terminals.Stderr != io.Writer(os.Stderr) {
		t.Fatal("the real terminals are not the process's own streams")
	}
}

func TestTelemetrySubcommandsTakeNoArguments(t *testing.T) {
	rig := newTelemetryRig(t)
	for _, sub := range []string{"status", "show", "enable", "disable", "reset"} {
		if _, err := rig.execute("telemetry", sub, "extra"); err == nil {
			t.Errorf("telemetry %s accepted an argument", sub)
		}
	}
	if rig.hasState() {
		t.Error("a refused command wrote the state file")
	}
}

func TestEnablingUnderDoNotTrackSaysNothingWillBeSent(t *testing.T) {
	rig := newTelemetryRig(t)
	rig.env["DO_NOT_TRACK"] = "1"
	out, err := rig.execute("telemetry", "enable")
	if err != nil || !strings.Contains(out, "nothing is sent in this environment") || !strings.Contains(out, "DO_NOT_TRACK") {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, _ = rig.execute("telemetry", "status"); !strings.Contains(out, "telemetry: off") || !strings.Contains(out, "DO_NOT_TRACK is set") {
		t.Fatalf("status under DO_NOT_TRACK:\n%s", out)
	}
}

func TestShowUnderTheEnvironmentOptInIsASampleUntilTheInstallIsKept(t *testing.T) {
	rig := newTelemetryRig(t)
	rig.env["CERTISTACK_TELEMETRY"] = "1"
	root := newRootCmd(nil)
	var out, stderr bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&stderr)
	root.SetArgs([]string{"telemetry", "show"})
	if err := root.ExecuteContext(context.Background()); err != nil || !strings.Contains(out.String(), `"install_id"`) {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if rig.hasState() {
		t.Fatal("show under CERTISTACK_TELEMETRY=1 wrote the state file")
	}
	if !strings.Contains(stderr.String(), "sample") || !strings.Contains(stderr.String(), rig.statePath) {
		t.Errorf("show did not say its install id is a sample and where the real one is kept:\n%s", stderr.String())
	}
}

// The first-run question is put by exactly the commands that do real work, to a
// person at a terminal, once.
func TestFirstRunQuestionIsPutByRunPlanDoctorAndInit(t *testing.T) {
	for _, command := range []string{"run", "plan", "doctor", "init"} {
		t.Run(command, func(t *testing.T) {
			rig := newTelemetryRig(t)
			stubRun(t, nil, io.EOF)
			rig.interactive("y\ny\n")
			_, _ = rig.execute(command)
			if !strings.Contains(rig.stderr.String(), telemetry.QuestionShare) || !strings.Contains(rig.stderr.String(), telemetry.QuestionBusiness) {
				t.Fatalf("%s did not ask:\n%s", command, rig.stderr.String())
			}
			if st := rig.state(); !st.Enabled || !st.BusinessUse || st.InstallID == "" {
				t.Fatalf("state after two yeses: %+v", st)
			}
			// Once: a second invocation is silent.
			rig.stderr.Reset()
			rig.interactive("n\nn\n")
			_, _ = rig.execute(command)
			if strings.Contains(rig.stderr.String(), telemetry.QuestionShare) {
				t.Fatalf("%s asked a second time", command)
			}
			if !rig.state().Enabled {
				t.Fatal("the second invocation changed the answer")
			}
		})
	}
}

func TestFirstRunNoIsStoredAndNeverAskedAgain(t *testing.T) {
	for name, input := range map[string]string{"n": "n\n", "empty": "\n", "end of input": "", "garbage": "perhaps\n"} {
		t.Run(name, func(t *testing.T) {
			rig := newTelemetryRig(t)
			rig.interactive(input)
			_, _ = rig.execute("doctor")
			if strings.Contains(rig.stderr.String(), telemetry.QuestionBusiness) {
				t.Fatalf("the business question was put after a no:\n%s", rig.stderr.String())
			}
			if st := rig.state(); !st.Answered || st.Enabled || st.InstallID != "" {
				t.Fatalf("state after %q: %+v", input, st)
			}
			rig.stderr.Reset()
			rig.interactive("y\ny\n")
			_, _ = rig.execute("doctor")
			if rig.stderr.Len() != 0 || rig.state().Enabled {
				t.Fatalf("asked again after a no:\n%s", rig.stderr.String())
			}
		})
	}
}

func TestNeverPromptsWhereNobodyCanAnswer(t *testing.T) {
	for name, setup := range map[string]func(r *telemetryRig){
		"stdin is not a terminal":  func(r *telemetryRig) { r.interactive("y\ny\n"); r.terminals.StdinTerminal = false },
		"stderr is not a terminal": func(r *telemetryRig) { r.interactive("y\ny\n"); r.terminals.StderrTerminal = false },
		"no terminal at all": func(r *telemetryRig) {
			r.interactive("y\ny\n")
			r.terminals.StdinTerminal, r.terminals.StderrTerminal = false, false
		},
		"CI is set":                func(r *telemetryRig) { r.interactive("y\ny\n"); r.env["CI"] = "true" },
		"DO_NOT_TRACK":             func(r *telemetryRig) { r.interactive("y\ny\n"); r.env["DO_NOT_TRACK"] = "1" },
		"CERTISTACK_TELEMETRY=off": func(r *telemetryRig) { r.interactive("y\ny\n"); r.env["CERTISTACK_TELEMETRY"] = "off" },
	} {
		t.Run(name, func(t *testing.T) {
			rig := newTelemetryRig(t)
			setup(rig)
			for _, command := range []string{"run", "plan", "doctor", "init"} {
				_, _ = rig.execute(command)
			}
			if rig.stderr.Len() != 0 {
				t.Fatalf("something was printed to a stream nobody reads:\n%s", rig.stderr.String())
			}
			if rig.hasState() {
				t.Fatal("a run that could not ask stored an answer")
			}
		})
	}
}

func TestOtherCommandsNeverPrompt(t *testing.T) {
	for _, args := range [][]string{
		// The commands that would do something on a host (keygen, recover and the
		// node-side ones) are held out of the prompt by the allowlist in
		// pkg/telemetry, whose own test names them.
		{"version"}, {"telemetry", "status"}, {"telemetry", "show"}, {"verify-report"}, {"validate"}, {"completion", "bash"}, {"help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			rig := newTelemetryRig(t)
			rig.interactive("y\ny\n")
			_, _ = rig.execute(args...)
			if strings.Contains(rig.stderr.String(), "usage statistics") || rig.hasState() {
				t.Fatalf("%v asked or stored an answer:\n%s", args, rig.stderr.String())
			}
		})
	}
}

func TestInterruptedQuestionStoresNothing(t *testing.T) {
	rig := newTelemetryRig(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	rig.terminals = telemetryTerminals{Stdin: pr, Stderr: rig.stderr, StdinTerminal: true, StderrTerminal: true}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { telemetryPreRun(ctx, "doctor"); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the question outlived the command's context")
	}
	if rig.hasState() {
		t.Fatal("an interrupted question stored an answer")
	}
}

// What `run` does after the verdict: one request when opted in, none otherwise,
// and the exit status is the run's own either way.
func TestRunSendsOneReportAfterACompletedRunAndNeverChangesTheOutcome(t *testing.T) {
	for _, tc := range []struct {
		name     string
		passed   bool
		wantCode int
	}{
		{"a passed run", true, 0},
		{"a failed validation", false, exitCodeValidationFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newCountingServer(t, nil)
			rig := newTelemetryRig(t)
			rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"

			runErr := func(result *controller.Result, err error) error {
				stubRun(t, result, err)
				_, got := rig.execute("run", "plan.yaml")
				return got
			}

			// Off: the same run, no request.
			offErr := runErr(finishedRun(tc.passed), nil)
			if srv.count() != 0 {
				t.Fatalf("%d requests while telemetry was off", srv.count())
			}
			if _, err := rig.execute("telemetry", "enable"); err != nil {
				t.Fatal(err)
			}
			onErr := runErr(finishedRun(tc.passed), nil)
			if srv.count() != 1 {
				t.Fatalf("%d requests after a completed run with telemetry on, want 1", srv.count())
			}
			if exitCodeForError(onErr) != tc.wantCode || exitCodeForError(offErr) != tc.wantCode {
				t.Fatalf("exit codes on=%d off=%d, want %d", exitCodeForError(onErr), exitCodeForError(offErr), tc.wantCode)
			}
			if (onErr == nil) != (offErr == nil) || (onErr != nil && onErr.Error() != offErr.Error()) {
				t.Fatalf("telemetry changed the command's result: %v vs %v", onErr, offErr)
			}
			var got telemetry.Payload
			dec := json.NewDecoder(strings.NewReader(srv.bodies[0]))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.ClusterCount != 1 || got.LastTestRun != "2026-10-01" || got.Version != "9.9.9-test" {
				t.Fatalf("payload = %+v", got)
			}
			// What the operator can read with `show` is what was sent.
			if shown, _ := rig.execute("telemetry", "show"); shown != srv.bodies[0] {
				t.Fatalf("show:\n%s\nsent:\n%s", shown, srv.bodies[0])
			}
			// A second run the same day does not send again.
			runErr(finishedRun(tc.passed), nil)
			if srv.count() != 1 {
				t.Fatalf("%d requests after two runs on one day", srv.count())
			}
		})
	}
}

func TestNothingOfTheRunReachesTheServer(t *testing.T) {
	srv := newCountingServer(t, nil)
	rig := newTelemetryRig(t)
	rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
	rig.env["PVE_TOKEN_SECRET"] = "tok-AbC123SecretValue"
	t.Setenv("PVE_URL", "https://10.99.88.77:8006")
	t.Setenv("PVE_TOKEN_SECRET", "tok-AbC123SecretValue")
	if _, err := rig.execute("telemetry", "enable", "--business"); err != nil {
		t.Fatal(err)
	}
	stubRun(t, finishedRun(true), nil)
	if _, err := rig.execute("run", "/srv/secret-plans/dr.yaml", "--node", "pve-secret-node", "--ssh-host", "10.99.88.77"); err != nil {
		t.Fatal(err)
	}
	if srv.count() != 1 {
		t.Fatalf("%d requests", srv.count())
	}
	st := rig.state()
	everything := strings.ToLower(srv.dumps[0])
	for _, secret := range []string{
		"pve-secret-node", "corp.example.net", "payroll", "ad-controller-02", "9001", "9002", "10.99.88.77",
		"tok-abc123secretvalue", "/srv/secret-plans", "/srv/secret-reports", "dr.yaml", "plan-payroll",
		strings.ToLower(st.Salt),
	} {
		if strings.Contains(everything, secret) {
			t.Errorf("%q reached the server:\n%s", secret, srv.dumps[0])
		}
	}
	for _, hash := range st.Clusters {
		if strings.Contains(everything, hash[:16]) {
			t.Error("a cluster hash reached the server")
		}
	}
	if !strings.HasPrefix(srv.dumps[0], "POST /api/telemetry certistack-telemetry/9.9.9-test application/json\n") {
		t.Errorf("request line, user agent or content type: %q", strings.SplitN(srv.dumps[0], "\n", 2)[0])
	}
}

func TestRunDoesNotReportARunThatTestedNothingOrWasInterrupted(t *testing.T) {
	srv := newCountingServer(t, nil)
	rig := newTelemetryRig(t)
	rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
	if _, err := rig.execute("telemetry", "enable"); err != nil {
		t.Fatal(err)
	}
	noVMs := finishedRun(false)
	noVMs.Report.VMRecords = nil
	for name, result := range map[string]*controller.Result{"no result": nil, "no report": {}, "a refusal that tested no VM": noVMs} {
		stubRun(t, result, io.ErrUnexpectedEOF)
		_, _ = rig.execute("run", "plan.yaml")
		if srv.count() != 0 {
			t.Fatalf("%s was reported", name)
		}
	}
	// An interrupted command (its context is done) sends nothing.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	telemetryAfterRun(ctx, io.Discard, finishedRun(true))
	if srv.count() != 0 {
		t.Fatal("an interrupted run was reported")
	}
	// A failed run that did test VMs is reported, whatever its error.
	stubRun(t, finishedRun(false), io.ErrUnexpectedEOF)
	_, _ = rig.execute("run", "plan.yaml")
	if srv.count() != 1 {
		t.Fatalf("a failed validation sent %d requests, want 1", srv.count())
	}
}

func TestAHangingEndpointCostsTheRunAtMostTheExitBudget(t *testing.T) {
	release := make(chan struct{})
	srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	rig := newTelemetryRig(t)
	rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
	if _, err := rig.execute("telemetry", "enable"); err != nil {
		t.Fatal(err)
	}
	telemetryExitBudget = 300 * time.Millisecond
	rig.timeout = 10 * time.Second
	stubRun(t, finishedRun(true), nil)
	start := time.Now()
	_, err := rig.execute("run", "plan.yaml")
	if err != nil {
		t.Fatalf("a hanging endpoint failed the run: %v", err)
	}
	// The send itself is allowed 10 s here, so it is the exit budget (300 ms)
	// that ended the wait.
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the run took %v", took)
	}
}

func TestTheExitBudgetIsTwoSeconds(t *testing.T) {
	if telemetryExitBudget != telemetry.ExitBudget || telemetry.ExitBudget != 2*time.Second {
		t.Fatalf("exit budget %v / %v, want 2s", telemetryExitBudget, telemetry.ExitBudget)
	}
}

func TestAFailingEndpointNeverChangesTheExitStatus(t *testing.T) {
	for _, status := range []int{500, 404, 301} {
		srv := newCountingServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		rig := newTelemetryRig(t)
		rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
		if _, err := rig.execute("telemetry", "enable"); err != nil {
			t.Fatal(err)
		}
		stubRun(t, finishedRun(false), nil)
		_, err := rig.execute("run", "plan.yaml")
		if exitCodeForError(err) != exitCodeValidationFailed || srv.count() != 1 {
			t.Fatalf("status %d: exit %d with %d requests", status, exitCodeForError(err), srv.count())
		}
	}
}

// The report is sent by `run` and by nothing else. plan, doctor, init, validate,
// verify-report and the node-side commands reach no telemetry code that sends,
// and the one send site is guarded by the decision in pkg/telemetry.
func TestOnlyRunSendsAReport(t *testing.T) {
	fset := token.NewFileSet()
	calls := map[string][]string{}
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".lab", "node_modules", "site":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join("..", ".."), path)
		rel = filepath.ToSlash(rel)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				if fn.Name == "telemetryAfterRun" {
					calls["telemetryAfterRun"] = append(calls["telemetryAfterRun"], rel)
				}
			case *ast.SelectorExpr:
				if fn.Sel.Name == "AfterRun" {
					calls["AfterRun"] = append(calls["AfterRun"], rel)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(calls["telemetryAfterRun"], ","); got != "cmd/certistack/cmd_run.go" {
		t.Errorf("telemetryAfterRun is called from %q, want only cmd/certistack/cmd_run.go", got)
	}
	if got := strings.Join(calls["AfterRun"], ","); got != "cmd/certistack/cmd_telemetry.go" {
		t.Errorf("Manager.AfterRun (the one send) is called from %q, want only cmd/certistack/cmd_telemetry.go", got)
	}
}

// pkg/telemetry is imported by the command-line layer alone: not by the
// controller, the orchestrator, the node worker's packages or any library a
// worker on a PVE node runs.
func TestOnlyTheCommandLineImportsTheTelemetryPackage(t *testing.T) {
	const marker = `"github.com/cliftcloud/certistack/pkg/telemetry"`
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".lab", "node_modules", "site":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if strings.Contains(string(data), marker) && rel != "cmd/certistack/cmd_telemetry.go" {
			t.Errorf("%s imports pkg/telemetry: only cmd/certistack/cmd_telemetry.go may", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The scheduled job of docs/automation.md runs as an account with no home. With
// CERTISTACK_TELEMETRY=1 in its unit and no configuration directory it can
// write, the run sent nothing and said nothing: the job's log held no sign of
// it. Nothing is still sent, and the run now ends with one warning that names
// the state file and the fix, the unit's line. Its exit status is unchanged.
func TestARunWhoseUsageStateCannotBeWrittenSaysSoOnce(t *testing.T) {
	srv := newCountingServer(t, nil)
	rig := newTelemetryRig(t)
	rig.env["CERTISTACK_TELEMETRY"] = "1"
	rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
	// As on the controller: a home (/home/certistack) that does not exist,
	// under a directory the account cannot write.
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions do not stop this user")
	}
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	rig.statePath = filepath.Join(home, "certistack", ".config", "certistack", "telemetry.json")
	runWithStderr := func() (string, error) {
		t.Helper()
		root := newRootCmd(nil)
		var stderr bytes.Buffer
		root.SetOut(io.Discard)
		root.SetErr(&stderr)
		root.SetArgs([]string{"run", "plan.yaml"})
		err := root.ExecuteContext(context.Background())
		return stderr.String(), err
	}
	stubRun(t, finishedRun(true), nil)
	stderr, err := runWithStderr()
	if err != nil {
		t.Fatalf("the run failed: %v", err)
	}
	if srv.count() != 0 {
		t.Fatalf("%d requests; a report whose state cannot be kept must not be sent", srv.count())
	}
	const warning = "Warning: no usage statistics were sent"
	if strings.Count(stderr, warning) != 1 || !strings.Contains(stderr, rig.statePath) || !strings.Contains(stderr, "Environment=XDG_CONFIG_HOME=%S/certistack") {
		t.Fatalf("want one warning naming %s and the fix:\n%s", rig.statePath, stderr)
	}
	if !strings.HasSuffix(strings.TrimRight(stderr, "\n"), telemetry.UnwritableFix) {
		t.Errorf("the warning is not the run's last line:\n%s", stderr)
	}

	// A failed validation keeps its exit status 1.
	stubRun(t, finishedRun(false), errors.New("DR validation failed"))
	if stderr, err := runWithStderr(); exitCodeForError(err) != exitCodeValidationFailed || strings.Count(stderr, warning) != 1 {
		t.Errorf("a failed validation: exit %d, warnings %d", exitCodeForError(err), strings.Count(stderr, warning))
	}

	// Where the state can be written, or the statistics are off, nothing is said.
	rig.statePath = filepath.Join(t.TempDir(), "certistack", "telemetry.json")
	stubRun(t, finishedRun(true), nil)
	if stderr, _ := runWithStderr(); strings.Contains(stderr, warning) || srv.count() != 1 {
		t.Errorf("a writable state: %d requests, stderr:\n%s", srv.count(), stderr)
	}
	rig.env["CERTISTACK_TELEMETRY"] = ""
	rig.statePath = filepath.Join(home, "certistack", ".config", "certistack", "telemetry.json")
	if stderr, _ := runWithStderr(); strings.Contains(stderr, warning) {
		t.Errorf("statistics off: a warning:\n%s", stderr)
	}
}

// reset with no state file said "The telemetry state file is deleted." (the
// removal page's reset of the scheduled job's account, which had none, read as
// if it had removed something). It now says there was nothing to reset and
// names the file it looked for, with or without CERTISTACK_TELEMETRY=1.
func TestTelemetryResetWithNoStateFileSaysThereWasNothingToReset(t *testing.T) {
	rig := newTelemetryRig(t)
	for _, environment := range []string{"", "1"} {
		rig.env["CERTISTACK_TELEMETRY"] = environment
		out, err := rig.execute("telemetry", "reset")
		if err != nil {
			t.Fatalf("CERTISTACK_TELEMETRY=%q: %v", environment, err)
		}
		if !strings.Contains(out, "Nothing to reset: there is no telemetry state file at "+rig.statePath+".") || strings.Contains(out, "deleted") || strings.Contains(out, "Forgotten") {
			t.Errorf("CERTISTACK_TELEMETRY=%q, no state file:\n%s", environment, out)
		}
		if environment == "1" && !strings.Contains(out, "still on") {
			t.Errorf("the environment still turns the reports on, and reset does not say so:\n%s", out)
		}
		if rig.hasState() {
			t.Fatal("reset made a state file")
		}
	}
	// A file that is there is deleted, and reset says so.
	rig.env["CERTISTACK_TELEMETRY"] = ""
	if _, err := rig.execute("telemetry", "enable"); err != nil {
		t.Fatal(err)
	}
	if out, err := rig.execute("telemetry", "reset"); err != nil || !strings.Contains(out, "deleted") || strings.Contains(out, "Nothing to reset") || rig.hasState() {
		t.Errorf("reset of a state file: %v\n%s", err, out)
	}
}

// The scheduled unit sent statistics (CERTISTACK_TELEMETRY=1 and its own
// configuration directory), and status, run for the same account without the
// variable, said "telemetry: off ... you have not been asked yet", and show
// "nothing is sent". Both now say that the state holds an install the
// environment opt-in keeps, when it last sent, and that this shell does not
// set the variable; never "not asked yet". A stored no says both.
func TestStatusAndShowSayWhatAnInstallKeptByTheEnvironmentDoes(t *testing.T) {
	srv := newCountingServer(t, nil)
	rig := newTelemetryRig(t)
	rig.env["CERTISTACK_TELEMETRY"] = "1"
	rig.env["CERTISTACK_TELEMETRY_URL"] = srv.URL + "/api/telemetry"
	stubRun(t, finishedRun(true), nil)
	if _, err := rig.execute("run", "plan.yaml"); err != nil || srv.count() != 1 {
		t.Fatalf("the unit's run: %v, %d requests", err, srv.count())
	}
	kept := rig.state()
	sent := kept.LastSent
	rig.env["CERTISTACK_TELEMETRY"] = ""

	want := "the state at " + rig.statePath + " holds an install kept by CERTISTACK_TELEMETRY=1 (last sent " + sent + "): reports are sent by runs that set it, such as the scheduled unit; this shell does not set it"
	status, err := rig.execute("telemetry", "status")
	if err != nil || !strings.Contains(status, want) || !strings.Contains(status, kept.InstallID) || strings.Contains(status, "not been asked") || strings.Contains(status, "not asked") {
		t.Errorf("status: %v\n%s\nwant it to say: %s", err, status, want)
	}
	show, err := rig.execute("telemetry", "show")
	if err != nil || !strings.Contains(show, "this shell sends nothing: "+want) || strings.Contains(show, "not been asked") {
		t.Errorf("show: %v\n%s", err, show)
	}

	// A no stored here: the install is still there, and runs that set the
	// variable still report.
	if _, err := rig.execute("telemetry", "disable"); err != nil {
		t.Fatal(err)
	}
	rig.env["CERTISTACK_TELEMETRY"] = "1"
	if _, err := rig.execute("run", "plan.yaml"); err != nil {
		t.Fatal(err)
	}
	rig.env["CERTISTACK_TELEMETRY"] = ""
	if st := rig.state(); st.HasInstall() && !st.Enabled {
		status, _ = rig.execute("telemetry", "status")
		if !strings.Contains(status, "you chose not to share") || !strings.Contains(status, "holds an install kept by CERTISTACK_TELEMETRY=1") {
			t.Errorf("status with a stored no and a kept install:\n%s", status)
		}
	} else {
		t.Fatalf("state after the run with the variable: %+v", st)
	}
}
