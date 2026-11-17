// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cliftcloud/certistack/internal/journal"
	"github.com/cliftcloud/certistack/pkg/attest"
	"github.com/cliftcloud/certistack/pkg/attest/attesttest"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/initplan"
)

// runRoot runs the whole command line with stdout going to out.
func runRoot(t *testing.T, out io.Writer, args ...string) error {
	t.Helper()
	root := newRootCmd(nil)
	root.SetOut(out)
	root.SetErr(io.Discard)
	root.SetArgs(args)
	return root.ExecuteContext(context.Background())
}

var errNoSpace = errors.New("write /dev/full: no space left on device")

// fullDiskWriter is /dev/full: it accepts budget bytes, then fails every write.
type fullDiskWriter struct{ budget int }

func (w *fullDiskWriter) Write(p []byte) (int, error) {
	if w.budget <= 0 {
		return 0, errNoSpace
	}
	if len(p) > w.budget {
		n := w.budget
		w.budget = 0
		return n, errNoSpace
	}
	w.budget -= len(p)
	return len(p), nil
}

// shortWriter accepts part of a write without an error.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

// When none or part of a text command's result reaches a full disk or a
// failing collector, the command fails and names the write failure, keeps its
// own exit status when it has one, and, where it changed something, says what
// it did.
func TestTextCommandsFailWhenTheirResultCannotBeWritten(t *testing.T) {
	t.Setenv("PVE_URL", "")
	root := t.TempDir()

	planPath := writeValidationFixture(t, root, "valid.yaml")
	publicKey, privateKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := attest.BuildReport(&config.Plan{PlanID: "text-output", Name: "plan"}, "node-a", time.Second, true, nil, "")
	if err := attesttest.SignReport(report, privateKey); err != nil {
		t.Fatal(err)
	}
	reportData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(root, "report.json")
	if err := os.WriteFile(reportPath, reportData, 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := journal.Write(filepath.Join(stateDir, "active.json"), journal.Record{RunID: "run-cleaned", Phase: "cleaned"}); err != nil {
		t.Fatal(err)
	}
	recoverState = func(context.Context, context.Context, string) error { return nil }
	t.Cleanup(func() { recoverState = recoveryFromPackage })

	for _, tc := range []struct {
		name string
		args func() []string
		// saved is what a failed write must still say was done.
		saved string
		// controlErr is the exit the command gives with a working stdout.
		controlErr string
	}{
		{"validate", func() []string { return []string{"validate", planPath} }, "", ""},
		{"verify-report text", func() []string {
			return []string{"verify-report", "--trusted-key", hex.EncodeToString(ed25519.PublicKey(publicKey)), reportPath}
		}, "", ""},
		{"doctor text", func() []string {
			return []string{"doctor", "--scratch", filepath.Join(root, "scratch"), "--state-dir", stateDir}
		}, "", "preflight diagnostics failed"},
		{"recover", func() []string { return []string{"recover", "--state-dir", stateDir} }, "crash recovery ran and completed", ""},
		{"inspect journal", func() []string { return []string{"inspect", "--state-dir", stateDir} }, "", ""},
		{"version", func() []string { return []string{"version"} }, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "doctor text" && runtime.GOOS != "linux" {
				tc.controlErr = ""
			}
			// A working stdout: the command's own answer, no write failure.
			var out bytes.Buffer
			err := runRoot(t, &out, tc.args()...)
			if (tc.controlErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.controlErr)) {
				t.Fatalf("with a working stdout: err = %v, want %q\n%s", err, tc.controlErr, out.String())
			}
			if err != nil && strings.Contains(err.Error(), "could not be written") {
				t.Fatalf("a write failure with a working stdout: %v", err)
			}
			if out.Len() == 0 {
				t.Fatal("the command wrote nothing")
			}
			for name, writer := range map[string]io.Writer{
				"stdout full from the start": &fullDiskWriter{},
				"stdout fills part way":      &fullDiskWriter{budget: 24},
				"stdout takes half a write":  shortWriter{},
			} {
				err := runRoot(t, writer, tc.args()...)
				if err == nil || !strings.Contains(err.Error(), "could not be written to standard output") {
					t.Errorf("%s: err = %v, want the write failure named", name, err)
					continue
				}
				if name != "stdout takes half a write" && !errors.Is(err, errNoSpace) {
					t.Errorf("%s: the write error is not kept: %v", name, err)
				}
				if tc.saved != "" && !strings.Contains(err.Error(), tc.saved) {
					t.Errorf("%s: the failure does not say what was done (%q): %v", name, tc.saved, err)
				}
				// Its own failure status is kept when it had one.
				if tc.controlErr != "" && (!strings.Contains(err.Error(), tc.controlErr) || exitCodeForError(err) != exitCodeInfrastructure) {
					t.Errorf("%s: the command's own failure was lost: %v (exit %d)", name, err, exitCodeForError(err))
				}
				if tc.controlErr == "" && exitCodeForError(err) != exitCodeInfrastructure {
					t.Errorf("%s: exit %d, want %d", name, exitCodeForError(err), exitCodeInfrastructure)
				}
			}
		})
	}
}

// Verify-report's text output is the only visible verdict of the
// signature, so a failed write must not exit zero (its JSON mode already
// returned the encoder's error). The evidence semantics are untouched: an
// unaccepted report still fails with its own status.
func TestVerifyReportTextKeepsItsVerdictStatusWhenTheWriteFails(t *testing.T) {
	publicKey, privateKey, err := attesttest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	report := attest.BuildReport(&config.Plan{PlanID: "verdict"}, "node-a", time.Second, true, nil, "")
	if err := attesttest.SignReport(report, privateKey); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(report)
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"verify-report", "--trusted-key", hex.EncodeToString(ed25519.PublicKey(publicKey)), "--expect-node", "another-node", path}
	var out bytes.Buffer
	control := runRoot(t, &out, args...)
	if control == nil || exitCodeForError(control) != exitCodeValidationFailed {
		t.Fatalf("an unaccepted report: %v (exit %d)", control, exitCodeForError(control))
	}
	err = runRoot(t, &fullDiskWriter{}, args...)
	if err == nil || !strings.Contains(err.Error(), "not accepted") || !strings.Contains(err.Error(), "could not be written") || exitCodeForError(err) != exitCodeValidationFailed {
		t.Fatalf("with a full stdout: %v (exit %d)", err, exitCodeForError(err))
	}
}

// Run's notice is the only place the report's path is printed, init's
// account is the only statement of what it wrote; both are checked.
func TestRunAndInitNoticesAreChecked(t *testing.T) {
	result := &controller.Result{ReportPath: "/var/lib/certistack/reports/report-1.json"}
	var out bytes.Buffer
	if err := deliverRun(&out, result, nil); err != nil || !strings.Contains(out.String(), result.ReportPath) {
		t.Fatalf("working stdout: %v, %q", err, out.String())
	}
	err := deliverRun(&fullDiskWriter{}, result, nil)
	if err == nil || !strings.Contains(err.Error(), "the report was saved to "+result.ReportPath) || exitCodeForError(err) != exitCodeInfrastructure {
		t.Fatalf("run notice lost: %v (exit %d)", err, exitCodeForError(err))
	}
	// A failed validation keeps its status, and the notice failure is added.
	failed := &controller.Result{ReportPath: result.ReportPath, Report: &attest.Report{AllPassed: false, TeardownEvidence: &attest.TeardownEvidence{AllCleaned: true}}}
	err = deliverRun(&fullDiskWriter{}, failed, nil)
	if err == nil || exitCodeForError(err) != exitCodeValidationFailed || !strings.Contains(err.Error(), "could not be written") {
		t.Fatalf("failed validation with a full stdout: %v (exit %d)", err, exitCodeForError(err))
	}

	res := &initplan.Result{VMs: 2, Notes: []string{"VM 105 left out"}}
	out.Reset()
	if err := finishInit(&out, "plan.yaml", res, "pve1", false, ""); err != nil || !strings.Contains(out.String(), "Wrote plan.yaml: 2 VM(s)") {
		t.Fatalf("init account: %v, %q", err, out.String())
	}
	err = finishInit(&fullDiskWriter{budget: 10}, "plan.yaml", res, "pve1", false, "")
	if err == nil || !strings.Contains(err.Error(), "the plan was written to plan.yaml") {
		t.Fatalf("init account lost: %v", err)
	}
	// The backup listing.
	out.Reset()
	d := &initplan.Discovery{}
	list := newCheckedOutput(&fullDiskWriter{})
	writeBackupList(list, d)
	if err := list.deliver(nil); err == nil {
		t.Fatal("a listing that could not be written exited zero")
	}
}

// Doctor, plan, run and recover discarded a surplus positional
// argument, and doctor, plan and run let a plan named twice, as argument and
// by flag, keep the flag's. Each refuses both, before reading any file,
// loading an environment or dispatching recovery.
func TestSurplusAndDuplicatedArgumentsAreRefusedBeforeAnyWork(t *testing.T) {
	recovered := false
	recoverState = func(context.Context, context.Context, string) error { recovered = true; return nil }
	t.Cleanup(func() { recoverState = recoveryFromPackage })
	missingEnv := filepath.Join(t.TempDir(), "no-such.env")
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"doctor, two plans":         {[]string{"doctor", "a.yaml", "b.yaml", "--env-file", missingEnv}, "accepts at most 1 arg"},
		"plan, two plans":           {[]string{"plan", "a.yaml", "b.yaml", "--env-file", missingEnv}, "accepts at most 1 arg"},
		"run, two plans":            {[]string{"run", "a.yaml", "b.yaml", "--env-file", missingEnv}, "accepts at most 1 arg"},
		"recover, a path":           {[]string{"recover", "/var/lib/other-state", "--env-file", missingEnv}, "unknown command"},
		"doctor, argument and flag": {[]string{"doctor", "a.yaml", "--plan", "b.yaml", "--env-file", missingEnv}, "either as an argument or via --plan"},
		"plan, argument and flag":   {[]string{"plan", "a.yaml", "--plan", "b.yaml", "--env-file", missingEnv}, "either as an argument or via --plan"},
		"run, argument and flag":    {[]string{"run", "a.yaml", "--plan", "b.yaml", "--env-file", missingEnv}, "either as an argument or via --plan"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runRoot(t, io.Discard, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "no-such.env") {
				t.Fatalf("the environment file was read before the arguments were checked: %v", err)
			}
		})
	}
	if recovered {
		t.Fatal("recovery ran although recover was given an argument")
	}
	// Positive controls: one plan, by argument or by flag, reaches its own work.
	planPath := writeValidationFixture(t, t.TempDir(), "valid.yaml")
	for _, args := range [][]string{{"doctor", planPath, "--state-dir", t.TempDir()}, {"doctor", "--plan", planPath, "--state-dir", t.TempDir()}} {
		var out bytes.Buffer
		_ = runRoot(t, &out, args...)
		if !strings.Contains(out.String(), "CertiStack Preflight Diagnostics") {
			t.Errorf("%v did not run: %q", args, out.String())
		}
	}
	if err := runRoot(t, io.Discard, "recover", "--state-dir", t.TempDir()); err != nil || !recovered {
		t.Fatalf("recover with no argument: %v (ran %v)", err, recovered)
	}
}

// preflightItems runs doctor with --json and returns each check by name.
func preflightItems(t *testing.T, args ...string) map[string]struct{ Status, Detail string } {
	t.Helper()
	var out bytes.Buffer
	_ = runRoot(t, &out, append([]string{"doctor", "--json"}, args...)...)
	var result struct {
		Checks []struct{ Name, Status, Detail string }
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("doctor --json: %v\n%s", err, out.String())
	}
	items := map[string]struct{ Status, Detail string }{}
	for _, check := range result.Checks {
		items[check.Name] = struct{ Status, Detail string }{check.Status, check.Detail}
	}
	return items
}

// Doctor took --scratch's default without asking the plan, so it
// diagnosed a different directory than the run would use.
func TestDoctorChecksTheScratchDirectoryARunWouldUse(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("doctor's checks run on Linux")
	}
	t.Setenv("PVE_URL", "")
	t.Setenv("CERTISTACK_SCRATCH_DIR", "")
	root := t.TempDir()
	planScratch := filepath.Join(root, "plan-scratch")
	flagScratch := filepath.Join(root, "flag-scratch")
	envScratch := filepath.Join(root, "env-scratch")
	for _, dir := range []string{planScratch, flagScratch, envScratch} {
		if err := os.Mkdir(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil { // unsafe on purpose: the check names the directory it looked at
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	withScratch := strings.Replace(string(data), "storage:", "storage:\n  scratch_dir: "+planScratch, 1)
	if withScratch == string(data) {
		withScratch = string(data) + "\nstorage:\n  scratch_dir: " + planScratch + "\n"
	}
	planPath := filepath.Join(root, "plan.yaml")
	if err := os.WriteFile(planPath, []byte(withScratch), 0o600); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()

	// The plan's directory, when nothing else names one.
	if item := preflightItems(t, planPath, "--state-dir", state)["scratch_path"]; !strings.Contains(item.Detail, planScratch) {
		t.Errorf("the plan's scratch_dir was not the one checked: %+v", item)
	}
	// The environment, as for run and plan.
	t.Setenv("CERTISTACK_SCRATCH_DIR", envScratch)
	if item := preflightItems(t, planPath, "--state-dir", state)["scratch_path"]; !strings.Contains(item.Detail, envScratch) {
		t.Errorf("CERTISTACK_SCRATCH_DIR was not the one checked: %+v", item)
	}
	// An explicit flag beats both.
	if item := preflightItems(t, planPath, "--state-dir", state, "--scratch", flagScratch)["scratch_path"]; !strings.Contains(item.Detail, flagScratch) {
		t.Errorf("--scratch was not the one checked: %+v", item)
	}
	// Without a plan or a value, the default.
	t.Setenv("CERTISTACK_SCRATCH_DIR", "")
	if item := preflightItems(t, "--state-dir", state)["scratch_path"]; !strings.Contains(item.Detail, "/var/lib/certistack/scratch") {
		t.Errorf("the default scratch directory was not the one checked: %+v", item)
	}
}

// Doctor checks the --state-dir directory as the worker prepares it: private,
// its own, and creatable.
func TestDoctorChecksTheStateDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("doctor's checks run on Linux")
	}
	t.Setenv("PVE_URL", "")
	root := t.TempDir()
	scratch := filepath.Join(root, "scratch")
	private := filepath.Join(root, "private")
	shared := filepath.Join(root, "shared")
	for dir, mode := range map[string]os.FileMode{private: 0o700, shared: 0o755} {
		if err := os.Mkdir(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
	}
	regular := filepath.Join(root, "a-file")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(state string) struct{ Status, Detail string } {
		return preflightItems(t, "--scratch", scratch, "--state-dir", state)["state_path"]
	}
	for _, tc := range []struct {
		name, state, status, detail string
	}{
		{"a private directory", private, "passed", "is private and usable"},
		{"a directory others can read", shared, "failed", "mode 0700"},
		{"the shared /tmp", "/tmp", "failed", "shared temporary directory"},
		{"a relative path", "relative/state", "failed", "must be absolute"},
		{"a file", regular, "failed", "not a directory"},
		{"a directory a run would create", filepath.Join(private, "not-yet"), "passed", "does not exist yet"},
		{"a directory that cannot be created", filepath.Join(regular, "state"), "failed", "not a directory"},
	} {
		if item := check(tc.state); item.Status != tc.status || !strings.Contains(item.Detail, tc.detail) {
			t.Errorf("%s: %+v, want %s naming %q", tc.name, item, tc.status, tc.detail)
		}
	}
	if _, err := os.Stat(filepath.Join(private, "not-yet")); err == nil {
		t.Error("doctor created the state directory")
	}
	// doctor's verdict follows: a state directory that fails makes it not ready.
	var out bytes.Buffer
	if err := runRoot(t, &out, "doctor", "--scratch", scratch, "--state-dir", shared); err == nil || !strings.Contains(out.String(), "state_path") {
		t.Errorf("doctor did not report the state directory: %v\n%s", err, out.String())
	}
}
