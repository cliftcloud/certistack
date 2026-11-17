// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/controller"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
	"github.com/spf13/cobra"
)

// The Community Edition writes its reports unsigned. These tests hold the
// command line to it: no signing key is asked for, taken or checked anywhere,
// no command has a signing-key flag, a plan stays portable between the
// editions, and the one place that mentions signing says whose it is.

// unsignedPlans are the repository's valid plan twice: with the signing key
// path it carries (a placeholder, as a plan from the Enterprise Edition has it)
// and with the field left out.
type unsignedPlans struct {
	dir     string
	with    string
	without string
}

func newUnsignedPlans(t *testing.T) unsignedPlans {
	t.Helper()
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "plans", "valid_plan.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`(?m)^ *sign_key_path:.*\n`)
	if !line.Match(data) {
		t.Fatal("the fixture plan has no sign_key_path")
	}
	p := unsignedPlans{dir: dir, with: filepath.Join(dir, "with.yaml"), without: filepath.Join(dir, "without.yaml")}
	if err := os.WriteFile(p.with, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.without, line.ReplaceAll(data, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// interceptSSH puts ssh and scp that record their command line and fail on
// PATH, and returns the log: a run that gets as far as the node leaves a line
// in it. They exit 1, a command that failed, not 255, a connection that was
// lost: the controller retries a lost connection for seven seconds.
func interceptSSH(t *testing.T) (log string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the interception is a shell script")
	}
	bin := t.TempDir()
	log = filepath.Join(t.TempDir(), "transport.log")
	script := "#!/bin/sh\necho \"$0 $*\" >> '" + log + "'\nexit 1\n"
	for _, name := range []string{"ssh", "scp"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin)
	return log
}

func transportCalls(t *testing.T, log string) int {
	t.Helper()
	data, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(data), "\n")
}

// clearControllerEnvironment gives a test an environment of its own.
func clearControllerEnvironment(t *testing.T) {
	t.Helper()
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "")
	}
}

// `run` needs no signing key, in the plan or given to the run, before it looks
// at the node. Through the whole command and the controller to the first command sent to the node (the interception fails
// every one): a plan that names nothing, a plan that names a placeholder path no
// file is at, and a plan that names a file that is there all reach the node,
// with no flag and no environment.
func TestRunNeedsNoSigningKey(t *testing.T) {
	clearControllerEnvironment(t)
	plans := newUnsignedPlans(t)
	reports := t.TempDir()
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := interceptSSH(t)
	for name, plan := range map[string]string{"the plan names no key": plans.without, "the plan names a path that is not there": plans.with} {
		t.Run(name, func(t *testing.T) {
			_ = os.Remove(log)
			err := runRoot(t, io.Discard, "run", plan, "--node", "pve-01", "--ssh-host", "pve.example", "--ssh-user", "root", "--ssh-known-hosts", knownHosts, "--output", reports)
			if err == nil {
				t.Fatal("the run succeeded against an interception that fails every command")
			}
			if strings.Contains(err.Error(), "sign_key_path") || strings.Contains(err.Error(), "signing key") {
				t.Fatalf("the run was refused for its signing key: %v", err)
			}
			if transportCalls(t, log) == 0 {
				t.Fatalf("the run was refused before it reached the node: %v", err)
			}
		})
	}
}

// No command takes a signing-key flag (--key, --signing-key): a script that
// passes one is told it is an unknown flag, at the usage exit status, before
// anything is read or sent.
func TestNoCommandTakesASigningKeyFlag(t *testing.T) {
	plans := newUnsignedPlans(t)
	for _, command := range []string{"run", "plan", "validate", "doctor", "init", "check"} {
		for _, flag := range []string{"--key", "--signing-key"} {
			t.Run(command+" "+flag, func(t *testing.T) {
				args := []string{command}
				if command == "run" || command == "plan" || command == "validate" || command == "doctor" || command == "check" {
					args = append(args, plans.without)
				}
				err := runRoot(t, io.Discard, append(args, flag, "/secure/certistack/controller-signing.ed25519")...)
				if err == nil || !strings.Contains(err.Error(), "unknown flag: "+flag) {
					t.Fatalf("%s %s: %v, want an unknown flag", command, flag, err)
				}
				if got := exitCodeForError(err); got != exitCodeInfrastructure {
					t.Errorf("exit status %d, want %d", got, exitCodeInfrastructure)
				}
			})
		}
	}
}

// The Community Edition does not sign, so it has no keygen command: the
// command is not in the tree, and the root help does not list it.
func TestKeygenIsNotACommand(t *testing.T) {
	for _, command := range rootCmd().Commands() {
		if command.Name() == "keygen" {
			t.Fatal("certistack has a keygen command")
		}
	}
	err := runRoot(t, io.Discard, "keygen", "--private", filepath.Join(t.TempDir(), "k"))
	if err == nil || !strings.Contains(err.Error(), `unknown command "keygen"`) {
		t.Fatalf("keygen = %v, want an unknown command", err)
	}
	// The signal handler lists the commands that only read, so that an interrupt
	// does not promise cleanup for them. keygen was one; a name it does not list
	// is assumed to have cleanup.
	previous, _ := activeCommand.Load().(string)
	activeCommand.Store("keygen")
	defer activeCommand.Store(previous)
	if !interruptHasCleanup() {
		t.Error("the signal handler still lists keygen among the commands that only read")
	}
}

// CERTISTACK_SIGN_KEY is not in the allowlist: a file that sets it is refused,
// at the line, with the reason that this edition writes unsigned reports and
// reads no key.
func TestAnEnvironmentFileWithTheSigningKeyIsRefusedWithTheReason(t *testing.T) {
	clearControllerEnvironment(t)
	plans := newUnsignedPlans(t)
	envFile := filepath.Join(t.TempDir(), "controller.env")
	if err := os.WriteFile(envFile, []byte("PVE_URL=https://pve.example:8006\nCERTISTACK_SIGN_KEY=/secure/certistack/controller-signing.ed25519\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, listed := controllerEnvironmentNames["CERTISTACK_SIGN_KEY"]; listed {
		t.Fatal("CERTISTACK_SIGN_KEY is still in the controller environment allowlist")
	}
	for _, args := range [][]string{
		{"validate", plans.without, "--env-file", envFile},
		{"plan", plans.without, "--env-file", envFile},
		{"run", plans.without, "--env-file", envFile},
		{"init", "--env-file", envFile},
		{"doctor", "--env-file", envFile},
	} {
		err := runRoot(t, io.Discard, args...)
		if err == nil {
			t.Errorf("%s: the file was accepted", args[0])
			continue
		}
		for _, want := range []string{`"CERTISTACK_SIGN_KEY" on line 2`, "unsigned", "Enterprise Edition", "remove the line"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal %q does not say %q", args[0], err, want)
			}
		}
		if strings.Contains(err.Error(), "controller-signing") {
			t.Errorf("%s: the refusal repeats the value: %q", args[0], err)
		}
		if got := exitCodeForError(err); got != exitCodeInfrastructure {
			t.Errorf("%s: exit status %d, want %d", args[0], got, exitCodeInfrastructure)
		}
	}
}

// validate accepts a plan with or without the Enterprise Edition's key path, looks
// at no file, and says in one line, for a plan that sets it, that this edition
// does not read it.
func TestValidateNotesASigningKeyPathOnceAndChecksNothingAboutIt(t *testing.T) {
	clearControllerEnvironment(t)
	plans := newUnsignedPlans(t)
	const note = "compliance.sign_key_path is set, but the Community Edition writes its reports unsigned and does not read it; the Enterprise Edition uses it to sign."

	var out bytes.Buffer
	if err := runRoot(t, &out, "validate", plans.with); err != nil {
		t.Fatalf("a plan with a signing key path that is not there: %v", err)
	}
	if got := strings.Count(out.String(), note); got != 1 || !strings.Contains(out.String(), "Plan is valid") {
		t.Fatalf("the output has the note %d times, want once:\n%s", got, out.String())
	}

	out.Reset()
	if err := runRoot(t, &out, "validate", plans.without); err != nil || strings.Contains(out.String(), "sign_key_path") || strings.Contains(out.String(), "Note:") {
		t.Fatalf("a plan without the field: err %v, output:\n%s", err, out.String())
	}

	// A directory of plans: each plan that sets the field is told once.
	out.Reset()
	if err := runRoot(t, &out, "validate", plans.dir); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), note); got != 1 {
		t.Fatalf("the directory's output has the note %d times, want once (one plan sets the field):\n%s", got, out.String())
	}

	// No existence, mode or format check: a file there with any mode, a directory,
	// and a path that is not a path are all the same to this edition.
	data, _ := os.ReadFile(plans.with)
	for name, value := range map[string]string{
		"a world-readable file": writeKeyLookalike(t, 0o644),
		"a directory":           plans.dir,
		"not a path":            "definitely not a path",
	} {
		path := filepath.Join(t.TempDir(), "plan.yaml")
		replaced := regexp.MustCompile(`(?m)^( *)sign_key_path:.*$`).ReplaceAllLiteralString(string(data), `  sign_key_path: "`+strings.ReplaceAll(value, `\`, `\\`)+`"`)
		if err := os.WriteFile(path, []byte(replaced), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := runRoot(t, io.Discard, "validate", path); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func writeKeyLookalike(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing.ed25519")
	if err := os.WriteFile(path, []byte("not a key"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// plan says the same once, on standard error, so that --json's reader still gets
// nothing but the plan; and it needs no key, on the node or from a controller.
func TestPlanNotesASigningKeyPathOnceAndNeedsNoKey(t *testing.T) {
	clearControllerEnvironment(t)
	for _, name := range []string{"CERTISTACK_SSH_HOST", "CERTISTACK_SCRATCH_DIR", "CERTISTACK_OVERLAY_STORAGE", "CERTISTACK_NODE"} {
		t.Setenv(name, "")
	}
	plans := newUnsignedPlans(t)
	state := t.TempDir()
	previousLocal, previousRemote := computeNodePlan, remotePlan
	t.Cleanup(func() { computeNodePlan, remotePlan = previousLocal, previousRemote })
	localCalls, remoteCalls := 0, 0
	computeNodePlan = func(_ *cobra.Command, plan *config.Plan, node, _, _, _, _ string) (*orchestrator.RunPlan, error) {
		localCalls++
		return &orchestrator.RunPlan{PlanID: plan.PlanID, Node: node, Mode: "release"}, nil
	}
	remotePlan = func(_ context.Context, opts controller.RunOptions) ([]byte, error) {
		remoteCalls++
		return []byte(`{"plan_id":"p","node":"pve-01","mode":"release","steps":[]}`), nil
	}
	const note = "note: compliance.sign_key_path is set, but the Community Edition writes its reports unsigned and does not read it; the Enterprise Edition uses it to sign."

	cases := []struct {
		name     string
		args     []string
		wantNote int
		local    int
		remote   int
	}{
		{"on the node, the field set", []string{"plan", plans.with, "--node", "pve-01", "--state-dir", state}, 1, 1, 0},
		{"on the node, the field left out", []string{"plan", plans.without, "--node", "pve-01", "--state-dir", state}, 0, 1, 0},
		{"from a controller, the field set", []string{"plan", plans.with, "--node", "pve-01", "--state-dir", state, "--ssh-host", "pve.example", "--ssh-known-hosts", filepath.Join(state, "known_hosts")}, 1, 0, 1},
		{"as JSON, the field set", []string{"plan", plans.with, "--json", "--node", "pve-01", "--state-dir", state}, 1, 1, 0},
	}
	for _, tc := range cases {
		localCalls, remoteCalls = 0, 0
		stdout, stderr, err := runReportCommand(t, tc.args...)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got := strings.Count(stderr, note); got != tc.wantNote {
			t.Errorf("%s: the note is on standard error %d times, want %d:\n%s", tc.name, got, tc.wantNote, stderr)
		}
		if strings.Contains(stdout, "sign_key_path") {
			t.Errorf("%s: the note is on standard output:\n%s", tc.name, stdout)
		}
		if localCalls != tc.local || remoteCalls != tc.remote {
			t.Errorf("%s: planned on the node %d times and through a worker %d times, want %d and %d", tc.name, localCalls, remoteCalls, tc.local, tc.remote)
		}
	}
}

// doctor checks a plan as the others do, with no key and none asked for.
func TestDoctorNeedsNoSigningKeyForThePlan(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("doctor's plan check runs on Linux")
	}
	clearControllerEnvironment(t)
	plans := newUnsignedPlans(t)
	scratch := filepath.Join(t.TempDir(), "scratch")
	for name, plan := range map[string]string{"the plan names no key": plans.without, "the plan names a path that is not there": plans.with} {
		item := preflightItems(t, plan, "--scratch", scratch, "--state-dir", t.TempDir())["plan"]
		if item.Status != "passed" {
			t.Errorf("%s: the plan check = %+v, want it passed", name, item)
		}
	}
}

// The words the program says about itself are true of this edition: its banner
// and the help of run do not claim that the Community Edition signs.
func TestTheCommandLineDoesNotClaimThatCommunityReportsAreSigned(t *testing.T) {
	root := rootCmd()
	if strings.Contains(root.Long, "cryptographically signed") || strings.Contains(root.Long, "signed compliance attestation") {
		t.Errorf("the banner says the reports are signed:\n%s", root.Long)
	}
	for _, want := range []string{"report", "unsigned"} {
		if !strings.Contains(root.Long, want) {
			t.Errorf("the banner does not say %q:\n%s", want, root.Long)
		}
	}
	run, _, err := root.Find([]string{"run"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(run.Long, "signs evidence") || strings.Contains(run.Long, "private signing key") {
		t.Errorf("run's help says it signs:\n%s", run.Long)
	}
}
