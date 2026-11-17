// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/orchestrator"
)

// withUserConfigDir gives the test a per-user directory of its own, with no
// PVE_URL in the process environment, and returns the pointer file's path in
// it. Where os.UserConfigDir does not read XDG_CONFIG_HOME the test would
// reach the account's own directory, so it is skipped there.
func withUserConfigDir(t *testing.T) string {
	t.Helper()
	switch runtime.GOOS {
	case "windows", "darwin", "ios", "plan9":
		t.Skip("os.UserConfigDir does not read XDG_CONFIG_HOME here")
	}
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("PVE_URL", "")
	pointer, err := envFilePointerPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(config, "certistack", "env-file"); pointer != want {
		t.Fatalf("the pointer is %s, want %s", pointer, want)
	}
	return pointer
}

// debugLog makes slog write debug lines to the returned buffer until the test
// ends.
func debugLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	var log bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &log
}

// The order: the flag; else the process environment when PVE_URL is set in it;
// else the file setup recorded; else none, as before setup. --debug says which
// and why.
func TestTheControllerEnvironmentFileIsTheFlagThenPVEURLThenTheRecordedFile(t *testing.T) {
	pointer := withUserConfigDir(t)
	log := debugLog(t)
	recorded := writeEnvFile(t, "PVE_URL=https://recorded.example:8006\n")
	other := writeEnvFile(t, "PVE_URL=https://other.example:8006\n")
	resolve := func(flag string) controllerEnvFile {
		t.Helper()
		log.Reset()
		chosen, err := resolveControllerEnvFile(flag)
		if err != nil {
			t.Fatalf("--env-file %q: %v", flag, err)
		}
		return chosen
	}

	// Before setup: no file, and nothing in the commands' suggestions.
	if got := resolve(""); got.path != "" || got.flag("x") != "" || !strings.Contains(log.String(), "certistack setup has recorded none") {
		t.Errorf("no pointer: %+v\n%s", got, log)
	}
	if got := resolve(other); got.path != other || got.isDefault || got.flag(other) != " --env-file "+other || !strings.Contains(log.String(), "given with --env-file") {
		t.Errorf("the flag, no pointer: %+v\n%s", got, log)
	}

	if err := recordEnvFile(pointer, recorded); err != nil {
		t.Fatal(err)
	}
	if got := resolve(""); got.path != recorded || !got.isDefault || got.flag(recorded) != "" || !strings.Contains(log.String(), "the default certistack setup recorded") || !strings.Contains(log.String(), pointer) {
		t.Errorf("the recorded file: %+v\n%s", got, log)
	}
	// The flag wins; given the recorded file itself, a command printed for
	// the reader can leave it out.
	if got := resolve(other); got.path != other || got.isDefault {
		t.Errorf("the flag over the recorded file: %+v", got)
	}
	if got := resolve(recorded); got.path != recorded || !got.isDefault {
		t.Errorf("the flag naming the recorded file: %+v", got)
	}

	// PVE_URL in the process environment: it is used as it is, as in the
	// controller container, and the recorded file is not read.
	t.Setenv("PVE_URL", "https://environment.example:8006")
	if got := resolve(""); got.path != "" || !strings.Contains(log.String(), "PVE_URL is set in the process environment") {
		t.Errorf("PVE_URL set: %+v\n%s", got, log)
	}
	// Without the flag the environment would be used, so it stays.
	if got := resolve(recorded); got.path != recorded || got.isDefault {
		t.Errorf("PVE_URL set, the flag naming the recorded file: %+v", got)
	}
	t.Setenv("PVE_URL", "")

	// The recorded file is gone: an error that names both files and the fix.
	if err := os.Remove(recorded); err != nil {
		t.Fatal(err)
	}
	_, err := resolveControllerEnvFile("")
	if err == nil {
		t.Fatal("a pointer to a file that is gone was accepted")
	}
	for _, want := range []string{pointer, recorded, "does not exist", "run certistack setup again", "--env-file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
	// The flag, and PVE_URL, still work without it.
	if got := resolve(other); got.path != other || got.isDefault {
		t.Errorf("the flag beside a stale pointer: %+v", got)
	}
	t.Setenv("PVE_URL", "https://environment.example:8006")
	if got := resolve(""); got.path != "" {
		t.Errorf("PVE_URL beside a stale pointer: %+v", got)
	}
}

// A pointer is one absolute path that only its owner can change; anything else
// is refused with its name and the fix, not followed.
func TestAMalformedPointerIsRefusedWithItsName(t *testing.T) {
	pointer := withUserConfigDir(t)
	target := writeEnvFile(t, "PVE_URL=https://recorded.example:8006\n")
	if err := os.MkdirAll(filepath.Dir(pointer), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		content string
		mode    os.FileMode
	}{
		"empty":                 {"", 0o600},
		"a relative path":       {"secure/controller.env\n", 0o600},
		"two lines":             {target + "\n" + target + "\n", 0o600},
		"writable by the group": {target + "\n", 0o620},
		"too large":             {"/" + strings.Repeat("a", maxEnvFilePointerBytes) + "\n", 0o600},
	} {
		if name == "writable by the group" && runtime.GOOS == "windows" {
			continue
		}
		if err := os.WriteFile(pointer, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(pointer, c.mode); err != nil {
			t.Fatal(err)
		}
		_, err := resolveControllerEnvFile("")
		if err == nil || !strings.Contains(err.Error(), pointer) || !strings.Contains(err.Error(), "run certistack setup again, or pass --env-file") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := os.Remove(pointer); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pointer, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveControllerEnvFile(""); err == nil || !strings.Contains(err.Error(), pointer) {
		t.Errorf("a directory: %v", err)
	}
}

// setup's record: the absolute path on one line, mode 0600, in a directory
// created 0700, replacing the earlier record by a rename, never by writing
// through what is there.
func TestRecordEnvFileWritesOneAbsolutePathAtomically(t *testing.T) {
	dir := t.TempDir()
	pointer := filepath.Join(dir, "config", "certistack", "env-file")
	t.Chdir(dir)
	if err := recordEnvFile(pointer, "secure/controller.env"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(pointer); string(got) != filepath.Join(dir, "secure", "controller.env")+"\n" {
		t.Errorf("the pointer holds %q", got)
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(pointer); info.Mode().Perm() != 0o600 {
			t.Errorf("pointer mode %04o, want 0600", info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Dir(pointer)); info.Mode().Perm() != 0o700 {
			t.Errorf("directory mode %04o, want 0700", info.Mode().Perm())
		}
	}

	// A link where the pointer is: replaced, and what it named is untouched.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pointer); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, pointer); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	if err := recordEnvFile(pointer, "/srv/certistack/controller.env"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(victim); string(got) != "keep\n" {
		t.Errorf("the record was written through the link: %q", got)
	}
	if info, err := os.Lstat(pointer); err != nil || !info.Mode().IsRegular() {
		t.Errorf("the pointer is not a regular file now: %v %v", info, err)
	}
	if got, _ := os.ReadFile(pointer); string(got) != filepath.Clean("/srv/certistack/controller.env")+"\n" {
		t.Errorf("the pointer holds %q", got)
	}
	entries, err := os.ReadDir(filepath.Dir(pointer))
	if err != nil || len(entries) != 1 || entries[0].Name() != "env-file" {
		t.Errorf("the directory holds %v (%v), want the pointer alone: no temporary file is left", entries, err)
	}
}

// setup records the file once it has written it, unattended too, and before
// its check, so that a check that fails can be run again without the flag. A
// setup that stops before the file is written records nothing, and a record
// that cannot be written is said and does not fail the setup.
func TestSetupRecordsTheEnvironmentFileOnceItIsWritten(t *testing.T) {
	t.Setenv("PVE_URL", "")
	unattended := func(t *testing.T) setupWizardOptions {
		return setupWizardOptions{NodeHost: "pve1.example.com", Yes: true, Fingerprint: fixedHostKey(t, 7).Fingerprint,
			PBSHost: "pbs.example.com", PBSDatastore: "datastore1", PBSNamespace: "/", PBSSSH: "root@pbs.example.com"}
	}

	t.Run("stopped before the file", func(t *testing.T) {
		f, dir := newWizardWorld(t)
		f.authorized = true
		if _, err := runWizard(t, f, dir, setupWizardOptions{NodeHost: "pve1.example.com"}, "", "", "yes", "", "n"); err == nil {
			t.Fatal("the setup did not stop at the no")
		}
		if _, err := os.Lstat(wizardPointerPath(dir)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("a pointer was written by a setup that wrote no environment file: %v", err)
		}
	})

	t.Run("unattended", func(t *testing.T) {
		f, dir := newWizardWorld(t)
		f.authorized = true
		out, err := runWizard(t, f, dir, unattended(t))
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		pointer := wizardPointerPath(dir)
		if got, _ := os.ReadFile(pointer); string(got) != filepath.Join(dir, "controller.env")+"\n" {
			t.Errorf("the pointer holds %q", got)
		}
		if runtime.GOOS != "windows" {
			if info, _ := os.Stat(pointer); info.Mode().Perm() != 0o600 {
				t.Errorf("pointer mode %04o", info.Mode().Perm())
			}
			if info, _ := os.Stat(filepath.Dir(pointer)); info.Mode().Perm() != 0o700 {
				t.Errorf("pointer directory mode %04o", info.Mode().Perm())
			}
		}
		if strings.Count(out, "Commands now use ") != 1 || strings.Count(out, "--env-file chooses another file") != 1 {
			t.Errorf("setup does not end with the one line on the default:\n%s", out)
		}
	})

	t.Run("check fails", func(t *testing.T) {
		f, dir := newWizardWorld(t)
		f.authorized = true
		deps := f.deps(t, dir)
		deps.check = func(context.Context, string, io.Writer) error { return errors.New("check failed at layer 5 (PVE API)") }
		opts := unattended(t)
		opts.Dir = dir
		var out strings.Builder
		if err := runSetupWizard(context.Background(), &out, strings.NewReader(""), opts, deps); err == nil || !strings.Contains(err.Error(), "certistack check did not pass") {
			t.Fatalf("%v\n%s", err, out.String())
		}
		if got, _ := os.ReadFile(wizardPointerPath(dir)); string(got) != filepath.Join(dir, "controller.env")+"\n" {
			t.Errorf("after a check that failed the pointer holds %q, want the file setup wrote", got)
		}
	})

	t.Run("the record cannot be written", func(t *testing.T) {
		f, dir := newWizardWorld(t)
		f.authorized = true
		deps := f.deps(t, dir)
		deps.envPointer = func() (string, error) { return "", errors.New("no per-user configuration directory") }
		opts := unattended(t)
		opts.Dir = dir
		var out strings.Builder
		if err := runSetupWizard(context.Background(), &out, strings.NewReader(""), opts, deps); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
		envPath := filepath.Join(dir, "controller.env")
		if !strings.Contains(out.String(), "could not be recorded as the default environment file (no per-user configuration directory): pass --env-file "+envPath+" to each command.") || strings.Contains(out.String(), "Commands now use") {
			t.Errorf("output:\n%s", out.String())
		}
	})
}

// The controller's commands, given no --env-file, use the file setup recorded
// with every check a given file has; the node worker's commands never do.
func TestControllerCommandsUseTheRecordedFileAndWorkerCommandsNever(t *testing.T) {
	pointer := withUserConfigDir(t)
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "")
	}
	for name := range workerEnvironmentNames {
		t.Setenv(name, "")
	}
	const sentinel = "recorded-namespace"
	recorded := writeEnvFile(t, "PVE_URL=https://recorded.example:8006\nPBS_NAMESPACE="+sentinel+"\n")
	if err := recordEnvFile(pointer, recorded); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	plan := writeValidationFixture(t, root, "plan.yaml")
	state, scratch := filepath.Join(root, "state"), filepath.Join(root, "scratch")
	for _, dir := range []string{state, scratch} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var seen string
	previousPlan, previousPreflight, previousDiscover, previousRecover := computeNodePlan, runPreflight, runnerDiscover, recoverState
	t.Cleanup(func() {
		computeNodePlan, runPreflight, runnerDiscover, recoverState = previousPlan, previousPreflight, previousDiscover, previousRecover
	})
	computeNodePlan = func(*cobra.Command, *config.Plan, string, string, string, string, string) (*orchestrator.RunPlan, error) {
		seen = os.Getenv("PBS_NAMESPACE")
		return &orchestrator.RunPlan{PlanID: "p1", Node: "pve1", Mode: "release"}, nil
	}
	runPreflight = func(context.Context, *config.Plan, preflight.Options) preflight.Result {
		seen = os.Getenv("PBS_NAMESPACE")
		return preflight.Result{Ready: true, Checks: []preflight.CheckItem{{Name: "kvm", Status: "passed", Detail: "/dev/kvm is accessible"}}}
	}
	runnerDiscover = func(context.Context, initplan.Request, string) (*initplan.Discovery, error) {
		seen = os.Getenv("PBS_NAMESPACE")
		return &initplan.Discovery{Node: "pve1"}, nil
	}
	recoverState = func(context.Context, context.Context, string) error {
		seen = os.Getenv("PBS_NAMESPACE")
		return nil
	}

	for name, args := range map[string][]string{
		"doctor": {"doctor", "--scratch", scratch, "--state-dir", state},
		"init":   {"init", "--node", "pve1"},
		"plan":   {"plan", plan, "--node", "pve1", "--state-dir", state},
	} {
		t.Run(name, func(t *testing.T) {
			seen = ""
			before := os.Environ()
			slices.Sort(before)
			if err := runRoot(t, io.Discard, args...); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if seen != sentinel {
				t.Errorf("%s without --env-file saw PBS_NAMESPACE=%q, want the recorded file's %q", name, seen, sentinel)
			}
			after := os.Environ()
			slices.Sort(after)
			if !slices.Equal(before, after) {
				t.Errorf("%s left the process environment changed:%s", name, environmentDifference(before, after))
			}
		})
	}

	// recover runs on the node with a worker's runtime.env: never the record.
	seen = ""
	if err := runRoot(t, io.Discard, "recover", "--state-dir", state); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if seen != "" {
		t.Errorf("recover without --env-file saw PBS_NAMESPACE=%q: it read the recorded file", seen)
	}

	// The recorded file is checked as a given one is: open to the group, it is
	// refused by each controller command, and not looked at by a worker's.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(recorded, 0o640); err != nil {
			t.Fatal(err)
		}
		const refused = "controller environment file must not be accessible by group or other users"
		for name, args := range map[string][]string{
			"validate":     {"validate", plan},
			"run":          {"run", plan},
			"doctor":       {"doctor", "--scratch", scratch, "--state-dir", state},
			"init":         {"init", "--node", "pve1"},
			"plan":         {"plan", plan, "--node", "pve1", "--state-dir", state},
			"setup pve-ca": {"setup", "pve-ca"},
		} {
			if err := runRoot(t, io.Discard, args...); err == nil || !strings.Contains(err.Error(), refused) {
				t.Errorf("%s with the recorded file open to the group: %v", name, err)
			}
		}
		if out, err := runRootWithInput(t, "", "check"); err == nil || !strings.Contains(out, "✗ 1. Environment file") || !strings.Contains(out, "chmod 600 "+recorded) {
			t.Errorf("check with the recorded file open to the group: %v\n%s", err, out)
		}
	}

	// A record of a file that is gone stops the controller's commands with
	// the fix, and none of the worker's.
	if err := os.Remove(recorded); err != nil {
		t.Fatal(err)
	}
	if err := runRoot(t, io.Discard, "validate", plan); err == nil || !strings.Contains(err.Error(), pointer) || !strings.Contains(err.Error(), recorded) {
		t.Errorf("validate with a record of a file that is gone: %v", err)
	}
	if err := runRoot(t, io.Discard, "recover", "--state-dir", state); err != nil {
		t.Errorf("recover read the record: %v", err)
	}
	for _, args := range [][]string{
		{"node-run", "--plan", plan, "--node", "pve1", "--state-dir", state, "--scratch", scratch},
		{"node-plan", "--plan", plan, "--node", "pve1", "--state-dir", state, "--scratch", scratch},
		{"node-check", "--node", "pve1"},
		{"node-discover", "--node", "pve1"},
		{"node-inspect", "--node", "pve1", "--target", "100=vm/100/2026-10-05T02:00:00Z", "--state-dir", state, "--scratch", scratch},
	} {
		err := runRoot(t, io.Discard, args...)
		if err == nil || !strings.Contains(err.Error(), `required flag(s) "env-file" not set`) || strings.Contains(err.Error(), pointer) {
			t.Errorf("%s without --env-file: %v, want the flag asked for and the record not read", args[0], err)
		}
	}
}

// What the commands print for the reader to run next leaves --env-file out when
// it names the file setup recorded, and keeps it for another file.
func TestPrintedCommandsLeaveTheRecordedFileOut(t *testing.T) {
	t.Run("init", func(t *testing.T) {
		dir := initNode(t)
		pointer := withUserConfigDir(t)
		recorded := writeEnvFile(t, "PVE_URL=https://recorded.example:8006\n")
		other := writeEnvFile(t, "PVE_URL=https://other.example:8006\n")
		if err := recordEnvFile(pointer, recorded); err != nil {
			t.Fatal(err)
		}
		planFile := filepath.Join(dir, "plan.yaml")
		for _, c := range []struct {
			name string
			args []string
			want string
		}{
			{"no flag", nil, ""},
			{"the recorded file", []string{"--env-file", recorded}, ""},
			{"another file", []string{"--env-file", other}, " --env-file " + other},
		} {
			stdout, stderr, err := runInit(t, context.Background(), initArgs(dir, append([]string{"--force"}, c.args...)...)...)
			if err != nil {
				t.Fatalf("%s: %v\n%s", c.name, err, stderr)
			}
			if !strings.Contains(stdout, "  2. certistack plan "+planFile+c.want+"   (shows") || !strings.Contains(stdout, "  3. certistack run "+planFile+c.want+"\n") {
				t.Errorf("%s: the next steps are not the plan and run commands with %q:\n%s", c.name, c.want, stdout)
			}
		}
	})

	t.Run("setup pve-ca", func(t *testing.T) {
		pointer := withUserConfigDir(t)
		c := newControllerDir(t)
		if err := recordEnvFile(pointer, c.env); err != nil {
			t.Fatal(err)
		}
		withNodeCA(t, pveTestCA(t, time.Date(2035, 10, 1, 0, 0, 0, 0, time.UTC), true), nil)
		out, err := runRootWithInput(t, "", "setup", "pve-ca")
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if !strings.HasSuffix(out, "\nThen run: certistack check\n") || !strings.Contains(out, "Add this line to "+c.env+":") {
			t.Errorf("output:\n%s", out)
		}
		if _, err := os.Stat(filepath.Join(c.dir, "pve-root-ca.pem")); err != nil {
			t.Errorf("the CA was not written next to the recorded file: %v", err)
		}
		// With PVE_URL set the file is not the default: pve-ca, which needs a
		// file, asks for the flag as before.
		t.Setenv("PVE_URL", "https://environment.example:8006")
		if _, err := runRootWithInput(t, "", "setup", "pve-ca"); err == nil || err.Error() != `required flag(s) "env-file" not set` {
			t.Errorf("PVE_URL set, no flag: %v", err)
		}
	})
}

// End to end: after certistack setup, check and validate run without
// --env-file use the file setup wrote, and say so only under --debug.
func TestACommandRunAfterSetupUsesTheFileSetupRecorded(t *testing.T) {
	withUserConfigDir(t)
	f, dir := newWizardWorld(t)
	f.authorized = true
	deps := f.deps(t, dir)
	deps.envPointer = envFilePointerPath // the per-user directory, this test's own
	var setupOut strings.Builder
	err := runSetupWizard(context.Background(), &setupOut, strings.NewReader(""), setupWizardOptions{Dir: dir, NodeHost: "pve1.example.com", Yes: true,
		Fingerprint: fixedHostKey(t, 7).Fingerprint, PBSHost: "pbs.example.com", PBSDatastore: "datastore1", PBSNamespace: "/", PBSSSH: "root@pbs.example.com"}, deps)
	if err != nil {
		t.Fatalf("setup: %v\n%s", err, setupOut.String())
	}
	envPath := filepath.Join(dir, "controller.env")

	withNode(t, &nodeStub{})
	out, err := runRootWithInput(t, "", "check")
	if err != nil {
		t.Fatalf("check without --env-file after setup: %v\n%s", err, out)
	}
	for _, want := range []string{
		"✓ 1. Environment file  " + envPath + ",",
		"✓ Every layer passed.",
		"Next: write a first plan with certistack init (quickstart step 3), or check one you have: certistack check <plan.yaml>\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "--env-file") {
		t.Errorf("check names --env-file for the file setup recorded:\n%s", out)
	}

	// The CLI as a process: --debug says which file and why; without it,
	// nothing is added.
	plan := writeValidationFixture(t, t.TempDir(), "plan.yaml")
	for _, debug := range []bool{true, false} {
		args := []string{"validate", plan}
		if debug {
			args = append(args, "--debug")
		}
		cmd := cliProcess(t, []string{"XDG_CONFIG_HOME=" + os.Getenv("XDG_CONFIG_HOME")}, args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("validate %v: %v\n%s%s", args, err, stdout.String(), stderr.String())
		}
		said := strings.Contains(stderr.String(), `msg="environment file: the default certistack setup recorded" path=`+envPath)
		if said != debug || strings.Contains(stdout.String(), "environment file") {
			t.Errorf("validate --debug=%v: stdout\n%s\nstderr\n%s", debug, stdout.String(), stderr.String())
		}
	}
}
