// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// spyOnInitDiscovery reports whether init reached the node. The discovery
// fails, so a test that gets past the output checks stops there.
func spyOnInitDiscovery(t *testing.T) *bool {
	t.Helper()
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "")
	}
	previous := runnerDiscover
	t.Cleanup(func() { runnerDiscover = previous })
	reached := new(bool)
	runnerDiscover = func(context.Context, initplan.Request, string) (*initplan.Discovery, error) {
		*reached = true
		return nil, errors.New("test: the node was reached")
	}
	return reached
}

// mkdirAdvice is the command the messages give, for a directory that needs no
// quoting; TestMkdirCommand pins the text itself.
func mkdirAdvice(dir string) string { return mkdirCommand(dir) }

func TestMkdirCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		if got := mkdirCommand(`C:\plans`); got != `mkdir C:\plans` {
			t.Errorf("mkdirCommand = %q", got)
		}
		if got := mkdirCommand(`C:\my plans`); got != `mkdir "C:\my plans"` {
			t.Errorf("mkdirCommand = %q", got)
		}
		return
	}
	for in, want := range map[string]string{
		"plans":       "mkdir -p plans",
		"a/b/c":       "mkdir -p a/b/c",
		"/srv/my dir": "mkdir -p '/srv/my dir'",
	} {
		if got := mkdirCommand(in); got != want {
			t.Errorf("mkdirCommand(%q) = %q, want %q", in, got, want)
		}
	}
}

// A plan written into a directory that is not there is found before init
// reads the node (a minute of discovery a newcomer would wait for), and says
// which directory is missing and the command that creates it.
func TestInitSaysWhichOutputDirectoryIsMissingBeforeReadingTheNode(t *testing.T) {
	reached := spyOnInitDiscovery(t)
	base := t.TempDir()
	dir := filepath.Join(base, "some", "missing", "dir")
	for _, force := range []bool{false, true} {
		args := []string{"init", "--node", "pve1", "--vm", "100", "--output", filepath.Join(dir, "plan.yaml")}
		if force {
			args = append(args, "--force")
		}
		_, _, err := runInit(t, context.Background(), args...)
		if err == nil {
			t.Fatalf("force=%v: init accepted a plan in a directory that does not exist", force)
		}
		for _, want := range []string{dir, "does not exist", mkdirAdvice(dir), "--output"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("force=%v: the error lacks %q: %v", force, want, err)
			}
		}
		if strings.Count(err.Error(), "\n") != 0 {
			t.Errorf("force=%v: the message is more than one line: %q", force, err)
		}
		if *reached {
			t.Errorf("force=%v: init read the node before it found the output directory missing", force)
		}
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Errorf("init left %d entries behind in %s", len(entries), base)
	}
}

// The write itself says the same if the directory goes away after the check,
// and leaves no temporary file.
func TestWritePlanFileSaysWhichDirectoryIsMissing(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "gone")
	err := writePlanFile(filepath.Join(dir, "plan.yaml"), []byte("version: 1\n"), false)
	if err == nil {
		t.Fatal("a plan was written into a directory that does not exist")
	}
	for _, want := range []string{dir, "does not exist", mkdirAdvice(dir)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Errorf("left %d entries behind", len(entries))
	}
}

// A directory that exists and cannot be written to gets a one-line cause, before
// the node is read, and no file is left.
func TestInitSaysWhyTheOutputDirectoryCannotBeWritten(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a read-only directory stops nobody on Windows or as root")
	}
	reached := spyOnInitDiscovery(t)
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	_, _, err := runInit(t, context.Background(), "init", "--node", "pve1", "--vm", "100", "--output", filepath.Join(dir, "plan.yaml"))
	if err == nil {
		t.Fatal("init accepted a plan in a directory it cannot write to")
	}
	for _, want := range []string{dir, "cannot write", "permission denied", "--output"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	if strings.Count(err.Error(), "\n") != 0 {
		t.Errorf("the message is more than one line: %q", err)
	}
	if *reached {
		t.Error("init read the node before it found the directory unwritable")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("init left %d entries in the directory", len(entries))
	}
}

// An output that exists is refused first, before the output directory is
// checked, and the directory check does not replace that refusal or its
// wording.
func TestInitKeepsItsRefusalOfAnExistingOutput(t *testing.T) {
	reached := spyOnInitDiscovery(t)
	existing := filepath.Join(t.TempDir(), "plan.yaml")
	if err := os.WriteFile(existing, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := runInit(t, context.Background(), "init", "--node", "pve1", "--vm", "100", "--output", existing)
	want := existing + " exists; choose another --output, or pass --force to replace it"
	if err == nil || err.Error() != want {
		t.Fatalf("init with an existing output: %v, want %q", err, want)
	}
	if *reached {
		t.Error("init read the node although the output exists")
	}
	if data, _ := os.ReadFile(existing); string(data) != "keep me\n" {
		t.Errorf("the existing file was changed: %q", data)
	}
}

// The list of backups writes no plan, so a missing output directory is no
// reason to refuse it.
func TestInitListingIgnoresTheOutputDirectory(t *testing.T) {
	reached := spyOnInitDiscovery(t)
	dir := filepath.Join(t.TempDir(), "missing")
	_, _, err := runInit(t, context.Background(), "init", "--node", "pve1", "--output", filepath.Join(dir, "plan.yaml"))
	if err == nil || !strings.Contains(err.Error(), "the node was reached") {
		t.Fatalf("the listing was refused for the output directory: %v", err)
	}
	if !*reached {
		t.Error("the listing did not read the node")
	}
}

// The advice quotes a directory that a shell would split.
func TestQuoteForShell(t *testing.T) {
	for in, want := range map[string]string{
		"plans":              "plans",
		"/var/lib/x-y_z.1":   "/var/lib/x-y_z.1",
		"my plans":           "'my plans'",
		"it's":               `'it'\''s'`,
		"a;b":                "'a;b'",
		"$(id)":              "'$(id)'",
		"":                   "''",
		"~/certistack plans": "'~/certistack plans'",
	} {
		if got := quoteForShell(in); got != want {
			t.Errorf("quoteForShell(%q) = %s, want %s", in, got, want)
		}
	}
}

// An environment file in a directory that does not exist says so, and keeps
// the message the guides quote.
func TestEnvironmentFileInAMissingDirectorySaysSo(t *testing.T) {
	spyOnInitDiscovery(t)
	dir := filepath.Join(t.TempDir(), "secure", "certistack")
	path := filepath.Join(dir, "controller.env")
	_, _, err := runInit(t, context.Background(), "init", "--node", "pve1", "--vm", "100", "--env-file", path)
	if err == nil {
		t.Fatal("init accepted an environment file that is not there")
	}
	for _, want := range []string{"open controller environment file: open " + path + ": ", "(the directory " + dir + " does not exist either)"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	// A missing file in a directory that is there says nothing of a directory.
	_, _, err = runInit(t, context.Background(), "init", "--node", "pve1", "--vm", "100", "--env-file", filepath.Join(t.TempDir(), "controller.env"))
	if err == nil || strings.Contains(err.Error(), "does not exist either") {
		t.Errorf("a missing file in an existing directory: %v", err)
	}
}

// init, plan and run with an environment file that is not there say what check
// says: run certistack setup (or write the file by hand), not "make the
// directory and write the file".
func TestAMissingEnvironmentFileSendsInitPlanAndRunToTheSetup(t *testing.T) {
	spyOnInitDiscovery(t)
	plan := writeValidationFixture(t, t.TempDir(), "plan.yaml")
	for _, dir := range []string{t.TempDir(), filepath.Join(t.TempDir(), "secure", "certistack")} {
		missing := filepath.Join(dir, "controller.env")
		for name, args := range map[string][]string{
			"init": {"init", "--node", "pve1", "--vm", "100", "--env-file", missing},
			"plan": {"plan", plan, "--env-file", missing},
			"run":  {"run", plan, "--env-file", missing},
		} {
			_, _, err := runInit(t, context.Background(), args...)
			if err == nil {
				t.Errorf("%s accepted an environment file that is not there", name)
				continue
			}
			for _, want := range []string{
				"open controller environment file: open " + missing + ": ",
				"Run certistack setup (quickstart step 2): it asks for a directory and writes controller.env there.",
				`Or write the file by hand (docs/manual-setup.md, "Set up by hand")`,
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("%s: the error lacks %q: %v", name, want, err)
				}
			}
			if strings.Contains(err.Error(), "mkdir") || strings.Contains(err.Error(), "create it with") {
				t.Errorf("%s: the error sends the reader to make the directory and write the file: %v", name, err)
			}
		}
	}
}

// check says the same about an environment file whose directory is not there,
// at layer 1, and keeps its generic fix.
func TestCheckLayer1SaysWhichDirectoryOfTheEnvironmentFileIsMissing(t *testing.T) {
	withNode(t, &nodeStub{})
	dir := filepath.Join(t.TempDir(), "secure", "certistack")
	missing := controllerDir{dir: dir, env: filepath.Join(dir, "controller.env")}
	out, _ := failsAt(t, missing)
	for _, want := range []string{"✗ 1. Environment file", missing.env + " does not exist", "the directory " + dir + " does not exist either", "quickstart step 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("layer 1 lacks %q:\n%s", want, out)
		}
	}
}

// With no --output the plan goes to the current directory, and the message
// names that directory instead of ".".
func TestInitNamesTheCurrentDirectoryWhenItCannotBeWritten(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a read-only directory stops nobody on Windows or as root")
	}
	reached := spyOnInitDiscovery(t)
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	t.Chdir(dir)
	_, _, err := runInit(t, context.Background(), "init", "--node", "pve1", "--vm", "100")
	if err == nil {
		t.Fatal("init accepted a plan in a directory it cannot write to")
	}
	for _, want := range []string{"the current directory", "cannot write", "permission denied", "--output"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "directory . ") {
		t.Errorf("the message calls the current directory \".\": %v", err)
	}
	if *reached {
		t.Error("init read the node before it found the directory unwritable")
	}
}
