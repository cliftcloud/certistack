// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// A password pasted under a typed variable's name (CERTISTACK_SSH_PORT=...,
// CERTISTACK_SSH_SUDO=...) was quoted back in the refusal when it was at most
// 32 plain characters and not shaped like a UUID or a 20-character token
// (IN-08). The refusal now describes what is wrong, without the value.
func TestATypedVariableNeverShowsItsValue(t *testing.T) {
	const password = "Zq7SecretValueKx9"
	for _, name := range []string{"CERTISTACK_SSH_PORT", "CERTISTACK_SSH_SUDO", "PVE_TLS_INSECURE"} {
		path := filepath.Join(t.TempDir(), "controller.env")
		if err := os.WriteFile(path, []byte(name+"="+password+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadControllerEnvironmentFile(path)
		if err == nil || strings.Contains(err.Error(), password) {
			t.Errorf("%s: the refusal shows the value: %v", name, err)
		}
	}
}

// --env-file "" (a script's unset variable, --env-file "$ENV") was taken for
// no --env-file: validate checked no file and said nothing of it, and run,
// plan, init and doctor read the process environment instead of the file the
// operator meant (IN-10). Every command that takes the flag refuses it empty.
func TestAnEmptyEnvFileFlagIsRefused(t *testing.T) {
	root := newRootCmd(nil)
	var commands []string
	var walk func(command *cobra.Command)
	walk = func(command *cobra.Command) {
		if command.Flags().Lookup("env-file") != nil {
			commands = append(commands, command.CommandPath())
		}
		for _, child := range command.Commands() {
			walk(child)
		}
	}
	walk(root)
	if len(commands) < 10 {
		t.Fatalf("only %d commands take --env-file: %v", len(commands), commands)
	}
	for _, path := range commands {
		for _, empty := range []string{"", "  "} {
			args := append(strings.Fields(strings.TrimPrefix(path, "certistack ")), "--env-file", empty)
			_, err := runRootWithInput(t, "", args...)
			if err == nil || !strings.Contains(err.Error(), "--env-file is empty") {
				t.Errorf("%s --env-file %q: %v, want --env-file is empty", path, empty, err)
			}
		}
	}
}

// validate refused a plan path that is a symbolic link, which run, plan and
// doctor follow and load; and in a directory it skipped a .yaml that is a
// link, a FIFO or a device without a word, and said "Validation complete: 1/1
// plans are valid" over a directory whose other plans it never read (IN-12).
// It reads a named path as run does, and names each entry it does not read.
func TestValidateChecksWhatRunReads(t *testing.T) {
	dir := t.TempDir()
	plan, err := os.ReadFile(filepath.Join("..", "..", "examples", "minimal-single-vm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(t.TempDir(), "nightly.yaml")
	if err := os.WriteFile(real, plan, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "weekly.yaml"), plan, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "nightly.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := runRootWithInput(t, "", "validate", link); err != nil {
		t.Errorf("validate refuses the linked plan that run loads: %v", err)
	}
	out, err := runRootWithInput(t, "", "validate", dir)
	if err == nil && !strings.Contains(out, "nightly.yaml") {
		t.Errorf("validate passed the directory without a word of nightly.yaml, which it did not read:\n%s", out)
	}
}
