// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The environment files the appliance and container guides tell an
// operator to create are accepted, as shipped, by the loader the appliance
// wrapper points at them, and once loaded they supply what every run needs.
// (One first-boot failure was "controller secret environment variable
// PVE_URL is required": nothing loaded the file.)
func TestShippedControllerEnvironmentExamplesLoadForARun(t *testing.T) {
	for name := range controllerEnvironmentNames {
		t.Setenv(name, os.Getenv(name))
	}
	for _, example := range []string{
		filepath.Join("..", "..", "deploy", "appliance", "files", "controller.env.example"),
		filepath.Join("..", "..", "deploy", "controller", "secrets", "controller.env.example"),
	} {
		data, err := os.ReadFile(example)
		if err != nil {
			t.Fatal(err)
		}
		// Loaded from a private copy, as the guides make it: mode 0600.
		file := filepath.Join(t.TempDir(), "controller.env")
		if err := os.WriteFile(file, data, 0o600); err != nil {
			t.Fatal(err)
		}
		for name := range controllerEnvironmentNames {
			os.Unsetenv(name)
		}
		if err := applyTestControllerEnvironment(t, file); err != nil {
			t.Errorf("%s: the loader refuses the example: %v", example, err)
			continue
		}
		for _, name := range []string{"PVE_URL", "PVE_TOKEN_ID", "PVE_TOKEN_SECRET", "PBS_REPOSITORY", "PBS_PASSWORD"} {
			if os.Getenv(name) == "" {
				t.Errorf("%s: %s is not set after loading, so a run would refuse to start", example, name)
			}
		}
	}
}

// The appliance wrapper adds --env-file to a fixed list of commands. Each
// must accept the flag (a command that does not would fail on it), and every
// controller command that takes the file must be on the list.
func TestApplianceWrapperEnvFileCommandsTakeTheFlag(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "deploy", "appliance", "files", "certistack-controller"))
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^\s*([a-z|-]+)\)\n\s*subcommand=`).FindSubmatch(script)
	if match == nil {
		t.Fatal("the wrapper has no command list for --env-file")
	}
	listed := map[string]bool{}
	for _, name := range strings.Split(string(match[1]), "|") {
		listed[name] = true
	}
	root := rootCmd()
	for name := range listed {
		sub, _, err := root.Find([]string{name})
		if err != nil || sub == root || sub.Flags().Lookup("env-file") == nil {
			t.Errorf("the wrapper adds --env-file to %q, which does not take it", name)
		}
	}
	// Commands the controller appliance runs that read the controller
	// environment. recover and node-run are node-side and take a worker
	// environment file from the workspace instead.
	for _, name := range []string{"run", "plan", "doctor", "init", "validate"} {
		if !listed[name] {
			t.Errorf("the wrapper does not give %q the environment file", name)
		}
	}
	// And every command a person types that takes the file is listed, so a
	// command given the flag later is not left without it on the appliance.
	for _, sub := range root.Commands() {
		// recover runs on a node, with a worker environment file.
		if sub.Name() == "recover" {
			continue
		}
		if !sub.Hidden && sub.Flags().Lookup("env-file") != nil && !listed[sub.Name()] {
			t.Errorf("%q takes --env-file, and the wrapper does not give it the environment file", sub.Name())
		}
	}
}
