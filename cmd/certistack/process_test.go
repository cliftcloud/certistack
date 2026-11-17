// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"os/exec"
	"testing"
)

// runMainEnvironment makes this test binary run main, as the CLI does, in
// the process it was started as. A test that needs the real process (real
// signals, real exit status, main's own signal handling) starts the test
// binary again with it set, instead of building the command.
const runMainEnvironment = "CERTISTACK_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	// The tests run on hosts that are no PVE node, with node names of their own
	// choosing, so the node-side check that a node name is the host's stands
	// aside, in this process and in the ones that run main; the tests of that
	// check put it back (onPVENode).
	verifyNodeIdentity = func(string) error { return nil }
	// Likewise the check that plan and init, without an SSH host, run on a PVE
	// node; the tests of that check say what the host is (onHost).
	hostIsPVENode = func() bool { return true }
	if os.Getenv(runMainEnvironment) == "1" {
		main()
		os.Exit(0)
	}
	// No test reads or writes the account's own per-user directory (its usage
	// statistics answer, the environment file certistack setup recorded): the
	// tests get an empty one of their own. A test that wants a recorded file
	// sets XDG_CONFIG_HOME itself.
	config, err := os.MkdirTemp("", "certistack-test-config-")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("XDG_CONFIG_HOME", config); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(config)
	os.Exit(code)
}

// cliProcess is the CLI as a process: this test binary running main with
// args, in an environment of only what is passed (and a private TMPDIR).
func cliProcess(t *testing.T, env []string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append([]string{runMainEnvironment + "=1", "TMPDIR=" + t.TempDir(), "HOME=" + t.TempDir()}, env...)
	return cmd
}
