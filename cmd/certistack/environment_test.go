// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestLoadControllerEnvironmentTreatsValuesAsLiteralsAndResolvesLocalPaths(t *testing.T) {
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "inherited")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "controller.env")
	contents := "# no shell syntax is evaluated\n" +
		"PVE_URL=\"https://pve.example:8006\"\n" +
		"PVE_TOKEN_ID='automation@pve!lab'\n" +
		"PVE_TOKEN_SECRET='literal-$(not-a-command)-${NO_EXPANSION}'\n" +
		"PBS_REPOSITORY=backup@pbs@pbs.example:store\n" +
		"PBS_PASSWORD='pa$$word'\n" +
		"CERTISTACK_SSH_KNOWN_HOSTS=secure/known_hosts\n" +
		"CERTISTACK_OUTPUT_DIR=secure/reports\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	if err := applyTestControllerEnvironment(t, path); err != nil {
		t.Fatalf("loadControllerEnvironment failed: %v", err)
	}
	if got := os.Getenv("PVE_TOKEN_SECRET"); got != "literal-$(not-a-command)-${NO_EXPANSION}" {
		t.Fatalf("secret was not treated as a literal: %q", got)
	}
	if got, want := os.Getenv("CERTISTACK_SSH_KNOWN_HOSTS"), filepath.Join(dir, "secure", "known_hosts"); got != want {
		t.Fatalf("known_hosts path = %q, want %q", got, want)
	}
	if got, want := os.Getenv("CERTISTACK_OUTPUT_DIR"), filepath.Join(dir, "secure", "reports"); got != want {
		t.Fatalf("output directory = %q, want %q", got, want)
	}
	if got := os.Getenv("PBS_FINGERPRINT"); got != "" {
		t.Fatalf("inherited controller environment leaked through: %q", got)
	}
	if got := os.Getenv(testModeOptInEnvironment); got != "" {
		t.Fatalf("inherited test-mode opt-in leaked through: %q", got)
	}
}

func TestLoadControllerEnvironmentAcceptsANodeWorkerRuntimeEnvFile(t *testing.T) {
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "")
	}

	// docs/configuration.md documents running `doctor --env-file` directly
	// against a node worker's own runtime.env (written by the controller for
	// the remote worker, not by an operator), to diagnose a stuck or failed
	// run in place. That file always carries CERTISTACK_PROGRESS_EVENTS=1;
	// doctor must accept it, not just a hand-authored controller-style file.
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime.env")
	contents := "PVE_URL=\"https://pve.example:8006\"\n" +
		"PVE_TOKEN_ID='automation@pve!lab'\n" +
		"PVE_TOKEN_SECRET='super-secret'\n" +
		"PBS_REPOSITORY=backup@pbs@pbs.example:store\n" +
		"PBS_PASSWORD='pa$$word'\n" +
		"CERTISTACK_PROGRESS_EVENTS=1\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	if err := applyTestControllerEnvironment(t, path); err != nil {
		t.Fatalf("doctor's env-file loader rejected a real node worker runtime.env: %v", err)
	}
	if got := os.Getenv("CERTISTACK_PROGRESS_EVENTS"); got != "1" {
		t.Fatalf("CERTISTACK_PROGRESS_EVENTS = %q, want %q", got, "1")
	}
}

func TestLoadControllerEnvironmentRejectsUnsupportedValuesWithoutChangingEnvironment(t *testing.T) {
	t.Setenv("PVE_URL", "https://inherited.example:8006")
	path := filepath.Join(t.TempDir(), "invalid.env")
	if err := os.WriteFile(path, []byte("PVE_URL=https://pve.example:8006\nPATH=/unsafe\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := applyTestControllerEnvironment(t, path); err == nil {
		t.Fatal("unsupported environment variable was accepted")
	}
	if got := os.Getenv("PVE_URL"); got != "https://inherited.example:8006" {
		t.Fatalf("environment changed after parse failure: %q", got)
	}
}

func TestParseEnvironmentFileRejectsGroupOrWorldPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not an ACL check on Windows")
	}
	path := filepath.Join(t.TempDir(), "insecure.env")
	if err := os.WriteFile(path, []byte("PVE_URL=https://pve.example:8006\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}

	if _, err := parseEnvironmentFile(path, controllerEnvironmentNames, "controller"); err == nil {
		t.Fatal("group-readable environment file was accepted")
	}
}

func TestApplyControllerEnvironmentDefaultsKeepsExplicitFlags(t *testing.T) {
	t.Setenv("CERTISTACK_NODE", "from-file-node")
	t.Setenv("CERTISTACK_SSH_HOST", "from-file-host")
	t.Setenv("CERTISTACK_SSH_USER", "from-file-user")
	t.Setenv("CERTISTACK_SSH_PORT", "2222")
	t.Setenv("CERTISTACK_SSH_SUDO", "false")
	t.Setenv("CERTISTACK_OUTPUT_DIR", "/controller/reports")

	cmd := &cobra.Command{Use: "test"}
	for _, name := range []string{"node", "scratch", "output", "state-dir", "ssh-host", "ssh-user", "ssh-identity", "ssh-known-hosts"} {
		cmd.Flags().String(name, "", "")
	}
	cmd.Flags().Int("ssh-port", 22, "")
	cmd.Flags().Bool("ssh-sudo", true, "")

	node, scratch, output, stateDir := "", "/remote/scratch", "/default/reports", "/remote/state"
	sshHost, sshUser, sshIdentity, sshKnownHosts := "", "certistack", "", ""
	sshPort, sshSudo := 22, true
	applyControllerEnvironmentDefaults(cmd, &node, &scratch, &output, &stateDir, &sshHost, &sshUser, &sshPort, &sshIdentity, &sshKnownHosts, &sshSudo)

	if node != "from-file-node" || sshHost != "from-file-host" || sshUser != "from-file-user" || sshPort != 2222 || sshSudo {
		t.Fatalf("environment defaults were not applied: node=%q host=%q user=%q port=%d sudo=%v", node, sshHost, sshUser, sshPort, sshSudo)
	}
	if output != "/controller/reports" {
		t.Fatalf("controller local defaults were not applied: output=%q", output)
	}

	if err := cmd.Flags().Set("ssh-user", "explicit-user"); err != nil {
		t.Fatal(err)
	}
	sshUser = "explicit-user"
	applyControllerEnvironmentDefaults(cmd, &node, &scratch, &output, &stateDir, &sshHost, &sshUser, &sshPort, &sshIdentity, &sshKnownHosts, &sshSudo)
	if sshUser != "explicit-user" {
		t.Fatalf("explicit command-line value was overridden: %q", sshUser)
	}
}

func TestRunDefaultsResolveAfterEnvironmentFileLoad(t *testing.T) {
	t.Setenv("CERTISTACK_SSH_HOST", "inherited-host")
	t.Setenv("CERTISTACK_SSH_PORT", "2299")
	cmd := runCmd()
	envFile := filepath.Join(t.TempDir(), "empty.env")
	if err := os.WriteFile(envFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyTestControllerEnvironment(t, envFile); err != nil {
		t.Fatal(err)
	}

	node, _ := cmd.Flags().GetString("node")
	scratch, _ := cmd.Flags().GetString("scratch")
	output, _ := cmd.Flags().GetString("output")
	stateDir, _ := cmd.Flags().GetString("state-dir")
	sshHost, _ := cmd.Flags().GetString("ssh-host")
	sshUser, _ := cmd.Flags().GetString("ssh-user")
	sshPort, _ := cmd.Flags().GetInt("ssh-port")
	sshIdentity, _ := cmd.Flags().GetString("ssh-identity")
	sshKnownHosts, _ := cmd.Flags().GetString("ssh-known-hosts")
	sshSudo, _ := cmd.Flags().GetBool("ssh-sudo")
	applyControllerEnvironmentDefaults(cmd, &node, &scratch, &output, &stateDir, &sshHost, &sshUser, &sshPort, &sshIdentity, &sshKnownHosts, &sshSudo)

	if sshHost != "" || sshPort != 22 {
		t.Fatalf("cleared environment leaked into run defaults: host=%q port=%d", sshHost, sshPort)
	}
}

// A port that is not a whole number from 1 to 65535 is an error, not a
// silent fall back to the default.
func TestEnvPortRequiresWholeValue(t *testing.T) {
	t.Setenv("CERTISTACK_SSH_PORT", "22abc")
	if got, err := envPortOrDefault("CERTISTACK_SSH_PORT", 22); err == nil {
		t.Fatalf("partial integer was accepted: %d", got)
	}
}

// The real run command, not a stand-in with the same flag names: a flag the
// operator typed beats the environment file's value, and an untouched one takes it.
func TestRunCommandExplicitFlagsBeatTheEnvironmentFile(t *testing.T) {
	t.Setenv("CERTISTACK_SSH_USER", "from-file-user")
	t.Setenv("CERTISTACK_SSH_HOST", "from-file-host")
	t.Setenv("CERTISTACK_SSH_PORT", "2222")
	cmd := runCmd()
	if err := cmd.Flags().Set("ssh-user", "explicit-user"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("ssh-port", "2022"); err != nil {
		t.Fatal(err)
	}
	node, _ := cmd.Flags().GetString("node")
	scratch, _ := cmd.Flags().GetString("scratch")
	output, _ := cmd.Flags().GetString("output")
	stateDir, _ := cmd.Flags().GetString("state-dir")
	sshHost, _ := cmd.Flags().GetString("ssh-host")
	sshUser, _ := cmd.Flags().GetString("ssh-user")
	sshPort, _ := cmd.Flags().GetInt("ssh-port")
	sshIdentity, _ := cmd.Flags().GetString("ssh-identity")
	sshKnownHosts, _ := cmd.Flags().GetString("ssh-known-hosts")
	sshSudo, _ := cmd.Flags().GetBool("ssh-sudo")
	applyControllerEnvironmentDefaults(cmd, &node, &scratch, &output, &stateDir, &sshHost, &sshUser, &sshPort, &sshIdentity, &sshKnownHosts, &sshSudo)
	if sshUser != "explicit-user" || sshPort != 2022 {
		t.Fatalf("the environment file overrode an explicit flag: user=%q port=%d", sshUser, sshPort)
	}
	if sshHost != "from-file-host" {
		t.Fatalf("an untouched flag did not take the environment file's value: host=%q", sshHost)
	}
}

// Quoting groups a literal and nothing else; anything that is not a clean
// single-line value is refused with a reason rather than guessed at.
func TestParseEnvironmentValueEdges(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		bad      bool
	}{
		{in: "", want: ""},
		{in: "plain", want: "plain"},
		{in: `'single quoted'`, want: "single quoted"},
		{in: `"double quoted"`, want: "double quoted"},
		{in: `''`, want: ""},
		{in: `""`, want: ""},
		{in: `'$(touch /tmp/x)'`, want: "$(touch /tmp/x)"},
		{in: "`id`", want: "`id`"},
		{in: `'it''s'`, want: "it''s"},
		{in: `"a'b"`, want: "a'b"},
		{in: `'unterminated`, bad: true},
		{in: `"unterminated`, bad: true},
		{in: `'mismatched"`, bad: true},
		{in: `"mismatched'`, bad: true},
		{in: `'`, bad: true},
		{in: `"`, bad: true},
		{in: "tab\tinside", want: "tab\tinside"},
		{in: "carriage\rreturn", bad: true},
		{in: "line\nbreak", bad: true},
		{in: "nul\x00byte", bad: true},
	} {
		got, err := parseEnvironmentValue(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("parseEnvironmentValue(%q) = %q, want an error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("parseEnvironmentValue(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

// docs/telemetry.md tells a container to opt in through its own environment,
// because the controller's literal loader refuses CERTISTACK_TELEMETRY in
// controller.env and leaves a variable the container set alone.
func TestControllerEnvironmentFileCannotSetTelemetryAndLeavesTheContainersOwn(t *testing.T) {
	t.Setenv("CERTISTACK_TELEMETRY", "1")
	path := filepath.Join(t.TempDir(), "controller.env")
	if err := os.WriteFile(path, []byte("PVE_URL=https://pve.example:8006\nCERTISTACK_TELEMETRY=0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyTestControllerEnvironment(t, path); err == nil || !strings.Contains(err.Error(), `unsupported controller environment variable "CERTISTACK_TELEMETRY"`) {
		t.Fatalf("a telemetry setting in controller.env: err = %v, want it refused as unsupported", err)
	}
	if err := os.WriteFile(path, []byte("PVE_URL=https://pve.example:8006\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyTestControllerEnvironment(t, path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("CERTISTACK_TELEMETRY"); got != "1" {
		t.Errorf("CERTISTACK_TELEMETRY = %q after loading controller.env, want the container's own 1", got)
	}
}
