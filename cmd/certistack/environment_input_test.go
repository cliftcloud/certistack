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

func writeEnvFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "controller.env")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A controller environment file with a malformed port or boolean
// passed the loader, and the defaults then quietly replaced them: port 70000
// became 22, and "treu" left sudo off. The loader now refuses each, naming
// the variable and its line; an empty value is still a value left out.
func TestEnvironmentFileRefusesMalformedTypedValues(t *testing.T) {
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "")
	}
	for _, tc := range []struct {
		name, line, want string
	}{
		{"port above 65535", "CERTISTACK_SSH_PORT=70000", `"CERTISTACK_SSH_PORT" on line 2`},
		{"port zero", "CERTISTACK_SSH_PORT=0", "is not a port"},
		{"port with a suffix", "CERTISTACK_SSH_PORT=22abc", "is not a port"},
		{"negative port", "CERTISTACK_SSH_PORT=-1", "is not a port"},
		{"port with a sign", "CERTISTACK_SSH_PORT=+22", "is not a port"},
		{"a misspelled boolean", "CERTISTACK_SSH_SUDO=treu", `"CERTISTACK_SSH_SUDO" on line 2`},
		{"an unknown TLS spelling", "PVE_TLS_INSECURE=maybe", "is not true or false"},
		{"the lab opt-in spelled oddly", "CERTISTACK_ALLOW_INSECURE_TLS_FOR_LAB=yes", "is not true or false"},
		{"test mode spelled true", "CERTISTACK_ALLOW_TEST_MODE=true", "only 1 turns it on"},
		{"progress events spelled yes", "CERTISTACK_PROGRESS_EVENTS=yes", "only 1 turns it on"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeEnvFile(t, "PVE_URL=https://pve.example:8006\n"+tc.line+"\n")
			err := applyTestControllerEnvironment(t, path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if os.Getenv("PVE_URL") != "" {
				t.Fatal("the environment changed although the file was refused")
			}
		})
	}
	// Valid values, and empty ones, still load and are honoured.
	path := writeEnvFile(t, "CERTISTACK_SSH_PORT=2222\nCERTISTACK_SSH_SUDO=True\nPVE_TLS_INSECURE=false\nCERTISTACK_PROGRESS_EVENTS=1\nCERTISTACK_SSH_USER=\n")
	if err := applyTestControllerEnvironment(t, path); err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Int("ssh-port", 22, "")
	cmd.Flags().Bool("ssh-sudo", false, "")
	port, sudo := 22, false
	var strs [10]string
	if err := applyControllerEnvironmentDefaults(cmd, &strs[0], &strs[1], &strs[2], &strs[3], &strs[4], &strs[5], &port, &strs[6], &strs[7], &sudo); err != nil {
		t.Fatal(err)
	}
	if port != 2222 || !sudo {
		t.Fatalf("valid values were not honoured: port %d, sudo %v", port, sudo)
	}
}

// The inherited environment is held to the same rules, and an
// explicit flag still wins over a malformed variable.
func TestInheritedEnvironmentPortAndSudoAreValidated(t *testing.T) {
	for name, tc := range map[string]struct{ port, sudo, want string }{
		"port":      {"70000", "", "CERTISTACK_SSH_PORT"},
		"sudo":      {"", "treu", "CERTISTACK_SSH_SUDO"},
		"both fine": {"2200", "no", ""},
		"unset":     {"", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("CERTISTACK_SSH_PORT", tc.port)
			t.Setenv("CERTISTACK_SSH_SUDO", tc.sudo)
			cmd := &cobra.Command{Use: "test"}
			cmd.Flags().Int("ssh-port", 22, "")
			cmd.Flags().Bool("ssh-sudo", true, "")
			port, sudo := 22, true
			var strs [10]string
			err := applyControllerEnvironmentDefaults(cmd, &strs[0], &strs[1], &strs[2], &strs[3], &strs[4], &strs[5], &port, &strs[6], &strs[7], &sudo)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %s named", err, tc.want)
			}
		})
	}
	t.Setenv("CERTISTACK_SSH_PORT", "70000")
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Int("ssh-port", 22, "")
	if err := cmd.Flags().Set("ssh-port", "2022"); err != nil {
		t.Fatal(err)
	}
	port := 2022
	var strs [10]string
	sudo := false
	if err := applyControllerEnvironmentDefaults(cmd, &strs[0], &strs[1], &strs[2], &strs[3], &strs[4], &strs[5], &port, &strs[6], &strs[7], &sudo); err != nil {
		t.Fatalf("an explicit --ssh-port was refused for a variable it overrides: %v", err)
	}
}

// The size limit is applied to what is read, not only to what a stat
// saw. The trigger of the reporter, reproduced without a race: the file passes
// the checks at 24 bytes and grows to a megabyte before it is read. It used
// to be read whole by path; it is refused now, after at most the limit and a
// byte.
func TestEnvironmentFileGrowthCannotBypassTheLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grows.env")
	if err := os.WriteFile(path, []byte("PVE_URL=https://pve.example:8006\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	afterEnvironmentChecks = func(target string) {
		file, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer file.Close()
		if _, err := file.WriteString("PVE_TOKEN_SECRET=" + strings.Repeat("x", 4*maxEnvironmentFileBytes) + "\n"); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { afterEnvironmentChecks = nil })
	for name := range controllerEnvironmentNames {
		t.Setenv(name, "")
	}
	err := applyTestControllerEnvironment(t, path)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("a file that grew past the limit was loaded: %v", err)
	}
	if os.Getenv("PVE_TOKEN_SECRET") != "" || os.Getenv("PVE_URL") != "" {
		t.Fatal("part of a refused file was installed")
	}
	// A stable file over the limit, and one within it, as before.
	afterEnvironmentChecks = nil
	big := filepath.Join(dir, "big.env")
	if err := os.WriteFile(big, []byte("PVE_TOKEN_SECRET="+strings.Repeat("x", maxEnvironmentFileBytes)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseEnvironmentFile(big, controllerEnvironmentNames, "controller"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("an oversized file: %v", err)
	}
	ok := writeEnvFile(t, "PVE_URL=https://pve.example:8006\n")
	if values, err := parseEnvironmentFile(ok, controllerEnvironmentNames, "controller"); err != nil || values["PVE_URL"] == "" {
		t.Fatalf("a small file: %v %v", values, err)
	}
}
