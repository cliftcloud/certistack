// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package controller

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
	"github.com/cliftcloud/certistack/pkg/pve"
)

// The controller copies PVE_TLS_INSECURE and the lab opt-in from its own
// environment into the worker's runtime.env, not only from a dotenv file, so a
// service manager's "PVE_TLS_INSECURE=no" would stage a workspace whose own
// file the worker then refuses. Every operation refuses such a value first,
// naming the variable and what it accepts, before any command reaches the node.
func TestInheritedTypedEnvironmentIsRefusedBeforeAnythingIsStaged(t *testing.T) {
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("pve.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	options := RunOptions{NodeName: "audit-node", StateDir: "/var/lib/certistack", SSH: SSHConfig{Host: "pve.example", User: "root", Port: 22, KnownHostsFile: knownHosts}}
	for _, name := range []string{"PVE_TLS_INSECURE", pve.InsecureTLSLabOptInEnv, "CERTISTACK_ALLOW_TEST_MODE"} {
		for _, value := range []string{"yes", "no", "on", "treu", "2"} {
			t.Run(name+"="+value, func(t *testing.T) {
				t.Setenv("PVE_URL", "https://pve.example:8006")
				t.Setenv("PVE_TOKEN_ID", "audit@pve!token")
				t.Setenv("PVE_TOKEN_SECRET", "audit-pve-secret")
				t.Setenv("PBS_REPOSITORY", "audit@pbs!token@pbs.example:8007:store")
				t.Setenv("PBS_PASSWORD", "audit-pbs-secret")
				t.Setenv(name, value)
				fake := &fakeCommandRunner{}
				executor := &Executor{runner: fake}
				_, discoverErr := executor.Discover(context.Background(), options, initplan.Request{Node: "audit-node"})
				if discoverErr == nil || !strings.Contains(discoverErr.Error(), name) || !strings.Contains(discoverErr.Error(), "is not") {
					t.Fatalf("discover: %v, want %s named with what it accepts", discoverErr, name)
				}
				if _, err := controllerRuntimeEnv("/var/lib/certistack/workers/w"); err == nil || !strings.Contains(err.Error(), name) {
					t.Fatalf("the runtime environment was built with %s=%s: %v", name, value, err)
				}
				if len(fake.calls) != 0 {
					t.Fatalf("a command reached the node before the value was refused: %v", fake.calls)
				}
			})
		}
	}
	// The values both sides accept still work end to end.
	for _, value := range []string{"true", "false", "1", "0", "TRUE"} {
		t.Setenv("PVE_TLS_INSECURE", value)
		t.Setenv(pve.InsecureTLSLabOptInEnv, value)
		if err := checkInheritedTypedEnvironment(); err != nil {
			t.Errorf("value %q was refused: %v", value, err)
		}
	}
	// Unset or empty is a value left out.
	t.Setenv("PVE_TLS_INSECURE", "")
	if err := checkInheritedTypedEnvironment(); err != nil {
		t.Errorf("an empty value was refused: %v", err)
	}
}
