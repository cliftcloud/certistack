// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/preflight"
	"github.com/cliftcloud/certistack/pkg/config"
	"github.com/cliftcloud/certistack/pkg/runner"
)

// readyHost gives doctor a host whose preflight passes, and (when sources is
// not nil) a PVE node that has proxmox-backup-client and answers sources for the
// plan's VMs. It returns the arguments that put doctor's scratch and state
// directories in a temporary directory.
func readyHost(t *testing.T, sources func(context.Context, *config.Plan, runner.Options) ([]runner.SourceCheck, error)) (root string, args []string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("doctor's plan checks run on Linux")
	}
	clearControllerEnvironment(t)
	previousPreflight, previousClient, previousSources := runPreflight, hasBackupClient, checkPlanSources
	t.Cleanup(func() {
		runPreflight, hasBackupClient, checkPlanSources = previousPreflight, previousClient, previousSources
	})
	runPreflight = func(context.Context, *config.Plan, preflight.Options) preflight.Result {
		return preflight.Result{Ready: true, Checks: []preflight.CheckItem{{Name: "kvm", Status: "passed", Detail: "/dev/kvm is accessible"}}}
	}
	if sources != nil {
		hasBackupClient = func() bool { return true }
		checkPlanSources = sources
	} else {
		hasBackupClient = func() bool { return false }
	}
	root = t.TempDir()
	return root, []string{"--scratch", filepath.Join(root, "scratch"), "--state-dir", root}
}

func failedSource(context.Context, *config.Plan, runner.Options) ([]runner.SourceCheck, error) {
	return []runner.SourceCheck{{VMID: 9100, Status: runner.SourceFailed,
		Detail: "resolve PBS snapshot for target VM 9100 (list PBS snapshots for vm/7011: exit status 255 (client output withheld; 42 bytes))"}}, nil
}

// A newcomer runs doctor on the node with the plan and no environment file: the
// PBS listing fails with the client's withheld 255, and nothing said that no
// credentials were passed (hardening F12, CR1-12).
func TestDoctorSaysWhenNoPBSCredentialsWerePassed(t *testing.T) {
	root, args := readyHost(t, failedSource)
	t.Setenv("PBS_PASSWORD", "")
	out, err := runRootWithInput(t, "", append([]string{"doctor", planWithScratch(t, root, "")}, args...)...)
	if err == nil {
		t.Fatalf("doctor passed with a failing backup:\n%s", out)
	}
	for _, want := range []string{"backup_vm_9100", "exit status 255", "no PBS credentials were passed", "--env-file", "certistack check"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "System is ready") {
		t.Errorf("a failed doctor says the system is ready:\n%s", out)
	}
}

// ... and says nothing of the kind when a PBS credential is in the environment,
// where the failure is something else.
func TestDoctorDoesNotBlameMissingCredentialsWhenTheyWerePassed(t *testing.T) {
	root, args := readyHost(t, failedSource)
	t.Setenv("PBS_PASSWORD", "a-token-secret")
	out, err := runRootWithInput(t, "", append([]string{"doctor", planWithScratch(t, root, "")}, args...)...)
	if err == nil {
		t.Fatalf("doctor passed with a failing backup:\n%s", out)
	}
	if strings.Contains(out, "no PBS credentials") || strings.Contains(out, "a-token-secret") {
		t.Errorf("the output blames missing credentials, or prints one:\n%s", out)
	}
}
