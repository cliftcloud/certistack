// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/internal/nodecheck"
)

// withoutTokenVariables rewrites a controller's environment file without the
// PVE token, as a handover file has it: the token is created only after SSH
// works and the access script has run on the node.
func withoutTokenVariables(t *testing.T, c controllerDir, names ...string) {
	t.Helper()
	if len(names) == 0 {
		names = checkTokenVariables
	}
	data, err := os.ReadFile(c.env)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		drop := false
		for _, name := range names {
			drop = drop || strings.HasPrefix(line, name+"=")
		}
		if !drop {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(c.env, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Layer 1 asks only for what layers 2 to 4 and 6 need. The PVE token can only
// exist after SSH works, so a handover file without it still learns whether the
// SSH files, the host key, the connection and the node's tools are right; layer
// 5 is where the missing token fails, with the access script as the fix.
func TestCheckWithoutAPVETokenStillChecksLayers1To4AndFailsLayer5(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the golden output is for an x86_64 controller")
	}
	c := readyController(t)
	withoutTokenVariables(t, c)
	stub := &nodeStub{}
	withNode(t, stub)
	secretBefore, tokenBefore := os.Getenv("PVE_TOKEN_SECRET"), os.Getenv("PVE_TOKEN_ID")

	out, err := failsAt(t, c)
	assertGolden(t, "check_no_token.golden", maskDir(out, c.dir))
	for _, want := range []string{
		"✓ 1. Environment file", "the 5 required variables are set",
		"✓ 2. SSH files", "✓ 3. SSH connection", "✓ 4. Node tools",
		"✗ 5. PVE API", "PVE_TOKEN_ID and PVE_TOKEN_SECRET are not set in " + c.env,
		"Fix: The PVE token does not exist yet",
		"certistack setup rbac --node pve-node-01 --overlay-storage <storage> --pbs-datastore datastore > certistack-access.sh",
		"run PART 1 as root on the PVE node", "put PVE_TOKEN_ID and PVE_TOKEN_SECRET in " + c.env,
		"- 6. PBS", "not checked",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if exitCodeForError(err) != exitCodeInfrastructure {
		t.Errorf("exit status %d, want %d", exitCodeForError(err), exitCodeInfrastructure)
	}

	// The worker was staged once, for the tools, and told to stop there: PVE was
	// never asked, with a token or without one.
	if len(stub.staged) != 1 || stub.through[0] != nodecheck.LayerTools {
		t.Errorf("staged %d time(s), through %v; want once, through %s", len(stub.staged), stub.through, nodecheck.LayerTools)
	}
	// Staging needs the variables set; they held a marker, not a credential, and
	// the environment is as it was afterwards.
	for _, name := range checkTokenVariables {
		if value := stub.environmentAt[name]; value == "" || !strings.HasPrefix(value, "not-set-") {
			t.Errorf("%s was %q while the worker was staged, want a not-set marker", name, value)
		}
	}
	if os.Getenv("PVE_TOKEN_SECRET") != secretBefore || os.Getenv("PVE_TOKEN_ID") != tokenBefore {
		t.Error("the markers stayed in the process environment")
	}
}

func TestCheckNamesTheTokenVariableThatIsMissing(t *testing.T) {
	for _, c := range []struct {
		drop string
		want string
	}{
		{"PVE_TOKEN_SECRET", "PVE_TOKEN_SECRET is not set in"},
		{"PVE_TOKEN_ID", "PVE_TOKEN_ID is not set in"},
	} {
		ctl := readyController(t, "CERTISTACK_OVERLAY_STORAGE=certistack-scratch")
		withoutTokenVariables(t, ctl, c.drop)
		withNode(t, &nodeStub{})
		out, _ := failsAt(t, ctl)
		if !strings.Contains(out, "✗ 5. PVE API") || !strings.Contains(out, c.want) {
			t.Errorf("without %s:\n%s", c.drop, out)
		}
		// The overlay storage the file names goes into the command.
		if !strings.Contains(out, "--overlay-storage certistack-scratch --pbs-datastore datastore > certistack-access.sh") {
			t.Errorf("without %s, the command does not use the file's storage:\n%s", c.drop, out)
		}
	}
}

// With the token present the whole node check runs, and nothing asks it to stop.
func TestCheckWithATokenAsksTheWorkerForEveryLayer(t *testing.T) {
	c := readyController(t)
	stub := &nodeStub{}
	withNode(t, stub)
	if out, err := runRootWithInput(t, "", "check", "--env-file", c.env); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(stub.through) != 1 || stub.through[0] != "" {
		t.Errorf("through = %v, want one full check", stub.through)
	}
	if stub.environmentAt["PVE_TOKEN_ID"] != "certistack-svc@pve!automation" {
		t.Errorf("the file's token was not what the worker was staged with: %q", stub.environmentAt["PVE_TOKEN_ID"])
	}
}

// A problem in a layer before the token's still comes first.
func TestCheckReportsAToolsProblemBeforeTheMissingToken(t *testing.T) {
	c := readyController(t)
	withoutTokenVariables(t, c)
	withNode(t, &nodeStub{report: nodecheck.Report{Layers: []nodecheck.Layer{{
		Name: nodecheck.LayerTools, Status: nodecheck.StatusFailed, Code: nodecheck.CodeToolsMissing,
		Detail:  "not installed on the node (or not on its PATH): guestfish",
		Missing: []nodecheck.Tool{{Name: "guestfish", Package: "libguestfs-tools"}},
	}}}})
	out, _ := failsAt(t, c)
	if !strings.Contains(out, "✗ 4. Node tools") || !strings.Contains(out, "apt install --no-upgrade libguestfs-tools") || strings.Contains(out, "PVE token does not exist yet") {
		t.Errorf("output:\n%s", out)
	}
}

// A node that cannot be staged is reported at the tools layer, as before, even
// when there is no token.
func TestCheckReportsAStagingFailureWithoutAToken(t *testing.T) {
	c := readyController(t)
	withoutTokenVariables(t, c)
	withNode(t, &nodeStub{stagingError: errors.New("create protected node workspace: Permission denied")})
	out, _ := failsAt(t, c)
	if !strings.Contains(out, "✗ 4. Node tools") || !strings.Contains(out, "CERTISTACK_SSH_SUDO=true") {
		t.Errorf("output:\n%s", out)
	}
}

// The command shown to the operator holds only words that are safe to paste;
// anything else is a placeholder.
func TestMissingTokenFixFillsInOnlySafeWords(t *testing.T) {
	t.Setenv("CERTISTACK_NODE", "pve-node-01")
	t.Setenv("CERTISTACK_OVERLAY_STORAGE", "")
	t.Setenv("PBS_REPOSITORY", "certistack-ro@pbs!ro@pbs.example.com:8007:backup-anchor")
	fix := missingTokenFix("/secure/controller.env")
	if !strings.Contains(fix, "certistack setup rbac --node pve-node-01 --overlay-storage <storage> --pbs-datastore backup-anchor > certistack-access.sh") {
		t.Errorf("fix:\n%s", fix)
	}
	t.Setenv("CERTISTACK_NODE", "pve; reboot")
	t.Setenv("CERTISTACK_OVERLAY_STORAGE", "$(id)")
	t.Setenv("PBS_REPOSITORY", "u@pbs:8007:data store")
	fix = missingTokenFix("/secure/controller.env")
	if !strings.Contains(fix, "--node <node> --overlay-storage <storage> --pbs-datastore <ds> >") || strings.Contains(fix, "reboot") || strings.Contains(fix, "$(id)") {
		t.Errorf("unsafe values were put into the command:\n%s", fix)
	}
	t.Setenv("PBS_REPOSITORY", "no-datastore-here")
	if got := repositoryDatastore("no-datastore-here"); got != "" {
		t.Errorf("repositoryDatastore = %q", got)
	}
}
