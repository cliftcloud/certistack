// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package repocontract

import (
	"strings"
	"testing"
)

// The guest-network tests that ask netplan's own generator which
// networkd file wins over the recovery profile skip where it is not installed.
// The Linux jobs that run the Go suite (CI's test job and the release gate)
// install netplan before the tests and set CERTISTACK_REQUIRE_NETPLAN, which
// turns a missing generator into a failure, so the guard cannot disappear
// silently on an image without it.
func TestWorkflowsInstallNetplanAndRequireIt(t *testing.T) {
	for _, c := range []struct{ workflow, job string }{{"ci.yml", "test"}, {"release.yml", "verify"}} {
		job, ok := readWorkflow(t, c.workflow).Jobs[c.job]
		if !ok {
			t.Fatalf("%s has no job %q", c.workflow, c.job)
		}
		if job.Env["CERTISTACK_REQUIRE_NETPLAN"] == "" {
			t.Errorf("%s %s does not set CERTISTACK_REQUIRE_NETPLAN, so a runner without netplan would skip the guest-network guard", c.workflow, c.job)
		}
		install, firstTest := -1, -1
		for i, step := range job.Steps {
			if strings.Contains(step.Run, "install") && strings.Contains(step.Run, "netplan.io") && install < 0 {
				install = i
				if step.If != "" || step.ContinueOnError != nil {
					t.Errorf("%s %s: the step %q that installs netplan is conditional or may fail silently", c.workflow, c.job, step.Name)
				}
			}
			if (strings.Contains(step.Run, "go test") || strings.Contains(step.Run, "make test")) && firstTest < 0 {
				firstTest = i
			}
		}
		switch {
		case install < 0:
			t.Errorf("%s %s never installs netplan (the netplan.io package)", c.workflow, c.job)
		case firstTest < 0:
			t.Fatalf("%s %s runs no Go tests; this check is looking in the wrong place", c.workflow, c.job)
		case install > firstTest:
			t.Errorf("%s %s installs netplan (step %d) after its first Go test (step %d)", c.workflow, c.job, install+1, firstTest+1)
		}
	}
}

// Windows has no netplan: the portability job must not require it.
func TestWindowsJobDoesNotRequireNetplan(t *testing.T) {
	job, ok := readWorkflow(t, "ci.yml").Jobs["windows-portability"]
	if !ok {
		t.Fatal("ci.yml has no windows-portability job")
	}
	if job.Env["CERTISTACK_REQUIRE_NETPLAN"] != "" {
		t.Error("the Windows job requires netplan, which does not exist there")
	}
}
